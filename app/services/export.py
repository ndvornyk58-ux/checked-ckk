"""Reports & Export — выгрузка записей и отчётов в JSON, CSV, XLSX, HTML, PDF.

Защита значений (ADR-0003) распространяется и на экспорт:
* по умолчанию столбец значения маскируется (``••••••``) — выгружается только длина;
* выгрузка значений в открытом виде возможна лишь при явном ``reveal_values=True``; тогда
  требуется разблокированное хранилище, факт выгрузки пишется в журнал операций, а в заголовке
  отчёта ставится предупреждение. Это сознательное действие пользователя, а не настройка по умолчанию.

Экспорт потоковый, насколько позволяет формат: JSON/JSONL и CSV пишутся по мере выборки страницами
(keyset-пагинация), память не растёт с числом записей. XLSX и PDF формат держит в памяти, поэтому
для них действует предел ``MAX_ROWS_IN_MEMORY`` с понятной ошибкой.
"""

from __future__ import annotations

import csv
import html
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.domain import MASK
from app.infrastructure.crypto import CryptoBox
from app.infrastructure.db.mapping import to_domain
from app.infrastructure.db.models import CookieRow
from app.services.common import now_ts, record_operation
from app.services.cookies import CookieFilter, CookieService, SortKey

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger(__name__)

PAGE: Final = 1000
MAX_ROWS_IN_MEMORY: Final = 200_000
# Шрифты для PDF поставляются с приложением (кириллица в стандартных шрифтах ReportLab отсутствует).
FONT_DIR: Final = Path(__file__).resolve().parents[2] / "resources" / "fonts"
_PDF_FONT = "DejaVuSans"
_PDF_FONT_BOLD = "DejaVuSans-Bold"
_fonts_registered = False


def _register_pdf_fonts() -> tuple[str, str]:
    """Зарегистрировать кириллические шрифты для PDF. При их отсутствии — стандартный Helvetica."""
    global _fonts_registered
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    regular, bold = FONT_DIR / "DejaVuSans.ttf", FONT_DIR / "DejaVuSans-Bold.ttf"
    if not regular.is_file():
        log.warning("Шрифт для PDF не найден (%s); кириллица может отображаться неверно", regular)
        return "Helvetica", "Helvetica-Bold"
    if not _fonts_registered:
        pdfmetrics.registerFont(TTFont(_PDF_FONT, str(regular)))
        pdfmetrics.registerFont(TTFont(_PDF_FONT_BOLD, str(bold if bold.is_file() else regular)))
        _fonts_registered = True
    return _PDF_FONT, _PDF_FONT_BOLD


class ExportFormat(StrEnum):
    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"
    XLSX = "xlsx"
    HTML = "html"
    PDF = "pdf"

    @property
    def extension(self) -> str:
        return "." + self.value

    @property
    def streaming(self) -> bool:
        return self in (ExportFormat.JSON, ExportFormat.JSONL, ExportFormat.CSV)


class Column(StrEnum):
    NAME = "name"
    DOMAIN = "domain"
    PATH = "path"
    VALUE = "value"  # маскируется, если не reveal_values
    VALUE_LENGTH = "value_length"
    HOST_ONLY = "host_only"
    SECURE = "secure"
    HTTP_ONLY = "http_only"
    SAME_SITE = "same_site"
    EXPIRES_AT = "expires_at"
    VALIDATION_STATUS = "validation_status"
    MAX_SEVERITY = "max_severity"
    IS_TEST_SESSION = "is_test_session"


COLUMN_LABELS: Final[dict[Column, str]] = {
    Column.NAME: "Имя",
    Column.DOMAIN: "Домен",
    Column.PATH: "Путь",
    Column.VALUE: "Значение",
    Column.VALUE_LENGTH: "Длина значения",
    Column.HOST_ONLY: "Host-only",
    Column.SECURE: "Secure",
    Column.HTTP_ONLY: "HttpOnly",
    Column.SAME_SITE: "SameSite",
    Column.EXPIRES_AT: "Истекает",
    Column.VALIDATION_STATUS: "Статус",
    Column.MAX_SEVERITY: "Критичность",
    Column.IS_TEST_SESSION: "Тестовая сессия",
}
DEFAULT_COLUMNS: Final[tuple[Column, ...]] = (
    Column.NAME,
    Column.DOMAIN,
    Column.PATH,
    Column.VALUE_LENGTH,
    Column.SECURE,
    Column.HTTP_ONLY,
    Column.SAME_SITE,
    Column.EXPIRES_AT,
    Column.VALIDATION_STATUS,
    Column.MAX_SEVERITY,
)


class ExportError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ExportOptions:
    fmt: ExportFormat
    columns: tuple[Column, ...] = DEFAULT_COLUMNS
    reveal_values: bool = False
    sort: SortKey = SortKey.DOMAIN
    descending: bool = False
    title: str = "Отчёт по cookies"

    def resolved_columns(self) -> tuple[Column, ...]:
        cols = self.columns or DEFAULT_COLUMNS
        if self.reveal_values and Column.VALUE not in cols:
            cols = (*cols, Column.VALUE)
        return cols


@dataclass(frozen=True, slots=True)
class ExportResult:
    path: Path
    rows: int
    fmt: ExportFormat
    values_revealed: bool


def _fmt_expiry(ts: int | None) -> str:
    return "Сессия" if ts is None else datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")


def _bool(v: bool) -> str:
    return "да" if v else "нет"


class _Row:
    """Одна строка экспорта: метаданные из CookieRow + при необходимости расшифрованное значение."""

    __slots__ = ("_box", "_reveal", "row")

    def __init__(self, row: CookieRow, box: CryptoBox | None, reveal: bool) -> None:
        self.row, self._box, self._reveal = row, box, reveal

    def cell(self, col: Column) -> Any:
        r = self.row
        if col is Column.VALUE:
            if not self._reveal:
                return MASK
            if r.value_ciphertext is None or self._box is None:
                return ""
            value = to_domain(r, self._box).value
            return value.reveal() if value is not None else ""
        if col is Column.EXPIRES_AT:
            return _fmt_expiry(r.expires_at)
        if col in (Column.HOST_ONLY, Column.SECURE, Column.HTTP_ONLY, Column.IS_TEST_SESSION):
            return getattr(r, col.value)
        if col is Column.VALUE_LENGTH:
            return r.value_length
        if col is Column.SAME_SITE:
            return r.same_site.value if r.same_site else ""
        if col in (Column.VALIDATION_STATUS, Column.MAX_SEVERITY):
            v = getattr(r, col.value)
            return v.value if v else ""
        return getattr(r, col.value)

    def display(self, col: Column) -> str:
        v = self.cell(col)
        if isinstance(v, bool):
            return _bool(v)
        return "" if v is None else str(v)


class ExportService:
    def __init__(self, sessions: sessionmaker[Session], box: CryptoBox | None = None) -> None:
        self._sessions = sessions
        self._box = box
        self._cookies = CookieService(sessions, box)

    def export(
        self,
        project_id: int,
        dest: Path,
        options: ExportOptions,
        filter: CookieFilter | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> ExportResult:
        if options.reveal_values and self._box is None:
            raise ExportError("Выгрузка значений в открытом виде недоступна: хранилище заблокировано")
        f = filter or CookieFilter()
        total = self._cookies.count(project_id, f)
        if not options.fmt.streaming and total > MAX_ROWS_IN_MEMORY:
            raise ExportError(
                f"Формат {options.fmt.value.upper()} готовит файл в памяти и ограничен {MAX_ROWS_IN_MEMORY:,} "
                f"записями (выбрано {total:,}). Используйте CSV, JSON или JSONL, либо уточните фильтр.".replace(
                    ",", " "
                )
            )
        dest = dest.with_suffix(options.fmt.extension) if dest.suffix != options.fmt.extension else dest
        dest.parent.mkdir(parents=True, exist_ok=True)

        writer = {
            ExportFormat.JSON: self._write_json,
            ExportFormat.JSONL: self._write_jsonl,
            ExportFormat.CSV: self._write_csv,
            ExportFormat.XLSX: self._write_xlsx,
            ExportFormat.HTML: self._write_html,
            ExportFormat.PDF: self._write_pdf,
        }[options.fmt]
        written = writer(project_id, dest, options, f, total, progress)

        if options.reveal_values:
            with self._sessions.begin() as s:
                record_operation(
                    s,
                    project_id=project_id,
                    kind="export.reveal",
                    outcome="ok",
                    summary=f"Экспорт со значениями в открытом виде: {written} записей, {options.fmt.value}",
                    details={"rows": written},
                )
        else:
            with self._sessions.begin() as s:
                record_operation(
                    s,
                    project_id=project_id,
                    kind="export",
                    outcome="ok",
                    summary=f"Экспорт {written} записей ({options.fmt.value})",
                    details={"rows": written, "format": options.fmt.value},
                )
        log.info(
            "Экспорт проекта %d: %d записей, формат %s, значения %s",
            project_id,
            written,
            options.fmt.value,
            "открыты" if options.reveal_values else "замаскированы",
        )
        return ExportResult(dest, written, options.fmt, options.reveal_values)

    # ------------------------------------------------------------------ выборка
    def _iter_rows(
        self,
        project_id: int,
        f: CookieFilter,
        options: ExportOptions,
        progress: Callable[[int, int], None] | None,
        total: int,
    ) -> Iterator[_Row]:
        from sqlalchemy import and_, or_, select

        from app.services.cookies import _sort_column  # переиспользуем keyset-логику сервиса

        col = _sort_column(options.sort)
        cond = self._cookies._conditions(project_id, f, now_ts())
        last_val: Any = None
        last_id = 0
        done = 0
        while True:
            c = list(cond)
            if last_val is not None or last_id:
                if options.descending:
                    c.append(or_(col < last_val, and_(col == last_val, CookieRow.id < last_id)))
                else:
                    c.append(or_(col > last_val, and_(col == last_val, CookieRow.id > last_id)))
            order = (col.desc(), CookieRow.id.desc()) if options.descending else (col.asc(), CookieRow.id.asc())
            with self._sessions() as s:
                rows = list(s.execute(select(CookieRow, col).where(*c).order_by(*order).limit(PAGE)).all())
                for row, sort_val in rows:
                    s.expunge(row)
                    yield _Row(row, self._box, options.reveal_values)
                    done += 1
                    last_val, last_id = sort_val, row.id
            if progress:
                progress(min(done, total), total)
            if len(rows) < PAGE:
                return

    # ------------------------------------------------------------------ форматы
    def _write_jsonl(
        self,
        project_id: int,
        dest: Path,
        o: ExportOptions,
        f: CookieFilter,
        total: int,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        cols = o.resolved_columns()
        n = 0
        with dest.open("w", encoding="utf-8") as fh:
            for r in self._iter_rows(project_id, f, o, progress, total):
                fh.write(json.dumps({c.value: r.cell(c) for c in cols}, ensure_ascii=False, default=str) + "\n")
                n += 1
        return n

    def _write_json(
        self,
        project_id: int,
        dest: Path,
        o: ExportOptions,
        f: CookieFilter,
        total: int,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        cols = o.resolved_columns()
        n = 0
        with dest.open("w", encoding="utf-8") as fh:
            fh.write('{\n  "tool": "Cookie Inspector Pro ' + __version__ + '",\n')
            fh.write('  "generated_at": "' + datetime.now(UTC).isoformat() + '",\n')
            fh.write('  "values_revealed": ' + ("true" if o.reveal_values else "false") + ",\n")
            fh.write('  "cookies": [')
            first = True
            for r in self._iter_rows(project_id, f, o, progress, total):
                fh.write("\n    " if first else ",\n    ")
                fh.write(json.dumps({c.value: r.cell(c) for c in cols}, ensure_ascii=False, default=str))
                first = False
                n += 1
            fh.write("\n  ]\n}\n")
        return n

    def _write_csv(
        self,
        project_id: int,
        dest: Path,
        o: ExportOptions,
        f: CookieFilter,
        total: int,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        cols = o.resolved_columns()
        n = 0
        with dest.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow([COLUMN_LABELS[c] for c in cols])
            for r in self._iter_rows(project_id, f, o, progress, total):
                w.writerow([r.display(c) for c in cols])
                n += 1
        return n

    def _write_xlsx(
        self,
        project_id: int,
        dest: Path,
        o: ExportOptions,
        f: CookieFilter,
        total: int,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        from openpyxl import Workbook
        from openpyxl.cell import WriteOnlyCell
        from openpyxl.styles import Font, PatternFill
        from openpyxl.utils import get_column_letter

        from app.domain.presentation import SEVERITY_COLORS, STATUS_COLORS

        cols = o.resolved_columns()
        wb = Workbook(write_only=True)
        ws = wb.create_sheet("Cookies")
        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill("solid", fgColor="2C3642")

        def cell(value: Any, *, font: Any = None, fill: Any = None) -> Any:
            c = WriteOnlyCell(ws, value=value)
            if font:
                c.font = font
            if fill:
                c.fill = fill
            return c

        ws.append([cell(COLUMN_LABELS[c], font=header_font, fill=header_fill) for c in cols])
        n = 0
        for r in self._iter_rows(project_id, f, o, progress, total):
            out = []
            for c in cols:
                fill = None
                raw = r.cell(c)
                if c is Column.VALIDATION_STATUS and raw:
                    fill = PatternFill("solid", fgColor=STATUS_COLORS.get(str(raw), "232B35").lstrip("#"))
                elif c is Column.MAX_SEVERITY and raw:
                    fill = PatternFill("solid", fgColor=SEVERITY_COLORS.get(str(raw), "232B35").lstrip("#"))
                out.append(cell(r.display(c), fill=fill))
            ws.append(out)
            n += 1
        for i, c in enumerate(cols, 1):
            ws.column_dimensions[get_column_letter(i)].width = 32 if c in (Column.DOMAIN, Column.VALUE) else 14
        wb.save(dest)
        return n

    def _write_html(
        self,
        project_id: int,
        dest: Path,
        o: ExportOptions,
        f: CookieFilter,
        total: int,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        from jinja2 import Environment

        from app.domain.presentation import SEVERITY_COLORS, STATUS_COLORS

        cols = o.resolved_columns()
        stats = self._cookies.stats(project_id)
        rows_html: list[str] = []
        n = 0
        for r in self._iter_rows(project_id, f, o, progress, total):
            cells = []
            for c in cols:
                text = html.escape(r.display(c))
                style = ""
                if c is Column.VALIDATION_STATUS and r.cell(c):
                    style = f' style="color:{STATUS_COLORS.get(str(r.cell(c)), "")}"'
                elif c is Column.MAX_SEVERITY and r.cell(c):
                    style = f' style="color:{SEVERITY_COLORS.get(str(r.cell(c)), "")}"'
                cells.append(f"<td{style}>{text}</td>")
            rows_html.append("<tr>" + "".join(cells) + "</tr>")
            n += 1
        env = Environment(autoescape=True)
        tmpl = env.from_string(_HTML_TEMPLATE)
        dest.write_text(
            tmpl.render(
                title=o.title,
                version=__version__,
                generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
                headers=[COLUMN_LABELS[c] for c in cols],
                rows="\n".join(rows_html),
                total=n,
                stats=stats,
                revealed=o.reveal_values,
                status_colors=STATUS_COLORS,
                status_labels=_STATUS_LABELS,
            ),
            encoding="utf-8",
        )
        return n

    def _write_pdf(
        self,
        project_id: int,
        dest: Path,
        o: ExportOptions,
        f: CookieFilter,
        total: int,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        cols = o.resolved_columns()
        font, font_bold = _register_pdf_fonts()
        styles = getSampleStyleSheet()
        for name in ("Title", "Normal"):
            styles[name].fontName = font_bold if name == "Title" else font
        data: list[list[str]] = [[COLUMN_LABELS[c] for c in cols]]
        n = 0
        for r in self._iter_rows(project_id, f, o, progress, total):
            data.append([r.display(c)[:40] for c in cols])
            n += 1
        doc = SimpleDocTemplate(
            str(dest),
            pagesize=landscape(A4),
            topMargin=15 * mm,
            bottomMargin=15 * mm,
            leftMargin=12 * mm,
            rightMargin=12 * mm,
            title=o.title,
        )
        story: list[Any] = [Paragraph(html.escape(o.title), styles["Title"])]
        meta = f"Cookie Inspector Pro {__version__} · {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} · записей: {n}"
        if o.reveal_values:
            meta += " · ВНИМАНИЕ: значения в открытом виде"
        story.append(Paragraph(html.escape(meta), styles["Normal"]))
        story.append(Spacer(1, 6 * mm))
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3642")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), font_bold),
                    ("FONTNAME", (0, 1), (-1, -1), font),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F4F6")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(table)
        doc.build(story)
        return n


_STATUS_LABELS: Final = {
    "valid": "Корректные",
    "warning": "С замечаниями",
    "expired": "Истекшие",
    "invalid": "Некорректные",
    "security_issue": "Проблемы безопасности",
    "unknown": "Не определено",
}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
:root { color-scheme: light dark; --bg:#ffffff; --fg:#1d2733; --muted:#5c6b7a; --surface:#f5f7f9;
        --border:#d0d7de; --accent:#1f7f8b; }
@media (prefers-color-scheme: dark) { :root { --bg:#1b2129; --fg:#dce3ea; --muted:#8a97a6;
        --surface:#232b35; --border:#3a4654; --accent:#4fb3bf; } }
* { box-sizing:border-box; } body { margin:0; padding:32px; background:var(--bg); color:var(--fg);
   font-family:"Segoe UI",system-ui,sans-serif; }
h1 { margin:0 0 4px; } .meta { color:var(--muted); margin-bottom:24px; }
.warn { color:#e0364f; font-weight:600; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:24px; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:12px 18px; }
.card .n { font-size:22px; font-weight:600; } .card .l { color:var(--muted); font-size:13px; }
table { border-collapse:collapse; width:100%; font-size:13px; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--border); }
th { position:sticky; top:0; background:var(--surface); color:var(--muted); }
tr:hover td { background:var(--surface); }
</style></head><body>
<h1>{{ title }}</h1>
<div class="meta">{{ version and "Cookie Inspector Pro " ~ version }} · {{ generated }} · записей: {{ total }}
{% if revealed %}<br><span class="warn">Значения cookies выгружены в открытом виде.</span>{% endif %}</div>
<div class="cards">
  <div class="card"><div class="n">{{ stats.total }}</div><div class="l">Всего записей</div></div>
  <div class="card"><div class="n">{{ stats.domains }}</div><div class="l">Доменов</div></div>
  {% for key, label in status_labels.items() %}{% if stats.by_status.get(key) %}
  <div class="card"><div class="n" style="color:{{ status_colors[key] }}">{{ stats.by_status[key] }}</div>
  <div class="l">{{ label }}</div></div>{% endif %}{% endfor %}
</div>
<table><thead><tr>{% for h in headers %}<th>{{ h }}</th>{% endfor %}</tr></thead>
<tbody>
{{ rows }}
</tbody></table>
</body></html>
"""
