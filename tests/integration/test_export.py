"""Reports & Export: шесть форматов, маскирование значений по умолчанию, выгрузка по фильтру."""

from __future__ import annotations

import csv
import json
import zipfile
from pathlib import Path

import pytest

from app.domain import MASK
from app.services.cookies import CookieFilter, SortKey
from app.services.export import (
    Column,
    ExportError,
    ExportFormat,
    ExportOptions,
    ExportService,
)
from tests.conftest import Services

SECRET = "SUPER-SECRET-COOKIE-VALUE-123"


@pytest.fixture
def loaded(svc: Services, tmp_path: Path) -> Services:
    src = tmp_path / "data.jsonl"
    rows = [f'{{"name":"sessionid","value":"{SECRET}","domain":"app.example.com","secure":false,"httpOnly":false}}']
    for i in range(40):
        rows.append(f'{{"name":"c{i}","value":"v{i}","domain":"s{i % 7}.example.test","secure":true}}')
    src.write_text("\n".join(rows) + "\n")
    svc.importer.run(svc.project_id, [src])
    svc.validator.run(svc.project_id)
    return svc


def _export(svc: Services, tmp_path: Path, fmt: ExportFormat, **kw) -> Path:  # type: ignore[no-untyped-def]
    es = ExportService(svc.sessions, svc.box)
    res = es.export(svc.project_id, tmp_path / "out", ExportOptions(fmt=fmt, **kw))
    assert res.path.exists() and res.rows == 41
    return res.path


@pytest.mark.parametrize("fmt", list(ExportFormat))
def test_every_format_masks_values_by_default(loaded: Services, tmp_path: Path, fmt: ExportFormat) -> None:
    path = _export(loaded, tmp_path, fmt, columns=(Column.NAME, Column.DOMAIN, Column.VALUE, Column.VALUE_LENGTH))
    raw = path.read_bytes()
    assert SECRET.encode() not in raw, f"{fmt}: значение утекло в экспорт"
    if fmt in (ExportFormat.JSON, ExportFormat.JSONL, ExportFormat.CSV, ExportFormat.HTML):
        assert MASK.encode() in raw


def test_json_structure_and_masking(loaded: Services, tmp_path: Path) -> None:
    path = _export(loaded, tmp_path, ExportFormat.JSON, columns=(Column.NAME, Column.VALUE, Column.VALUE_LENGTH))
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["values_revealed"] is False and len(doc["cookies"]) == 41
    sess = next(c for c in doc["cookies"] if c["name"] == "sessionid")
    assert sess["value"] == MASK and sess["value_length"] == len(SECRET)


def test_jsonl_one_object_per_line(loaded: Services, tmp_path: Path) -> None:
    path = _export(loaded, tmp_path, ExportFormat.JSONL)
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 41 and all(json.loads(line)["domain"] for line in lines)


def test_csv_headers_and_bom(loaded: Services, tmp_path: Path) -> None:
    path = _export(loaded, tmp_path, ExportFormat.CSV, columns=(Column.NAME, Column.DOMAIN, Column.SECURE))
    assert path.read_bytes().startswith(b"\xef\xbb\xbf"), "BOM для Excel"
    with path.open(encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        assert next(reader) == ["Имя", "Домен", "Secure"]
        body = list(reader)
    assert len(body) == 41 and body[0][2] in ("да", "нет")


def test_xlsx_is_valid_workbook(loaded: Services, tmp_path: Path) -> None:
    from openpyxl import load_workbook

    path = _export(loaded, tmp_path, ExportFormat.XLSX)
    assert zipfile.is_zipfile(path)
    wb = load_workbook(path, read_only=True)
    ws = wb["Cookies"]
    rows = list(ws.iter_rows(values_only=True))
    assert len(rows) == 42 and rows[0][0] == "Имя"  # заголовок + 41
    wb.close()


def test_html_is_self_contained(loaded: Services, tmp_path: Path) -> None:
    path = _export(loaded, tmp_path, ExportFormat.HTML, title="Мой отчёт")
    text = path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in text and "Мой отчёт" in text
    assert "http://" not in text and "https://" not in text, "никаких внешних ресурсов"
    assert "Всего записей" in text


def test_pdf_header(loaded: Services, tmp_path: Path) -> None:
    path = _export(loaded, tmp_path, ExportFormat.PDF)
    assert path.read_bytes().startswith(b"%PDF-")


def test_reveal_requires_unlocked_and_is_audited(loaded: Services, tmp_path: Path) -> None:
    from sqlalchemy import select

    from app.infrastructure.db.models import Operation

    es = ExportService(loaded.sessions, loaded.box)
    res = es.export(
        loaded.project_id,
        tmp_path / "plain",
        ExportOptions(fmt=ExportFormat.CSV, columns=(Column.NAME, Column.VALUE), reveal_values=True),
    )
    assert SECRET in res.path.read_text(encoding="utf-8-sig") and res.values_revealed
    with loaded.sessions() as s:
        kinds = set(s.scalars(select(Operation.kind)))
    assert "export.reveal" in kinds

    locked = ExportService(loaded.sessions, None)
    with pytest.raises(ExportError, match="заблокировано"):
        locked.export(loaded.project_id, tmp_path / "x", ExportOptions(fmt=ExportFormat.CSV, reveal_values=True))


def test_export_respects_filter_and_sort(loaded: Services, tmp_path: Path) -> None:
    es = ExportService(loaded.sessions, loaded.box)
    res = es.export(
        loaded.project_id,
        tmp_path / "secure",
        ExportOptions(fmt=ExportFormat.JSONL, sort=SortKey.NAME),
        filter=CookieFilter(secure=True),
    )
    lines = [json.loads(line) for line in res.path.read_text(encoding="utf-8").splitlines()]
    assert res.rows == 40 and all(line["domain"] != "app.example.com" for line in lines)
    names = [line["name"] for line in lines]
    assert names == sorted(names), "сортировка по имени соблюдена"


def test_extension_is_added(loaded: Services, tmp_path: Path) -> None:
    es = ExportService(loaded.sessions, loaded.box)
    res = es.export(loaded.project_id, tmp_path / "report", ExportOptions(fmt=ExportFormat.JSON))
    assert res.path.name == "report.json"


def test_memory_limit_for_non_streaming(loaded: Services, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.export as mod

    monkeypatch.setattr(mod, "MAX_ROWS_IN_MEMORY", 10)
    es = ExportService(loaded.sessions, loaded.box)
    with pytest.raises(ExportError, match="XLSX"):
        es.export(loaded.project_id, tmp_path / "big", ExportOptions(fmt=ExportFormat.XLSX))
    # потоковый формат ограничение не затрагивает
    res = es.export(loaded.project_id, tmp_path / "ok", ExportOptions(fmt=ExportFormat.CSV))
    assert res.rows == 41


def test_empty_project_exports_header_only(svc: Services, tmp_path: Path) -> None:
    es = ExportService(svc.sessions, svc.box)
    res = es.export(svc.project_id, tmp_path / "empty", ExportOptions(fmt=ExportFormat.CSV))
    assert res.rows == 0 and res.path.exists()
    res_x = es.export(svc.project_id, tmp_path / "empty", ExportOptions(fmt=ExportFormat.XLSX))
    assert res_x.rows == 0


def test_findings_export_via_detail(loaded: Services, tmp_path: Path) -> None:
    """Статусы и критичность выгружаются как столбцы (находки агрегированы в статус записи)."""
    es = ExportService(loaded.sessions, loaded.box)
    res = es.export(
        loaded.project_id,
        tmp_path / "audit",
        ExportOptions(fmt=ExportFormat.CSV, columns=(Column.NAME, Column.VALIDATION_STATUS, Column.MAX_SEVERITY)),
    )
    text = res.path.read_text(encoding="utf-8-sig")
    assert "security_issue" in text or "Проблемы" in text or "invalid" in text
