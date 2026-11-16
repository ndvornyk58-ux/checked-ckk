"""Импорт файлов cookies.

Семантика:
* Все данные пакета пишутся **одной транзакцией**: отмена откатывает пакет целиком —
  после отмены в проекте нет ни одной записи из этого пакета.
* Ошибка в одном файле не прерывает пакет; файл получает статус ``failed`` или ``partial``
  (записи до места повреждения сохраняются), ошибки фиксируются по строкам.
* Повторный импорт того же файла (по SHA-256) в тот же проект пропускается, если не указано ``force``.
* Дубликаты (ключ RFC 6265 §5.3) обрабатываются политикой: skip / keep / replace.
* Значения шифруются до записи; в БД, журналы и отчёты об ошибках они не попадают.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.domain import Cookie, SourceFormat
from app.infrastructure.crypto import CryptoBox
from app.infrastructure.db.mapping import to_row_dict
from app.infrastructure.db.models import CookieRow, ImportBatch, ImportErrorRow, Project, SourceFile
from app.parsers import Detection, FileCorruptedError, ParseIssue, ParserRegistry, open_text, read_head
from app.services.common import CancelToken, OperationCancelled, now_ts, record_operation

log = logging.getLogger(__name__)

CHUNK: Final = 2000
DIR_EXTENSIONS: Final = frozenset({".txt", ".cookies", ".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".cipx"})


class DuplicatePolicy(StrEnum):
    SKIP = "skip"  # оставить существующую запись, новую не импортировать
    KEEP = "keep"  # импортировать обе (дубликат будет отмечен валидатором)
    REPLACE = "replace"  # заменить существующую запись новой


class FileStatus(StrEnum):
    IMPORTED = "imported"
    PARTIAL = "partial"
    FAILED = "failed"
    ALREADY_IMPORTED = "already_imported"


@dataclass(frozen=True, slots=True)
class ImportOptions:
    duplicates: DuplicatePolicy = DuplicatePolicy.SKIP
    force_reimport: bool = False
    max_issues_per_file: int = 1000
    format_override: SourceFormat | None = None


@dataclass(frozen=True, slots=True)
class ImportProgress:
    files_done: int
    files_total: int
    current_file: str | None
    bytes_done: int
    bytes_total: int
    records_ok: int
    records_failed: int


@dataclass(slots=True)
class FileReport:
    path: str
    status: FileStatus
    fmt: SourceFormat | None = None
    confidence: float | None = None
    ambiguous_with: SourceFormat | None = None
    records_ok: int = 0
    records_failed: int = 0
    duplicates: int = 0
    replaced: int = 0
    warnings: int = 0
    error_code: str | None = None
    error: str | None = None
    issues: list[ParseIssue] = field(default_factory=list)


@dataclass(slots=True)
class ImportReport:
    batch_id: int
    status: str
    files: list[FileReport]
    duration_s: float

    @property
    def records_ok(self) -> int:
        return sum(f.records_ok for f in self.files)

    @property
    def records_failed(self) -> int:
        return sum(f.records_failed for f in self.files)

    @property
    def duplicates(self) -> int:
        return sum(f.duplicates for f in self.files)


@dataclass(frozen=True, slots=True)
class PreviewItem:
    """Запись предпросмотра. Значение не раскрывается — только длина."""

    name: str
    domain: str
    path: str
    host_only: bool
    secure: bool
    http_only: bool
    same_site: str
    expires_at: int | None
    value_length: int | None
    line: int | None


@dataclass(slots=True)
class ImportPreview:
    path: str
    fmt: SourceFormat | None
    confidence: float | None
    ambiguous_with: SourceFormat | None
    items: list[PreviewItem]
    issues: list[ParseIssue]
    error: str | None = None


def collect_files(paths: Iterable[Path]) -> list[Path]:
    """Развернуть каталоги (рекурсивно, только известные расширения, без скрытых файлов).

    Явно указанные файлы берутся с любым расширением. Порядок детерминирован.
    """
    out: list[Path] = []
    seen: set[Path] = set()
    for p in paths:
        p = p.expanduser()
        if p.is_dir():
            found = sorted(
                f
                for f in p.rglob("*")
                if f.is_file()
                and f.suffix.lower() in DIR_EXTENSIONS
                and not any(part.startswith(".") for part in f.relative_to(p).parts)
            )
        elif p.is_file():
            found = [p]
        else:
            raise FileNotFoundError(f"Не найден: {p}")
        for f in found:
            r = f.resolve()
            if r not in seen:
                seen.add(r)
                out.append(f)
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class ImportService:
    def __init__(self, sessions: sessionmaker[Session], box: CryptoBox, registry: ParserRegistry | None = None) -> None:
        self._sessions = sessions
        self._box = box
        self._registry = registry or ParserRegistry()

    # ------------------------------------------------------------------ предпросмотр
    def preview(self, path: Path, limit: int = 50) -> ImportPreview:
        """Определить формат и показать первые записи. Ничего не пишет в БД."""
        try:
            det = self._registry.detect_file(path)
        except FileCorruptedError as e:
            return ImportPreview(str(path), None, None, None, [], [], e.message)
        items: list[PreviewItem] = []
        issues: list[ParseIssue] = []
        error = None
        try:
            with open_text(path) as (text, _):
                for item in det.parser.parse(text, str(path)):
                    if isinstance(item, Cookie):
                        items.append(_preview_item(item))
                    else:
                        issues.append(item)
                    if len(items) >= limit:
                        break
        except FileCorruptedError as e:
            error = e.message
        except UnicodeDecodeError:
            error = "Файл содержит байты не в кодировке UTF-8"
        return ImportPreview(str(path), det.fmt, det.confidence, det.ambiguous_with, items, issues[:limit], error)

    # ------------------------------------------------------------------ импорт
    def run(
        self,
        project_id: int,
        paths: Iterable[Path],
        options: ImportOptions | None = None,
        *,
        progress: Callable[[ImportProgress], None] | None = None,
        cancel: CancelToken | None = None,
    ) -> ImportReport:
        opts = options or ImportOptions()
        cancel = cancel or CancelToken()
        files = collect_files(paths)
        started = time.monotonic()
        with self._sessions.begin() as s:
            if s.get(Project, project_id) is None:
                raise ValueError(f"Проект {project_id} не найден")
            batch = ImportBatch(
                project_id=project_id,
                started_at=now_ts(),
                status="running",
                options={"duplicates": opts.duplicates.value, "force": opts.force_reimport, "files": len(files)},
                stats={},
            )
            s.add(batch)
            s.flush()
            batch_id = batch.id

        reports: list[FileReport] = []
        sizes = [f.stat().st_size for f in files]
        state = {"bytes": 0, "ok": 0, "failed": 0}

        def notify(i: int, current: str | None, extra_bytes: int = 0) -> None:
            if progress:
                progress(
                    ImportProgress(
                        i, len(files), current, state["bytes"] + extra_bytes, sum(sizes), state["ok"], state["failed"]
                    )
                )

        status = "completed"
        try:
            with self._sessions.begin() as s:
                for i, path in enumerate(files):
                    cancel.raise_if_cancelled()
                    notify(i, str(path))
                    rep = self._import_file(
                        s, project_id, batch_id, path, opts, cancel, functools.partial(notify, i, str(path))
                    )
                    reports.append(rep)
                    state["bytes"] += sizes[i]
                    state["ok"] += rep.records_ok
                    state["failed"] += rep.records_failed
                    log.info(
                        "Импорт файла: %s статус=%s формат=%s ok=%d failed=%d dup=%d",
                        path.name,
                        rep.status,
                        rep.fmt,
                        rep.records_ok,
                        rep.records_failed,
                        rep.duplicates,
                    )
                cancel.raise_if_cancelled()
                notify(len(files), None)
        except OperationCancelled:
            status = "cancelled"
            for r in reports:
                r.records_ok = r.duplicates = r.replaced = 0
        except Exception:
            status = "failed"
            log.exception("Импорт пакета %d прерван ошибкой", batch_id)
            raise
        finally:
            self._finish_batch(batch_id, project_id, status, reports, time.monotonic() - started)
        return ImportReport(batch_id, status, reports, time.monotonic() - started)

    def _finish_batch(
        self, batch_id: int, project_id: int, status: str, reports: list[FileReport], duration: float
    ) -> None:
        stats = {
            "files": len(reports),
            "files_failed": sum(r.status is FileStatus.FAILED for r in reports),
            "records_ok": sum(r.records_ok for r in reports),
            "records_failed": sum(r.records_failed for r in reports),
            "duplicates": sum(r.duplicates for r in reports),
            "duration_s": round(duration, 3),
        }
        with self._sessions.begin() as s:
            s.execute(
                update(ImportBatch)
                .where(ImportBatch.id == batch_id)
                .values(status=status, finished_at=now_ts(), stats=stats)
            )
            summary = {
                "completed": f"Импортировано записей: {stats['records_ok']} из {len(reports)} файл(ов)",
                "cancelled": "Импорт отменён, изменения откатаны",
                "failed": "Импорт прерван ошибкой, изменения откатаны",
            }[status]
            record_operation(
                s,
                project_id=project_id,
                kind="import",
                outcome=status,
                summary=summary,
                details={"batch_id": batch_id, **stats},
            )

    def _import_file(
        self,
        s: Session,
        project_id: int,
        batch_id: int,
        path: Path,
        opts: ImportOptions,
        cancel: CancelToken,
        on_bytes: Callable[[int], None],
    ) -> FileReport:
        rep = FileReport(path=str(path), status=FileStatus.IMPORTED)
        try:
            digest, size = _sha256(path), path.stat().st_size
        except OSError as e:
            rep.status, rep.error_code, rep.error = FileStatus.FAILED, "io", f"Не удалось прочитать файл: {e.strerror}"
            return rep
        if not opts.force_reimport and s.scalar(
            select(SourceFile.id)
            .join(ImportBatch)
            .where(
                ImportBatch.project_id == project_id,
                ImportBatch.status == "completed",
                SourceFile.sha256 == digest,
                SourceFile.status.in_(("imported", "partial")),
            )
        ):
            rep.status, rep.error = FileStatus.ALREADY_IMPORTED, "Этот файл уже импортирован в проект"
            return rep

        sf = SourceFile(batch_id=batch_id, path=str(path), size_bytes=size, sha256=digest, status="running")
        s.add(sf)
        s.flush()
        try:
            det = self._detect(path, opts)
            rep.fmt, rep.confidence, rep.ambiguous_with = det.fmt, det.confidence, det.ambiguous_with
            with open_text(path) as (text, counter):
                pending: list[Cookie] = []
                try:
                    for item in det.parser.parse(text, str(path)):
                        if isinstance(item, Cookie):
                            pending.append(item)
                            if len(pending) >= CHUNK:
                                cancel.raise_if_cancelled()
                                self._flush(s, project_id, batch_id, sf.id, pending, opts.duplicates, rep)
                                pending.clear()
                                on_bytes(counter.bytes_read)
                        else:
                            self._issue(s, sf.id, rep, item, opts.max_issues_per_file)
                except (FileCorruptedError, UnicodeDecodeError):
                    # Записи, прочитанные до места повреждения, сохраняются (статус файла — partial).
                    self._flush(s, project_id, batch_id, sf.id, pending, opts.duplicates, rep)
                    raise
                self._flush(s, project_id, batch_id, sf.id, pending, opts.duplicates, rep)
        except FileCorruptedError as e:
            rep.error_code, rep.error = e.code, e.message + (f" (строка {e.line})" if e.line else "")
            rep.status = FileStatus.PARTIAL if rep.records_ok or rep.duplicates else FileStatus.FAILED
        except UnicodeDecodeError:
            rep.error_code, rep.error = "encoding", "Файл содержит байты не в кодировке UTF-8"
            rep.status = FileStatus.PARTIAL if rep.records_ok or rep.duplicates else FileStatus.FAILED
        sf.detected_format, sf.format_confidence = rep.fmt, rep.confidence
        sf.status = rep.status.value
        sf.records_ok, sf.records_failed, sf.records_duplicate = rep.records_ok, rep.records_failed, rep.duplicates
        if rep.error:
            s.add(ImportErrorRow(source_file_id=sf.id, line=None, code=rep.error_code or "error", message=rep.error))
        return rep

    def _detect(self, path: Path, opts: ImportOptions) -> Detection:
        if opts.format_override is not None:
            read_head(path)  # всё равно отсеять бинарные и не-UTF-8 файлы
            return Detection(self._registry.get(opts.format_override), 1.0)
        return self._registry.detect_file(path)

    def _issue(self, s: Session, sf_id: int, rep: FileReport, issue: ParseIssue, cap: int) -> None:
        if issue.skipped:
            rep.records_failed += 1
        else:
            rep.warnings += 1
        if len(rep.issues) < cap:
            rep.issues.append(issue)
            s.add(ImportErrorRow(source_file_id=sf_id, line=issue.line, code=issue.code, message=issue.message))

    def _flush(
        self,
        s: Session,
        project_id: int,
        batch_id: int,
        sf_id: int,
        cookies: list[Cookie],
        policy: DuplicatePolicy,
        rep: FileReport,
    ) -> None:
        if not cookies:
            return
        ts = now_ts()
        rows = [
            to_row_dict(c, self._box, project_id=project_id, batch_id=batch_id, source_file_id=sf_id, now=ts)
            for c in cookies
        ]
        hashes = {r["identity_hash"] for r in rows}
        existing: dict[bytes, int] = dict(
            s.execute(
                select(CookieRow.identity_hash, CookieRow.id).where(
                    CookieRow.project_id == project_id, CookieRow.identity_hash.in_(hashes)
                )
            ).all()
        )
        inserts: dict[bytes, dict[str, Any]] = {}
        keep_extra: list[dict[str, Any]] = []
        updates: list[dict[str, Any]] = []
        for r in rows:
            h = r["identity_hash"]
            if h not in existing and h not in inserts:
                inserts[h] = r
                continue
            rep.duplicates += 1
            if policy is DuplicatePolicy.KEEP:
                keep_extra.append(r)
            elif policy is DuplicatePolicy.REPLACE:
                if h in existing:
                    updates.append({**r, "id": existing[h]})
                    rep.replaced += 1
                else:
                    inserts[h] = r  # внутри файла побеждает последняя запись
        to_insert = [*inserts.values(), *keep_extra]
        if to_insert:
            s.execute(insert(CookieRow), to_insert)
        if updates:
            s.execute(
                update(CookieRow),
                [
                    {k: v for k, v in u.items() if k != "imported_at"}
                    | {"validation_status": None, "max_severity": None, "analyzed_at": None}
                    for u in updates
                ],
            )
        rep.records_ok += len(to_insert) + len(updates)


def _preview_item(c: Cookie) -> PreviewItem:
    return PreviewItem(
        name=c.name,
        domain=c.domain,
        path=c.path,
        host_only=c.host_only,
        secure=c.secure,
        http_only=c.http_only,
        same_site=c.same_site.value,
        expires_at=int(c.expires_at.timestamp()) if c.expires_at else None,
        value_length=len(c.value) if c.value is not None else None,
        line=c.source.line,
    )


def iter_reports(report: ImportReport) -> Iterator[str]:
    """Человекочитаемые строки отчёта (для CLI и журнала операций)."""
    for f in report.files:
        line = f"{f.status.value:16} {Path(f.path).name}"
        if f.fmt:
            line += f"  [{f.fmt.value}, {f.confidence:.0%}]"
        line += f"  импорт: {f.records_ok}, ошибок: {f.records_failed}, дубликатов: {f.duplicates}"
        if f.ambiguous_with:
            line += f"  (формат неоднозначен: возможно, {f.ambiguous_with.value})"
        if f.error:
            line += f"\n                 └ {f.error}"
        yield line
