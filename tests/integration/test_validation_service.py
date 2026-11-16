from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select, update

from app.domain import Severity, ValidationStatus
from app.infrastructure.db.models import AnalysisRun, CookieRow, FindingRow
from app.services.common import CancelToken
from app.services.importing import DuplicatePolicy, ImportOptions
from app.services.validation import ValidationProgress
from tests.conftest import TEST_DATA, Services

NOW = datetime(2026, 11, 16, tzinfo=UTC)


def _write(tmp: Path, name: str, lines: list[str]) -> Path:
    p = tmp / name
    p.write_text("\n".join(lines) + "\n")
    return p


def test_statuses_and_findings_persisted(svc: Services) -> None:
    svc.importer.run(svc.project_id, [TEST_DATA / "edge"])
    rep = svc.validator.run(svc.project_id, now=NOW)
    assert rep.status == "completed" and rep.checked == 9
    assert rep.by_status.get("invalid", 0) >= 6
    with svc.sessions() as s:
        assert s.scalar(select(func.count()).select_from(CookieRow).where(CookieRow.validation_status.is_(None))) == 0
        run = s.scalar(select(AnalysisRun))
        assert run is not None and run.finished_at and run.stats["checked"] == 9
        rules = set(s.scalars(select(FindingRow.rule_id)))
    assert {
        "name.invalid-chars",
        "value.forbidden-chars",
        "domain.public-suffix",
        "prefix.host",
        "prefix.secure",
        "samesite.none-insecure",
        "path.not-absolute",
        "size.too-large",
    } <= rules


def test_duplicates_and_shadowing_across_files(svc: Services, tmp_path: Path) -> None:
    a = _write(
        tmp_path,
        "a.jsonl",
        ['{"name":"sid","value":"1","domain":"app.example.com"}', '{"name":"sid","value":"x","domain":".example.com"}'],
    )
    b = _write(tmp_path, "b.jsonl", ['{"name":"sid","value":"2","domain":"app.example.com"}'])
    svc.importer.run(svc.project_id, [a])
    svc.importer.run(svc.project_id, [b], ImportOptions(duplicates=DuplicatePolicy.KEEP))
    svc.validator.run(svc.project_id, now=NOW)
    with svc.sessions() as s:
        by_cookie: dict[int, set[str]] = {}
        for cid, rule in s.execute(select(FindingRow.cookie_id, FindingRow.rule_id)):
            by_cookie.setdefault(cid, set()).add(rule)
    dup = [r for r in by_cookie.values() if "duplicate.identity" in r]
    assert len(dup) == 2, "обе записи-дубликата отмечены"
    assert all("sec.cookie-shadowing" in r for r in by_cookie.values()), "конфликт имён sid"


def test_revalidation_replaces_findings_keeps_run_history(svc: Services) -> None:
    svc.importer.run(svc.project_id, [TEST_DATA / "valid"])
    svc.validator.run(svc.project_id, now=NOW)
    with svc.sessions() as s:
        first = s.scalar(select(func.count()).select_from(FindingRow))
    svc.validator.run(svc.project_id, now=NOW)
    with svc.sessions() as s:
        assert s.scalar(select(func.count()).select_from(FindingRow)) == first
        assert s.scalar(select(func.count()).select_from(AnalysisRun)) == 2


def test_scope_by_batch_and_ids(svc: Services) -> None:
    r1 = svc.importer.run(svc.project_id, [TEST_DATA / "valid" / "netscape.txt"])
    svc.importer.run(svc.project_id, [TEST_DATA / "valid" / "selenium.jsonl"])
    assert svc.validator.run(svc.project_id, batch_id=r1.batch_id, now=NOW).checked == 3
    one = svc.cookies.ids(svc.project_id)[:1]
    assert svc.validator.run(svc.project_id, cookie_ids=one, now=NOW).checked == 1


def test_tampered_ciphertext_reported_not_crashed(svc: Services) -> None:
    svc.importer.run(svc.project_id, [TEST_DATA / "valid" / "netscape.txt"])
    with svc.sessions.begin() as s:
        cid = s.scalar(select(CookieRow.id).limit(1))
        s.execute(update(CookieRow).where(CookieRow.id == cid).values(value_ciphertext=b"\x01" + b"0" * 40))
    rep = svc.validator.run(svc.project_id, now=NOW)
    assert rep.by_status.get("unknown") == 1
    d = svc.cookies.detail(cid)  # type: ignore[arg-type]
    assert d.findings[0].rule_id == "storage.decrypt"


def test_progress_and_cancel(svc: Services, tmp_path: Path) -> None:
    big = _write(tmp_path, "big.txt", [f".x.test\tTRUE\t/\tFALSE\t0\tn{i}\tv" for i in range(2500)])
    svc.importer.run(svc.project_id, [big])
    seen: list[ValidationProgress] = []
    svc.validator.run(svc.project_id, progress=seen.append, now=NOW)
    assert [p.done for p in seen] == [1000, 2000, 2500] and seen[-1].total == 2500
    token = CancelToken()

    def stop(p: ValidationProgress) -> None:
        token.cancel()

    rep = svc.validator.run(svc.project_id, progress=stop, cancel=token, now=NOW)
    assert rep.status == "cancelled" and rep.checked == 1000


def test_severity_summary_on_cookie(svc: Services, tmp_path: Path) -> None:
    p = _write(tmp_path, "s.jsonl", ['{"name":"sessionid","value":"1234","domain":"example.com","secure":false}'])
    svc.importer.run(svc.project_id, [p])
    svc.validator.run(svc.project_id, now=NOW)
    with svc.sessions() as s:
        row = s.scalar(select(CookieRow))
    assert row is not None and row.max_severity is Severity.HIGH
    assert row.validation_status is ValidationStatus.SECURITY_ISSUE
