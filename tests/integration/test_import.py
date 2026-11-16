from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.domain import SourceFormat
from app.infrastructure.db.models import CookieRow, ImportBatch, ImportErrorRow, Operation
from app.services.common import CancelToken
from app.services.importing import DuplicatePolicy, FileStatus, ImportOptions, ImportProgress, collect_files
from tests.conftest import TEST_DATA, Services


def count(svc: Services) -> int:
    with svc.sessions() as s:
        return int(s.scalar(select(func.count()).select_from(CookieRow)) or 0)


def test_import_all_valid_fixtures(svc: Services) -> None:
    rep = svc.importer.run(svc.project_id, [TEST_DATA / "valid"])
    assert rep.status == "completed"
    assert {f.status for f in rep.files} == {FileStatus.IMPORTED}
    assert {f.fmt for f in rep.files} == set(SourceFormat) - {
        SourceFormat.FIREFOX_PROFILE,
        SourceFormat.CHROMIUM_PROFILE,
        SourceFormat.MANUAL,
    }
    assert rep.records_ok == count(svc) == 13


def test_broken_files_do_not_stop_the_batch(svc: Services) -> None:
    files = sorted((TEST_DATA / "broken").iterdir())
    rep = svc.importer.run(svc.project_id, files)
    by = {Path(f.path).name: f for f in rep.files}
    assert rep.status == "completed"
    assert by["garbage.bin"].status is FileStatus.FAILED and by["garbage.bin"].error_code == "binary"
    assert by["latin1.txt"].error_code == "encoding"
    assert by["truncated.json"].status is FileStatus.PARTIAL and by["truncated.json"].records_ok == 1
    assert by["mixed.txt"].status is FileStatus.IMPORTED and by["mixed.txt"].records_ok == 2
    assert by["mixed.txt"].records_failed == 3
    assert [i.line for i in by["mixed.txt"].issues] == [3, 4, 5]
    assert by["records.json"].records_ok == 1 and by["records.json"].records_failed == 4
    with svc.sessions() as s:
        assert s.scalar(select(func.count()).select_from(ImportErrorRow)) >= 7


def test_partial_file_keeps_records_before_corruption(svc: Services, tmp_path: Path) -> None:
    p = tmp_path / "p.json"
    p.write_text('[{"name":"a","value":"1","domain":"x.test"},\n{"name":"b","value":"2","domain":"x.test"},\n{"br')
    rep = svc.importer.run(svc.project_id, [p])
    f = rep.files[0]
    assert f.status is FileStatus.PARTIAL and f.records_ok == 2 and "строка 3" in (f.error or "")


def test_reimport_detection_and_force(svc: Services) -> None:
    path = TEST_DATA / "valid" / "netscape.txt"
    svc.importer.run(svc.project_id, [path])
    second = svc.importer.run(svc.project_id, [path])
    assert second.files[0].status is FileStatus.ALREADY_IMPORTED and count(svc) == 3
    forced = svc.importer.run(svc.project_id, [path], ImportOptions(force_reimport=True))
    assert forced.files[0].duplicates == 3 and count(svc) == 3


@pytest.mark.parametrize(
    ("policy", "rows", "dups"),
    [(DuplicatePolicy.SKIP, 1, 1), (DuplicatePolicy.KEEP, 2, 1), (DuplicatePolicy.REPLACE, 1, 1)],
)
def test_duplicate_policies_within_project(
    svc: Services, tmp_path: Path, policy: DuplicatePolicy, rows: int, dups: int
) -> None:
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    a.write_text('{"name":"d","value":"first","domain":"x.test"}\n')
    b.write_text('{"name":"d","value":"second","domain":"x.test"}\n')
    svc.importer.run(svc.project_id, [a])
    rep = svc.importer.run(svc.project_id, [b], ImportOptions(duplicates=policy))
    assert rep.duplicates == dups and count(svc) == rows
    ids = svc.cookies.ids(svc.project_id)
    values = sorted(svc.cookies.detail(i, reveal=True).value.reveal() for i in ids)  # type: ignore[union-attr]
    expected = {"skip": ["first"], "keep": ["first", "second"], "replace": ["second"]}[policy.value]
    assert values == expected


def test_cancel_rolls_back_entire_batch(svc: Services, tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text("".join(f".x.test\tTRUE\t/\tFALSE\t0\tn{i}\tv\n" for i in range(5000)))
    token = CancelToken()
    seen: list[ImportProgress] = []

    def on_progress(p: ImportProgress) -> None:
        seen.append(p)
        if p.records_ok or p.bytes_done:
            token.cancel()

    rep = svc.importer.run(
        svc.project_id, [TEST_DATA / "valid" / "netscape.txt", big], progress=on_progress, cancel=token
    )
    assert rep.status == "cancelled" and count(svc) == 0
    with svc.sessions() as s:
        assert s.scalar(select(ImportBatch.status)) == "cancelled"
        assert s.scalar(select(Operation.outcome).where(Operation.kind == "import")) == "cancelled"
    assert seen


def test_progress_reports_bytes_and_files(svc: Services) -> None:
    seen: list[ImportProgress] = []
    svc.importer.run(svc.project_id, [TEST_DATA / "valid"], progress=seen.append)
    last = seen[-1]
    assert last.files_done == last.files_total == 7 and last.current_file is None
    assert last.bytes_done == last.bytes_total > 0 and last.records_ok == 13


def test_preview_writes_nothing_and_masks_values(svc: Services) -> None:
    pv = svc.importer.preview(TEST_DATA / "valid" / "netscape.txt")
    assert pv.fmt is SourceFormat.NETSCAPE and len(pv.items) == 3 and count(svc) == 0
    assert pv.items[1].value_length == 32 and not hasattr(pv.items[1], "value")
    bad = svc.importer.preview(TEST_DATA / "broken" / "garbage.bin")
    assert bad.error and bad.fmt is None


def test_format_override(svc: Services, tmp_path: Path) -> None:
    p = tmp_path / "data.dat"
    p.write_text('{"name":"a","value":"1","domain":"x.test"}\n')
    rep = svc.importer.run(svc.project_id, [p], ImportOptions(format_override=SourceFormat.JSONL))
    assert rep.files[0].fmt is SourceFormat.JSONL and rep.records_ok == 1


def test_collect_files(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / ".hidden").mkdir()
    for name in ("a.txt", "sub/b.json", "c.exe", ".hidden/d.txt"):
        (tmp_path / name).write_text("x")
    found = [f.relative_to(tmp_path).as_posix() for f in collect_files([tmp_path, tmp_path / "a.txt"])]
    assert found == ["a.txt", "sub/b.json"]
    assert collect_files([tmp_path / "c.exe"]) == [tmp_path / "c.exe"]
    with pytest.raises(FileNotFoundError):
        collect_files([tmp_path / "missing"])


def test_unknown_project(svc: Services) -> None:
    with pytest.raises(ValueError):
        svc.importer.run(9999, [TEST_DATA / "valid" / "netscape.txt"])
