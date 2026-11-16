"""Batch Processor: очередь файлов, параллелизм, пауза/возобновление, остановка, повтор, персистентность."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.infrastructure.db.models import CookieRow, Operation
from app.services.importing import DuplicatePolicy, ImportOptions
from app.workers.batch import (
    DEFAULT_WORKERS,
    BatchService,
    JobKind,
    JobStatus,
    TaskStatus,
)
from tests.conftest import TEST_DATA, Services

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))


def _batch(svc: Services) -> BatchService:
    return BatchService(svc.sessions, svc.box)


def _many(tmp_path: Path, n: int, rows: int = 50) -> list[Path]:
    paths = []
    for i in range(n):
        p = tmp_path / f"file_{i}.jsonl"
        p.write_text(
            "\n".join(
                f'{{"name":"c{j}","value":"v{j}","domain":"d{i}-{j}.example.test","secure":true}}' for j in range(rows)
            )
            + "\n"
        )
        paths.append(p)
    return paths


def test_import_validate_whole_batch(svc: Services, tmp_path: Path) -> None:
    b = _batch(svc)
    job_id = b.create_job(svc.project_id, [TEST_DATA / "valid"], max_workers=4)
    summary = b.job(job_id)
    assert summary.status is JobStatus.QUEUED and summary.total == 7 and summary.kind is JobKind.IMPORT_VALIDATE
    result = b.run_job(job_id)
    assert result.status is JobStatus.COMPLETED and result.done == 7 and result.records_ok == 13
    assert result.failed_tasks == 0
    with svc.sessions() as s:
        assert s.scalar(select(func.count()).select_from(CookieRow)) == 13
        assert (
            s.scalar(select(func.count()).select_from(CookieRow).where(CookieRow.validation_status.is_(None))) == 0
        ), "весь импорт проверен"
    tasks = b.tasks(job_id)
    assert {t.status for t in tasks} == {TaskStatus.DONE} and all(t.fmt for t in tasks)


def test_broken_file_fails_only_its_task(svc: Services, tmp_path: Path) -> None:
    b = _batch(svc)
    files = [
        TEST_DATA / "valid" / "netscape.txt",
        TEST_DATA / "broken" / "garbage.bin",
        TEST_DATA / "valid" / "selenium.jsonl",
    ]
    job_id = b.create_job(svc.project_id, files)
    result = b.run_job(job_id)
    assert result.status is JobStatus.FAILED  # есть упавший файл
    by_name = {t.name: t for t in b.tasks(job_id)}
    assert by_name["garbage.bin"].status is TaskStatus.FAILED and by_name["garbage.bin"].error
    assert by_name["netscape.txt"].status is TaskStatus.DONE
    assert by_name["selenium.jsonl"].status is TaskStatus.DONE
    assert svc.cookies.count(svc.project_id) == 5  # 3 + 2, битый файл не дал записей


def test_retry_failed(svc: Services, tmp_path: Path) -> None:
    b = _batch(svc)
    bad = tmp_path / "bad.json"
    bad.write_text("{ broken")
    good = tmp_path / "good.jsonl"
    good.write_text('{"name":"a","value":"1","domain":"x.test"}\n')
    job_id = b.create_job(svc.project_id, [bad, good])
    assert b.run_job(job_id).status is JobStatus.FAILED
    # починили файл и повторили только упавшую задачу
    bad.write_text('{"name":"b","value":"2","domain":"y.test"}\n')
    assert b.retry_failed(job_id) == 1
    assert b.job(job_id).status is JobStatus.QUEUED
    result = b.run_job(job_id)
    assert result.status is JobStatus.COMPLETED and result.failed_tasks == 0
    assert svc.cookies.count(svc.project_id) == 2
    # повторная обработка уже импортированного файла помечается skipped
    assert any(t.status is TaskStatus.SKIPPED for t in b.tasks(job_id)) is False


def test_duplicate_options_passthrough(svc: Services, tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    a.write_text('{"name":"dup","value":"1","domain":"x.test"}\n')
    b_file = tmp_path / "b.jsonl"
    b_file.write_text('{"name":"dup","value":"2","domain":"x.test"}\n')
    b = _batch(svc)
    job = b.create_job(svc.project_id, [a, b_file], options=ImportOptions(duplicates=DuplicatePolicy.KEEP))
    b.run_job(job)
    assert svc.cookies.count(svc.project_id) == 2
    assert b.job(job).duplicates == 1


def test_pause_resume_persists(svc: Services, tmp_path: Path) -> None:
    b = _batch(svc)
    paths = _many(tmp_path, 20, rows=100)
    job_id = b.create_job(svc.project_id, paths, max_workers=1)
    paused_at = {}

    def on_progress(p) -> None:  # type: ignore[no-untyped-def]
        if p.done >= 3 and job_id not in paused_at:
            paused_at[job_id] = p.done
            b.pause(job_id)

    result = b.run_job(job_id, progress=on_progress)
    assert result.status is JobStatus.PAUSED
    done_after_pause = result.done
    assert 3 <= done_after_pause < 20
    # новый экземпляр сервиса = как после перезапуска приложения
    b2 = _batch(svc)
    resumable = b2.resumable_jobs(svc.project_id)
    assert [j.id for j in resumable] == [job_id]
    b2.resume(job_id)
    final = b2.run_job(job_id)
    assert final.status is JobStatus.COMPLETED and final.done == 20
    assert svc.cookies.count(svc.project_id) == 20 * 100
    assert final.records_ok == 20 * 100, "записи не задвоились после паузы"


def test_cancel_marks_remaining(svc: Services, tmp_path: Path) -> None:
    b = _batch(svc)
    paths = _many(tmp_path, 30)
    job_id = b.create_job(svc.project_id, paths, max_workers=2)

    def on_progress(p) -> None:  # type: ignore[no-untyped-def]
        if p.done >= 4:
            b.cancel(job_id)

    result = b.run_job(job_id, progress=on_progress)
    assert result.status is JobStatus.CANCELLED
    statuses = [t.status for t in b.tasks(job_id)]
    assert TaskStatus.CANCELLED in statuses and statuses.count(TaskStatus.QUEUED) == 0
    assert b.resumable_jobs(svc.project_id) == []  # отменённая задача не возобновляется


def test_parallel_workers_used(svc: Services, tmp_path: Path) -> None:
    b = _batch(svc)
    job_id = b.create_job(svc.project_id, _many(tmp_path, 8), max_workers=4)
    peak = {"n": 0}
    lock = threading.Lock()
    original = b._process_file

    def traced(*args, **kwargs):  # type: ignore[no-untyped-def]
        with lock:
            traced.active += 1  # type: ignore[attr-defined]
            peak["n"] = max(peak["n"], traced.active)  # type: ignore[attr-defined]
        try:
            time.sleep(0.03)
            return original(*args, **kwargs)
        finally:
            with lock:
                traced.active -= 1  # type: ignore[attr-defined]

    traced.active = 0  # type: ignore[attr-defined]
    b._process_file = traced  # type: ignore[method-assign]
    b.run_job(job_id)
    assert peak["n"] >= 2, "файлы должны обрабатываться параллельно"


def test_create_requires_files(svc: Services, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Не найдено файлов"):
        _batch(svc).create_job(svc.project_id, [tmp_path])  # пустая папка


def test_locked_vault_blocks_run(svc: Services) -> None:
    from app.workers.batch import BatchService as BS

    locked = BS(svc.sessions, None)
    job_id = _batch(svc).create_job(svc.project_id, [TEST_DATA / "valid" / "netscape.txt"])
    with pytest.raises(ValueError, match="заблокировано"):
        locked.run_job(job_id)


def test_default_workers_and_history(svc: Services, tmp_path: Path) -> None:
    b = _batch(svc)
    job_id = b.create_job(svc.project_id, _many(tmp_path, 3))
    assert b.job(job_id).max_workers == DEFAULT_WORKERS
    b.run_job(job_id)
    assert [j.id for j in b.jobs(svc.project_id)] == [job_id]
    with svc.sessions() as s:
        kinds = set(s.scalars(select(Operation.kind)))
    assert {"batch.create", "batch"} <= kinds


def test_values_not_leaked_by_batch(svc: Services, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    import logging
    import secrets

    marker = "BATCHCANARY" + secrets.token_hex(8)
    caplog.set_level(logging.DEBUG)
    f = tmp_path / "canary.jsonl"
    f.write_text(f'{{"name":"sid","value":"{marker}","domain":"x.test"}}\n')
    b = _batch(svc)
    b.run_job(b.create_job(svc.project_id, [f]))
    assert marker not in caplog.text
    db = Path(str(svc.sessions.kw["bind"].url.database))
    assert marker.encode() not in db.read_bytes()
