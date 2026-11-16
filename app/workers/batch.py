"""Batch Processor — пакетная обработка файлов через очередь задач.

Отличие от прямого импорта (ImportService): каждый файл — отдельная единица работы (task) со своим
статусом, журналом и возможностью повтора; задача целиком переживает паузу, остановку и даже
перезапуск приложения (состояние хранится в таблицах ``jobs`` и ``job_tasks``).

Что batch делает и чего не делает (ADR-0004): это локальная обработка файлов — разбор, проверка
корректности и аудит безопасности. Сетевого шага здесь нет: массово отправить импортированные
cookies на какой-либо сервер невозможно по построению.

Параллелизм: файлы обрабатываются пулом рабочих потоков (число настраивается). Разбор одного файла
последовательный и потоковый, запись в БД сериализуется сервисным слоем. Пауза/остановка —
кооперативные, проверяются между файлами и между чанками внутри файла.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, cast

from sqlalchemy import CursorResult, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.crypto import CryptoBox
from app.infrastructure.db.models import Job, JobTask
from app.services.common import now_ts, record_operation
from app.services.importing import (
    DuplicatePolicy,
    FileStatus,
    ImportOptions,
    ImportService,
    collect_files,
)
from app.services.validation import ValidationService

log = logging.getLogger(__name__)

DEFAULT_WORKERS: Final = 4
MAX_WORKERS: Final = 16
POLL_S: Final = 0.05


class JobKind(StrEnum):
    IMPORT = "import"  # разобрать и сохранить файлы
    IMPORT_VALIDATE = "import_validate"  # + проверить корректность и безопасность


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class TaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"  # файл уже импортирован ранее
    CANCELLED = "cancelled"


_TERMINAL_JOB = {JobStatus.COMPLETED, JobStatus.CANCELLED, JobStatus.FAILED}


@dataclass(frozen=True, slots=True)
class TaskView:
    id: int
    seq: int
    path: str
    status: TaskStatus
    attempts: int
    records_ok: int
    records_failed: int
    duplicates: int
    fmt: str | None
    error: str | None

    @property
    def name(self) -> str:
        return Path(self.path).name


@dataclass(frozen=True, slots=True)
class JobSummary:
    id: int
    project_id: int
    kind: JobKind
    status: JobStatus
    max_workers: int
    done: int
    total: int
    records_ok: int
    records_failed: int
    duplicates: int
    failed_tasks: int
    created_at: int
    finished_at: int | None

    @property
    def active(self) -> bool:
        return self.status in (JobStatus.RUNNING, JobStatus.PAUSED, JobStatus.QUEUED)


@dataclass(frozen=True, slots=True)
class BatchProgress:
    job_id: int
    status: JobStatus
    done: int
    total: int
    records_ok: int
    records_failed: int
    current_files: tuple[str, ...]


class _Control:
    """Разделяемые между потоками флаги паузы и остановки одной задачи."""

    def __init__(self) -> None:
        self.pause = threading.Event()
        self.cancel = threading.Event()
        self._resume = threading.Event()
        self._resume.set()

    def set_paused(self, paused: bool) -> None:
        self.pause.set() if paused else self.pause.clear()
        self._resume.clear() if paused else self._resume.set()

    def wait_if_paused(self) -> None:
        # Между файлами ждём снятия паузы, но не дольше, чтобы быстро реагировать на отмену.
        while self.pause.is_set() and not self.cancel.is_set():
            self._resume.wait(0.1)


class BatchService:
    """Создаёт задачи и выполняет их пулом потоков. Один экземпляр на приложение."""

    def __init__(self, sessions: sessionmaker[Session], box: CryptoBox | None) -> None:
        self._sessions = sessions
        self._box = box
        self._controls: dict[int, _Control] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ создание
    def create_job(
        self,
        project_id: int,
        paths: Iterable[Path],
        *,
        kind: JobKind = JobKind.IMPORT_VALIDATE,
        options: ImportOptions | None = None,
        max_workers: int = DEFAULT_WORKERS,
    ) -> int:
        """Развернуть пути в список файлов и создать задачу со статусом queued."""
        files = collect_files(paths)
        if not files:
            raise ValueError("Не найдено файлов для обработки")
        opts = options or ImportOptions()
        workers = max(1, min(max_workers, MAX_WORKERS))
        ts = now_ts()
        with self._sessions.begin() as s:
            job = Job(
                project_id=project_id,
                kind=kind.value,
                status=JobStatus.QUEUED.value,
                max_workers=workers,
                progress_done=0,
                progress_total=len(files),
                options={"duplicates": opts.duplicates.value, "force": opts.force_reimport},
                created_at=ts,
            )
            s.add(job)
            s.flush()
            s.add_all(
                JobTask(job_id=job.id, seq=i, status=TaskStatus.QUEUED.value, attempts=0, payload={"path": str(p)})
                for i, p in enumerate(files)
            )
            record_operation(
                s,
                project_id=project_id,
                kind="batch.create",
                outcome="ok",
                summary=f"Создана пакетная задача: файлов {len(files)}",
                details={"job_id": job.id},
            )
            return job.id

    # ------------------------------------------------------------------ выполнение
    def run_job(self, job_id: int, *, progress: Callable[[BatchProgress], None] | None = None) -> JobSummary:
        """Выполнить задачу до завершения, паузы или остановки. Блокирующий вызов (его запускают в потоке)."""
        control = self._control(job_id)
        control.cancel.clear()
        opts = self._options(job_id)
        importer = ImportService(self._sessions, self._require_box())
        validator = ValidationService(self._sessions, self._require_box())
        do_validate = self._kind(job_id) is JobKind.IMPORT_VALIDATE
        self._set_status(job_id, JobStatus.RUNNING, started=True)

        current: dict[int, str] = {}
        current_lock = threading.Lock()
        queue = list(self._pending_tasks(job_id))
        queue_lock = threading.Lock()

        def emit() -> None:
            if progress:
                progress(self._progress(job_id, tuple(current.values())))

        def claim() -> tuple[int, int, str] | None:
            with queue_lock:
                return queue.pop(0) if queue else None

        def worker() -> None:
            # Поток берёт файлы по одному и сразу выходит, если нажата пауза или остановка —
            # паузу «пережидает» не поток в пуле, а сама задача (её возобновят новым run_job).
            while not control.pause.is_set() and not control.cancel.is_set():
                claimed = claim()
                if claimed is None:
                    return
                task_id, seq, path = claimed
                with current_lock:
                    current[seq] = Path(path).name
                try:
                    view = self._process_file(
                        importer, validator, job_id, task_id, Path(path), opts, do_validate, control
                    )
                finally:
                    with current_lock:
                        current.pop(seq, None)
                emit()
                log.info(
                    "batch job=%d task=%d %s: %s ok=%d",
                    job_id,
                    task_id,
                    Path(path).name,
                    view.status.value,
                    view.records_ok,
                )

        workers = self._summary(job_id).max_workers
        emit()
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=f"batch-{job_id}") as pool:
            for f in [pool.submit(worker) for _ in range(workers)]:
                f.result()  # исключения уже обработаны внутри worker

        self._finalize(job_id, control)
        emit()
        return self._summary(job_id)

    def _process_file(
        self,
        importer: ImportService,
        validator: ValidationService,
        job_id: int,
        task_id: int,
        path: Path,
        opts: ImportOptions,
        do_validate: bool,
        control: _Control,
    ) -> TaskView:
        self._set_task(task_id, TaskStatus.RUNNING, started=True, bump_attempt=True)
        started = time.monotonic()
        try:
            report = importer.run(self._project_id(job_id), [path], opts, cancel=_cancel_adapter(control))
        except Exception as exc:
            log.exception("batch job=%d task=%d: ошибка обработки файла", job_id, task_id)
            return self._set_task(task_id, TaskStatus.FAILED, error=f"{type(exc).__name__}: {exc}")
        if report.status == "cancelled":
            # Прерывание по паузе: импорт откатан, файл возвращается в очередь и будет обработан
            # при возобновлении. Прерывание по остановке: файл помечается отменённым.
            return self._set_task(task_id, TaskStatus.CANCELLED if control.cancel.is_set() else TaskStatus.QUEUED)
        file_rep = report.files[0]
        batch_id = report.batch_id
        if do_validate and file_rep.records_ok:
            try:
                validator.run(self._project_id(job_id), batch_id=batch_id, cancel=_cancel_adapter(control))
            except Exception:
                log.exception("batch job=%d task=%d: ошибка проверки", job_id, task_id)
        status = {
            FileStatus.IMPORTED: TaskStatus.DONE,
            FileStatus.PARTIAL: TaskStatus.DONE,
            FileStatus.FAILED: TaskStatus.FAILED,
            FileStatus.ALREADY_IMPORTED: TaskStatus.SKIPPED,
        }[file_rep.status]
        return self._set_task(
            task_id,
            status,
            fmt=file_rep.fmt.value if file_rep.fmt else None,
            error=file_rep.error,
            records_ok=file_rep.records_ok,
            records_failed=file_rep.records_failed,
            duplicates=file_rep.duplicates,
            elapsed=time.monotonic() - started,
        )

    # ------------------------------------------------------------------ управление
    def pause(self, job_id: int) -> None:
        self._control(job_id).set_paused(True)
        with self._sessions.begin() as s:
            s.execute(
                update(Job)
                .where(Job.id == job_id, Job.status == JobStatus.RUNNING.value)
                .values(status=JobStatus.PAUSED.value)
            )

    def resume(self, job_id: int) -> None:
        self._control(job_id).set_paused(False)
        with self._sessions.begin() as s:
            s.execute(
                update(Job)
                .where(Job.id == job_id, Job.status == JobStatus.PAUSED.value)
                .values(status=JobStatus.RUNNING.value)
            )

    def cancel(self, job_id: int) -> None:
        c = self._control(job_id)
        c.cancel.set()
        c.set_paused(False)

    def retry_failed(self, job_id: int) -> int:
        """Вернуть упавшие файлы в очередь. Задачу после этого запускают снова."""
        with self._sessions.begin() as s:
            result = s.execute(
                update(JobTask)
                .where(
                    JobTask.job_id == job_id, JobTask.status.in_([TaskStatus.FAILED.value, TaskStatus.CANCELLED.value])
                )
                .values(status=TaskStatus.QUEUED.value, error=None)
            )
            n = cast("CursorResult[Any]", result).rowcount
            if n:
                s.execute(update(Job).where(Job.id == job_id).values(status=JobStatus.QUEUED.value, finished_at=None))
        return int(n)

    def resumable_jobs(self, project_id: int | None = None) -> list[JobSummary]:
        """Задачи, прерванные выходом из приложения (running/paused/queued с незавершёнными файлами)."""
        with self._sessions() as s:
            q = select(Job).where(
                Job.status.in_([s.value for s in (JobStatus.RUNNING, JobStatus.PAUSED, JobStatus.QUEUED)])
            )
            if project_id is not None:
                q = q.where(Job.project_id == project_id)
            return [self._to_summary(s, j) for j in s.scalars(q.order_by(Job.id.desc()))]

    # ------------------------------------------------------------------ чтение
    def job(self, job_id: int) -> JobSummary:
        return self._summary(job_id)

    def jobs(self, project_id: int, limit: int = 50) -> list[JobSummary]:
        with self._sessions() as s:
            return [
                self._to_summary(s, j)
                for j in s.scalars(select(Job).where(Job.project_id == project_id).order_by(Job.id.desc()).limit(limit))
            ]

    def tasks(self, job_id: int) -> list[TaskView]:
        with self._sessions() as s:
            return [
                _task_view(t) for t in s.scalars(select(JobTask).where(JobTask.job_id == job_id).order_by(JobTask.seq))
            ]

    # ------------------------------------------------------------------ внутреннее
    def _control(self, job_id: int) -> _Control:
        with self._lock:
            return self._controls.setdefault(job_id, _Control())

    def _require_box(self) -> CryptoBox:
        if self._box is None:
            raise ValueError("Хранилище заблокировано — пакетная обработка недоступна")
        return self._box

    def _pending_tasks(self, job_id: int) -> list[tuple[int, int, str]]:
        with self._sessions() as s:
            rows = s.execute(
                select(JobTask.id, JobTask.seq, JobTask.payload)
                .where(JobTask.job_id == job_id, JobTask.status == TaskStatus.QUEUED.value)
                .order_by(JobTask.seq)
            ).all()
            return [(tid, seq, payload.get("path", "")) for tid, seq, payload in rows]

    def _project_id(self, job_id: int) -> int:
        return self._summary(job_id).project_id

    def _kind(self, job_id: int) -> JobKind:
        return JobKind(self._summary(job_id).kind)

    def _options(self, job_id: int) -> ImportOptions:
        with self._sessions() as s:
            job = s.get(Job, job_id)
            o = job.options if job else {}
        return ImportOptions(
            duplicates=DuplicatePolicy(o.get("duplicates", "skip")), force_reimport=bool(o.get("force"))
        )

    def _set_status(self, job_id: int, status: JobStatus, *, started: bool = False) -> None:
        with self._sessions.begin() as s:
            vals: dict[str, Any] = {"status": status.value}
            if started:
                job = s.get(Job, job_id)
                if job and job.started_at is None:
                    vals["started_at"] = now_ts()
            s.execute(update(Job).where(Job.id == job_id).values(**vals))

    def _set_task(
        self,
        task_id: int,
        status: TaskStatus,
        *,
        started: bool = False,
        bump_attempt: bool = False,
        error: str | None = None,
        fmt: str | None = None,
        records_ok: int = 0,
        records_failed: int = 0,
        duplicates: int = 0,
        elapsed: float | None = None,
    ) -> TaskView:
        with self._sessions.begin() as s:
            t = s.get(JobTask, task_id)
            if t is None:
                raise LookupError(f"Задача-файл {task_id} не найдена")
            t.status = status.value
            if started:
                t.started_at = now_ts()
            if bump_attempt:
                t.attempts += 1
            if status in (TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.SKIPPED, TaskStatus.CANCELLED):
                t.finished_at = now_ts()
            t.error = error
            cp = dict(t.checkpoint)
            cp.update(
                {
                    "fmt": fmt,
                    "records_ok": records_ok,
                    "records_failed": records_failed,
                    "duplicates": duplicates,
                    "elapsed_s": round(elapsed, 3) if elapsed else None,
                }
            )
            t.checkpoint = cp
            return _task_view(t)

    def _finalize(self, job_id: int, control: _Control) -> JobStatus:
        with self._sessions.begin() as s:
            remaining = (
                s.scalar(
                    select(func.count())
                    .select_from(JobTask)
                    .where(JobTask.job_id == job_id, JobTask.status == TaskStatus.QUEUED.value)
                )
                or 0
            )
            failed = (
                s.scalar(
                    select(func.count())
                    .select_from(JobTask)
                    .where(JobTask.job_id == job_id, JobTask.status == TaskStatus.FAILED.value)
                )
                or 0
            )
            if control.cancel.is_set():
                status = JobStatus.CANCELLED
                s.execute(
                    update(JobTask)
                    .where(JobTask.job_id == job_id, JobTask.status == TaskStatus.QUEUED.value)
                    .values(status=TaskStatus.CANCELLED.value)
                )
            elif control.pause.is_set() and remaining:
                status = JobStatus.PAUSED
            elif remaining:
                status = JobStatus.PAUSED  # вышли по паузе
            else:
                status = JobStatus.FAILED if failed else JobStatus.COMPLETED
            job = s.get(Job, job_id)
            if job:
                job.status = status.value
                if status in _TERMINAL_JOB:
                    job.finished_at = now_ts()
                    record_operation(
                        s,
                        project_id=job.project_id,
                        kind="batch",
                        outcome=status.value,
                        summary=f"Пакетная обработка: {status.value}, файлов {job.progress_total}",
                        details={"job_id": job_id},
                    )
            return status

    def _progress(self, job_id: int, current: tuple[str, ...]) -> BatchProgress:
        summary = self._summary(job_id)
        return BatchProgress(
            job_id, summary.status, summary.done, summary.total, summary.records_ok, summary.records_failed, current
        )

    def _summary(self, job_id: int) -> JobSummary:
        with self._sessions() as s:
            job = s.get(Job, job_id)
            if job is None:
                raise LookupError(f"Задача {job_id} не найдена")
            return self._to_summary(s, job)

    def _to_summary(self, s: Session, job: Job) -> JobSummary:
        rows = s.execute(select(JobTask.status, JobTask.checkpoint).where(JobTask.job_id == job.id)).all()
        done = sum(
            st in (TaskStatus.DONE.value, TaskStatus.FAILED.value, TaskStatus.SKIPPED.value, TaskStatus.CANCELLED.value)
            for st, _ in rows
        )
        failed = sum(st == TaskStatus.FAILED.value for st, _ in rows)
        ok = sum(int((cp or {}).get("records_ok", 0)) for _, cp in rows)
        bad = sum(int((cp or {}).get("records_failed", 0)) for _, cp in rows)
        dup = sum(int((cp or {}).get("duplicates", 0)) for _, cp in rows)
        return JobSummary(
            job.id,
            job.project_id,
            JobKind(job.kind),
            JobStatus(job.status),
            job.max_workers,
            done,
            len(rows),
            ok,
            bad,
            dup,
            failed,
            job.created_at,
            job.finished_at,
        )


def _task_view(t: JobTask) -> TaskView:
    cp = t.checkpoint or {}
    return TaskView(
        t.id,
        t.seq,
        t.payload.get("path", ""),
        TaskStatus(t.status),
        t.attempts,
        int(cp.get("records_ok", 0)),
        int(cp.get("records_failed", 0)),
        int(cp.get("duplicates", 0)),
        cp.get("fmt"),
        t.error,
    )


def _cancel_adapter(control: _Control):  # type: ignore[no-untyped-def]
    """Адаптер флагов batch к интерфейсу CancelToken сервисов импорта/проверки.

    Пауза внутри файла тоже прерывает импорт этого файла (с откатом), чтобы быстро
    освободить поток; недоделанный файл остаётся в очереди и обработается при возобновлении.
    """
    from app.services.common import CancelToken

    class _Token(CancelToken):
        @property
        def cancelled(self) -> bool:
            return control.cancel.is_set() or control.pause.is_set()

        def raise_if_cancelled(self) -> None:
            if self.cancelled:
                from app.services.common import OperationCancelled

                raise OperationCancelled

    return _Token()
