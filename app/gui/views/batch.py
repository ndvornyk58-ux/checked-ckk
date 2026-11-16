"""Batch Processor: очередь файлов, воркеры, прогресс, пауза/стоп/повтор, таблица результатов."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
)

from app.app_context import VaultLockedError, Workspace
from app.gui.tasks import TaskRunner
from app.gui.theming import STATUS_COLORS
from app.gui.views.base import Page
from app.gui.widgets.dropzone import DropZone
from app.gui.widgets.toast import Notifier
from app.services.importing import DuplicatePolicy, ImportOptions
from app.workers.batch import BatchProgress, JobKind, JobStatus, JobSummary, TaskStatus, TaskView

TASK_STATE = {
    TaskStatus.QUEUED: ("В очереди", STATUS_COLORS["unknown"]),
    TaskStatus.RUNNING: ("Обрабатывается", "#4FB3BF"),
    TaskStatus.DONE: ("Готово", STATUS_COLORS["valid"]),
    TaskStatus.FAILED: ("Ошибка", STATUS_COLORS["invalid"]),
    TaskStatus.SKIPPED: ("Пропущен", STATUS_COLORS["warning"]),
    TaskStatus.CANCELLED: ("Отменён", STATUS_COLORS["unknown"]),
}
JOB_STATE = {
    JobStatus.QUEUED: "В очереди",
    JobStatus.RUNNING: "Выполняется",
    JobStatus.PAUSED: "Пауза",
    JobStatus.COMPLETED: "Завершено",
    JobStatus.CANCELLED: "Остановлено",
    JobStatus.FAILED: "Завершено с ошибками",
}
DUPLICATES = [
    ("Пропускать дубликаты", DuplicatePolicy.SKIP),
    ("Заменять существующие", DuplicatePolicy.REPLACE),
    ("Сохранять обе записи", DuplicatePolicy.KEEP),
]


def _cell(text: str, color: str | None = None) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
    if color:
        it.setForeground(QColor(color))
    return it


class BatchPage(Page):
    title = "Пакет"

    def __init__(self, ws: Workspace, notifier: Notifier, runner: TaskRunner) -> None:
        super().__init__(ws, notifier, runner)
        self.job_id: int | None = None
        self._tasks: list[TaskView] = []

        hint = QLabel(
            "Пакетная обработка больших наборов файлов: разбор, проверка корректности и аудит "
            "безопасности. Каждый файл обрабатывается отдельно, задача переживает паузу, остановку и "
            "перезапуск программы. Файлы не отправляются в сеть."
        )
        hint.setWordWrap(True)
        hint.setProperty("role", "muted")
        self.root.addWidget(hint)

        self.drop = DropZone()
        self.root.addWidget(self.drop)
        tools = QHBoxLayout()
        self.add_files_btn = QPushButton("Добавить файлы…")
        self.add_dir_btn = QPushButton("Добавить папку…")
        self.clear_btn = QPushButton("Очистить список")
        for b in (self.add_files_btn, self.add_dir_btn, self.clear_btn):
            tools.addWidget(b)
        tools.addStretch(1)
        tools.addWidget(QLabel("Потоков:"))
        self.workers = QSpinBox()
        self.workers.setRange(1, 16)
        self.workers.setValue(4)
        tools.addWidget(self.workers)
        self.validate = QCheckBox("Проверять после импорта")
        self.validate.setChecked(True)
        tools.addWidget(self.validate)
        self.duplicates = QComboBox()
        for label, pol in DUPLICATES:
            self.duplicates.addItem(label, pol.value)
        tools.addWidget(self.duplicates)
        self.root.addLayout(tools)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.queue = QListWidget()
        self.queue.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Файл", "Статус", "Формат", "Записей", "Ошибок / причина"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        split.addWidget(self.queue)
        split.addWidget(self.table)
        split.setSizes([340, 760])
        self.root.addWidget(split, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setVisible(False)
        self.status_label = QLabel("")
        self.status_label.setProperty("role", "muted")
        self.root.addWidget(self.progress)
        self.root.addWidget(self.status_label)

        controls = QHBoxLayout()
        self.start_btn = QPushButton("Запустить обработку")
        self.start_btn.setProperty("primary", True)
        self.pause_btn = QPushButton("Пауза")
        self.resume_btn = QPushButton("Продолжить")
        self.stop_btn = QPushButton("Остановить")
        self.stop_btn.setProperty("danger", True)
        self.retry_btn = QPushButton("Повторить ошибки")
        controls.addWidget(self.start_btn)
        controls.addWidget(self.pause_btn)
        controls.addWidget(self.resume_btn)
        controls.addWidget(self.stop_btn)
        controls.addWidget(self.retry_btn)
        controls.addStretch(1)
        self.root.addLayout(controls)

        self.drop.dropped.connect(self.add_paths)
        self.add_files_btn.clicked.connect(self._pick_files)
        self.add_dir_btn.clicked.connect(self._pick_dir)
        self.clear_btn.clicked.connect(self._clear)
        self.start_btn.clicked.connect(self.start)
        self.pause_btn.clicked.connect(self.pause)
        self.resume_btn.clicked.connect(self.resume)
        self.stop_btn.clicked.connect(self.stop)
        self.retry_btn.clicked.connect(self.retry)
        ws.on_lock_change(lambda _u: self._sync())
        self._poll = QTimer(self)
        self._poll.setInterval(400)
        self._poll.timeout.connect(self._refresh_table)
        self._sync()

    # ------------------------------------------------------------------ очередь
    def paths(self) -> list[Path]:
        return [Path(self.queue.item(i).data(Qt.ItemDataRole.UserRole)) for i in range(self.queue.count())]

    def add_paths(self, paths: list[Path]) -> None:
        known = {str(p) for p in self.paths()}
        for p in paths:
            if str(p) not in known:
                it = QListWidgetItem(("📁 " if p.is_dir() else "") + p.name)
                it.setToolTip(str(p))
                it.setData(Qt.ItemDataRole.UserRole, str(p))
                self.queue.addItem(it)
                known.add(str(p))
        self._sync()

    def _pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self, "Файлы cookies", "", "Cookies (*.txt *.json *.jsonl *.ndjson *.csv *.tsv *.cipx);;Все файлы (*)"
        )
        self.add_paths([Path(f) for f in files])

    def _pick_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Папка с файлами")
        if d:
            self.add_paths([Path(d)])

    def _clear(self) -> None:
        self.queue.clear()
        self._sync()

    def refresh(self) -> None:
        # Подхватить прерванную перезапуском задачу этого проекта.
        if self.project_id is None or self.job_id is not None:
            return
        resumable = self.ws.batch().resumable_jobs(self.project_id)
        if resumable:
            self.job_id = resumable[0].id
            self._load_tasks()
            self.status_label.setText("Найдена незавершённая задача — можно продолжить.")
        self._sync()

    # ------------------------------------------------------------------ запуск
    def start(self) -> None:
        if self.project_id is None or not self.paths():
            return
        try:
            batch = self.ws.batch()
            opts = ImportOptions(duplicates=DuplicatePolicy(self.duplicates.currentData()))
            kind = JobKind.IMPORT_VALIDATE if self.validate.isChecked() else JobKind.IMPORT
            self.job_id = batch.create_job(
                self.project_id, self.paths(), kind=kind, options=opts, max_workers=self.workers.value()
            )
        except (VaultLockedError, ValueError) as e:
            self.error(e)
            return
        self._run()

    def _run(self) -> None:
        if self.job_id is None:
            return
        job_id = self.job_id
        try:
            batch = self.ws.batch()
        except VaultLockedError as e:
            self.error(e)
            return
        self.table.setRowCount(0)
        self.progress.setVisible(True)
        self._poll.start()
        self._set_running(True)
        # progress= получает колбэк задачи (вызывается из рабочего потока); TaskRunner переправляет
        # его значения в главный поток через сигнал on_progress.
        self.runner.start(
            lambda report: batch.run_job(job_id, progress=report),
            on_done=self._finished,
            on_error=self._failed,
            on_progress=self._on_progress,
        )

    def _on_progress(self, p: BatchProgress) -> None:
        frac = p.done / p.total if p.total else 0
        self.progress.setValue(int(frac * 1000))
        current = ", ".join(p.current_files) if p.current_files else "—"
        self.status_label.setText(
            f"{JOB_STATE[p.status]}: {p.done} из {p.total}; записей {p.records_ok}; сейчас: {current}"
        )

    def pause(self) -> None:
        if self.job_id is not None:
            self.ws.batch().pause(self.job_id)
            self.status_label.setText("Приостановка после текущих файлов…")

    def resume(self) -> None:
        if self.job_id is not None:
            self.ws.batch().resume(self.job_id)
            self._run()

    def stop(self) -> None:
        if self.job_id is not None:
            self.ws.batch().cancel(self.job_id)
            self.status_label.setText("Остановка…")

    def retry(self) -> None:
        if self.job_id is None:
            return
        n = self.ws.batch().retry_failed(self.job_id)
        if n:
            self.notify.show(f"Повторная обработка файлов: {n}", "info")
            self._run()
        else:
            self.notify.show("Нет файлов с ошибками для повтора", "info")

    # ------------------------------------------------------------------ результат
    def _finished(self, summary: JobSummary) -> None:
        self._poll.stop()
        self._set_running(False)
        self._load_tasks()
        status = summary.status
        if status is JobStatus.PAUSED:
            self.status_label.setText(f"Пауза: обработано {summary.done} из {summary.total}. Нажмите «Продолжить».")
        elif status is JobStatus.CANCELLED:
            self.status_label.setText(f"Остановлено: обработано {summary.done} из {summary.total}.")
            self.notify.show("Пакетная обработка остановлена", "warning")
        else:
            self.progress.setValue(1000)
            msg = (
                f"Готово: файлов {summary.total}, импортировано записей {summary.records_ok}, "
                f"дубликатов {summary.duplicates}"
            )
            if summary.failed_tasks:
                msg += f", файлов с ошибками {summary.failed_tasks} — можно повторить"
            self.status_label.setText(msg)
            self.notify.show(msg, "warning" if summary.failed_tasks else "success")
            self.on_data_changed()
            if not summary.failed_tasks:
                self.queue.clear()
                self.job_id = None  # задача без ошибок завершена; для повтора ничего не осталось
        self._sync()

    def _failed(self, exc: Exception) -> None:
        self._poll.stop()
        self._set_running(False)
        self.error(exc)
        self._sync()

    def _load_tasks(self) -> None:
        if self.job_id is None:
            return
        self._tasks = self.ws.batch().tasks(self.job_id)
        self._render_tasks()

    def _refresh_table(self) -> None:
        if self.job_id is not None:
            self._tasks = self.ws.batch().tasks(self.job_id)
            self._render_tasks()

    def _render_tasks(self) -> None:
        self.table.setRowCount(len(self._tasks))
        for r, t in enumerate(self._tasks):
            label, color = TASK_STATE[t.status]
            detail = t.error or (f"дубликатов: {t.duplicates}" if t.duplicates else "")
            for c, (text, col) in enumerate(
                ((t.name, None), (label, color), (t.fmt or "—", None), (str(t.records_ok), None), (detail, None))
            ):
                cell = _cell(text, col)
                if c == 0:
                    cell.setToolTip(t.path)
                self.table.setItem(r, c, cell)

    # ------------------------------------------------------------------ состояние кнопок
    def _set_running(self, on: bool) -> None:
        for w in (
            self.add_files_btn,
            self.add_dir_btn,
            self.clear_btn,
            self.drop,
            self.workers,
            self.validate,
            self.duplicates,
            self.start_btn,
        ):
            w.setEnabled(not on)
        self._running = on
        self._sync()

    def _sync(self) -> None:
        running = getattr(self, "_running", False)
        has_queue = self.queue.count() > 0
        unlocked = self.ws.unlocked
        job = None
        if self.job_id is not None:
            try:
                job = self.ws.batch().job(self.job_id)
            except LookupError:
                self.job_id = None
        paused = job is not None and job.status is JobStatus.PAUSED
        failed = job is not None and job.failed_tasks > 0 and not running
        self.start_btn.setEnabled(has_queue and unlocked and not running and self.job_id is None)
        self.start_btn.setToolTip("" if unlocked else "Хранилище заблокировано")
        self.pause_btn.setEnabled(running and not paused)
        self.resume_btn.setEnabled(paused and unlocked and not running)
        self.stop_btn.setEnabled(running or paused)
        self.retry_btn.setEnabled(failed and unlocked)
        for w in (self.add_files_btn, self.add_dir_btn, self.clear_btn):
            w.setEnabled(not running)
