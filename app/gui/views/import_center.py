"""Import Center: очередь файлов, предпросмотр, параметры, прогресс с отменой, отчёт."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from app.app_context import VaultLockedError, Workspace
from app.gui.models.cookie_table import fmt_expiry
from app.gui.tasks import TaskRunner
from app.gui.theming import STATUS_COLORS
from app.gui.views.base import Page
from app.gui.widgets.dropzone import DropZone
from app.gui.widgets.toast import Notifier
from app.services.common import CancelToken
from app.services.importing import (
    DuplicatePolicy,
    FileStatus,
    ImportOptions,
    ImportPreview,
    ImportProgress,
    ImportReport,
)

FILE_STATUS = {
    FileStatus.IMPORTED: ("Импортирован", STATUS_COLORS["valid"]),
    FileStatus.PARTIAL: ("Частично", STATUS_COLORS["warning"]),
    FileStatus.FAILED: ("Ошибка", STATUS_COLORS["invalid"]),
    FileStatus.ALREADY_IMPORTED: ("Уже импортирован", STATUS_COLORS["unknown"]),
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


class ImportPage(Page):
    title = "Импорт"
    imported = Signal()

    def __init__(self, ws: Workspace, notifier: Notifier, runner: TaskRunner) -> None:
        super().__init__(ws, notifier, runner)
        self.token: CancelToken | None = None
        self.drop = DropZone()
        self.root.addWidget(self.drop)

        tools = QHBoxLayout()
        self.add_files_btn = QPushButton("Добавить файлы…")
        self.add_dir_btn = QPushButton("Добавить папку…")
        self.remove_btn = QPushButton("Убрать из списка")
        self.clear_btn = QPushButton("Очистить список")
        for b in (self.add_files_btn, self.add_dir_btn, self.remove_btn, self.clear_btn):
            tools.addWidget(b)
        tools.addStretch(1)
        self.root.addLayout(tools)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.queue = QListWidget()
        self.queue.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        prev = QFrame()
        prev.setProperty("card", True)
        pl = QVBoxLayout(prev)
        self.preview_title = QLabel("Предпросмотр")
        self.preview_title.setProperty("role", "h2")
        self.preview_info = QLabel("Выберите файл в списке, чтобы увидеть, как он будет прочитан.")
        self.preview_info.setWordWrap(True)
        self.preview_info.setProperty("role", "muted")
        self.preview = QTableWidget(0, 6)
        self.preview.setHorizontalHeaderLabels(["Строка", "Имя", "Домен", "Путь", "Истекает", "Значение"])
        self.preview.verticalHeader().setVisible(False)
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        pl.addWidget(self.preview_title)
        pl.addWidget(self.preview_info)
        pl.addWidget(self.preview, 1)
        split.addWidget(self.queue)
        split.addWidget(prev)
        split.setSizes([320, 700])
        self.root.addWidget(split, 1)

        opts = QHBoxLayout()
        self.duplicates = QComboBox()
        for label, pol in DUPLICATES:
            self.duplicates.addItem(label, pol.value)
        self.duplicates.setCurrentIndex(self.duplicates.findData(ws.settings.get("import.duplicates")))
        self.force = QCheckBox("Импортировать повторно уже загруженные файлы")
        self.validate = QCheckBox("Проверить после импорта")
        self.validate.setChecked(bool(ws.settings.get("import.validate")))
        self.start_btn = QPushButton("Импортировать")
        self.start_btn.setProperty("primary", True)
        self.cancel_btn = QPushButton("Отменить")
        for w in (self.duplicates, self.force, self.validate):
            opts.addWidget(w)
        opts.addStretch(1)
        opts.addWidget(self.cancel_btn)
        opts.addWidget(self.start_btn)
        self.root.addLayout(opts)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress_label = QLabel("")
        self.progress_label.setProperty("role", "muted")
        self.root.addWidget(self.progress)
        self.root.addWidget(self.progress_label)

        self.report = QTableWidget(0, 6)
        self.report.setHorizontalHeaderLabels(["Файл", "Результат", "Формат", "Записей", "Ошибок", "Подробности"])
        self.report.verticalHeader().setVisible(False)
        self.report.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.report.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.report.setMaximumHeight(200)
        self.report.setVisible(False)
        self.root.addWidget(self.report)

        self.drop.dropped.connect(self.add_paths)
        self.add_files_btn.clicked.connect(self._pick_files)
        self.add_dir_btn.clicked.connect(self._pick_dir)
        self.remove_btn.clicked.connect(self._remove_selected)
        self.clear_btn.clicked.connect(self.queue.clear)
        self.clear_btn.clicked.connect(self._sync)
        self.queue.currentItemChanged.connect(lambda cur, _prev: self._preview(cur))
        self.start_btn.clicked.connect(self.start)
        self.cancel_btn.clicked.connect(self.cancel)
        self.duplicates.currentIndexChanged.connect(
            lambda _i: ws.settings.set("import.duplicates", self.duplicates.currentData())
        )
        self.validate.toggled.connect(lambda on: ws.settings.set("import.validate", on))
        ws.on_lock_change(lambda _u: self._sync())
        self._running(False)

    # ------------------------------------------------------------------ очередь
    def paths(self) -> list[Path]:
        return [Path(self.queue.item(i).data(Qt.ItemDataRole.UserRole)) for i in range(self.queue.count())]

    def add_paths(self, paths: list[Path]) -> None:
        known = {str(p) for p in self.paths()}
        for p in paths:
            if str(p) in known:
                continue
            it = QListWidgetItem(("📁 " if p.is_dir() else "") + p.name)
            it.setToolTip(str(p))
            it.setData(Qt.ItemDataRole.UserRole, str(p))
            self.queue.addItem(it)
            known.add(str(p))
        if self.queue.currentRow() < 0 and self.queue.count():
            self.queue.setCurrentRow(0)
        self._sync()

    def _pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self, "Файлы cookies", "", "Cookies (*.txt *.json *.jsonl *.ndjson *.csv *.tsv *.cipx);;Все файлы (*)"
        )
        self.add_paths([Path(f) for f in files])

    def _pick_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Папка с файлами cookies")
        if d:
            self.add_paths([Path(d)])

    def _remove_selected(self) -> None:
        for it in self.queue.selectedItems():
            self.queue.takeItem(self.queue.row(it))
        self._sync()

    def _sync(self) -> None:
        running = self.token is not None
        has = self.queue.count() > 0
        self.start_btn.setEnabled(has and not running and self.ws.unlocked)
        self.start_btn.setToolTip("" if self.ws.unlocked else "Хранилище заблокировано")
        self.remove_btn.setEnabled(has and not running)
        self.clear_btn.setEnabled(has and not running)

    def _preview(self, item: QListWidgetItem | None) -> None:
        self.preview.setRowCount(0)
        if item is None:
            self.preview_title.setText("Предпросмотр")
            self.preview_info.setText("Выберите файл в списке, чтобы увидеть, как он будет прочитан.")
            return
        path = Path(item.data(Qt.ItemDataRole.UserRole))
        if path.is_dir():
            self.preview_title.setText(path.name)
            self.preview_info.setText("Папка: будут импортированы все файлы cookies внутри, включая вложенные папки.")
            return
        self.preview_title.setText(path.name)
        self.preview_info.setText("Чтение…")
        try:
            imp = self.ws.importer()
        except VaultLockedError as e:
            self.preview_info.setText(str(e))
            return
        self.runner.start(lambda _p: imp.preview(path, limit=100), on_done=self._show_preview, on_error=self.error)

    def _show_preview(self, pv: ImportPreview) -> None:
        cur = self.queue.currentItem()
        if cur is None or cur.data(Qt.ItemDataRole.UserRole) != pv.path:
            return  # пока читали, выбрали другой файл
        if pv.fmt is None:
            self.preview_info.setText(f"Файл не будет импортирован: {pv.error}")
            return
        info = f"Формат: {pv.fmt.value}, уверенность {pv.confidence:.0%}."
        if pv.ambiguous_with:
            info += f" Возможно, это {pv.ambiguous_with.value} — проверьте записи ниже."
        if pv.issues:
            info += (
                f" Проблемных строк в начале файла: {len(pv.issues)} (первая: {pv.issues[0].message}"
                + (f", строка {pv.issues[0].line}" if pv.issues[0].line else "")
                + ")."
            )
        if pv.error:
            info += f" Файл повреждён: {pv.error}"
        self.preview_info.setText(info)
        self.preview.setRowCount(len(pv.items))
        for r, it in enumerate(pv.items):
            val = "нет значения" if it.value_length is None else f"•••••• ({it.value_length} симв.)"
            for c, text in enumerate((str(it.line or ""), it.name, it.domain, it.path, fmt_expiry(it.expires_at), val)):
                self.preview.setItem(r, c, _cell(text))

    # ------------------------------------------------------------------ импорт
    def _running(self, on: bool) -> None:
        self.cancel_btn.setEnabled(on)
        self.cancel_btn.setVisible(on)
        self.progress.setVisible(on)
        for w in (self.add_files_btn, self.add_dir_btn, self.duplicates, self.force, self.validate, self.drop):
            w.setEnabled(not on)
        self._sync()

    def start(self) -> None:
        paths, pid = self.paths(), self.project_id
        if not paths or pid is None:
            return
        try:
            importer, validator = self.ws.importer(), self.ws.validator()
        except VaultLockedError as e:
            self.error(e)
            return
        opts = ImportOptions(
            duplicates=DuplicatePolicy(self.duplicates.currentData()), force_reimport=self.force.isChecked()
        )
        do_validate = self.validate.isChecked()
        token = self.token = CancelToken()
        self.report.setRowCount(0)
        self.progress.setValue(0)
        self.progress_label.setText("Подготовка…")
        self._running(True)

        def job(progress: Any) -> tuple[ImportReport, Any]:
            rep = importer.run(pid, paths, opts, progress=progress, cancel=token)
            vr = None
            if rep.status == "completed" and do_validate and rep.records_ok:
                vr = validator.run(pid, batch_id=rep.batch_id, cancel=token, progress=progress)
            return rep, vr

        self.runner.start(job, on_done=self._finished, on_error=self._failed, on_progress=self._on_progress)

    def _on_progress(self, p: Any) -> None:
        if isinstance(p, ImportProgress):
            frac = p.bytes_done / p.bytes_total if p.bytes_total else 0
            self.progress.setValue(int(frac * 1000))
            name = Path(p.current_file).name if p.current_file else ""
            self.progress_label.setText(
                f"Файл {min(p.files_done + 1, p.files_total)} из {p.files_total} {name} — "
                f"записей: {p.records_ok}, ошибок: {p.records_failed}"
            )
        else:  # ValidationProgress
            self.progress.setValue(int(p.done / max(p.total, 1) * 1000))
            self.progress_label.setText(f"Проверка: {p.done} из {p.total}")

    def cancel(self) -> None:
        if self.token:
            self.token.cancel()
            self.cancel_btn.setEnabled(False)
            self.progress_label.setText("Отмена…")

    def _finished(self, result: tuple[ImportReport, Any]) -> None:
        rep, vr = result
        self.token = None
        self._running(False)
        self.report.setVisible(True)
        self.report.setRowCount(len(rep.files))
        for r, f in enumerate(rep.files):
            label, color = FILE_STATUS[f.status]
            if rep.status == "cancelled":
                label, color = "Отменён", STATUS_COLORS["unknown"]
            detail = f.error or (f"дубликатов: {f.duplicates}" if f.duplicates else "")
            if f.warnings:
                detail += (", " if detail else "") + f"замечаний: {f.warnings}"
            for c, (text, col) in enumerate(
                (
                    (Path(f.path).name, None),
                    (label, color),
                    (f.fmt.value if f.fmt else "—", None),
                    (str(f.records_ok), None),
                    (str(f.records_failed), None),
                    (detail, None),
                )
            ):
                cell = _cell(text, col)
                cell.setToolTip(f.path if c == 0 else text)
                self.report.setItem(r, c, cell)
        if rep.status == "cancelled":
            self.progress_label.setText("Импорт отменён. Изменения не сохранены.")
            self.notify.show("Импорт отменён — данные проекта не изменились.", "warning")
            return
        self.progress_label.setText(
            f"Готово за {rep.duration_s:.1f} с: импортировано {rep.records_ok}, ошибок {rep.records_failed}, "
            f"дубликатов {rep.duplicates}"
            + ("; проверка прервана" if vr is not None and vr.status != "completed" else "")
        )
        failed = sum(f.status is FileStatus.FAILED for f in rep.files)
        self.notify.show(
            f"Импортировано записей: {rep.records_ok}" + (f". Файлов с ошибками: {failed}" if failed else ""),
            "warning" if failed else "success",
        )
        self.queue.clear()
        self._sync()
        self.imported.emit()

    def _failed(self, exc: Exception) -> None:
        self.token = None
        self._running(False)
        self.progress_label.setText("Импорт прерван ошибкой, изменения откатаны.")
        self.error(exc)
