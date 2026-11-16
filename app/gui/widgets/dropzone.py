"""Зона перетаскивания файлов и каталогов."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDropEvent
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


class DropZone(QFrame):
    dropped = Signal(list)  # list[Path]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("dropzone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(110)
        lay = QVBoxLayout(self)
        title = QLabel("Перетащите файлы или папки с cookies сюда", self)
        title.setProperty("role", "h2")
        hint = QLabel(
            "Netscape, JSON, JSON Lines, CSV и CIPX — формат определится автоматически. "
            "Файлы обрабатываются только на этом компьютере.",
            self,
        )
        hint.setProperty("role", "muted")
        hint.setWordWrap(True)
        for w in (title, hint):
            w.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lay.addWidget(w)

    def _set_active(self, on: bool) -> None:
        self.setProperty("active", on)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e: QDragEnterEvent) -> None:
        if e.mimeData().hasUrls() and any(u.isLocalFile() for u in e.mimeData().urls()):
            e.acceptProposedAction()
            self._set_active(True)

    def dragLeaveEvent(self, _e: QDragLeaveEvent) -> None:
        self._set_active(False)

    def dropEvent(self, e: QDropEvent) -> None:
        self._set_active(False)
        paths = [Path(u.toLocalFile()) for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.dropped.emit(paths)
            e.acceptProposedAction()
