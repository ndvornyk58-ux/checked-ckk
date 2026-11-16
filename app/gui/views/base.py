"""Общая основа экранов."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from app.gui.tasks import TaskRunner
from app.gui.widgets.toast import Notifier
from app.services.workspace import Workspace

if TYPE_CHECKING:
    from collections.abc import Callable


class Page(QWidget):
    """Экран раздела. ``set_project`` вызывается при смене проекта, ``refresh`` — при показе."""

    title = ""

    def __init__(self, ws: Workspace, notifier: Notifier, runner: TaskRunner) -> None:
        super().__init__()
        self.setObjectName("page")
        self.ws, self.notify, self.runner = ws, notifier, runner
        self.project_id: int | None = None
        self.on_data_changed: Callable[[], None] = lambda: None
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(24, 20, 24, 20)
        self.root.setSpacing(14)
        heading = QLabel(self.title, self)
        heading.setProperty("role", "h1")
        self.root.addWidget(heading)

    def set_project(self, project_id: int) -> None:
        self.project_id = project_id
        self.refresh()

    def refresh(self) -> None:
        """Перечитать данные. Переопределяется экранами."""

    def error(self, exc: Exception) -> None:
        self.notify.show(str(exc) or type(exc).__name__, "error")
