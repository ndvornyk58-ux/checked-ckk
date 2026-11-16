"""Главное окно: боковая навигация, выбор проекта, состояние хранилища, экраны."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QKeySequence, QResizeEvent, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from app.gui.dialogs.vault import VaultDialog
from app.gui.tasks import TaskRunner
from app.gui.views.base import Page
from app.gui.views.cookies import CookiesPage
from app.gui.views.dashboard import DashboardPage
from app.gui.views.diagnostics import DiagnosticsPage
from app.gui.views.import_center import ImportPage
from app.gui.views.settings import SettingsPage
from app.gui.widgets.toast import Notifier
from app.services.projects import ProjectError
from app.services.workspace import Workspace


class MainWindow(QMainWindow):
    def __init__(self, ws: Workspace, apply_theme: Any = None) -> None:
        super().__init__()
        self.ws = ws
        self._apply_theme = apply_theme
        self.setWindowTitle("Cookie Inspector Pro")
        self.resize(1360, 840)
        self.setMinimumSize(1000, 640)
        self.runner = TaskRunner(self)
        central = QWidget()
        self.setCentralWidget(central)
        self.notifier = Notifier(central)
        outer = QHBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(200)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 12)
        sl.setSpacing(2)
        brand = QLabel("Cookie Inspector")
        brand.setObjectName("brand")
        sl.addWidget(brand)

        args = (ws, self.notifier, self.runner)
        self.dashboard, self.cookies = DashboardPage(*args), CookiesPage(*args)
        self.importer, self.settings = ImportPage(*args), SettingsPage(*args)
        self.diagnostics = DiagnosticsPage(*args)
        self.pages: list[Page] = [self.dashboard, self.cookies, self.importer, self.diagnostics, self.settings]
        self.stack = QStackedWidget()
        self.nav = QButtonGroup(self)
        self.nav.setExclusive(True)
        self.nav_buttons: list[QPushButton] = []
        for i, page in enumerate(self.pages):
            self.stack.addWidget(page)
            b = QPushButton(page.title)
            b.setProperty("nav", True)
            b.setCheckable(True)
            b.setFocusPolicy(Qt.FocusPolicy.TabFocus)
            b.setToolTip(f"Ctrl+{i + 1}")
            b.clicked.connect(lambda _=False, idx=i: self.show_page(idx))
            self.nav.addButton(b, i)
            self.nav_buttons.append(b)
            sl.addWidget(b)
            self._shortcut(f"Ctrl+{i + 1}", lambda idx=i: self.show_page(idx))
        sl.addStretch(1)
        self.vault_btn = QPushButton()
        self.vault_btn.setProperty("nav", True)
        self.vault_btn.clicked.connect(self.toggle_vault)
        sl.addWidget(self.vault_btn)
        outer.addWidget(side)

        main = QVBoxLayout()
        main.setSpacing(0)
        top = QFrame()
        top.setObjectName("topbar")
        tl = QHBoxLayout(top)
        tl.setContentsMargins(24, 10, 24, 10)
        label = QLabel("Проект")
        label.setProperty("role", "muted")
        self.project_box = QComboBox()
        self.project_box.setMinimumWidth(240)
        self.new_project_btn = QPushButton("Новый проект…")
        tl.addWidget(label)
        tl.addWidget(self.project_box)
        tl.addWidget(self.new_project_btn)
        tl.addStretch(1)
        main.addWidget(top)
        main.addWidget(self.stack, 1)
        outer.addLayout(main, 1)
        self.statusBar().showMessage("Готово")

        for p in self.pages:
            p.on_data_changed = self.data_changed
        self.dashboard.open_cookies.connect(self._open_cookies)
        self.dashboard.open_import.connect(lambda: self.show_page(2))
        self.importer.imported.connect(self.data_changed)
        self.settings.theme_changed.connect(lambda name: self._apply_theme and self._apply_theme(name))
        self.settings.project_deleted.connect(self._project_deleted)
        self.project_box.currentIndexChanged.connect(self._project_selected)
        self.new_project_btn.clicked.connect(self.new_project)
        self._shortcut("Ctrl+F", self._focus_search)
        self._shortcut("Ctrl+I", lambda: self.show_page(2))
        self._shortcut("F5", self.refresh_current)
        ws.on_lock_change(lambda _u: self._sync_vault())

        self.load_projects(ws.default_project().id)
        self._sync_vault()
        self.show_page(0)

    def _shortcut(self, keys: str, fn: Any) -> QShortcut:
        sc = QShortcut(QKeySequence(keys), self)
        sc.activated.connect(fn)
        return sc

    # ------------------------------------------------------------------ навигация
    def show_page(self, idx: int) -> None:
        self.nav_buttons[idx].setChecked(True)
        self.stack.setCurrentIndex(idx)
        self.pages[idx].refresh()

    def current_page(self) -> Page:
        return self.pages[self.stack.currentIndex()]

    def refresh_current(self) -> None:
        self.current_page().refresh()
        self.statusBar().showMessage("Обновлено", 2000)

    def _focus_search(self) -> None:
        self.show_page(1)
        self.cookies.search.setFocus()
        self.cookies.search.selectAll()

    def _open_cookies(self, spec: dict[str, Any]) -> None:
        self.nav_buttons[1].setChecked(True)
        self.stack.setCurrentIndex(1)
        self.cookies.set_filter(spec)

    # ------------------------------------------------------------------ проекты
    def load_projects(self, select_id: int | None = None) -> None:
        self.project_box.blockSignals(True)
        self.project_box.clear()
        for p in self.ws.projects.list():
            self.project_box.addItem(f"{p.name}  ({p.cookie_count})", p.id)
        idx = self.project_box.findData(select_id) if select_id is not None else 0
        self.project_box.setCurrentIndex(max(idx, 0))
        self.project_box.blockSignals(False)
        self._project_selected()

    @property
    def project_id(self) -> int:
        return int(self.project_box.currentData())

    def _project_selected(self) -> None:
        pid = self.project_box.currentData()
        if pid is None:
            return
        self.ws.settings.set("last_project", pid)
        for p in self.pages:
            p.project_id = pid
        self.current_page().refresh()

    def new_project(self) -> None:
        name, ok = QInputDialog.getText(self, "Новый проект", "Название проекта:")
        if not ok or not name.strip():
            return
        try:
            p = self.ws.projects.create(name)
        except ProjectError as e:
            self.notifier.show(str(e), "error")
            return
        self.load_projects(p.id)
        self.notifier.show(f"Создан проект «{p.name}»", "success")

    def _project_deleted(self) -> None:
        self.load_projects(self.ws.default_project().id)
        self.show_page(0)

    def data_changed(self) -> None:
        """После импорта, удаления и т.п.: обновить счётчики проектов и текущий экран."""
        self.load_projects(self.project_id)

    # ------------------------------------------------------------------ хранилище
    def _sync_vault(self) -> None:
        self.vault_btn.setText("Хранилище открыто" if self.ws.unlocked else "Разблокировать хранилище")
        self.vault_btn.setToolTip(
            "Нажмите, чтобы заблокировать"
            if self.ws.unlocked
            else "Значения cookies недоступны, пока хранилище заблокировано"
        )
        self.cookies._selection_changed()

    def toggle_vault(self) -> None:
        if self.ws.unlocked:
            self.ws.lock()
            self.notifier.show("Хранилище заблокировано", "info")
        elif VaultDialog(self.ws, self).exec():
            self.notifier.show("Хранилище разблокировано", "success")

    # ------------------------------------------------------------------ события окна
    def resizeEvent(self, e: QResizeEvent) -> None:
        super().resizeEvent(e)
        self.notifier.relayout()

    def closeEvent(self, e: QCloseEvent) -> None:
        if self.importer.token is not None:
            self.importer.cancel()
        self.runner.wait(10_000)
        super().closeEvent(e)


__all__ = ["MainWindow", "Qt"]
