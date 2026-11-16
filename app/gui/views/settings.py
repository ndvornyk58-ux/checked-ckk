"""Настройки: оформление, защита ключа, данные проекта, сведения об установке."""

from __future__ import annotations

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from app import __version__
from app.app_context import Workspace
from app.gui.dialogs.vault import ChangePasswordDialog
from app.gui.tasks import TaskRunner
from app.gui.views.base import Page
from app.gui.widgets.toast import Notifier
from app.services.keys import KeyProtection


def _section(title: str, text: str) -> tuple[QFrame, QVBoxLayout, QLabel]:
    f = QFrame()
    f.setProperty("card", True)
    lay = QVBoxLayout(f)
    h = QLabel(title)
    h.setProperty("role", "h2")
    t = QLabel(text)
    t.setWordWrap(True)
    t.setProperty("role", "muted")
    lay.addWidget(h)
    lay.addWidget(t)
    return f, lay, t


class SettingsPage(Page):
    title = "Настройки"
    theme_changed = Signal(str)
    project_deleted = Signal()

    def __init__(self, ws: Workspace, notifier: Notifier, runner: TaskRunner) -> None:
        super().__init__(ws, notifier, runner)
        look, ll, _ = _section("Оформление", "Тема применяется сразу.")
        self.theme = QComboBox()
        self.theme.addItem("Тёмная", "dark")
        self.theme.addItem("Светлая", "light")
        self.theme.setCurrentIndex(self.theme.findData(ws.settings.get("theme")))
        ll.addWidget(self.theme)
        self.root.addWidget(look)

        sec, sl, self.protection_text = _section("Защита значений", "")
        row = QHBoxLayout()
        self.change_pw_btn = QPushButton("Сменить мастер-пароль…")
        self.lock_btn = QPushButton("Заблокировать хранилище")
        row.addWidget(self.change_pw_btn)
        row.addWidget(self.lock_btn)
        row.addStretch(1)
        sl.addLayout(row)
        self.root.addWidget(sec)

        data, dl, _ = _section(
            "Данные проекта",
            "Очистка значений удаляет сами значения cookies, сохраняя имена, "
            "домены, флаги и результаты проверок. Удаление проекта необратимо.",
        )
        row2 = QHBoxLayout()
        self.purge_btn = QPushButton("Очистить значения…")
        self.purge_btn.setProperty("danger", True)
        self.rename_btn = QPushButton("Переименовать проект…")
        self.delete_btn = QPushButton("Удалить проект…")
        self.delete_btn.setProperty("danger", True)
        for b in (self.rename_btn, self.purge_btn, self.delete_btn):
            row2.addWidget(b)
        row2.addStretch(1)
        dl.addLayout(row2)
        self.root.addWidget(data)

        about, al, _ = _section(
            "О программе",
            f"Cookie Inspector Pro {__version__}. Данные хранятся в: {ws.data_dir}"
            + (" (портативный режим)" if ws.portable else ""),
        )
        self.open_dir_btn = QPushButton("Открыть папку данных")
        al.addWidget(self.open_dir_btn)
        self.root.addWidget(about)
        self.root.addStretch(1)

        self.theme.currentIndexChanged.connect(self._theme)
        self.change_pw_btn.clicked.connect(self._change_password)
        self.lock_btn.clicked.connect(self._lock)
        self.purge_btn.clicked.connect(self._purge)
        self.rename_btn.clicked.connect(self._rename)
        self.delete_btn.clicked.connect(self._delete)
        self.open_dir_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ws.data_dir))))
        ws.on_lock_change(lambda _u: self.refresh())

    def refresh(self) -> None:
        prot = self.ws.keys.protection()
        text = {
            KeyProtection.KEYRING: "Ключ защищён системным хранилищем ключей.",
            KeyProtection.PASSWORD: "Ключ защищён мастер-паролем.",
            KeyProtection.NONE: "Ключ не создан.",
        }[prot]
        self.protection_text.setText(
            text + (" Хранилище разблокировано." if self.ws.unlocked else " Хранилище заблокировано.")
        )
        self.change_pw_btn.setVisible(prot is KeyProtection.PASSWORD)
        self.lock_btn.setEnabled(self.ws.unlocked)

    def _theme(self) -> None:
        name = self.theme.currentData()
        self.ws.settings.set("theme", name)
        self.theme_changed.emit(name)

    def _change_password(self) -> None:
        if ChangePasswordDialog(self.ws, self).exec():
            self.notify.show("Мастер-пароль изменён", "success")

    def _lock(self) -> None:
        self.ws.lock()
        self.notify.show("Хранилище заблокировано. Значения недоступны до разблокировки.", "info")

    def _confirm(self, title: str, text: str) -> bool:
        return (
            QMessageBox.question(
                self,
                title,
                text,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            == QMessageBox.StandardButton.Yes
        )

    def _purge(self) -> None:
        if self.project_id is not None and self._confirm("Очистка значений", "Удалить значения всех cookies проекта?"):
            n = self.ws.cookies.purge_values(self.project_id)
            self.notify.show(f"Значения удалены у записей: {n}", "success")
            self.on_data_changed()

    def _rename(self) -> None:
        if self.project_id is None:
            return
        name, ok = QInputDialog.getText(self, "Переименовать проект", "Новое имя:")
        if ok and name.strip():
            try:
                self.ws.projects.rename(self.project_id, name)
            except Exception as e:  # noqa: BLE001
                self.error(e)
                return
            self.notify.show("Проект переименован", "success")
            self.on_data_changed()

    def _delete(self) -> None:
        if self.project_id is not None and self._confirm(
            "Удаление проекта", "Удалить проект со всеми данными? Действие необратимо."
        ):
            self.ws.projects.delete(self.project_id)
            self.notify.show("Проект удалён", "success")
            self.project_deleted.emit()
