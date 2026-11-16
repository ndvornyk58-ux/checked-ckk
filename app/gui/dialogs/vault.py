"""Настройка и разблокировка хранилища значений.

Вычисление ключа из пароля (scrypt) намеренно медленное, поэтому выполняется в фоне —
окно остаётся отзывчивым, а кнопки блокируются на время проверки.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from app.app_context import Workspace
from app.gui.tasks import TaskRunner
from app.services.keys import KeyError_, KeyProtection, KeyUnavailableError, WrongKeyError

MIN_PASSWORD = 8


class VaultDialog(QDialog):
    """Первый запуск — создание ключа; дальше — ввод мастер-пароля."""

    def __init__(self, ws: Workspace, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ws = ws
        self.runner = TaskRunner(self)
        self.setup_mode = ws.keys.protection() is KeyProtection.NONE
        self.setWindowTitle("Cookie Inspector Pro")
        self.setMinimumWidth(440)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)

        title = QLabel("Защита сохранённых значений" if self.setup_mode else "Разблокировка хранилища", self)
        title.setProperty("role", "h2")
        lay.addWidget(title)
        intro = QLabel(
            "Значения cookies хранятся только в зашифрованном виде. Выберите, чем защитить ключ шифрования."
            if self.setup_mode
            else "Введите мастер-пароль, чтобы работать со значениями cookies.",
            self,
        )
        intro.setWordWrap(True)
        intro.setProperty("role", "muted")
        lay.addWidget(intro)

        self.use_keyring = QRadioButton("Системное хранилище ключей Windows / macOS / Linux", self)
        self.use_password = QRadioButton("Мастер-пароль", self)
        group = QButtonGroup(self)
        for rb in (self.use_keyring, self.use_password):
            group.addButton(rb)
            rb.setVisible(self.setup_mode)
            lay.addWidget(rb)
        self.use_keyring.setChecked(True)

        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Мастер-пароль")
        self.confirm = QLineEdit(self)
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm.setPlaceholderText("Повторите пароль")
        lay.addWidget(self.password)
        lay.addWidget(self.confirm)
        self.warning = QLabel("Пароль не восстанавливается: без него сохранённые значения прочитать нельзя.", self)
        self.warning.setWordWrap(True)
        self.warning.setProperty("role", "muted")
        lay.addWidget(self.warning)
        self.error = QLabel("", self)
        self.error.setWordWrap(True)
        self.error.setStyleSheet("color:#E0364F;")
        lay.addWidget(self.error)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.quit_btn = QPushButton("Выйти", self)
        self.ok_btn = QPushButton("Создать ключ" if self.setup_mode else "Разблокировать", self)
        self.ok_btn.setProperty("primary", True)
        self.ok_btn.setDefault(True)
        buttons.addWidget(self.quit_btn)
        buttons.addWidget(self.ok_btn)
        lay.addLayout(buttons)

        self.quit_btn.clicked.connect(self.reject)
        self.ok_btn.clicked.connect(self.submit)
        self.use_keyring.toggled.connect(self._sync)
        self.password.returnPressed.connect(self.submit)
        self._sync()

    def _sync(self) -> None:
        pw = not self.setup_mode or self.use_password.isChecked()
        self.password.setVisible(pw)
        self.confirm.setVisible(self.setup_mode and pw)
        self.warning.setVisible(self.setup_mode and pw)
        if pw:
            self.password.setFocus()

    def submit(self) -> None:
        self.error.setText("")
        pw = self.password.text()
        keys = self.ws.keys
        if self.setup_mode and self.use_keyring.isChecked():
            fn: Any = lambda _p: keys.initialize_with_keyring()  # noqa: E731
        else:
            if self.setup_mode:
                if len(pw) < MIN_PASSWORD:
                    self.error.setText(f"Пароль должен содержать не менее {MIN_PASSWORD} символов.")
                    return
                if pw != self.confirm.text():
                    self.error.setText("Пароли не совпадают.")
                    return
                fn = lambda _p: keys.initialize_with_password(pw)  # noqa: E731
            else:
                fn = lambda _p: keys.unlock_with_password(pw)  # noqa: E731
        self._busy(True)
        self.runner.start(fn, on_done=self._done, on_error=self._failed)

    def _busy(self, on: bool) -> None:
        for w in (self.ok_btn, self.password, self.confirm, self.use_keyring, self.use_password):
            w.setEnabled(not on)
        self.ok_btn.setText("Проверка…" if on else ("Создать ключ" if self.setup_mode else "Разблокировать"))

    def _done(self, box: Any) -> None:
        self.ws.attach(box)
        self.accept()

    def _failed(self, exc: Exception) -> None:
        self._busy(False)
        if isinstance(exc, KeyUnavailableError) and self.setup_mode:
            self.use_password.setChecked(True)
            self.error.setText(f"{exc}. Используйте мастер-пароль.")
        elif isinstance(exc, WrongKeyError):
            self.error.setText("Неверный мастер-пароль.")
            self.password.selectAll()
            self.password.setFocus()
        elif isinstance(exc, KeyError_ | ValueError):
            self.error.setText(str(exc))
        else:
            self.error.setText(f"Не удалось открыть хранилище: {type(exc).__name__}")


def unlock_without_dialog(ws: Workspace) -> str | None:
    """Если ключ защищён системным хранилищем — разблокировать без вопросов.

    Возвращает текст ошибки, если системное хранилище недоступно, иначе ``None``.
    """
    if ws.keys.protection() is not KeyProtection.KEYRING:
        return None
    try:
        ws.attach(ws.keys.unlock_with_keyring())
    except KeyError_ as e:
        return str(e)
    return None


class ChangePasswordDialog(QDialog):
    def __init__(self, ws: Workspace, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ws = ws
        self.runner = TaskRunner(self)
        self.setWindowTitle("Смена мастер-пароля")
        self.setMinimumWidth(400)
        lay = QVBoxLayout(self)
        self.old, self.new, self.again = (QLineEdit(self) for _ in range(3))
        for w, ph in ((self.old, "Текущий пароль"), (self.new, "Новый пароль"), (self.again, "Повторите новый")):
            w.setEchoMode(QLineEdit.EchoMode.Password)
            w.setPlaceholderText(ph)
            lay.addWidget(w)
        self.error = QLabel("", self)
        self.error.setStyleSheet("color:#E0364F;")
        lay.addWidget(self.error)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("Отмена", self)
        self.ok = QPushButton("Сменить пароль", self)
        self.ok.setProperty("primary", True)
        row.addWidget(cancel)
        row.addWidget(self.ok)
        lay.addLayout(row)
        cancel.clicked.connect(self.reject)
        self.ok.clicked.connect(self.submit)

    def submit(self) -> None:
        if len(self.new.text()) < MIN_PASSWORD:
            self.error.setText(f"Новый пароль — не менее {MIN_PASSWORD} символов.")
            return
        if self.new.text() != self.again.text():
            self.error.setText("Новые пароли не совпадают.")
            return
        old, new = self.old.text(), self.new.text()
        self.ok.setEnabled(False)
        self.runner.start(
            lambda _p: self.ws.keys.change_password(old, new), on_done=lambda _r: self.accept(), on_error=self._failed
        )

    def _failed(self, exc: Exception) -> None:
        self.ok.setEnabled(True)
        self.error.setText("Текущий пароль неверен." if isinstance(exc, WrongKeyError) else str(exc))
