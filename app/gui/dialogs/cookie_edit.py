"""Редактирование локальной записи cookie."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import QDateTime, QTimeZone
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.domain import SameSite, SecretValue
from app.services.cookies import CookieDetail, CookieEdit


class CookieEditDialog(QDialog):
    """Поля заполнены текущими значениями. Значение cookie меняется, только если введено новое."""

    def __init__(self, detail: CookieDetail, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        it = detail.item
        self.setWindowTitle(f"Изменить cookie «{it.name}»")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.name, self.domain, self.path = QLineEdit(it.name), QLineEdit(it.domain), QLineEdit(it.path)
        self.value = QLineEdit()
        self.value.setEchoMode(QLineEdit.EchoMode.Password)
        self.value.setPlaceholderText("Оставьте пустым, чтобы не менять значение")
        self.host_only, self.secure, self.http_only = (
            QCheckBox(t) for t in ("Только этот хост (без Domain)", "Secure", "HttpOnly")
        )
        self.host_only.setChecked(it.host_only)
        self.secure.setChecked(it.secure)
        self.http_only.setChecked(it.http_only)
        self.same_site = QComboBox()
        for s in SameSite:
            self.same_site.addItem(s.value.capitalize() if s is not SameSite.UNSPECIFIED else "Не указан", s.value)
        self.same_site.setCurrentIndex(self.same_site.findData(it.same_site))
        self.session = QCheckBox("Сессионная (без срока)")
        self.expires = QDateTimeEdit()
        self.expires.setTimeZone(QTimeZone.utc())
        self.expires.setDisplayFormat("dd.MM.yyyy HH:mm 'UTC'")
        self.expires.setCalendarPopup(True)
        if it.expires_at is None:
            self.session.setChecked(True)
            self.expires.setDateTime(QDateTime.currentDateTimeUtc().addDays(30))
        else:
            self.expires.setDateTime(QDateTime.fromSecsSinceEpoch(it.expires_at, QTimeZone.utc()))
        self.expires.setEnabled(not self.session.isChecked())
        self.session.toggled.connect(lambda on: self.expires.setEnabled(not on))
        for label, w in (
            ("Имя", self.name),
            ("Домен", self.domain),
            ("Путь", self.path),
            ("Новое значение", self.value),
            ("", self.host_only),
            ("", self.secure),
            ("", self.http_only),
            ("SameSite", self.same_site),
            ("", self.session),
            ("Истекает", self.expires),
        ):
            form.addRow(label, w)
        lay.addLayout(form)
        note = QLabel("После сохранения запись будет проверена заново.")
        note.setProperty("role", "muted")
        lay.addWidget(note)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel, save = QPushButton("Отмена"), QPushButton("Сохранить")
        save.setProperty("primary", True)
        row.addWidget(cancel)
        row.addWidget(save)
        lay.addLayout(row)
        cancel.clicked.connect(self.reject)
        save.clicked.connect(self.accept)

    def edit(self) -> CookieEdit:
        exp = (
            None
            if self.session.isChecked()
            else datetime.fromtimestamp(self.expires.dateTime().toSecsSinceEpoch(), tz=UTC)
        )
        return CookieEdit(
            name=self.name.text(),
            domain=self.domain.text(),
            path=self.path.text(),
            value=SecretValue(self.value.text()) if self.value.text() else None,
            host_only=self.host_only.isChecked(),
            secure=self.secure.isChecked(),
            http_only=self.http_only.isChecked(),
            same_site=SameSite(self.same_site.currentData()),
            expires_at=exp,
            clear_expiry=self.session.isChecked(),
        )
