"""Фасад приложения для слоя представления (composition over services + workers).

GUI получает один объект :class:`Workspace` из composition root и обращается только к нему:
сервисы, текущий проект и состояние хранилища (заблокировано / разблокировано).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.crypto import CryptoBox
from app.services.activity import ActivityService
from app.services.cookies import CookieService
from app.services.diagnostics import DiagnosticsService
from app.services.export import ExportService
from app.services.importing import ImportService
from app.services.keys import KeyService
from app.services.projects import ProjectInfo, ProjectService
from app.services.settings import SettingsService
from app.services.validation import ValidationService
from app.workers.batch import BatchService


class VaultLockedError(Exception):
    """Операция требует разблокированного хранилища."""


class Workspace:
    def __init__(
        self, sessions: sessionmaker[Session], data_dir: Path, *, portable: bool = False, scrypt_n: int = 2**17
    ) -> None:
        self._sessions = sessions
        self.data_dir = data_dir
        self.portable = portable
        self._box: CryptoBox | None = None
        self.keys = KeyService(sessions, scrypt_n=scrypt_n)
        self.projects = ProjectService(sessions)
        self.settings = SettingsService(sessions)
        self.activity = ActivityService(sessions)
        self._lock_listeners: list[Callable[[bool], None]] = []

    # ------------------------------------------------------------------ хранилище
    @property
    def unlocked(self) -> bool:
        return self._box is not None

    def attach(self, box: CryptoBox) -> None:
        self._box = box
        for cb in self._lock_listeners:
            cb(True)

    def lock(self) -> None:
        self._box = None
        for cb in self._lock_listeners:
            cb(False)

    def on_lock_change(self, cb: Callable[[bool], None]) -> None:
        self._lock_listeners.append(cb)

    def _require_box(self) -> CryptoBox:
        if self._box is None:
            raise VaultLockedError("Хранилище заблокировано — введите мастер-пароль")
        return self._box

    # ------------------------------------------------------------------ сервисы
    @property
    def cookies(self) -> CookieService:
        """Чтение метаданных работает и при заблокированном хранилище; значения — нет."""
        return CookieService(self._sessions, self._box)

    def importer(self) -> ImportService:
        return ImportService(self._sessions, self._require_box())

    def exporter(self) -> ExportService:
        """Экспорт. Чтение метаданных — без ключа; выгрузка значений в открытом виде — только с ключом."""
        return ExportService(self._sessions, self._box)

    def batch(self) -> BatchService:
        """Пакетная обработка файлов. Создание задач не требует ключа; запуск — требует."""
        return BatchService(self._sessions, self._box)

    def diagnostics(self) -> DiagnosticsService:
        """Список адресов и история доступны всегда; сама проверка требует разблокированного хранилища."""
        return DiagnosticsService(self._sessions, self._box)

    def validator(self) -> ValidationService:
        return ValidationService(self._sessions, self._require_box())

    # ------------------------------------------------------------------ проект
    def default_project(self) -> ProjectInfo:
        """Последний открытый проект или «Default», если проектов ещё нет."""
        last = self.settings.get("last_project")
        projects = self.projects.list()
        for p in projects:
            if p.id == last:
                return p
        return projects[0] if projects else self.projects.create("Default")
