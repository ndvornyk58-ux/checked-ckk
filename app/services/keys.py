"""Ключ шифрования: настройка, разблокировка, смена способа защиты — для GUI и CLI."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.crypto import (
    CryptoBox,
    KeyError_,
    KeyManager,
    KeyringKeyProvider,
    KeyUnavailableError,
    PasswordKeyProvider,
    WrongKeyError,
)
from app.services.common import record_operation

__all__ = ["KeyError_", "KeyProtection", "KeyService", "KeyUnavailableError", "WrongKeyError"]


class KeyProtection(StrEnum):
    NONE = "none"
    KEYRING = "keyring"
    PASSWORD = "scrypt"  # noqa: S105 — название способа защиты, а не пароль


class KeyService:
    def __init__(self, sessions: sessionmaker[Session], *, scrypt_n: int = 2**17) -> None:
        self._sessions = sessions
        self._km = KeyManager(sessions)
        self._n = scrypt_n

    def _pw(self, password: str) -> PasswordKeyProvider:
        return PasswordKeyProvider(password, n=self._n)

    def protection(self) -> KeyProtection:
        return KeyProtection(self._km.protection() or "none")

    def initialize_with_keyring(self) -> CryptoBox:
        box = self._km.initialize(KeyringKeyProvider())
        self._log("key.init", "Ключ создан, защита — системное хранилище")
        return box

    def initialize_with_password(self, password: str) -> CryptoBox:
        box = self._km.initialize(self._pw(password))
        self._log("key.init", "Ключ создан, защита — мастер-пароль")
        return box

    def unlock_with_keyring(self) -> CryptoBox:
        return self._km.unlock(KeyringKeyProvider())

    def unlock_with_password(self, password: str) -> CryptoBox:
        return self._km.unlock(self._pw(password))

    def change_password(self, old: str, new: str) -> None:
        self._km.change_protection(self._pw(old), self._pw(new))
        self._log("key.protection", "Мастер-пароль изменён")

    def switch_to_keyring(self, password: str) -> None:
        self._km.change_protection(self._pw(password), KeyringKeyProvider())
        self._log("key.protection", "Защита ключа переведена на системное хранилище")

    def switch_to_password(self, new: str) -> None:
        self._km.change_protection(KeyringKeyProvider(), self._pw(new))
        self._log("key.protection", "Защита ключа переведена на мастер-пароль")

    def _log(self, kind: str, summary: str) -> None:
        with self._sessions.begin() as s:
            record_operation(s, project_id=None, kind=kind, outcome="ok", summary=summary, details={})
