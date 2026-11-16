"""Управление ключом данных (DEK) и ключами-обёртками (KEK).

DEK генерируется один раз и хранится в ``key_store`` только в обёрнутом виде.
KEK получается одним из провайдеров:

* :class:`KeyringKeyProvider` — случайный ключ в системном хранилище ОС;
* :class:`PasswordKeyProvider` — scrypt от мастер-пароля.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.crypto.box import KEY_LEN, NONCE_LEN, CryptoBox
from app.infrastructure.db.models import KeyStore

PURPOSE: Final = "values"
_CHECK_PLAINTEXT: Final = b"cookie-inspector-pro:key-check:v1"
_WRAP_AAD: Final = b"cookie-inspector-pro:dek-wrap:v1"
KEYRING_SERVICE: Final = "CookieInspectorPro"


class KeyError_(Exception):
    """Базовая ошибка ключей."""


class KeyNotInitializedError(KeyError_):
    """Ключ данных ещё не создан."""


class KeyAlreadyInitializedError(KeyError_):
    """Ключ данных уже создан."""


class WrongKeyError(KeyError_):
    """Неверный мастер-пароль или чужой ключ."""


class KeyUnavailableError(KeyError_):
    """Хранилище ключа недоступно (например, нет бэкенда keyring)."""


class KeyProvider(Protocol):
    kdf: str

    def create(self) -> tuple[bytes, dict[str, Any]]:
        """Создать новый KEK. Возвращает ключ и параметры для его повторного получения."""

    def derive(self, params: dict[str, Any]) -> bytes:
        """Получить существующий KEK по сохранённым параметрам."""


class PasswordKeyProvider:
    """KEK из мастер-пароля через scrypt. ``n`` можно уменьшить только в тестах."""

    kdf = "scrypt"

    def __init__(self, password: str, *, n: int = 2**17, r: int = 8, p: int = 1) -> None:
        if len(password) < 8:
            raise ValueError("Мастер-пароль должен содержать не менее 8 символов")
        self._password = password.encode("utf-8")
        self._n, self._r, self._p = n, r, p

    def __repr__(self) -> str:
        return "PasswordKeyProvider(<hidden>)"

    def _kdf(self, salt: bytes, n: int, r: int, p: int) -> bytes:
        return Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p).derive(self._password)

    def create(self) -> tuple[bytes, dict[str, Any]]:
        salt = os.urandom(16)
        params = {"salt": base64.b64encode(salt).decode(), "n": self._n, "r": self._r, "p": self._p}
        return self._kdf(salt, self._n, self._r, self._p), params

    def derive(self, params: dict[str, Any]) -> bytes:
        return self._kdf(base64.b64decode(params["salt"]), int(params["n"]), int(params["r"]), int(params["p"]))


class KeyringKeyProvider:
    """KEK — случайный ключ в системном хранилище (Credential Manager / Keychain / Secret Service)."""

    kdf = "keyring"

    def create(self) -> tuple[bytes, dict[str, Any]]:
        account = f"kek-{secrets.token_hex(8)}"
        kek = os.urandom(KEY_LEN)
        try:
            import keyring

            keyring.set_password(KEYRING_SERVICE, account, base64.b64encode(kek).decode())
        except Exception as exc:  # keyring бросает разнородные исключения бэкендов
            raise KeyUnavailableError(f"Системное хранилище ключей недоступно: {type(exc).__name__}") from exc
        return kek, {"account": account}

    def derive(self, params: dict[str, Any]) -> bytes:
        try:
            import keyring

            stored = keyring.get_password(KEYRING_SERVICE, str(params["account"]))
        except Exception as exc:
            raise KeyUnavailableError(f"Системное хранилище ключей недоступно: {type(exc).__name__}") from exc
        if stored is None:
            raise KeyUnavailableError("Ключ не найден в системном хранилище (другой пользователь или компьютер?)")
        return base64.b64decode(stored)


def _wrap(kek: bytes, data: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(kek).encrypt(nonce, data, _WRAP_AAD)


def _unwrap(kek: bytes, blob: bytes) -> bytes:
    return AESGCM(kek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], _WRAP_AAD)


class KeyManager:
    """Создание, разблокировка и смена способа защиты ключа данных."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def _row(self, s: Session) -> KeyStore | None:
        return s.scalar(select(KeyStore).where(KeyStore.purpose == PURPOSE))

    def is_initialized(self) -> bool:
        with self._sessions() as s:
            return self._row(s) is not None

    def protection(self) -> str | None:
        """Способ защиты: ``keyring``, ``scrypt`` или ``None``, если ключа нет."""
        with self._sessions() as s:
            row = self._row(s)
            return row.kdf if row else None

    def initialize(self, provider: KeyProvider) -> CryptoBox:
        with self._sessions.begin() as s:
            if self._row(s) is not None:
                raise KeyAlreadyInitializedError("Ключ данных уже создан")
            dek = os.urandom(KEY_LEN)
            kek, params = provider.create()
            s.add(
                KeyStore(
                    purpose=PURPOSE,
                    wrapped_key=_wrap(kek, dek),
                    kdf=provider.kdf,
                    kdf_params=params,
                    key_check=_wrap(dek, _CHECK_PLAINTEXT),
                    created_at=int(time.time()),
                    rotated_at=None,
                )
            )
        return CryptoBox(dek)

    def unlock(self, provider: KeyProvider) -> CryptoBox:
        with self._sessions() as s:
            row = self._row(s)
            if row is None:
                raise KeyNotInitializedError("Ключ данных не создан")
            if row.kdf != provider.kdf:
                raise WrongKeyError(f"Ключ защищён способом «{row.kdf}», а не «{provider.kdf}»")
            kek = provider.derive(row.kdf_params)
            try:
                dek = _unwrap(kek, row.wrapped_key)
                if _unwrap(dek, row.key_check) != _CHECK_PLAINTEXT:
                    raise WrongKeyError("Контрольная проверка ключа не прошла")
            except InvalidTag as exc:
                raise WrongKeyError("Неверный мастер-пароль или ключ") from exc
        return CryptoBox(dek)

    def change_protection(self, current: KeyProvider, new: KeyProvider) -> None:
        """Перевернуть DEK новым KEK (смена пароля / переход на keyring). Данные не перешифровываются."""
        with self._sessions.begin() as s:
            row = self._row(s)
            if row is None:
                raise KeyNotInitializedError("Ключ данных не создан")
            try:
                dek = _unwrap(current.derive(row.kdf_params), row.wrapped_key)
            except InvalidTag as exc:
                raise WrongKeyError("Неверный текущий пароль или ключ") from exc
            kek, params = new.create()
            row.wrapped_key, row.kdf, row.kdf_params = _wrap(kek, dek), new.kdf, params
            row.rotated_at = int(time.time())
