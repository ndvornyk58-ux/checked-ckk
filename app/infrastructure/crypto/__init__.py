"""Шифрование значений cookies (AES-256-GCM), управление ключами (keyring/scrypt), HMAC-индекс."""

from app.infrastructure.crypto.box import CryptoBox, DecryptionError
from app.infrastructure.crypto.keys import (
    KeyAlreadyInitializedError,
    KeyError_,
    KeyManager,
    KeyNotInitializedError,
    KeyProvider,
    KeyringKeyProvider,
    KeyUnavailableError,
    PasswordKeyProvider,
    WrongKeyError,
)

__all__ = [
    "CryptoBox",
    "DecryptionError",
    "KeyAlreadyInitializedError",
    "KeyError_",
    "KeyManager",
    "KeyNotInitializedError",
    "KeyProvider",
    "KeyUnavailableError",
    "KeyringKeyProvider",
    "PasswordKeyProvider",
    "WrongKeyError",
]
