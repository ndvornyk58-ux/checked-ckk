"""Шифрование значений cookies (ADR-0003).

Формат шифротекста: ``0x01 || nonce(12) || AES-256-GCM(ciphertext || tag)``.
Из одного ключа данных (DEK) через HKDF выводятся независимые подключи:
для шифрования значений и для HMAC (поиск дубликатов без расшифровки).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.domain.secret import SecretValue

FORMAT_V1: Final = b"\x01"
NONCE_LEN: Final = 12
KEY_LEN: Final = 32
_AAD: Final = b"cookie-inspector:value:v1"


class DecryptionError(Exception):
    """Шифротекст повреждён или зашифрован другим ключом. Текст ошибки не содержит данных."""


def _subkey(dek: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info).derive(dek)


class CryptoBox:
    """Операции над значениями с уже разблокированным ключом данных."""

    __slots__ = ("_aead", "_mac_key")

    def __init__(self, dek: bytes) -> None:
        if len(dek) != KEY_LEN:
            raise ValueError("Ключ данных должен быть 32 байта")
        self._aead = AESGCM(_subkey(dek, b"cip/value-encryption/v1"))
        self._mac_key = _subkey(dek, b"cip/value-hmac/v1")

    def __repr__(self) -> str:
        return "CryptoBox(<unlocked>)"

    def encrypt(self, value: SecretValue) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        return FORMAT_V1 + nonce + self._aead.encrypt(nonce, value.reveal().encode("utf-8"), _AAD)

    def decrypt(self, blob: bytes) -> SecretValue:
        if len(blob) < 1 + NONCE_LEN + 16 or blob[:1] != FORMAT_V1:
            raise DecryptionError("Неизвестный формат шифротекста")
        nonce, ct = blob[1 : 1 + NONCE_LEN], blob[1 + NONCE_LEN :]
        try:
            return SecretValue(self._aead.decrypt(nonce, ct, _AAD).decode("utf-8"))
        except InvalidTag as exc:
            raise DecryptionError("Шифротекст повреждён или ключ не подходит") from exc

    def value_mac(self, value: SecretValue) -> bytes:
        """Ключевой HMAC значения: одинаковые значения дают одинаковый MAC, подбор без ключа невозможен."""
        return hmac.new(self._mac_key, value.reveal().encode("utf-8"), hashlib.sha256).digest()
