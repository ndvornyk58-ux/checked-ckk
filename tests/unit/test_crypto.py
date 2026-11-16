from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.domain import SecretValue
from app.infrastructure.crypto import (
    CryptoBox,
    DecryptionError,
    KeyAlreadyInitializedError,
    KeyManager,
    KeyNotInitializedError,
    KeyringKeyProvider,
    KeyUnavailableError,
    PasswordKeyProvider,
    WrongKeyError,
)
from tests.conftest import fast_provider


def test_roundtrip_and_randomized_nonce() -> None:
    box = CryptoBox(b"k" * 32)
    v = SecretValue("значение ✓")
    a, b = box.encrypt(v), box.encrypt(v)
    assert a != b, "одинаковые значения не должны давать одинаковый шифротекст"
    assert box.decrypt(a) == v and box.decrypt(b) == v
    assert v.reveal().encode() not in a


def test_tamper_and_wrong_key_detected() -> None:
    box = CryptoBox(b"k" * 32)
    blob = bytearray(box.encrypt(SecretValue("x")))
    blob[-1] ^= 1
    with pytest.raises(DecryptionError):
        box.decrypt(bytes(blob))
    with pytest.raises(DecryptionError):
        CryptoBox(b"z" * 32).decrypt(box.encrypt(SecretValue("x")))
    with pytest.raises(DecryptionError):
        box.decrypt(b"\x02" + b"0" * 40)


def test_value_mac_is_keyed_and_deterministic() -> None:
    a, b = CryptoBox(b"k" * 32), CryptoBox(b"z" * 32)
    assert a.value_mac(SecretValue("v")) == a.value_mac(SecretValue("v"))
    assert a.value_mac(SecretValue("v")) != b.value_mac(SecretValue("v"))


def test_repr_hides_key() -> None:
    assert "k" * 8 not in repr(CryptoBox(b"k" * 32))
    assert "pass" not in repr(PasswordKeyProvider("password123", n=2**10))


def test_key_lifecycle(sessions: sessionmaker[Session]) -> None:
    km = KeyManager(sessions)
    assert not km.is_initialized()
    with pytest.raises(KeyNotInitializedError):
        km.unlock(fast_provider())
    box = km.initialize(fast_provider())
    blob = box.encrypt(SecretValue("secret"))
    with pytest.raises(KeyAlreadyInitializedError):
        km.initialize(fast_provider())
    assert km.unlock(fast_provider()).decrypt(blob).reveal() == "secret"
    with pytest.raises(WrongKeyError):
        km.unlock(fast_provider("another-password"))
    km.change_protection(fast_provider(), fast_provider("new-password-1"))
    assert km.unlock(fast_provider("new-password-1")).decrypt(blob).reveal() == "secret"
    with pytest.raises(WrongKeyError):
        km.unlock(fast_provider())


def test_short_password_rejected() -> None:
    with pytest.raises(ValueError):
        PasswordKeyProvider("short")


class _MemoryKeyring:
    """Минимальный бэкенд keyring в памяти."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}


def test_keyring_provider(sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring

    mem = _MemoryKeyring()
    monkeypatch.setattr(keyring, "set_password", lambda s, a, p: mem.store.__setitem__((s, a), p))
    monkeypatch.setattr(keyring, "get_password", lambda s, a: mem.store.get((s, a)))
    km = KeyManager(sessions)
    blob = km.initialize(KeyringKeyProvider()).encrypt(SecretValue("v"))
    assert km.protection() == "keyring"
    assert km.unlock(KeyringKeyProvider()).decrypt(blob).reveal() == "v"
    mem.store.clear()
    with pytest.raises(KeyUnavailableError):
        km.unlock(KeyringKeyProvider())
    with pytest.raises(WrongKeyError, match="keyring"):
        km.unlock(fast_provider())


def test_keyring_backend_failure_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring

    def boom(*_: object) -> None:
        raise RuntimeError("no backend")

    monkeypatch.setattr(keyring, "set_password", boom)
    with pytest.raises(KeyUnavailableError):
        KeyringKeyProvider().create()
