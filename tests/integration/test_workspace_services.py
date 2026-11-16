from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.app_context import VaultLockedError, Workspace
from app.services.keys import KeyProtection, KeyService, WrongKeyError
from app.services.settings import SettingsService
from tests.conftest import TEST_DATA


def test_key_service_password_lifecycle(sessions: sessionmaker[Session]) -> None:
    ks = KeyService(sessions, scrypt_n=2**10)
    assert ks.protection() is KeyProtection.NONE
    box = ks.initialize_with_password("first-password")
    assert ks.protection() is KeyProtection.PASSWORD
    ks.change_password("first-password", "second-password")
    with pytest.raises(WrongKeyError):
        ks.unlock_with_password("first-password")
    assert type(ks.unlock_with_password("second-password")) is type(box)


def test_key_service_keyring_switch(sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring

    store: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(keyring, "set_password", lambda s, a, p: store.__setitem__((s, a), p))
    monkeypatch.setattr(keyring, "get_password", lambda s, a: store.get((s, a)))
    ks = KeyService(sessions, scrypt_n=2**10)
    ks.initialize_with_password("first-password")
    ks.switch_to_keyring("first-password")
    assert ks.protection() is KeyProtection.KEYRING
    ks.unlock_with_keyring()
    ks.switch_to_password("back-to-password")
    assert ks.protection() is KeyProtection.PASSWORD
    ks.unlock_with_password("back-to-password")


def test_settings_defaults_and_persistence(sessions: sessionmaker[Session]) -> None:
    st = SettingsService(sessions)
    assert st.get("theme") == "dark" and st.get("missing") is None
    st.set("theme", "light")
    st.set("theme", "dark")
    st.set("list", [1, 2])
    assert SettingsService(sessions).get("theme") == "dark" and st.get("list") == [1, 2]


def test_workspace_lock_and_activity(sessions: sessionmaker[Session], tmp_path: Path) -> None:
    ws = Workspace(sessions, tmp_path, scrypt_n=2**10)
    events: list[bool] = []
    ws.on_lock_change(events.append)
    with pytest.raises(VaultLockedError):
        ws.importer()
    p = ws.default_project()
    assert p.name == "Default" and ws.default_project().id == p.id
    ws.attach(ws.keys.initialize_with_password("password-123"))
    ws.importer().run(p.id, [TEST_DATA / "valid" / "netscape.txt"])
    ws.validator().run(p.id)
    ws.lock()
    assert events == [True, False] and not ws.unlocked
    assert ws.cookies.count(p.id) == 3, "метаданные читаются без ключа"
    kinds = [a.kind for a in ws.activity.recent(p.id)]
    assert kinds[:2] == ["validate", "import"] and "key.init" in kinds
    daily = ws.activity.daily_counts(p.id, days=7)
    assert len(daily) == 7 and daily[-1][1] >= 2
    old = ws.activity.daily_counts(p.id, days=3, today=date(2020, 1, 1))
    assert sum(n for _, n in old) == 0

    other = ws.projects.create("Other")
    ws.settings.set("last_project", other.id)
    assert ws.default_project().id == other.id


def test_domain_counts(svc) -> None:  # type: ignore[no-untyped-def]
    svc.importer.run(svc.project_id, [TEST_DATA / "valid"])
    groups = svc.cookies.domain_counts(svc.project_id)
    assert sum(n for _, n in groups) == 13
    assert groups == sorted(groups, key=lambda g: (-g[1], g[0]))
    assert svc.cookies.domain_counts(svc.project_id, limit=2) == groups[:2]
    _ = datetime.now(UTC)
