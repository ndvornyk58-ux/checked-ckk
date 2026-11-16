from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine

from app.infrastructure.db import migrations
from app.infrastructure.db.engine import make_engine, sqlite_url


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    """Пустая файловая SQLite-база (не :memory: — нужны WAL и реальное поведение)."""
    e = make_engine(sqlite_url(tmp_path / "test.db"))
    yield e
    e.dispose()


@pytest.fixture
def migrated_engine(engine: Engine) -> Engine:
    migrations.upgrade(engine)
    return engine


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ни один тест не должен трогать реальный каталог данных пользователя."""
    monkeypatch.setenv("CIP_DATA_DIR", str(tmp_path / "appdata"))


# ----------------------------------------------------------------------------- PHASE 2
from dataclasses import dataclass  # noqa: E402

from sqlalchemy.orm import Session, sessionmaker  # noqa: E402

from app.infrastructure.crypto import CryptoBox, KeyManager, PasswordKeyProvider  # noqa: E402
from app.infrastructure.db.engine import make_session_factory  # noqa: E402

TEST_DATA = Path(__file__).resolve().parents[1] / "test_data"
FAST_PASSWORD = "test-master-password"


def fast_provider(password: str = FAST_PASSWORD) -> PasswordKeyProvider:
    """scrypt с малой стоимостью — только для тестов."""
    return PasswordKeyProvider(password, n=2**10)


@pytest.fixture
def sessions(migrated_engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(migrated_engine)


@pytest.fixture
def box(sessions: sessionmaker[Session]) -> CryptoBox:
    return KeyManager(sessions).initialize(fast_provider())


@dataclass
class Services:
    sessions: sessionmaker[Session]
    box: CryptoBox
    project_id: int

    @property
    def importer(self):  # type: ignore[no-untyped-def]
        from app.services.importing import ImportService

        return ImportService(self.sessions, self.box)

    @property
    def validator(self):  # type: ignore[no-untyped-def]
        from app.services.validation import ValidationService

        return ValidationService(self.sessions, self.box)

    @property
    def cookies(self):  # type: ignore[no-untyped-def]
        from app.services.cookies import CookieService

        return CookieService(self.sessions, self.box)


@pytest.fixture
def svc(sessions: sessionmaker[Session], box: CryptoBox) -> Services:
    from app.services.projects import ProjectService

    return Services(sessions, box, ProjectService(sessions).create("test").id)
