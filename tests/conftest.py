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
