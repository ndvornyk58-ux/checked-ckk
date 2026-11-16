"""Сборка приложения (composition root).

Единственное место, где знают обо всех слоях сразу. GUI и CLI получают готовый
:class:`AppContext` и дальше работают только через сервисы.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.db import migrations
from app.infrastructure.db.engine import make_engine, make_session_factory, sqlite_url
from app.infrastructure.paths import AppPaths, resolve_paths


@dataclass(slots=True)
class AppContext:
    paths: AppPaths
    engine: Engine
    sessions: sessionmaker[Session]

    def close(self) -> None:
        self.engine.dispose()


def build_context(paths: AppPaths | None = None, *, migrate: bool = True) -> AppContext:
    """Создать контекст приложения; при ``migrate=True`` схема БД приводится к актуальной."""
    paths = (paths or resolve_paths()).ensure()
    engine = make_engine(sqlite_url(paths.database))
    if migrate:
        migrations.upgrade(engine)
    return AppContext(paths=paths, engine=engine, sessions=make_session_factory(engine))
