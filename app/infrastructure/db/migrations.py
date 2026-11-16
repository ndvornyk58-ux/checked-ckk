"""Программный интерфейс миграций схемы."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

_INI = Path(__file__).with_name("alembic.ini")


def _config(engine: Engine) -> Config:
    cfg = Config(str(_INI))
    cfg.set_main_option("script_location", str(_INI.parent / "alembic"))
    cfg.attributes["engine"] = engine
    return cfg


def upgrade(engine: Engine, revision: str = "head") -> None:
    """Обновить схему до ``revision`` (по умолчанию — последняя)."""
    cfg = _config(engine)
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, revision)


def downgrade(engine: Engine, revision: str) -> None:
    """Откатить схему до ``revision`` (``base`` — полностью)."""
    cfg = _config(engine)
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, revision)


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def head_revision(engine: Engine) -> str | None:
    return ScriptDirectory.from_config(_config(engine)).get_current_head()


def is_up_to_date(engine: Engine) -> bool:
    return current_revision(engine) == head_revision(engine)


def autogenerate(engine: Engine, message: str) -> None:
    """Сгенерировать новую ревизию по разнице ORM и БД (инструмент разработчика)."""
    cfg = _config(engine)
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.revision(cfg, message=message, autogenerate=True)
