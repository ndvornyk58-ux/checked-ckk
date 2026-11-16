"""Окружение Alembic. Соединение передаётся через config.attributes['connection']."""

from __future__ import annotations

from alembic import context

from app.infrastructure.db.alembic_filters import include_name
from app.infrastructure.db.models import Base


def run_migrations_online() -> None:
    connection = context.config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("Миграции запускаются только через app.infrastructure.db.migrations")
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        include_name=include_name,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


run_migrations_online()
