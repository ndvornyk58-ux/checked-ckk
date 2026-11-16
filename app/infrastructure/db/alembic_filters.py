"""Фильтры объектов схемы для Alembic (общие для env.py и тестов на дрейф схемы)."""

from __future__ import annotations

from typing import Any

FTS_PREFIX = "cookies_fts"


def include_name(name: str | None, type_: str, _parent: Any) -> bool:
    """Исключить FTS5-таблицу и её теневые таблицы: ими управляет миграция вручную."""
    return not (type_ == "table" and name is not None and name.startswith(FTS_PREFIX))
