"""Пользовательские настройки (несекретные) в таблице settings."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.db.models import Setting
from app.services.common import now_ts

DEFAULTS: dict[str, Any] = {
    "theme": "dark",
    "last_project": None,
    "import.duplicates": "skip",
    "import.validate": True,
    "table.page_size": 200,
}


class SettingsService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def get(self, key: str) -> Any:
        with self._sessions() as s:
            row = s.get(Setting, key)
            return row.value.get("v") if row else DEFAULTS.get(key)

    def set(self, key: str, value: Any) -> None:
        with self._sessions.begin() as s:
            row = s.get(Setting, key)
            if row is None:
                s.add(Setting(key=key, value={"v": value}, updated_at=now_ts()))
            else:
                row.value, row.updated_at = {"v": value}, now_ts()
