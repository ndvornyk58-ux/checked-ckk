"""Общие типы сервисного слоя: отмена, журнал операций, время."""

from __future__ import annotations

import threading
import time
from typing import Any

from sqlalchemy.orm import Session

from app.infrastructure.db.models import Operation


class OperationCancelled(Exception):
    """Операция отменена пользователем."""


class CancelToken:
    """Потокобезопасный флаг отмены. Проверяется сервисами на границах чанков."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise OperationCancelled


def now_ts() -> int:
    return int(time.time())


def record_operation(
    s: Session, *, project_id: int | None, kind: str, outcome: str, summary: str, details: dict[str, Any]
) -> None:
    """Запись в журнал операций (Activity Timeline). Никаких значений cookies в summary/details."""
    s.add(Operation(project_id=project_id, ts=now_ts(), kind=kind, outcome=outcome, summary=summary, details=details))
