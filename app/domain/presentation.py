"""Представленческие константы, не зависящие от GUI: цвета и подписи статусов/критичности.

Лежат в доменном слое, чтобы и сервисы (экспорт, отчёты), и GUI брали их из одного места,
не создавая зависимости сервисов от Qt. Здесь нет ни Qt, ни QSS — только данные.
"""

from __future__ import annotations

from typing import Final

STATUS_COLORS: Final = {
    "valid": "#3FA77A",
    "warning": "#D9A23A",
    "expired": "#8B7FC7",
    "invalid": "#D9584E",
    "security_issue": "#E0364F",
    "unknown": "#7D8794",
}

SEVERITY_COLORS: Final = {
    "critical": "#E0364F",
    "high": "#E06A3F",
    "medium": "#D9A23A",
    "low": "#5B9BD5",
    "informational": "#7D8794",
}

STATUS_LABELS: Final = {
    "valid": "Корректные",
    "warning": "С замечаниями",
    "expired": "Истекшие",
    "invalid": "Некорректные",
    "security_issue": "Проблемы безопасности",
    "unknown": "Не определено",
}

SEVERITY_LABELS: Final = {
    "critical": "Критическая",
    "high": "Высокая",
    "medium": "Средняя",
    "low": "Низкая",
    "informational": "Информация",
}
