"""Перечисления предметной области."""

from __future__ import annotations

from enum import StrEnum


class ValidationStatus(StrEnum):
    """Итоговый статус проверки структуры cookie.

    Важно: VALID означает только «структура корректна и срок не истёк».
    Это НЕ утверждение, что сессия действительна или активна на сервере.
    """

    VALID = "valid"
    WARNING = "warning"
    EXPIRED = "expired"
    INVALID = "invalid"
    SECURITY_ISSUE = "security_issue"
    UNKNOWN = "unknown"

    @property
    def precedence(self) -> int:
        """Приоритет при сведении нескольких находок к одному статусу (больше — важнее)."""
        return _STATUS_PRECEDENCE[self]

    @classmethod
    def worst(cls, statuses: list[ValidationStatus]) -> ValidationStatus:
        """Свести набор статусов к одному. Пустой набор — VALID (нет находок)."""
        if not statuses:
            return cls.VALID
        return max(statuses, key=lambda s: s.precedence)


_STATUS_PRECEDENCE: dict[ValidationStatus, int] = {
    ValidationStatus.VALID: 0,
    ValidationStatus.WARNING: 1,
    ValidationStatus.UNKNOWN: 2,
    ValidationStatus.EXPIRED: 3,
    ValidationStatus.INVALID: 4,
    ValidationStatus.SECURITY_ISSUE: 5,
}


class Severity(StrEnum):
    """Критичность находки Security Analyzer."""

    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class SameSite(StrEnum):
    """Значение атрибута SameSite. UNSPECIFIED — атрибут отсутствовал в источнике."""

    STRICT = "strict"
    LAX = "lax"
    NONE = "none"
    UNSPECIFIED = "unspecified"


class ValueState(StrEnum):
    """Доступность значения cookie.

    BROWSER_ENCRYPTED — значение зашифровано браузером средствами ОС, приложение его не расшифровывает
    (см. docs/adr/0005-browser-integration.md).
    """

    PRESENT = "present"
    BROWSER_ENCRYPTED = "browser_encrypted"
    ABSENT = "absent"


class SourceFormat(StrEnum):
    """Источник, из которого получена запись."""

    NETSCAPE = "netscape"
    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"
    CIPX = "cipx"
    FIREFOX_PROFILE = "firefox_profile"
    CHROMIUM_PROFILE = "chromium_profile"
    MANUAL = "manual"


class FindingEngine(StrEnum):
    """Какой движок породил находку."""

    VALIDATION = "validation"
    SECURITY = "security"
