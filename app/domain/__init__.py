"""Предметная область: модели и перечисления. Не зависит ни от Qt, ни от БД."""

from app.domain.cookie import Cookie, SourceRef, normalize_domain
from app.domain.enums import (
    FindingEngine,
    SameSite,
    Severity,
    SourceFormat,
    ValidationStatus,
    ValueState,
)
from app.domain.finding import Finding
from app.domain.secret import MASK, SecretValue

__all__ = [
    "MASK",
    "Cookie",
    "Finding",
    "FindingEngine",
    "SameSite",
    "SecretValue",
    "Severity",
    "SourceFormat",
    "SourceRef",
    "ValidationStatus",
    "ValueState",
    "normalize_domain",
]
