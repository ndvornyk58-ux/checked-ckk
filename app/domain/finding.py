"""Находки движков проверки и анализа безопасности."""

from __future__ import annotations

from dataclasses import dataclass

from app.domain.enums import FindingEngine, Severity, ValidationStatus


@dataclass(frozen=True, slots=True)
class Finding:
    """Одна находка правила по конкретной cookie.

    Поля соответствуют требованию ТЗ: название, описание, причина, риск, рекомендация.
    Для валидатора заполняется ``status``, для анализатора безопасности — ``severity``.
    Тексты не должны содержать значение cookie.
    """

    rule_id: str
    engine: FindingEngine
    title: str
    description: str
    reason: str
    risk: str = ""
    recommendation: str = ""
    status: ValidationStatus | None = None
    severity: Severity | None = None

    def __post_init__(self) -> None:
        if self.engine is FindingEngine.VALIDATION and self.status is None:
            raise ValueError("Находка валидатора требует status")
        if self.engine is FindingEngine.SECURITY and self.severity is None:
            raise ValueError("Находка анализатора безопасности требует severity")
