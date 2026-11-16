"""Движок правил: общий для валидатора и анализатора безопасности.

Правило — объект с ``rule_id``, ``engine`` и методом ``evaluate(cookie, ctx)``, возвращающим
находки. Правила не знают о хранилище; данные о наборе в целом (дубликаты, конфликты
имён) приходят через :class:`RuleContext`.

Сведение к статусу: статусы находок валидатора + отображение критичности находок
безопасности (HIGH/CRITICAL → SECURITY_ISSUE, MEDIUM → WARNING). Нет находок → VALID.
Упавшее правило не скрывается: оно превращается в находку UNKNOWN, исключение журналируется.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from app.domain import Cookie, Finding, FindingEngine, Severity, ValidationStatus

log = logging.getLogger(__name__)

Identity = tuple[str, str, str, bool, bool]
Scope = tuple[str, bool, str]  # (domain, host_only, path)


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Сведения о наборе данных, нужные правилам уровня «весь набор»."""

    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    duplicate_identities: frozenset[Identity] = frozenset()
    name_scopes: Mapping[str, Sequence[Scope]] = field(default_factory=dict)


class Rule(Protocol):
    @property
    def rule_id(self) -> str: ...

    @property
    def engine(self) -> FindingEngine: ...

    def evaluate(self, cookie: Cookie, ctx: RuleContext) -> Iterable[Finding]: ...


@dataclass(frozen=True, slots=True)
class Evaluation:
    findings: tuple[Finding, ...]
    status: ValidationStatus
    max_severity: Severity | None


_SEVERITY_TO_STATUS: dict[Severity, ValidationStatus] = {
    Severity.CRITICAL: ValidationStatus.SECURITY_ISSUE,
    Severity.HIGH: ValidationStatus.SECURITY_ISSUE,
    Severity.MEDIUM: ValidationStatus.WARNING,
}


def summarize(findings: Sequence[Finding]) -> tuple[ValidationStatus, Severity | None]:
    statuses = [f.status for f in findings if f.status is not None]
    severities = [f.severity for f in findings if f.severity is not None]
    statuses += [_SEVERITY_TO_STATUS[s] for s in severities if s in _SEVERITY_TO_STATUS]
    top = max(severities, key=lambda s: s.rank) if severities else None
    return ValidationStatus.worst(statuses), top


class RuleEngine:
    """Применяет набор правил к cookie."""

    def __init__(self, rules: Sequence[Rule], version: str) -> None:
        ids = [r.rule_id for r in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Идентификаторы правил должны быть уникальны")
        self._rules = tuple(rules)
        self.version = version

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def evaluate(self, cookie: Cookie, ctx: RuleContext) -> Evaluation:
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                findings.extend(rule.evaluate(cookie, ctx))
            except Exception as exc:  # noqa: BLE001 — упавшее правило становится находкой UNKNOWN, а не роняет анализ
                log.error("Правило %s упало: %s", rule.rule_id, type(exc).__name__)
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        engine=FindingEngine.VALIDATION,
                        title="Ошибка правила проверки",
                        description="Правило не смогло выполниться для этой записи.",
                        reason=f"Внутренняя ошибка правила: {type(exc).__name__}",
                        recommendation="Сообщите об ошибке; результат для этой записи неполный.",
                        status=ValidationStatus.UNKNOWN,
                    )
                )
        status, sev = summarize(findings)
        return Evaluation(tuple(findings), status, sev)


@dataclass(frozen=True, slots=True)
class FuncRule:
    """Правило из функции — основной способ описывать встроенные правила."""

    rule_id: str
    engine: FindingEngine
    fn: Callable[[Cookie, RuleContext], Iterable[Finding]]

    def evaluate(self, cookie: Cookie, ctx: RuleContext) -> Iterable[Finding]:
        return self.fn(cookie, ctx)
