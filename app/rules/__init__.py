"""Движок правил (RuleEngine) и наборы правил: корректность (validation) и безопасность (security).

Один движок для обоих наборов — сведение результатов и обработка ошибок правил не дублируются.
"""

from typing import Final

from app.rules.base import Evaluation, FuncRule, Rule, RuleContext, RuleEngine, summarize

RULESET_VERSION: Final = "2026.11.1"


def default_engine() -> RuleEngine:
    """Движок со всеми встроенными правилами (валидация + безопасность)."""
    from app.rules.security import build_security_rules
    from app.rules.validation import build_validation_rules

    return RuleEngine([*build_validation_rules(), *build_security_rules()], RULESET_VERSION)


__all__ = [
    "RULESET_VERSION",
    "Evaluation",
    "FuncRule",
    "Rule",
    "RuleContext",
    "RuleEngine",
    "default_engine",
    "summarize",
]
