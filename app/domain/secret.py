"""Обёртка для чувствительного значения cookie.

Защищает от случайной утечки: repr/str/format всегда маскируют значение,
а получить его можно только явным вызовом :meth:`SecretValue.reveal`.
"""

from __future__ import annotations

import hmac
from typing import Final

MASK: Final = "••••••"


class SecretValue:
    """Неизменяемое чувствительное строковое значение."""

    __slots__ = ("_value",)
    _value: str

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("SecretValue принимает только str")
        object.__setattr__(self, "_value", value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretValue неизменяем")

    def reveal(self) -> str:
        """Вернуть значение в открытом виде. Вызывать только там, где это действительно нужно."""
        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def masked(self, visible_prefix: int = 0) -> str:
        """Маскированное представление; ``visible_prefix`` первых символов можно показать явно."""
        if visible_prefix <= 0 or not self._value:
            return MASK
        return self._value[:visible_prefix] + MASK

    def __repr__(self) -> str:
        return f"SecretValue({MASK}, len={len(self._value)})"

    def __str__(self) -> str:
        return MASK

    def __format__(self, format_spec: str) -> str:
        return MASK

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    def __hash__(self) -> int:
        return hash(("SecretValue", self._value))

    def __reduce__(self) -> tuple[type[SecretValue], tuple[str]]:
        # Нужен для передачи между процессами (ProcessPoolExecutor). Значение не попадает в логи.
        return (SecretValue, (self._value,))
