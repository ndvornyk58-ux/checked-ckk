"""Доменная модель cookie.

Модель намеренно сделана ``slots``-dataclass, а не Pydantic: она живёт в горячем пути
(сотни тысяч экземпляров при импорте), а проверка корректности — задача движка правил,
а не конструктора. Конструктор нормализует только то, что однозначно (регистр домена,
ведущая точка), и ничего не «чинит» молча.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domain.enums import SameSite, SourceFormat, ValueState
from app.domain.secret import SecretValue


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Откуда взялась запись — для точных сообщений об ошибках и истории импорта."""

    path: str | None = None
    line: int | None = None
    fmt: SourceFormat = SourceFormat.MANUAL


@dataclass(frozen=True, slots=True)
class Cookie:
    """Одна cookie в нормализованном виде.

    ``domain`` хранится в нижнем регистре и без ведущей точки; признак того,
    была ли cookie host-only (без атрибута Domain), хранится отдельно в ``host_only``.
    ``expires_at`` — момент истечения в UTC; ``None`` означает сессионную cookie.
    """

    name: str
    domain: str
    path: str = "/"
    value: SecretValue | None = None
    value_state: ValueState = ValueState.PRESENT
    host_only: bool = False
    expires_at: datetime | None = None
    secure: bool = False
    http_only: bool = False
    same_site: SameSite = SameSite.UNSPECIFIED
    partitioned: bool = False
    created_at: datetime | None = None
    last_accessed_at: datetime | None = None
    source: SourceRef = field(default_factory=SourceRef)

    def __post_init__(self) -> None:
        if self.value is None and self.value_state is ValueState.PRESENT:
            raise ValueError("value_state=PRESENT требует value")
        if self.value is not None and self.value_state is not ValueState.PRESENT:
            raise ValueError(f"value_state={self.value_state} несовместим с переданным value")
        for ts_name in ("expires_at", "created_at", "last_accessed_at"):
            ts = getattr(self, ts_name)
            if ts is not None and ts.tzinfo is None:
                raise ValueError(f"{ts_name} должен содержать часовой пояс (ожидается UTC)")
        object.__setattr__(self, "domain", normalize_domain(self.domain))

    @property
    def is_session(self) -> bool:
        """Сессионная cookie (без срока истечения)."""
        return self.expires_at is None

    def is_expired(self, now: datetime | None = None) -> bool:
        """Истёк ли срок. Сессионная cookie по сроку не истекает."""
        if self.expires_at is None:
            return False
        return self.expires_at <= (now or datetime.now(UTC))

    @property
    def identity(self) -> tuple[str, str, str, bool, bool]:
        """Ключ идентичности по RFC 6265 §5.3 (+ partitioned): по нему определяются дубликаты."""
        return (self.name, self.domain, self.path, self.host_only, self.partitioned)


def normalize_domain(domain: str) -> str:
    """Нижний регистр, без пробелов по краям и без одной ведущей точки.

    Не выполняет IDNA-преобразование и не проверяет корректность — это работа валидатора.
    """
    d = domain.strip().lower()
    return d[1:] if d.startswith(".") else d
