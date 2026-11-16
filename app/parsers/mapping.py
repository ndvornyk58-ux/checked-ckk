"""Преобразование «записи-словаря» (JSON, JSONL, CSV, CIPX) в доменную Cookie.

Одно место для всех форматов с именованными полями: распознавание синонимов полей,
булевых значений, SameSite и сроков. Ничего не «чинится» молча — сомнительное либо
отклоняется с кодом ошибки, либо принимается с замечанием.

Соглашения по сроку (``expires``):
* число секунд Unix (целое или дробное) или ISO 8601 (для CSV);
* ``-1`` — сессионная cookie (так пишет Playwright); иные отрицательные — ошибка;
* значения позже 9999-12-31 отвергаются с подсказкой «возможно, миллисекунды».

Определение host-only, если поле не указано явно: ведущая точка в домене — доменная
cookie, без точки — host-only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from app.domain import Cookie, SameSite, SecretValue, SourceFormat, SourceRef, ValueState

MAX_TS: Final = 253402300799  # 9999-12-31T23:59:59Z

_ALIASES: Final[dict[str, tuple[str, ...]]] = {
    "name": ("name",),
    "value": ("value",),
    "value_state": ("valuestate",),
    "domain": ("domain", "host", "hostkey"),
    "path": ("path",),
    "expires": ("expires", "expirationdate", "expiry", "expirationtime", "expiresat"),
    "secure": ("secure", "issecure"),
    "http_only": ("httponly", "ishttponly"),
    "same_site": ("samesite",),
    "host_only": ("hostonly",),
    "session": ("session", "issession"),
    "partitioned": ("partitioned", "partitionkey"),
    "created": ("created", "creationdate", "creationtime", "createdat"),
    "last_accessed": ("lastaccessed", "lastaccessdate", "lastaccesstime"),
}
_LOOKUP: Final = {alias: canon for canon, aliases in _ALIASES.items() for alias in aliases}
_NON_ALNUM = re.compile(r"[^a-z0-9]")
_TRUE: Final = frozenset({"true", "1", "yes", "y", "on"})
_FALSE: Final = frozenset({"false", "0", "no", "n", "off", ""})
_SAMESITE: Final = {
    "strict": SameSite.STRICT,
    "lax": SameSite.LAX,
    "none": SameSite.NONE,
    "norestriction": SameSite.NONE,
    "unspecified": SameSite.UNSPECIFIED,
    "": SameSite.UNSPECIFIED,
}


class RecordError(Exception):
    """Запись отклонена. ``code`` машиночитаемый, ``message`` — для человека, без значения cookie."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def canonical_key(key: str) -> str | None:
    """Имя поля → каноническое (``HttpOnly``/``http_only``/``httpOnly`` → ``http_only``)."""
    return _LOOKUP.get(_NON_ALNUM.sub("", key.lower()))


def canonicalize(record: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Привести ключи записи к каноническим. Возвращает (поля, нераспознанные ключи)."""
    out: dict[str, Any] = {}
    unknown: list[str] = []
    for k, v in record.items():
        canon = canonical_key(str(k))
        if canon is None:
            unknown.append(str(k))
        elif canon not in out:
            out[canon] = v
    return out, unknown


def parse_bool(v: Any, field: str) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, int | float):
        if v in (0, 1):
            return bool(v)
    elif isinstance(v, str) and v.strip().lower() in _TRUE | _FALSE:
        return v.strip().lower() in _TRUE
    raise RecordError("bad_bool", f"Поле «{field}»: ожидается логическое значение, получено {type(v).__name__}")


def parse_same_site(v: Any) -> tuple[SameSite, str | None]:
    """Вернуть SameSite и, если значение не распознано, текст замечания."""
    if v is None:
        return SameSite.UNSPECIFIED, None
    key = _NON_ALNUM.sub("", str(v).lower())
    if key in _SAMESITE:
        return _SAMESITE[key], None
    return SameSite.UNSPECIFIED, "Нераспознанное значение SameSite — браузеры трактуют его как отсутствующее"


def parse_timestamp(v: Any, field: str, *, allow_session_marker: bool) -> datetime | None:
    """Секунды Unix / ISO 8601 → aware datetime (UTC). ``None``/пусто → ``None``."""
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    if isinstance(v, bool):
        raise RecordError("bad_timestamp", f"Поле «{field}»: логическое значение вместо времени")
    if isinstance(v, str):
        s = v.strip()
        try:
            v = float(s)
        except ValueError:
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError as exc:
                raise RecordError("bad_timestamp", f"Поле «{field}»: не число и не дата ISO 8601") from exc
            return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    if not isinstance(v, int | float):
        raise RecordError("bad_timestamp", f"Поле «{field}»: неподдерживаемый тип {type(v).__name__}")
    if v != v:  # NaN
        raise RecordError("bad_timestamp", f"Поле «{field}»: NaN")
    if allow_session_marker and v == -1:
        return None
    if v < 0:
        raise RecordError("bad_timestamp", f"Поле «{field}»: отрицательное время {v}")
    if v > MAX_TS:
        raise RecordError(
            "bad_timestamp",
            f"Поле «{field}»: время позже 9999 года — возможно, указано в миллисекундах, а не в секундах",
        )
    return datetime.fromtimestamp(v, tz=UTC)


def record_to_cookie(
    record: Mapping[str, Any], fmt: SourceFormat, source: SourceRef
) -> tuple[Cookie, list[tuple[str, str]]]:
    """Собрать Cookie из записи. Возвращает cookie и список замечаний (код, текст).

    :raises RecordError: запись нельзя импортировать.
    """
    f, _unknown = canonicalize(record)
    notes: list[tuple[str, str]] = []

    for req in ("name", "domain"):
        if req not in f or f[req] is None:
            raise RecordError("missing_field", f"Нет обязательного поля «{req}»")
        if not isinstance(f[req], str):
            raise RecordError("bad_type", f"Поле «{req}» должно быть строкой")
    name: str = f["name"]
    raw_domain: str = f["domain"]

    path = f.get("path", "/")
    if path is None or path == "":
        path = "/"
        notes.append(("default_path", "Путь не указан — принят «/»"))
    if not isinstance(path, str):
        raise RecordError("bad_type", "Поле «path» должно быть строкой")

    value: SecretValue | None = None
    state_raw = f.get("value_state")
    if state_raw is not None:
        try:
            state = ValueState(str(state_raw))
        except ValueError as exc:
            raise RecordError("bad_value_state", "Неизвестное значение value_state") from exc
    else:
        state = ValueState.PRESENT if "value" in f and f["value"] is not None else ValueState.ABSENT
        if state is ValueState.ABSENT:
            notes.append(("missing_value", "Значение cookie отсутствует в источнике"))
    if state is ValueState.PRESENT:
        raw_value = f.get("value")
        if isinstance(raw_value, bool) or not isinstance(raw_value, str | int | float):
            raise RecordError("bad_type", "Поле «value» должно быть строкой")
        value = SecretValue(str(raw_value))

    if "host_only" in f and f["host_only"] is not None:
        host_only = parse_bool(f["host_only"], "hostOnly")
    else:
        host_only = not raw_domain.strip().startswith(".")

    session = parse_bool(f["session"], "session") if f.get("session") is not None else False
    expires = None if session else parse_timestamp(f.get("expires"), "expires", allow_session_marker=True)

    same_site, ss_note = parse_same_site(f.get("same_site"))
    if ss_note:
        notes.append(("unknown_samesite", ss_note))

    part = f.get("partitioned")
    partitioned = bool(part) if isinstance(part, dict | str) else parse_bool(part, "partitioned")

    cookie = Cookie(
        name=name,
        domain=raw_domain,
        path=path,
        value=value,
        value_state=state,
        host_only=host_only,
        expires_at=expires,
        secure=parse_bool(f.get("secure"), "secure"),
        http_only=parse_bool(f.get("http_only"), "httpOnly"),
        same_site=same_site,
        partitioned=partitioned,
        created_at=parse_timestamp(f.get("created"), "created", allow_session_marker=False),
        last_accessed_at=parse_timestamp(f.get("last_accessed"), "lastAccessed", allow_session_marker=False),
        source=source,
    )
    return cookie, notes
