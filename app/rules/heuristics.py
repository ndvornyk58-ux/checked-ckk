"""Эвристики: похожа ли cookie на сессионную/аутентификационную, разбор JWT, энтропия.

Эвристики только повышают внимание анализатора и всегда называются эвристиками в отчётах.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import math
import re
import string
from typing import Any, Final
from urllib.parse import unquote

_SENSITIVE = re.compile(
    r"(^|[_.\-])(sess(ion)?|sid|auth|token|jwt|login|logged|remember|refresh|access|identity|user[_-]?id)"
    r"([_.\-]|$)|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|_session$|sessionid",
    re.IGNORECASE,
)
_CSRF = re.compile(r"csrf|xsrf", re.IGNORECASE)
_JWT = re.compile(r"^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*$")
PRIVILEGE_KEYS: Final = frozenset(
    {
        "role",
        "roles",
        "admin",
        "isadmin",
        "is_admin",
        "userid",
        "user_id",
        "uid",
        "email",
        "password",
        "passwd",
        "permissions",
        "scope",
        "group",
        "groups",
        "privilege",
        "level",
    }
)


def is_csrf_name(name: str) -> bool:
    return bool(_CSRF.search(name))


def is_sensitive_name(name: str) -> bool:
    return not is_csrf_name(name) and bool(_SENSITIVE.search(name))


def _b64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def jwt_header(value: str) -> dict[str, Any] | None:
    """Заголовок JWT, если значение похоже на JWT (подпись не проверяется)."""
    v = unquote(value)
    if not _JWT.match(v):
        return None
    try:
        header = json.loads(_b64url(v.split(".", 1)[0]))
    except (ValueError, binascii.Error):
        return None
    return header if isinstance(header, dict) and "alg" in header else None


def decoded_json_object(value: str) -> dict[str, Any] | None:
    """Значение — JSON-объект как есть, после URL-декодирования или после base64."""
    candidates = [value, unquote(value)]
    for c in list(candidates):
        with contextlib.suppress(binascii.Error, ValueError):
            candidates.append(base64.b64decode(c, validate=True).decode("utf-8"))
    for c in candidates:
        c = c.strip()
        if c.startswith("{"):
            try:
                obj = json.loads(c)
            except ValueError:
                continue
            if isinstance(obj, dict):
                return obj
    return None


def privilege_keys(obj: dict[str, Any]) -> set[str]:
    return {k for k in obj if isinstance(k, str) and k.lower() in PRIVILEGE_KEYS}


def estimated_entropy_bits(value: str) -> float:
    """Верхняя оценка энтропии по длине и использованным классам символов."""
    if not value:
        return 0.0
    classes = [(string.ascii_lowercase, 26), (string.ascii_uppercase, 26), (string.digits, 10), ("-_+/=.~", 7)]
    alphabet = sum(size for chars, size in classes if any(ch in chars for ch in value))
    if any(not any(ch in chars for chars, _ in classes) for ch in value):
        alphabet += 32
    if set(value) <= set(string.hexdigits):
        alphabet = 16
    # Однообразное значение («aaaa…», «1212…») не может иметь энтропию больше, чем даёт число различных символов.
    alphabet = min(alphabet, len(set(value)))
    return len(value) * math.log2(max(alphabet, 2))
