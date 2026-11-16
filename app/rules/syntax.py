"""Синтаксис cookies по RFC 6265 / 6265bis и вспомогательные классификаторы."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Final

from publicsuffixlist import PublicSuffixList

# token (RFC 9110 tchar)
_TCHAR: Final = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
# cookie-octet: %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
_COOKIE_OCTET: Final = frozenset(
    chr(c) for c in [0x21, *range(0x23, 0x2C), *range(0x2D, 0x3B), *range(0x3C, 0x5C), *range(0x5D, 0x7F)]
)
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
MAX_NAME_VALUE_BYTES: Final = 4096
MAX_ATTRIBUTE_BYTES: Final = 1024
MAX_LIFETIME_DAYS: Final = 400


def is_ctl(ch: str) -> bool:
    return ord(ch) < 0x20 or ord(ch) == 0x7F


def first_non_token(name: str) -> tuple[int, str] | None:
    for i, ch in enumerate(name):
        if ch not in _TCHAR:
            return i, ch
    return None


def first_forbidden_in_value(value: str) -> tuple[int, str] | None:
    """Символы, из-за которых браузер отвергнет cookie: управляющие (кроме TAB) и «;»."""
    for i, ch in enumerate(value):
        if (is_ctl(ch) and ch != "\t") or ch == ";":
            return i, ch
    return None


def non_rfc_value_chars(value: str) -> set[str]:
    """Символы вне cookie-octet, которые браузеры терпят, но RFC 6265 не разрешает."""
    v = value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
    return {ch for ch in v if ch not in _COOKIE_OCTET and not is_ctl(ch) and ch != ";"}


def cap(text: str) -> str:
    """Первая буква заглавная, остальное без изменений (в отличие от str.capitalize)."""
    return text[:1].upper() + text[1:]


def describe_char(ch: str) -> str:
    if is_ctl(ch):
        return f"управляющий символ U+{ord(ch):04X}"
    if ch == " ":
        return "пробел"
    return f"«{ch}» (U+{ord(ch):04X})"


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def domain_syntax_error(domain: str) -> str | None:
    """Причина синтаксической некорректности домена или ``None``."""
    if is_ip(domain):
        return None
    if len(domain) > 253:
        return "длина домена больше 253 символов"
    if domain.endswith("."):
        return "домен оканчивается точкой"
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return "домен нельзя преобразовать в IDNA"
    for label in ascii_domain.split("."):
        if not label:
            return "пустая метка (две точки подряд)"
        if not _LABEL.match(label):
            return f"недопустимая метка «{label}»"
    return None


@lru_cache(maxsize=1)
def _psl() -> PublicSuffixList:
    return PublicSuffixList()


def is_public_suffix(domain: str) -> bool:
    if domain == "localhost" or is_ip(domain):
        return False
    try:
        return bool(_psl().is_public(domain.encode("idna").decode("ascii")))
    except UnicodeError:
        return False


def is_local_host(domain: str) -> bool:
    if domain in ("localhost",) or domain.endswith((".localhost", ".test", ".local")):
        return True
    if is_ip(domain):
        ip = ipaddress.ip_address(domain.strip("[]"))
        return ip.is_loopback or ip.is_private
    return False


def domains_overlap(a: str, b: str) -> bool:
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def paths_overlap(a: str, b: str) -> bool:
    def within(child: str, parent: str) -> bool:
        return child == parent or child.startswith(parent if parent.endswith("/") else parent + "/")

    return within(a, b) or within(b, a)
