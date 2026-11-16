"""Netscape cookie file (curl, wget, yt-dlp, расширения браузеров).

Строка: ``domain <TAB> include_subdomains <TAB> path <TAB> secure <TAB> expiry <TAB> name <TAB> value``.
Префикс ``#HttpOnly_`` у домена означает HttpOnly; прочие строки на ``#`` — комментарии.
``expiry = 0`` — сессионная cookie. ``include_subdomains = FALSE`` — host-only.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Final

from app.domain import Cookie, SecretValue, SourceFormat, SourceRef
from app.parsers.base import ParseIssue, ParseItem
from app.parsers.mapping import MAX_TS

HTTPONLY_PREFIX: Final = "#HttpOnly_"
_HEADERS: Final = ("# netscape http cookie file", "# http cookie file")
_BOOL: Final = {"TRUE": True, "FALSE": False}


class NetscapeParser:
    fmt = SourceFormat.NETSCAPE
    extensions = (".txt", ".cookies")

    def sniff(self, head: str) -> float:
        lines = [ln for ln in head.splitlines() if ln.strip()]
        if not lines:
            return 0.0
        if lines[0].strip().lower().startswith(_HEADERS):
            return 1.0
        data = [ln for ln in lines if not ln.startswith("#") or ln.startswith(HTTPONLY_PREFIX)]
        if not data:
            return 0.1
        good = sum(1 for ln in data if _looks_like_row(ln))
        return 0.9 * good / len(data)

    def parse(self, stream: io.TextIOBase, source_path: str | None) -> Iterator[ParseItem]:
        for lineno, raw in enumerate(stream, start=1):
            line = raw.rstrip("\r\n")
            if not line.strip():
                continue
            http_only = False
            if line.startswith(HTTPONLY_PREFIX):
                http_only, line = True, line[len(HTTPONLY_PREFIX) :]
            elif line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 7:
                hint = " (похоже, вместо табуляции пробелы)" if len(fields) == 1 and " " in line else ""
                yield ParseIssue(
                    "field_count", f"Ожидалось 7 полей через табуляцию, найдено {len(fields)}{hint}", line=lineno
                )
                continue
            domain, sub, path, secure, expiry, name, value = fields
            if sub.upper() not in _BOOL or secure.upper() not in _BOOL:
                yield ParseIssue("bad_bool", "Поля include_subdomains и secure должны быть TRUE или FALSE", line=lineno)
                continue
            try:
                exp_int = int(expiry)
            except ValueError:
                yield ParseIssue("bad_timestamp", "Срок истечения не является целым числом", line=lineno)
                continue
            if exp_int < 0 or exp_int > MAX_TS:
                yield ParseIssue("bad_timestamp", "Срок истечения вне допустимого диапазона", line=lineno)
                continue
            yield Cookie(
                name=name,
                domain=domain,
                path=path,
                value=SecretValue(value),
                host_only=not _BOOL[sub.upper()],
                expires_at=None if exp_int == 0 else datetime.fromtimestamp(exp_int, tz=UTC),
                secure=_BOOL[secure.upper()],
                http_only=http_only,
                source=SourceRef(path=source_path, line=lineno, fmt=self.fmt),
            )


def _looks_like_row(line: str) -> bool:
    if line.startswith(HTTPONLY_PREFIX):
        line = line[len(HTTPONLY_PREFIX) :]
    f = line.split("\t")
    return len(f) == 7 and f[1].upper() in _BOOL and f[3].upper() in _BOOL and f[4].lstrip("-").isdigit()
