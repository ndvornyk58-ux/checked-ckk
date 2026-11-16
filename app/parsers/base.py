"""Общие типы парсеров.

Парсер — генератор: выдаёт по одной :class:`~app.domain.Cookie` или :class:`ParseIssue`
и никогда не держит файл в памяти целиком. Ошибка, после которой продолжать чтение
файла невозможно, — исключение :class:`FileCorruptedError`; записи, выданные до неё, остаются.

Ни одно сообщение об ошибке не содержит значения cookie.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol

from app.domain import Cookie, SourceFormat


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """Проблема с конкретной записью.

    ``skipped=True`` — запись отброшена; ``False`` — запись импортирована, но есть замечание.
    """

    code: str
    message: str
    line: int | None = None
    record: int | None = None
    skipped: bool = True


class FileCorruptedError(Exception):
    """Файл нельзя дочитать: бинарный, не та кодировка, разрушенная структура."""

    def __init__(self, code: str, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.code, self.message, self.line = code, message, line


ParseItem = Cookie | ParseIssue


class Parser(Protocol):
    """Интерфейс формата. Реализации регистрируются в :mod:`app.parsers.registry`."""

    @property
    def fmt(self) -> SourceFormat: ...

    @property
    def extensions(self) -> tuple[str, ...]: ...

    def sniff(self, head: str) -> float:
        """Уверенность 0..1, что ``head`` (начало файла) — этот формат."""

    def parse(self, stream: io.TextIOBase, source_path: str | None) -> Iterator[ParseItem]:
        """Разобрать поток. ``stream`` — текст, уже декодированный из UTF-8."""


class CountingReader(io.RawIOBase):
    """Обёртка над бинарным потоком, считающая прочитанные байты (для прогресса импорта)."""

    def __init__(self, raw: io.BufferedIOBase) -> None:
        self._raw = raw
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._raw.read(len(b))
        n = len(data)
        b[:n] = data
        self.bytes_read += n
        return n
