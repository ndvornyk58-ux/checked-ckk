"""Реестр форматов и автоопределение.

Определение формата: проверка «это вообще текст в UTF-8?» → оценка уверенности
каждым парсером по первым 64 КБ → небольшой бонус за подходящее расширение.
Если лучший результат ниже порога или два формата почти равны — это сообщается явно.
"""

from __future__ import annotations

import codecs
import io
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from app.domain import SourceFormat
from app.parsers.base import CountingReader, FileCorruptedError, Parser
from app.parsers.csv_format import CsvParser
from app.parsers.json_formats import CipxParser, JsonLinesParser, JsonParser
from app.parsers.netscape import NetscapeParser

HEAD_BYTES: Final = 64 * 1024
MIN_CONFIDENCE: Final = 0.5
EXT_BONUS: Final = 0.05

_SIGNATURES: Final[tuple[tuple[bytes, str], ...]] = (
    (b"SQLite format 3\x00", "Это база данных SQLite (возможно, профиль браузера) — используйте Browser Integration"),
    (b"PK\x03\x04", "Это ZIP-архив — распакуйте его и импортируйте файлы"),
    (b"\x1f\x8b", "Это gzip-архив — распакуйте его и импортируйте файл"),
    (b"%PDF", "Это PDF-документ, а не файл cookies"),
)


@dataclass(frozen=True, slots=True)
class Detection:
    parser: Parser
    confidence: float
    ambiguous_with: SourceFormat | None = None

    @property
    def fmt(self) -> SourceFormat:
        return self.parser.fmt


class ParserRegistry:
    """Набор доступных форматов. Плагины добавляют свои через :meth:`register`."""

    def __init__(self, parsers: list[Parser] | None = None) -> None:
        self._parsers: dict[SourceFormat, Parser] = {}
        for p in parsers or default_parsers():
            self.register(p)

    def register(self, parser: Parser) -> None:
        self._parsers[parser.fmt] = parser

    def get(self, fmt: SourceFormat) -> Parser:
        try:
            return self._parsers[fmt]
        except KeyError as exc:
            raise ValueError(f"Формат {fmt} не зарегистрирован") from exc

    @property
    def formats(self) -> list[SourceFormat]:
        return list(self._parsers)

    def detect_text(self, head: str, filename: str = "") -> Detection:
        if not head.strip():
            raise FileCorruptedError("empty", "Файл пуст")
        suffix = Path(filename).suffix.lower()
        scored = sorted(
            (
                (min(1.0, p.sniff(head) + (EXT_BONUS if suffix in p.extensions else 0.0)), p)
                for p in self._parsers.values()
            ),
            key=lambda t: t[0],
            reverse=True,
        )
        best_score, best = scored[0]
        if best_score < MIN_CONFIDENCE:
            by_ext = next((p for p in self._parsers.values() if suffix and suffix in p.extensions), None)
            if by_ext is not None:
                raise FileCorruptedError(
                    "unknown_format",
                    f"Файл {suffix} не распознан как {by_ext.fmt.value}: не найдены обязательные поля name и domain",
                )
            raise FileCorruptedError("unknown_format", "Формат не распознан: файл не похож ни на один поддерживаемый")
        ambiguous = scored[1][1].fmt if len(scored) > 1 and best_score - scored[1][0] < 0.05 else None
        return Detection(best, best_score, ambiguous)

    def detect_file(self, path: Path) -> Detection:
        return self.detect_text(read_head(path), path.name)


def default_parsers() -> list[Parser]:
    return [NetscapeParser(), JsonParser(), JsonLinesParser(), CsvParser(), CipxParser()]


def read_head(path: Path) -> str:
    """Прочитать начало файла как UTF-8; бинарные и не-UTF-8 файлы — FileCorruptedError."""
    with path.open("rb") as fh:
        raw = fh.read(HEAD_BYTES)
    for sig, message in _SIGNATURES:
        if raw.startswith(sig):
            raise FileCorruptedError("binary", message)
    if b"\x00" in raw:
        raise FileCorruptedError("binary", "Файл двоичный (содержит нулевые байты), а не текстовый")
    try:
        return codecs.getincrementaldecoder("utf-8-sig")("strict").decode(raw, final=False)
    except UnicodeDecodeError as exc:
        raise FileCorruptedError(
            "encoding", f"Файл не в кодировке UTF-8 (некорректный байт на позиции {exc.start})"
        ) from exc


@contextmanager
def open_text(path: Path) -> Iterator[tuple[io.TextIOWrapper, CountingReader]]:
    """Открыть файл как текст UTF-8 со счётчиком прочитанных байт."""
    with path.open("rb") as fh:
        counter = CountingReader(fh)
        text = io.TextIOWrapper(io.BufferedReader(counter), encoding="utf-8-sig", errors="strict")
        try:
            yield text, counter
        finally:
            text.detach()
