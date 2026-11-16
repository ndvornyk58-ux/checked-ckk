"""Потоковые парсеры форматов cookies и реестр с автоопределением формата.

Поддерживаются: Netscape cookie file, JSON (массив / Playwright / одиночный объект),
JSON Lines, CSV, нативный CIPX. Парсеры не зависят от хранилища и не держат файл в памяти.
"""

from app.parsers.base import FileCorruptedError, ParseIssue, ParseItem, Parser
from app.parsers.registry import Detection, ParserRegistry, open_text, read_head

__all__ = [
    "Detection",
    "FileCorruptedError",
    "ParseIssue",
    "ParseItem",
    "Parser",
    "ParserRegistry",
    "open_text",
    "read_head",
]
