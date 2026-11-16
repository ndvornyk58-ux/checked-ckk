"""JSON, JSON Lines и нативный формат CIPX.

JSON поддерживается в виде:
* массива cookie-объектов (расширения браузеров, Selenium) — читается потоково;
* объекта ``{"cookies": [...]}`` (Playwright storage_state) — читается целиком, это небольшие файлы;
* одиночного cookie-объекта.

Потоковое чтение массива: после разрушения структуры JSON синхронизироваться
невозможно, поэтому файл помечается повреждённым начиная с этой строки, а уже
прочитанные записи сохраняются.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from typing import Any, Final

from app.domain import SourceFormat, SourceRef
from app.parsers.base import FileCorruptedError, ParseIssue, ParseItem
from app.parsers.mapping import RecordError, canonicalize, record_to_cookie

_CHUNK: Final = 1 << 20
_MAX_WHOLE_JSON: Final = 256 << 20
CIPX_VERSION: Final = 1


def _emit(obj: Any, fmt: SourceFormat, path: str | None, line: int, idx: int) -> Iterator[ParseItem]:
    if not isinstance(obj, dict):
        yield ParseIssue("not_an_object", f"Запись #{idx} не является объектом", line=line, record=idx)
        return
    try:
        cookie, notes = record_to_cookie(obj, fmt, SourceRef(path=path, line=line, fmt=fmt))
    except RecordError as e:
        yield ParseIssue(e.code, e.message, line=line, record=idx)
        return
    yield cookie
    for code, msg in notes:
        yield ParseIssue(code, msg, line=line, record=idx, skipped=False)


def _looks_like_cookie(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    f, _ = canonicalize(obj)
    return "name" in f and "domain" in f


class _ArrayReader:
    """Потоковый разбор JSON-массива верхнего уровня с подсчётом строк."""

    def __init__(self, stream: io.TextIOBase) -> None:
        self._s = stream
        self._buf = ""
        self._pos = 0
        self._eof = False
        self.line = 1
        self._dec = json.JSONDecoder()

    def _fill(self) -> bool:
        if self._eof:
            return False
        self.line += self._buf.count("\n", 0, self._pos)
        self._buf = self._buf[self._pos :]
        self._pos = 0
        chunk = self._s.read(_CHUNK)
        if not chunk:
            self._eof = True
            return False
        self._buf += chunk
        return True

    def _skip_ws(self) -> str | None:
        while True:
            while self._pos < len(self._buf) and self._buf[self._pos] in " \t\r\n":
                self._pos += 1
            if self._pos < len(self._buf):
                return self._buf[self._pos]
            if not self._fill():
                return None

    def _cur_line(self) -> int:
        return self.line + self._buf.count("\n", 0, self._pos)

    def items(self) -> Iterator[tuple[Any, int]]:
        if self._skip_ws() != "[":
            raise FileCorruptedError("bad_structure", "Ожидался JSON-массив", self._cur_line())
        self._pos += 1
        first = True
        while True:
            ch = self._skip_ws()
            if ch is None:
                raise FileCorruptedError("truncated", "Файл обрывается внутри JSON-массива", self._cur_line())
            if ch == "]":
                self._pos += 1
                if self._skip_ws() is not None:
                    raise FileCorruptedError("trailing_data", "Лишние данные после JSON-массива", self._cur_line())
                return
            if not first:
                if ch != ",":
                    raise FileCorruptedError("bad_structure", "Ожидалась запятая между элементами", self._cur_line())
                self._pos += 1
                if self._skip_ws() is None:
                    raise FileCorruptedError("truncated", "Файл обрывается внутри JSON-массива", self._cur_line())
            first = False
            start_line = self._cur_line()
            while True:
                try:
                    obj, end = self._dec.raw_decode(self._buf, self._pos)
                except json.JSONDecodeError as exc:
                    if self._fill():
                        continue
                    raise FileCorruptedError("bad_json", f"Повреждённый JSON: {exc.msg}", start_line) from exc
                if end == len(self._buf) and not self._eof and self._fill():
                    continue  # число могло оборваться на границе блока
                self._pos = end
                yield obj, start_line
                break


class JsonParser:
    fmt = SourceFormat.JSON
    extensions = (".json",)

    def sniff(self, head: str) -> float:
        s = head.lstrip("\ufeff \t\r\n")
        if not s or s[0] not in "[{":
            return 0.0
        if s[0] == "{" and _second_line_is_object(s):
            return 0.3  # скорее JSONL
        score = 0.6
        if '"name"' in s and '"domain"' in s:
            score = 0.95
        return score

    def parse(self, stream: io.TextIOBase, source_path: str | None) -> Iterator[ParseItem]:
        first = stream.read(1)
        while first and first in "\ufeff \t\r\n":
            first = stream.read(1)
        if not first:
            raise FileCorruptedError("empty", "Файл пуст")
        if first == "[":
            rest = _Prefixed(first, stream)
            for idx, (obj, line) in enumerate(_ArrayReader(rest).items(), start=1):
                yield from _emit(obj, self.fmt, source_path, line, idx)
            return
        if first != "{":
            raise FileCorruptedError("bad_structure", "Файл не начинается с JSON-массива или объекта", 1)
        text = first + stream.read(_MAX_WHOLE_JSON)
        if stream.read(1):
            raise FileCorruptedError("too_large", "JSON-объект больше 256 МБ — используйте массив или JSON Lines")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FileCorruptedError("bad_json", f"Повреждённый JSON: {exc.msg}", exc.lineno) from exc
        if isinstance(data, dict) and isinstance(data.get("cookies"), list):
            for idx, obj in enumerate(data["cookies"], start=1):
                yield from _emit(obj, self.fmt, source_path, 0, idx)
        elif _looks_like_cookie(data):
            yield from _emit(data, self.fmt, source_path, 1, 1)
        else:
            raise FileCorruptedError("bad_structure", 'JSON-объект не похож ни на cookie, ни на {"cookies": [...]}')


class JsonLinesParser:
    fmt = SourceFormat.JSONL
    extensions = (".jsonl", ".ndjson")

    def sniff(self, head: str) -> float:
        s = head.lstrip("\ufeff \t\r\n")
        if not s.startswith("{"):
            return 0.0
        if _is_cipx_header(s.splitlines()[0]):
            return 0.2
        return 0.95 if _second_line_is_object(s) else 0.4

    def parse(self, stream: io.TextIOBase, source_path: str | None) -> Iterator[ParseItem]:
        yield from _parse_lines(stream, source_path, self.fmt, skip_header=False)


class CipxParser:
    """Нативный формат: JSON Lines с первой строкой-заголовком ``{"cipx": 1, ...}``."""

    fmt = SourceFormat.CIPX
    extensions = (".cipx",)

    def sniff(self, head: str) -> float:
        s = head.lstrip("\ufeff \t\r\n")
        return 1.0 if s and _is_cipx_header(s.splitlines()[0]) else 0.0

    def parse(self, stream: io.TextIOBase, source_path: str | None) -> Iterator[ParseItem]:
        yield from _parse_lines(stream, source_path, self.fmt, skip_header=True)


def _parse_lines(
    stream: io.TextIOBase, source_path: str | None, fmt: SourceFormat, *, skip_header: bool
) -> Iterator[ParseItem]:
    idx = 0
    header_seen = not skip_header
    for lineno, raw in enumerate(stream, start=1):
        line = raw.strip().lstrip("\ufeff")
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            yield ParseIssue("bad_json", f"Строка не является JSON: {exc.msg}", line=lineno)
            continue
        if not header_seen:
            header_seen = True
            if not (isinstance(obj, dict) and "cipx" in obj):
                raise FileCorruptedError("bad_header", "Нет заголовка CIPX", lineno)
            if obj.get("cipx") != CIPX_VERSION:
                raise FileCorruptedError("unsupported_version", f"Версия CIPX {obj.get('cipx')!r} не поддерживается")
            continue
        idx += 1
        yield from _emit(obj, fmt, source_path, lineno, idx)


def _is_cipx_header(line: str) -> bool:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return False
    return isinstance(obj, dict) and "cipx" in obj


def _second_line_is_object(s: str) -> bool:
    lines = [ln.strip() for ln in s.splitlines() if ln.strip()]
    if len(lines) < 2 or not lines[1].startswith("{"):
        return False
    try:
        json.loads(lines[0])
    except json.JSONDecodeError:
        return False
    return True


class _Prefixed(io.TextIOBase):
    """Текстовый поток, у которого уже прочитан первый символ."""

    def __init__(self, prefix: str, stream: io.TextIOBase) -> None:
        self._prefix, self._s = prefix, stream

    def read(self, size: int | None = -1) -> str:
        p, self._prefix = self._prefix, ""
        if size is None or size < 0:
            return p + self._s.read()
        return p + self._s.read(max(0, size - len(p)))
