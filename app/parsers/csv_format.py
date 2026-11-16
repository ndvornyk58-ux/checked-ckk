"""CSV с заголовком. Разделитель определяется автоматически (``,`` ``;`` ``\\t`` ``|``).

Названия колонок распознаются по тем же синонимам, что и поля JSON
(``HttpOnly``, ``http_only``, ``httpOnly`` и т.п.). Срок — секунды Unix или ISO 8601.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator

from app.domain import SourceFormat
from app.parsers.base import FileCorruptedError, ParseIssue, ParseItem
from app.parsers.json_formats import _emit
from app.parsers.mapping import canonical_key

_DELIMS = ",;\t|"


def _header_delimiter(header_line: str) -> str | None:
    """Разделитель, при котором в заголовке находятся колонки name и domain.

    Детерминированно и устойчиво к «рваным» строкам данных (в отличие от csv.Sniffer).
    """
    best: tuple[int, str] | None = None
    for d in _DELIMS:
        cols = next(csv.reader([header_line], delimiter=d))
        canon = {canonical_key(c) for c in cols}
        if {"name", "domain"} <= canon and (best is None or len(cols) > best[0]):
            best = (len(cols), d)
    return best[1] if best else None


class CsvParser:
    fmt = SourceFormat.CSV
    extensions = (".csv", ".tsv")

    def sniff(self, head: str) -> float:
        lines = head.lstrip("\ufeff").splitlines()
        if not lines or lines[0].lstrip().startswith(("{", "[", "#")):
            return 0.0
        return 0.9 if _header_delimiter(lines[0]) else 0.0

    def parse(self, stream: io.TextIOBase, source_path: str | None) -> Iterator[ParseItem]:
        sample = stream.read(64 * 1024)
        if not sample.strip():
            raise FileCorruptedError("empty", "Файл пуст")
        sample = sample.lstrip("\ufeff")
        delimiter = _header_delimiter(sample.splitlines()[0])
        if delimiter is None:
            raise FileCorruptedError(
                "missing_columns", "В заголовке CSV не найдены обязательные колонки name и domain", 1
            )
        reader = csv.reader(_Chain(sample, stream), delimiter=delimiter)
        header = next(reader)
        canon = [canonical_key(h) for h in header]
        idx = 0
        while True:
            try:
                row = next(reader)
            except StopIteration:
                return
            except csv.Error as exc:
                raise FileCorruptedError("bad_csv", f"Ошибка CSV: {exc}", reader.line_num) from exc
            if not any(cell.strip() for cell in row):
                continue
            idx += 1
            line = reader.line_num
            if len(row) != len(header):
                yield ParseIssue(
                    "column_count", f"Колонок {len(row)}, в заголовке {len(header)}", line=line, record=idx
                )
                continue
            record = {h: (None if c == "" else c) for h, c in zip(header, row, strict=True)}
            if "value" in canon:
                vh = header[canon.index("value")]
                record[vh] = row[canon.index("value")]  # пустое значение cookie допустимо и не равно отсутствию
            yield from _emit(record, self.fmt, source_path, line, idx)


class _Chain:
    """Итератор строк: сначала уже прочитанный образец, затем остаток потока."""

    def __init__(self, head: str, stream: io.TextIOBase) -> None:
        self._parts = iter([io.StringIO(head, newline=""), stream])
        self._cur: io.TextIOBase | io.StringIO = next(self._parts)
        self._carry = ""

    def __iter__(self) -> _Chain:
        return self

    def __next__(self) -> str:
        while True:
            line = self._cur.readline()
            if line:
                line, self._carry = self._carry + line, ""
                if line.endswith("\n"):
                    return line
                self._carry = line  # строка разрезана границей образца — дочитаем из потока
                continue
            nxt = next(self._parts, None)
            if nxt is None:
                if self._carry:
                    line, self._carry = self._carry, ""
                    return line
                raise StopIteration
            self._cur = nxt
