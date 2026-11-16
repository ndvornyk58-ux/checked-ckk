from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

from app.domain import Cookie, SameSite, SourceFormat, ValueState
from app.parsers import FileCorruptedError, ParseIssue, ParserRegistry, json_formats
from app.parsers.mapping import RecordError, canonical_key, parse_bool, parse_timestamp
from app.parsers.netscape import NetscapeParser

REG = ParserRegistry()


def parse(fmt: SourceFormat, text: str) -> tuple[list[Cookie], list[ParseIssue]]:
    items = list(REG.get(fmt).parse(io.StringIO(text), "f"))
    return [i for i in items if isinstance(i, Cookie)], [i for i in items if isinstance(i, ParseIssue)]


class TestNetscape:
    def test_full_row_semantics(self) -> None:
        cs, issues = parse(
            SourceFormat.NETSCAPE,
            "#HttpOnly_.a.test\tTRUE\t/p\tTRUE\t2000000000\tn\tv\na.test\tFALSE\t/\tFALSE\t0\ts\t\n",
        )
        assert not issues
        a, b = cs
        assert (a.domain, a.host_only, a.http_only, a.secure, a.path) == ("a.test", False, True, True, "/p")
        assert a.expires_at == datetime.fromtimestamp(2_000_000_000, UTC)
        assert b.host_only and b.is_session and b.value is not None and b.value.reveal() == ""
        assert a.source.line == 1 and b.source.line == 2

    def test_comments_blank_crlf(self) -> None:
        cs, issues = parse(SourceFormat.NETSCAPE, "# c\r\n\r\n.a.test\tTRUE\t/\tFALSE\t0\tn\tv\r\n")
        assert len(cs) == 1 and not issues and cs[0].value is not None and cs[0].value.reveal() == "v"

    @pytest.mark.parametrize(
        ("line", "code"),
        [
            (".a.test TRUE / FALSE 0 n v", "field_count"),
            (".a.test\tTRUE\t/\tFALSE\t0\tn", "field_count"),
            (".a.test\tYES\t/\tFALSE\t0\tn\tv", "bad_bool"),
            (".a.test\tTRUE\t/\tFALSE\tsoon\tn\tv", "bad_timestamp"),
            (".a.test\tTRUE\t/\tFALSE\t-5\tn\tv", "bad_timestamp"),
            (".a.test\tTRUE\t/\tFALSE\t99999999999999\tn\tv", "bad_timestamp"),
        ],
    )
    def test_bad_rows_reported_and_skipped(self, line: str, code: str) -> None:
        cs, issues = parse(SourceFormat.NETSCAPE, line + "\n.ok.test\tTRUE\t/\tFALSE\t0\tok\t1\n")
        assert [c.name for c in cs] == ["ok"]
        assert issues[0].code == code and issues[0].line == 1 and issues[0].skipped

    def test_error_messages_never_contain_value(self) -> None:
        secret = "SUPER-SECRET-VALUE"
        _, issues = parse(SourceFormat.NETSCAPE, f".a.test\tMAYBE\t/\tFALSE\t0\tn\t{secret}\na b c {secret}\n")
        assert issues and all(secret not in i.message for i in issues)


class TestJson:
    def test_extension_export(self) -> None:
        cs, issues = parse(
            SourceFormat.JSON,
            json.dumps(
                [
                    {
                        "domain": ".x.test",
                        "hostOnly": False,
                        "httpOnly": True,
                        "name": "a",
                        "path": "/",
                        "sameSite": "no_restriction",
                        "secure": True,
                        "session": False,
                        "expirationDate": 1999999999.5,
                        "value": "1",
                    },
                    {"domain": "x.test", "name": "b", "value": "2", "session": True, "expirationDate": 1},
                ]
            ),
        )
        assert not issues
        assert cs[0].same_site is SameSite.NONE and not cs[0].host_only and cs[0].expires_at is not None
        assert cs[1].is_session, "session=true важнее expirationDate"

    def test_playwright_and_single_object(self) -> None:
        cs, _ = parse(
            SourceFormat.JSON,
            json.dumps(
                {
                    "cookies": [{"name": "s", "value": "v", "domain": "x.test", "expires": -1, "sameSite": "Strict"}],
                    "origins": [],
                }
            ),
        )
        assert cs[0].is_session and cs[0].same_site is SameSite.STRICT
        cs, _ = parse(SourceFormat.JSON, '{"name": "one", "value": "1", "domain": "x.test"}')
        assert [c.name for c in cs] == ["one"]

    def test_record_errors_and_warnings(self) -> None:
        cs, issues = parse(
            SourceFormat.JSON,
            json.dumps(
                [
                    {"name": "ok", "value": "1", "domain": "x.test"},
                    {"value": "x"},
                    7,
                    {"name": "ms", "value": "1", "domain": "x.test", "expires": 1700000000000},
                    {"name": "nov", "domain": "x.test"},
                    {"name": "ss", "value": "1", "domain": "x.test", "sameSite": "weird"},
                    {"name": 5, "domain": "x.test"},
                    {"name": "b", "value": "1", "domain": "x.test", "secure": "perhaps"},
                ]
            ),
        )
        assert [c.name for c in cs] == ["ok", "nov", "ss"]
        assert cs[1].value_state is ValueState.ABSENT
        codes = [(i.code, i.skipped) for i in issues]
        assert ("missing_field", True) in codes and ("not_an_object", True) in codes
        assert ("bad_timestamp", True) in codes and ("bad_type", True) in codes and ("bad_bool", True) in codes
        assert ("missing_value", False) in codes and ("unknown_samesite", False) in codes
        ms = next(i for i in issues if i.code == "bad_timestamp")
        assert "миллисекунд" in ms.message

    def test_streaming_across_tiny_chunks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Объекты и числа, разрезанные границей блока, собираются корректно; номера строк точны."""
        monkeypatch.setattr(json_formats, "_CHUNK", 7)
        recs = [{"name": f"n{i}", "value": "v" * i, "domain": "x.test", "expires": 1999999999 + i} for i in range(50)]
        text = "[\n" + ",\n".join(json.dumps(r) for r in recs) + "\n]"
        cs, issues = parse(SourceFormat.JSON, text)
        assert not issues and [c.name for c in cs] == [r["name"] for r in recs]
        assert cs[-1].expires_at == datetime.fromtimestamp(1999999999 + 49, UTC)
        assert [c.source.line for c in cs] == list(range(2, 52))

    @pytest.mark.parametrize(
        ("text", "code"),
        [
            ("", "empty"),
            ('[{"name": "a", "domain": "x.test"}, {"na', "bad_json"),
            ('[{"name": "a", "value": "1", "domain": "x.test"}', "truncated"),
            ('[{"name": "a", "value": "1", "domain": "x.test"} {"name": "b"}]', "bad_structure"),
            ("[] trailing", "trailing_data"),
            ('{"unrelated": 1}', "bad_structure"),
            ("hello", "bad_structure"),
        ],
    )
    def test_corruption(self, text: str, code: str) -> None:
        with pytest.raises(FileCorruptedError) as ei:
            parse(SourceFormat.JSON, text)
        assert ei.value.code == code

    def test_records_before_corruption_are_kept(self) -> None:
        p = REG.get(SourceFormat.JSON).parse(io.StringIO('[{"name":"a","value":"1","domain":"x.test"},\n{"bro'), "f")
        assert isinstance(next(p), Cookie)
        with pytest.raises(FileCorruptedError) as ei:
            next(p)
        assert ei.value.line == 2


class TestJsonLinesAndCipx:
    def test_jsonl_bad_lines_isolated(self) -> None:
        cs, issues = parse(
            SourceFormat.JSONL,
            '{"name":"a","value":"1","domain":"x.test"}\nnope\n\n{"name":"b","value":"2","domain":"x.test"}\n',
        )
        assert [c.name for c in cs] == ["a", "b"] and issues[0].code == "bad_json" and issues[0].line == 2

    def test_cipx(self) -> None:
        cs, _ = parse(
            SourceFormat.CIPX,
            '{"cipx":1}\n{"name":"a","value_state":"browser_encrypted","domain":"x.test","host_only":true}\n',
        )
        assert cs[0].value_state is ValueState.BROWSER_ENCRYPTED and cs[0].value is None
        for bad, code in (('{"name":"a"}\n', "bad_header"), ('{"cipx":2}\n', "unsupported_version")):
            with pytest.raises(FileCorruptedError) as ei:
                parse(SourceFormat.CIPX, bad)
            assert ei.value.code == code


class TestCsv:
    def test_semicolon_quotes_multiline_empty_value(self) -> None:
        cs, issues = parse(
            SourceFormat.CSV,
            'Name;Value;Domain;HttpOnly;Expires\n"a;b";"x\ny";x.test;yes;\ne;;x.test;0;2030-01-01T00:00:00Z\nshort;1\n',
        )
        assert [c.name for c in cs] == ["a;b", "e"]
        assert cs[0].value is not None and cs[0].value.reveal() == "x\ny" and cs[0].http_only
        assert cs[1].value is not None and cs[1].value.reveal() == "" and cs[1].expires_at is not None
        assert issues[0].code == "column_count"

    def test_header_line_split_across_sample(self) -> None:
        long_rows = "".join(f"n{i},{'v' * 100},x.test\n" for i in range(800))  # > 64 КБ образца
        cs, issues = parse(SourceFormat.CSV, "name,value,domain\n" + long_rows)
        assert len(cs) == 800 and not issues

    def test_missing_columns(self) -> None:
        with pytest.raises(FileCorruptedError) as ei:
            parse(SourceFormat.CSV, "foo,bar\n1,2\n")
        assert ei.value.code == "missing_columns"


class TestMapping:
    def test_aliases(self) -> None:
        assert canonical_key("HttpOnly") == canonical_key("http_only") == canonical_key("httpOnly") == "http_only"
        assert canonical_key("expirationDate") == "expires" and canonical_key("whatever") is None

    @pytest.mark.parametrize(
        ("v", "out"), [(True, True), ("TRUE", True), ("yes", True), (1, True), ("0", False), ("", False), (None, False)]
    )
    def test_bool(self, v: object, out: bool) -> None:
        assert parse_bool(v, "f") is out

    @pytest.mark.parametrize("v", ["maybe", 2, [], {}])
    def test_bad_bool(self, v: object) -> None:
        with pytest.raises(RecordError):
            parse_bool(v, "f")

    def test_timestamps(self) -> None:
        assert parse_timestamp(-1, "e", allow_session_marker=True) is None
        assert parse_timestamp("2030-01-01T00:00:00Z", "e", allow_session_marker=False) == datetime(
            2030, 1, 1, tzinfo=UTC
        )
        assert parse_timestamp("2030-01-01T00:00:00", "e", allow_session_marker=False).tzinfo is UTC  # type: ignore[union-attr]
        assert parse_timestamp(0, "e", allow_session_marker=True) == datetime(1970, 1, 1, tzinfo=UTC)
        for bad in (-1, float("nan"), True, "zzz", []):
            with pytest.raises(RecordError):
                parse_timestamp(bad, "e", allow_session_marker=False)


class TestRegistry:
    @pytest.mark.parametrize(
        ("name", "fmt"),
        [
            ("valid/netscape.txt", SourceFormat.NETSCAPE),
            ("valid/extension.json", SourceFormat.JSON),
            ("valid/playwright.json", SourceFormat.JSON),
            ("valid/selenium.jsonl", SourceFormat.JSONL),
            ("valid/semicolon.csv", SourceFormat.CSV),
            ("valid/native.cipx", SourceFormat.CIPX),
            ("valid/bom_crlf.txt", SourceFormat.NETSCAPE),
        ],
    )
    def test_detects_fixtures(self, name: str, fmt: SourceFormat) -> None:
        from tests.conftest import TEST_DATA

        d = REG.detect_file(TEST_DATA / name)
        assert d.fmt is fmt and d.confidence >= 0.5

    @pytest.mark.parametrize(
        ("name", "code", "hint"),
        [
            ("broken/garbage.bin", "binary", "двоичный"),
            ("broken/fake_sqlite.txt", "binary", "SQLite"),
            ("broken/latin1.txt", "encoding", "UTF-8"),
            ("broken/empty.json", "empty", "пуст"),
            ("broken/unknown.txt", "unknown_format", "не распознан"),
            ("broken/no_columns.csv", "unknown_format", ".csv"),
        ],
    )
    def test_rejects_broken(self, name: str, code: str, hint: str) -> None:
        from tests.conftest import TEST_DATA

        with pytest.raises(FileCorruptedError) as ei:
            REG.detect_file(TEST_DATA / name)
        assert ei.value.code == code and hint in ei.value.message

    def test_unregistered_format(self) -> None:
        reg = ParserRegistry([NetscapeParser()])
        with pytest.raises(ValueError):
            reg.get(SourceFormat.CSV)
        assert reg.formats == [SourceFormat.NETSCAPE]
