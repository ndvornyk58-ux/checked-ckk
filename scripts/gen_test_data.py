"""Генератор тестовых данных.

    python scripts/gen_test_data.py fixtures          # небольшие фикстуры в test_data/ (в репозитории)
    python scripts/gen_test_data.py large 100000 out/ # большой набор для тестов производительности

Все домены — зарезервированные для тестов (.test, example.com/.org/.net по RFC 2606),
значения — случайные; никаких реальных сессий.
"""

from __future__ import annotations

import json
import random
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "test_data"
FUTURE = 2_000_000_000  # 2033 г.
PAST = 1_600_000_000  # 2020 г.


def w(path: Path, text: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.write_bytes if isinstance(text, bytes) else lambda t: path.write_text(t, encoding="utf-8"))(text)


def fixtures() -> None:
    v, b, e = ROOT / "valid", ROOT / "broken", ROOT / "edge"
    w(
        v / "netscape.txt",
        "# Netscape HTTP Cookie File\n# комментарий\n\n"
        f".example.test\tTRUE\t/\tTRUE\t{FUTURE}\ttheme\tdark\n"
        f"#HttpOnly_app.example.test\tFALSE\t/\tTRUE\t0\tsessionid\t{'a' * 32}\n"
        f"app.example.test\tFALSE\t/api\tFALSE\t{PAST}\told\t1\n",
    )
    w(
        v / "extension.json",
        json.dumps(
            [
                {
                    "domain": ".shop.example.test",
                    "hostOnly": False,
                    "httpOnly": True,
                    "name": "cart",
                    "path": "/",
                    "sameSite": "lax",
                    "secure": True,
                    "session": False,
                    "expirationDate": FUTURE + 0.5,
                    "value": "x1",
                },
                {
                    "domain": "shop.example.test",
                    "hostOnly": True,
                    "httpOnly": False,
                    "name": "pref",
                    "path": "/",
                    "sameSite": "no_restriction",
                    "secure": True,
                    "session": True,
                    "value": "y2",
                },
            ],
            indent=2,
        ),
    )
    w(
        v / "playwright.json",
        json.dumps(
            {
                "cookies": [
                    {
                        "name": "auth_token",
                        "value": secrets.token_urlsafe(24),
                        "domain": "localhost",
                        "path": "/",
                        "expires": -1,
                        "httpOnly": True,
                        "secure": False,
                        "sameSite": "Strict",
                    }
                ],
                "origins": [],
            }
        ),
    )
    w(
        v / "selenium.jsonl",
        "\n".join(
            json.dumps(x)
            for x in [
                {"name": "a", "value": "1", "domain": "example.org", "path": "/", "expiry": FUTURE, "secure": True},
                {
                    "name": "b",
                    "value": "2",
                    "domain": ".example.org",
                    "path": "/x",
                    "httpOnly": True,
                    "sameSite": "None",
                },
            ]
        )
        + "\n",
    )
    w(
        v / "semicolon.csv",
        "Name;Value;Domain;Path;Expires;HttpOnly;Secure;SameSite\n"
        "sid;abc;example.net;/;2030-01-01T00:00:00Z;true;true;Strict\n"
        '"q;x";"multi\nline";example.net;/;;no;0;lax\n',
    )
    w(
        v / "native.cipx",
        json.dumps({"cipx": 1, "masked": False})
        + "\n"
        + json.dumps(
            {
                "name": "n",
                "value": "v",
                "value_state": "present",
                "domain": "native.test",
                "host_only": True,
                "path": "/",
                "expires": None,
                "secure": True,
                "http_only": True,
                "same_site": "lax",
            }
        )
        + "\n"
        + json.dumps(
            {
                "name": "enc",
                "value_state": "browser_encrypted",
                "domain": "native.test",
                "host_only": True,
                "path": "/",
                "secure": True,
                "http_only": True,
                "same_site": "lax",
            }
        )
        + "\n",
    )
    w(v / "bom_crlf.txt", "\ufeff# Netscape HTTP Cookie File\r\n.example.test\tTRUE\t/\tFALSE\t0\tbom\tok\r\n")

    w(b / "empty.json", "")
    w(b / "truncated.json", '[{"name": "a", "value": "1", "domain": "x.test"}, {"name": "b", "val')
    w(b / "garbage.bin", bytes(range(256)) * 4)
    w(b / "fake_sqlite.txt", b"SQLite format 3\x00" + b"\x00" * 100)
    w(b / "latin1.txt", "# Netscape HTTP Cookie File\n.x.test\tTRUE\t/\tFALSE\t0\tname\tcaf\xe9\n".encode("latin-1"))
    w(
        b / "mixed.txt",
        "# Netscape HTTP Cookie File\n"
        ".x.test\tTRUE\t/\tFALSE\t0\tgood\t1\n"
        ".x.test TRUE / FALSE 0 spaces 1\n"
        ".x.test\tMAYBE\t/\tFALSE\t0\tbadbool\t1\n"
        ".x.test\tTRUE\t/\tFALSE\tsoon\tbadexp\t1\n"
        ".x.test\tTRUE\t/\tFALSE\t0\tgood2\t2\n",
    )
    w(b / "no_columns.csv", "foo,bar\n1,2\n")
    w(
        b / "records.json",
        json.dumps(
            [
                {"name": "ok", "value": "1", "domain": "x.test"},
                {"value": "no-name"},
                {"name": "ms", "value": "1", "domain": "x.test", "expires": 1700000000000},
                "string",
                {"name": 5, "domain": "x.test"},
            ]
        ),
    )
    w(b / "cipx_wrong_version.cipx", '{"cipx": 99}\n{"name":"a","value":"1","domain":"x.test"}\n')
    w(b / "unknown.txt", "Это просто текст,\nа не файл cookies.\n")

    w(
        e / "rfc_violations.jsonl",
        "\n".join(
            json.dumps(x)
            for x in [
                {"name": "bad name", "value": "v", "domain": "x.example.com"},
                {"name": "ctl", "value": "a\u0001b", "domain": "x.example.com"},
                {"name": "suffix", "value": "v", "domain": ".co.uk"},
                {"name": "__Host-x", "value": "v", "domain": ".example.com", "secure": True},
                {"name": "__Secure-x", "value": "v", "domain": "example.com"},
                {"name": "ssn", "value": "v", "domain": "example.com", "sameSite": "None"},
                {"name": "relpath", "value": "v", "domain": "example.com", "path": "api"},
                {"name": "huge", "value": "x" * 5000, "domain": "example.com"},
                {"name": "dup", "value": "1", "domain": "example.com"},
                {"name": "dup", "value": "2", "domain": "example.com"},
            ]
        )
        + "\n",
    )


def large(n: int, out: Path) -> Path:
    """Netscape-файл из n записей с реалистичным разбросом атрибутов."""
    rnd = random.Random(42)  # noqa: S311 — детерминированные тестовые данные, не криптография
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"large_{n}.txt"
    names = ["sessionid", "csrftoken", "theme", "lang", "cart", "_ga", "pref", "auth", "tracking", "consent"]
    with path.open("w", encoding="utf-8") as fh:
        fh.write("# Netscape HTTP Cookie File\n")
        for i in range(n):
            sub = rnd.random() < 0.6
            dom = f"{'.' if sub else ''}s{i % 5000}.example.test"
            exp = 0 if rnd.random() < 0.2 else rnd.choice([PAST, FUTURE, FUTURE + i])
            prefix = "#HttpOnly_" if rnd.random() < 0.5 else ""
            fh.write(
                f"{prefix}{dom}\t{'TRUE' if sub else 'FALSE'}\t/\t{rnd.choice(['TRUE', 'FALSE'])}\t{exp}\t"
                f"{rnd.choice(names)}{i}\t{secrets.token_hex(16)}\n"
            )
    return path


if __name__ == "__main__":
    if sys.argv[1:2] == ["fixtures"]:
        fixtures()
        print(f"Фикстуры записаны в {ROOT}")
    elif sys.argv[1:2] == ["large"]:
        print(large(int(sys.argv[2]), Path(sys.argv[3] if len(sys.argv) > 3 else "out")))
    else:
        print(__doc__)
        sys.exit(2)
