from __future__ import annotations

import pytest

from app.cli import main
from tests.conftest import TEST_DATA


def test_info_upgrade_status(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info"]) == 0
    assert "не создана" in capsys.readouterr().out
    assert main(["db", "status"]) == 1
    assert main(["db", "upgrade"]) == 0
    assert "0001" in capsys.readouterr().out
    assert main(["db", "status"]) == 0


def test_full_workflow(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CIP_MASTER_PASSWORD", "cli-test-password")
    assert main(["import", str(TEST_DATA / "valid"), "--project", "p"]) == 2
    assert "key init" in capsys.readouterr().err
    assert main(["key", "init", "--password"]) == 0
    assert main(["key", "status"]) == 0 and "scrypt" in capsys.readouterr().out
    assert main(["key", "init"]) == 2

    assert main(["import", str(TEST_DATA / "valid"), "--project", "p"]) == 0
    out = capsys.readouterr().out
    assert "импортировано 13" in out and "Проверка:" in out
    assert main(["stats", "--project", "p"]) == 0 and "Всего записей : 13" in capsys.readouterr().out
    assert main(["list", "--project", "p", "--search", "sessionid"]) == 0
    listing = capsys.readouterr().out
    assert "sessionid" in listing and "a" * 32 not in listing, "значения не выводятся"
    assert main(["validate", "--project", "p"]) == 0 and "Проверено 13" in capsys.readouterr().out
    assert main(["project", "list"]) == 0 and "13 записей" in capsys.readouterr().out

    monkeypatch.setenv("CIP_MASTER_PASSWORD", "wrong-password!")
    assert main(["validate", "--project", "p"]) == 2 and "Неверный" in capsys.readouterr().err
    assert main(["project", "delete", "p"]) == 2
    assert main(["project", "delete", "p", "--yes"]) == 0
    assert main(["stats", "--project", "p"]) == 2


def test_keyring_unavailable_falls_back_to_password(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CIP_MASTER_PASSWORD", "cli-test-password")
    assert main(["key", "init", "--keyring"]) == 2  # в контейнере нет бэкенда keyring
    assert main(["key", "init"]) == 0
    assert "мастер-пароль" in capsys.readouterr().out


def test_diag_commands(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import threading
    from http.server import ThreadingHTTPServer

    import httpx

    from tests.integration.test_diagnostics import _Site

    _Site.valid, _Site.forget_logout = {"good-session"}, False
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        url = f"{base}/api/me"
        monkeypatch.setenv("CIP_MASTER_PASSWORD", "cli-test-password")
        assert main(["key", "init", "--password"]) == 0
        src = tmp_path / "c.jsonl"
        src.write_text('{"name":"sid","value":"good-session","domain":"127.0.0.1","hostOnly":true}\n')
        assert main(["import", str(src), "--project", "site"]) == 0
        assert main(["diag", "add", url, "--project", "site"]) == 2
        assert "код ответа сам по себе" in capsys.readouterr().err
        assert main(["diag", "add", url, "--project", "site", "--contains", "alice", "--not-contains", "Войти"]) == 0
        assert "не требуется" in capsys.readouterr().out
        assert main(["diag", "cookies", url, "--project", "site"]) == 0
        assert "Нет тестовых сессий" in capsys.readouterr().out
        assert main(["diag", "mark", "1", "--project", "site"]) == 0
        assert main(["diag", "run", url, "--project", "site"]) == 0
        out = capsys.readouterr().out
        assert "СОВПАЛО" in out and "good-session" not in out

        assert main(["diag", "run", url, "--project", "site", "--phase", "before"]) == 0
        pair = capsys.readouterr().out.split("--pair ")[1].split()[0]
        httpx.get(f"{base}/logout", cookies={"sid": "good-session"})
        assert main(["diag", "run", url, "--project", "site", "--phase", "after", "--pair", pair]) == 0
        assert "аннулировал" in capsys.readouterr().out
        assert main(["diag", "history", url, "--project", "site"]) == 0
        assert len(capsys.readouterr().out.strip().splitlines()) == 3
        assert main(["diag", "list", "--project", "site"]) == 0 and "локальный" in capsys.readouterr().out
        assert main(["diag", "verify", "https://nope.example.com/", "--project", "site"]) == 2
    finally:
        srv.shutdown()


def test_batch_commands(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CIP_MASTER_PASSWORD", "cli-test-password")
    assert main(["key", "init", "--password"]) == 0
    good = tmp_path / "a.jsonl"
    good.write_text('{"name":"x","value":"1","domain":"a.test"}\n')
    bad = tmp_path / "b.json"
    bad.write_text("{ broken")
    assert main(["batch", str(good), str(bad), "--project", "p", "--workers", "2"]) == 1
    out = capsys.readouterr().out
    assert "✓ a.jsonl" in out and "✗ b.json" in out and "файлов с ошибками 1" in out
    job_id = int(out.split("Задача #")[1].split(":")[0])
    bad.write_text('{"name":"y","value":"2","domain":"b.test"}\n')
    assert main(["batch-retry", str(job_id), "--project", "p"]) == 0
    assert "файлов с ошибками 0" in capsys.readouterr().out
    assert main(["stats", "--project", "p"]) == 0 and "Всего записей : 2" in capsys.readouterr().out


def test_diag_run_all(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import threading
    from http.server import ThreadingHTTPServer

    from tests.integration.test_diagnostics import _Site

    _Site.valid, _Site.forget_logout = {"good-session"}, False
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/api/me"
        monkeypatch.setenv("CIP_MASTER_PASSWORD", "cli-test-password")
        assert main(["key", "init", "--password"]) == 0
        src = tmp_path / "c.jsonl"
        src.write_text('{"name":"sid","value":"good-session","domain":"127.0.0.1","hostOnly":true}\n')
        assert main(["import", str(src), "--project", "s"]) == 0
        assert main(["diag", "add", url, "--project", "s", "--contains", "alice"]) == 0
        assert main(["diag", "mark", "1", "--project", "s"]) == 0
        assert main(["diag", "run-all", "--project", "s"]) == 0
        out = capsys.readouterr().out
        assert "СОВПАЛО" in out and "сессия принята на 1" in out
    finally:
        srv.shutdown()


def test_export_command(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CIP_MASTER_PASSWORD", "cli-test-password")
    assert main(["key", "init", "--password"]) == 0
    src = tmp_path / "c.jsonl"
    src.write_text('{"name":"sid","value":"SECRET-XYZ","domain":"x.example.test"}\n')
    assert main(["import", str(src), "--project", "p"]) == 0
    out_csv = tmp_path / "r.csv"
    assert main(["export", str(out_csv), "--project", "p", "--format", "csv"]) == 0
    assert "замаскированы" in capsys.readouterr().out
    assert "SECRET-XYZ" not in out_csv.read_text(encoding="utf-8-sig")
    out_pdf = tmp_path / "r.pdf"
    assert main(["export", str(out_pdf), "--project", "p", "--format", "pdf"]) == 0
    assert out_pdf.read_bytes().startswith(b"%PDF-")
    out2 = tmp_path / "plain.csv"
    assert main(["export", str(out2), "--project", "p", "--columns", "name", "value", "--reveal-values"]) == 0
    assert "открытом виде" in capsys.readouterr().out and "SECRET-XYZ" in out2.read_text(encoding="utf-8-sig")
