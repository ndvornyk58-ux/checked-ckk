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
