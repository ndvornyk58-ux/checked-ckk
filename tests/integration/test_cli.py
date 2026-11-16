from __future__ import annotations

import pytest

from app.cli import main


def test_info_upgrade_status(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["info"]) == 0
    assert "не создана" in capsys.readouterr().out
    assert main(["db", "status"]) == 1
    assert main(["db", "upgrade"]) == 0
    assert "0001" in capsys.readouterr().out
    assert main(["db", "status"]) == 0
