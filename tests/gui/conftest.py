from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

pytest.importorskip("PySide6")

from app.app_context import Workspace
from app.gui.app import apply_theme, create_app
from app.gui.shell.main_window import MainWindow

PASSWORD = "gui-test-password"


@pytest.fixture
def ws(sessions: sessionmaker[Session], tmp_path: Path) -> Workspace:
    return Workspace(sessions, tmp_path / "appdata", scrypt_n=2**10)


@pytest.fixture
def unlocked(ws: Workspace) -> Workspace:
    ws.attach(ws.keys.initialize_with_password(PASSWORD))
    return ws


@pytest.fixture
def window(qtbot, unlocked: Workspace) -> Iterator[MainWindow]:  # type: ignore[no-untyped-def]
    app = create_app([])
    apply_theme(app, "dark")
    w = MainWindow(unlocked, apply_theme=lambda n: apply_theme(app, n))
    qtbot.addWidget(w)
    w.resize(1400, 900)
    w.show()
    yield w
    w.runner.wait(10_000)


def settle(qtbot, w: MainWindow) -> None:  # type: ignore[no-untyped-def]
    """Дождаться фоновых задач и обработать их сигналы."""
    qtbot.waitUntil(lambda: not w.runner.busy, timeout=30_000)
    qtbot.wait(20)
