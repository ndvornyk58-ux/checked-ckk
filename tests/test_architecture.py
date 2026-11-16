"""Архитектурные инварианты проверяются автоматически, а не на ревью."""

from __future__ import annotations

import importlib
import pkgutil
import shutil
import subprocess
from pathlib import Path

import pytest

import app

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("lint-imports") is None, reason="import-linter не установлен")
def test_layer_contracts() -> None:
    r = subprocess.run(["lint-imports"], cwd=ROOT, capture_output=True, text=True, check=False)  # noqa: S607
    assert r.returncode == 0, r.stdout + r.stderr


def test_every_package_documents_its_responsibility() -> None:
    for mod in pkgutil.walk_packages(app.__path__, "app."):
        if mod.name.startswith("app.gui"):
            continue  # GUI импортирует PySide6 начиная с PHASE 3
        m = importlib.import_module(mod.name)
        if mod.ispkg:
            assert (m.__doc__ or "").strip(), f"{mod.name}: нет докстринга пакета"
