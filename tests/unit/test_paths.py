from __future__ import annotations

from pathlib import Path

import pytest

from app.infrastructure.paths import PORTABLE_FLAG, resolve_paths


def test_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CIP_DATA_DIR", str(tmp_path / "d"))
    p = resolve_paths()
    assert p.data_dir == (tmp_path / "d").resolve() and not p.portable


def test_portable_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CIP_DATA_DIR", raising=False)
    (tmp_path / PORTABLE_FLAG).touch()
    p = resolve_paths(app_root=tmp_path).ensure()
    assert p.portable and p.data_dir == tmp_path / "data"
    assert p.logs_dir.is_dir() and p.backups_dir.is_dir() and p.plugins_dir.is_dir()


def test_default_is_user_dir_not_app_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CIP_DATA_DIR", raising=False)
    p = resolve_paths(app_root=tmp_path)
    assert not p.portable and tmp_path not in p.data_dir.parents
