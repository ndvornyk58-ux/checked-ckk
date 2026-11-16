"""Расположение данных приложения.

Порядок выбора каталога данных:
1. Переменная окружения ``CIP_DATA_DIR`` (тесты, нестандартные установки).
2. Портативный режим: если рядом с исполняемым файлом/``main.py`` лежит ``portable.flag``,
   данные хранятся в ``./data`` рядом с ним — ничего не пишется в профиль пользователя.
   Удобно для рабочих компьютеров, где нельзя ставить приложения.
3. Стандартный каталог данных пользователя ОС (platformdirs).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_data_dir

APP_NAME = "CookieInspectorPro"
APP_AUTHOR = "CookieInspectorPro"
PORTABLE_FLAG = "portable.flag"


def _app_root() -> Path:
    if getattr(sys, "frozen", False):  # сборка PyInstaller
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class AppPaths:
    """Набор каталогов приложения. Создаётся через :func:`resolve_paths`."""

    data_dir: Path
    portable: bool

    @property
    def database(self) -> Path:
        return self.data_dir / "cookie_inspector.db"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def plugins_dir(self) -> Path:
        return self.data_dir / "plugins"

    def ensure(self) -> AppPaths:
        """Создать каталоги, если их нет."""
        for p in (self.data_dir, self.logs_dir, self.backups_dir, self.plugins_dir):
            p.mkdir(parents=True, exist_ok=True)
        return self


def resolve_paths(app_root: Path | None = None) -> AppPaths:
    """Определить каталоги приложения согласно правилам из докстринга модуля."""
    env = os.environ.get("CIP_DATA_DIR")
    if env:
        return AppPaths(data_dir=Path(env).expanduser().resolve(), portable=False)
    root = app_root or _app_root()
    if (root / PORTABLE_FLAG).is_file():
        return AppPaths(data_dir=root / "data", portable=True)
    return AppPaths(data_dir=Path(user_data_dir(APP_NAME, APP_AUTHOR)), portable=False)
