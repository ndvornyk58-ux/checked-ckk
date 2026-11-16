"""Точка входа Cookie Inspector Pro.

Без аргументов — графический интерфейс; с аргументами — командная строка (``python main.py --help``).
"""

from __future__ import annotations

import logging
import sys


def run() -> int:
    if len(sys.argv) > 1:
        from app.cli import main

        return main()
    from app.bootstrap import build_context
    from app.infrastructure.logging import setup_logging
    from app.services.workspace import Workspace

    ctx = build_context()
    setup_logging(ctx.paths.logs_dir, level=logging.INFO)
    try:
        from app.gui.app import run_gui
    except ImportError as e:
        print(f"Графический интерфейс недоступен: {e}. Установите PySide6: pip install PySide6", file=sys.stderr)
        return 2
    try:
        return run_gui(Workspace(ctx.sessions, ctx.paths.data_dir, portable=ctx.paths.portable))
    finally:
        ctx.close()


if __name__ == "__main__":
    sys.exit(run())
