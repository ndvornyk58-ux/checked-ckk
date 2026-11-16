"""Точка входа Cookie Inspector Pro.

С аргументами — командная строка (``python main.py info``).
Без аргументов — графический интерфейс. GUI реализуется в PHASE 3; до этого
запуск без аргументов честно сообщает об этом и показывает доступные команды.
"""

from __future__ import annotations

import sys

from app.cli import build_parser, main


def run() -> int:
    if len(sys.argv) > 1:
        return main()
    print("Графический интерфейс появится в PHASE 3 (см. docs/STATUS.md). Доступные команды:\n")
    build_parser().print_help()
    return 0


if __name__ == "__main__":
    sys.exit(run())
