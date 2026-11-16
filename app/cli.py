"""Командная строка. Работает без GUI — удобно для проверки установки и обслуживания БД."""

from __future__ import annotations

import argparse
import sys

from app import __version__
from app.bootstrap import build_context
from app.infrastructure.db import migrations


def _cmd_info(_args: argparse.Namespace) -> int:
    ctx = build_context(migrate=False)
    try:
        cur = migrations.current_revision(ctx.engine)
        head = migrations.head_revision(ctx.engine)
        print(f"Cookie Inspector Pro {__version__}")
        print(f"Каталог данных : {ctx.paths.data_dir}{'  (портативный режим)' if ctx.paths.portable else ''}")
        print(f"База данных    : {ctx.paths.database}")
        print(f"Схема          : {cur or 'не создана'} (актуальная: {head})")
    finally:
        ctx.close()
    return 0


def _cmd_db_upgrade(_args: argparse.Namespace) -> int:
    ctx = build_context(migrate=True)
    try:
        print(f"Схема обновлена до ревизии {migrations.current_revision(ctx.engine)}")
    finally:
        ctx.close()
    return 0


def _cmd_db_status(_args: argparse.Namespace) -> int:
    ctx = build_context(migrate=False)
    try:
        ok = migrations.is_up_to_date(ctx.engine)
        print("Схема актуальна" if ok else "Требуется обновление: cookie-inspector db upgrade")
        return 0 if ok else 1
    finally:
        ctx.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cookie-inspector", description="Cookie Inspector Pro")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("info", help="сведения об установке и данных").set_defaults(func=_cmd_info)
    db = sub.add_parser("db", help="обслуживание базы данных").add_subparsers(dest="db_command", required=True)
    db.add_parser("upgrade", help="применить миграции").set_defaults(func=_cmd_db_upgrade)
    db.add_parser("status", help="проверить актуальность схемы").set_defaults(func=_cmd_db_status)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
