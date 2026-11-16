"""Командная строка. Позволяет работать с ядром без GUI: ключи, проекты, импорт, проверка, отчёты.

Мастер-пароль запрашивается интерактивно; для автоматизации его можно передать через
переменную окружения ``CIP_MASTER_PASSWORD`` (она не журналируется).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from app import __version__
from app.bootstrap import AppContext, build_context
from app.domain import SourceFormat, ValidationStatus
from app.infrastructure.crypto import (
    CryptoBox,
    KeyError_,
    KeyManager,
    KeyProvider,
    KeyringKeyProvider,
    KeyUnavailableError,
    PasswordKeyProvider,
)
from app.infrastructure.db import migrations
from app.services.common import CancelToken
from app.services.cookies import CookieFilter, CookieService, SortKey
from app.services.importing import DuplicatePolicy, ImportOptions, ImportProgress, ImportService, iter_reports
from app.services.projects import ProjectError, ProjectService
from app.services.validation import ValidationService


class CliError(Exception):
    pass


# ----------------------------------------------------------------------------- вспомогательное
def _password(prompt: str, *, confirm: bool = False) -> str:
    env = os.environ.get("CIP_MASTER_PASSWORD")
    if env:
        return env
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("Повторите пароль: ") != pw:
        raise CliError("Пароли не совпадают")
    return pw


def _provider_for(km: KeyManager) -> KeyProvider:
    prot = km.protection()
    if prot is None:
        raise CliError("Хранилище ещё не настроено. Выполните: cookie-inspector key init")
    if prot == "keyring":
        return KeyringKeyProvider()
    return PasswordKeyProvider(_password("Мастер-пароль: "))


def _unlock(ctx: AppContext) -> CryptoBox:
    km = KeyManager(ctx.sessions)
    try:
        return km.unlock(_provider_for(km))
    except KeyError_ as e:
        raise CliError(str(e)) from e


def _project_id(ctx: AppContext, name: str, *, create: bool = False) -> int:
    ps = ProjectService(ctx.sessions)
    p = ps.ensure(name) if create else ps.get_by_name(name)
    if p is None:
        raise CliError(f"Проект «{name}» не найден")
    return p.id


def _fmt_ts(ts: int | None) -> str:
    return "сессия" if ts is None else datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d")


# ----------------------------------------------------------------------------- команды
def _cmd_info(_a: argparse.Namespace, ctx: AppContext) -> int:
    cur, head = migrations.current_revision(ctx.engine), migrations.head_revision(ctx.engine)
    print(f"Cookie Inspector Pro {__version__}")
    print(f"Каталог данных : {ctx.paths.data_dir}{'  (портативный режим)' if ctx.paths.portable else ''}")
    print(f"База данных    : {ctx.paths.database}")
    print(f"Схема          : {cur or 'не создана'} (актуальная: {head})")
    if cur == head:
        print(f"Защита ключа   : {KeyManager(ctx.sessions).protection() or 'не настроена'}")
    return 0


def _cmd_db_upgrade(_a: argparse.Namespace, ctx: AppContext) -> int:
    migrations.upgrade(ctx.engine)
    print(f"Схема обновлена до ревизии {migrations.current_revision(ctx.engine)}")
    return 0


def _cmd_db_status(_a: argparse.Namespace, ctx: AppContext) -> int:
    ok = migrations.is_up_to_date(ctx.engine)
    print("Схема актуальна" if ok else "Требуется обновление: cookie-inspector db upgrade")
    return 0 if ok else 1


def _cmd_key_init(a: argparse.Namespace, ctx: AppContext) -> int:
    km = KeyManager(ctx.sessions)
    if km.is_initialized():
        raise CliError("Ключ уже создан")
    if not a.password:
        try:
            km.initialize(KeyringKeyProvider())
            print("Ключ создан и защищён системным хранилищем ключей.")
            return 0
        except KeyUnavailableError as e:
            if a.keyring:
                raise CliError(str(e)) from e
            print(f"{e}. Будет использован мастер-пароль.")
    km.initialize(PasswordKeyProvider(_password("Новый мастер-пароль (не меньше 8 символов): ", confirm=True)))
    print("Ключ создан и защищён мастер-паролем. Без пароля значения cookies восстановить невозможно.")
    return 0


def _cmd_key_status(_a: argparse.Namespace, ctx: AppContext) -> int:
    print(f"Защита ключа: {KeyManager(ctx.sessions).protection() or 'не настроена'}")
    return 0


def _cmd_project_list(_a: argparse.Namespace, ctx: AppContext) -> int:
    projects = ProjectService(ctx.sessions).list()
    if not projects:
        print("Проектов нет")
    for p in projects:
        print(f"{p.name:30} {p.cookie_count:>10} записей")
    return 0


def _cmd_project_create(a: argparse.Namespace, ctx: AppContext) -> int:
    ProjectService(ctx.sessions).create(a.name, a.description or "")
    print(f"Создан проект «{a.name}»")
    return 0


def _cmd_project_delete(a: argparse.Namespace, ctx: AppContext) -> int:
    if not a.yes:
        raise CliError("Удаление необратимо. Повторите с --yes")
    ProjectService(ctx.sessions).delete(_project_id(ctx, a.name))
    print(f"Проект «{a.name}» удалён")
    return 0


def _cmd_import(a: argparse.Namespace, ctx: AppContext) -> int:
    box = _unlock(ctx)
    pid = _project_id(ctx, a.project, create=True)
    opts = ImportOptions(
        duplicates=DuplicatePolicy(a.duplicates),
        force_reimport=a.force,
        format_override=SourceFormat(a.format) if a.format else None,
    )

    def progress(p: ImportProgress) -> None:
        if sys.stderr.isatty() and p.bytes_total:
            print(
                f"\r  {p.bytes_done * 100 // p.bytes_total:3d}%  файлов {p.files_done}/{p.files_total}"
                f"  записей {p.records_ok}",
                end="",
                file=sys.stderr,
                flush=True,
            )

    token = CancelToken()
    try:
        rep = ImportService(ctx.sessions, box).run(
            pid, [Path(x) for x in a.paths], opts, progress=progress, cancel=token
        )
    except KeyboardInterrupt:
        token.cancel()
        raise
    if sys.stderr.isatty():
        print(file=sys.stderr)
    for line in iter_reports(rep):
        print(line)
    print(
        f"Итог: {rep.status}; импортировано {rep.records_ok}, ошибок {rep.records_failed}, "
        f"дубликатов {rep.duplicates}, {rep.duration_s:.1f} с"
    )
    if rep.status == "completed" and not a.no_validate:
        vr = ValidationService(ctx.sessions, box).run(pid, batch_id=rep.batch_id)
        print("Проверка:", ", ".join(f"{k}: {v}" for k, v in sorted(vr.by_status.items())))
    return 0 if rep.status == "completed" else 1


def _cmd_validate(a: argparse.Namespace, ctx: AppContext) -> int:
    vr = ValidationService(ctx.sessions, _unlock(ctx)).run(_project_id(ctx, a.project))
    print(f"Проверено {vr.checked}:", ", ".join(f"{k}: {v}" for k, v in sorted(vr.by_status.items())))
    if vr.by_severity:
        print("Безопасность:", ", ".join(f"{k}: {v}" for k, v in sorted(vr.by_severity.items())))
    return 0


def _cmd_stats(a: argparse.Namespace, ctx: AppContext) -> int:
    st = CookieService(ctx.sessions).stats(_project_id(ctx, a.project))
    print(
        f"Всего записей : {st.total}\nДоменов       : {st.domains}\nИстекших      : {st.expired}\n"
        f"Сессионных    : {st.session}\nSecure        : {st.secure} / без Secure: {st.insecure}\n"
        f"HttpOnly      : {st.http_only}\nНе проверено  : {st.not_analyzed}"
    )
    for k, v in sorted(st.by_status.items()):
        print(f"  {k:15} {v}")
    return 0


def _cmd_list(a: argparse.Namespace, ctx: AppContext) -> int:
    f = CookieFilter(text=a.search, statuses=frozenset(ValidationStatus(s) for s in a.status or []))
    page = CookieService(ctx.sessions).page(_project_id(ctx, a.project), f, sort=SortKey(a.sort), limit=a.limit)
    print(f"{'ID':>7}  {'СТАТУС':14} {'КРИТИЧН.':13} {'ИМЯ':24} {'ДОМЕН':28} {'СРОК':10} ФЛАГИ")
    for i in page.items:
        flags = "".join(c for c, on in (("S", i.secure), ("H", i.http_only), ("h", i.host_only)) if on)
        print(
            f"{i.id:>7}  {i.validation_status or '-':14} {i.max_severity or '-':13} {i.name[:24]:24} "
            f"{i.domain[:28]:28} {_fmt_ts(i.expires_at):10} {flags}"
        )
    if page.next_cursor:
        print("… показаны первые записи; уточните фильтр или увеличьте --limit")
    return 0


# ----------------------------------------------------------------------------- разбор аргументов
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cookie-inspector", description="Cookie Inspector Pro")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="сведения об установке и данных").set_defaults(func=_cmd_info, migrate=False)
    db = sub.add_parser("db", help="обслуживание базы данных").add_subparsers(dest="db_command", required=True)
    db.add_parser("upgrade", help="применить миграции").set_defaults(func=_cmd_db_upgrade, migrate=False)
    db.add_parser("status", help="проверить актуальность схемы").set_defaults(func=_cmd_db_status, migrate=False)

    key = sub.add_parser("key", help="ключ шифрования значений").add_subparsers(dest="key_command", required=True)
    ki = key.add_parser("init", help="создать ключ (по умолчанию — системное хранилище, иначе пароль)")
    g = ki.add_mutually_exclusive_group()
    g.add_argument("--keyring", action="store_true", help="только системное хранилище ключей")
    g.add_argument("--password", action="store_true", help="мастер-пароль")
    ki.set_defaults(func=_cmd_key_init)
    key.add_parser("status", help="способ защиты ключа").set_defaults(func=_cmd_key_status)

    pr = sub.add_parser("project", help="проекты").add_subparsers(dest="project_command", required=True)
    pr.add_parser("list", help="список проектов").set_defaults(func=_cmd_project_list)
    pc = pr.add_parser("create", help="создать проект")
    pc.add_argument("name")
    pc.add_argument("--description")
    pc.set_defaults(func=_cmd_project_create)
    pd = pr.add_parser("delete", help="удалить проект со всеми данными")
    pd.add_argument("name")
    pd.add_argument("--yes", action="store_true")
    pd.set_defaults(func=_cmd_project_delete)

    im = sub.add_parser("import", help="импортировать файлы или каталоги")
    im.add_argument("paths", nargs="+")
    im.add_argument("--project", required=True, help="имя проекта (будет создан при отсутствии)")
    im.add_argument("--duplicates", choices=[d.value for d in DuplicatePolicy], default=DuplicatePolicy.SKIP.value)
    im.add_argument("--force", action="store_true", help="импортировать уже импортированные файлы повторно")
    im.add_argument(
        "--format",
        choices=[
            f.value
            for f in (SourceFormat.NETSCAPE, SourceFormat.JSON, SourceFormat.JSONL, SourceFormat.CSV, SourceFormat.CIPX)
        ],
    )
    im.add_argument("--no-validate", action="store_true")
    im.set_defaults(func=_cmd_import)

    va = sub.add_parser("validate", help="проверить все записи проекта")
    va.add_argument("--project", required=True)
    va.set_defaults(func=_cmd_validate)
    stt = sub.add_parser("stats", help="сводка по проекту")
    stt.add_argument("--project", required=True)
    stt.set_defaults(func=_cmd_stats)
    ls = sub.add_parser("list", help="список записей (значения не выводятся)")
    ls.add_argument("--project", required=True)
    ls.add_argument("--search")
    ls.add_argument("--status", action="append", choices=[s.value for s in ValidationStatus])
    ls.add_argument("--sort", choices=[s.value for s in SortKey], default=SortKey.IMPORTED.value)
    ls.add_argument("--limit", type=int, default=50)
    ls.set_defaults(func=_cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ctx = build_context(migrate=getattr(args, "migrate", True))
    try:
        result: int = args.func(args, ctx)
        return result
    except (CliError, ProjectError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2
    finally:
        ctx.close()


if __name__ == "__main__":
    sys.exit(main())
