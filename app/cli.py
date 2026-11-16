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
from app.services.diagnostics import DiagnosticsError, DiagnosticsService, EndpointInfo, Markers, Outcome
from app.services.importing import DuplicatePolicy, ImportOptions, ImportProgress, ImportService, iter_reports
from app.services.projects import ProjectError, ProjectService
from app.services.validation import ValidationService
from app.workers.batch import BatchProgress, BatchService, JobKind, JobStatus


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


_OUTCOME = {
    Outcome.MATCHED: "СОВПАЛО — ответ соответствует действующей сессии",
    Outcome.NOT_MATCHED: "НЕ СОВПАЛО — ответ не соответствует ожидаемому",
    Outcome.ERROR: "ОШИБКА — запрос не выполнен",
}


def _endpoint(
    ctx: AppContext, project: str, url: str, box: CryptoBox | None = None
) -> tuple[DiagnosticsService, EndpointInfo]:
    ds = DiagnosticsService(ctx.sessions, box)
    ep = next((e for e in ds.endpoints(_project_id(ctx, project)) if e.url == url), None)
    if ep is None:
        raise CliError(f"Адрес {url} не добавлен. Сначала: cookie-inspector diag add {url} --project {project} ...")
    return ds, ep


def _cmd_diag_add(a: argparse.Namespace, ctx: AppContext) -> int:
    ds = DiagnosticsService(ctx.sessions, None)
    m = Markers(
        status=tuple(a.status or [200]),
        body_contains=tuple(a.contains or []),
        body_not_contains=tuple(a.not_contains or []),
        location_contains=a.location,
    )
    ep = ds.add_endpoint(_project_id(ctx, a.project, create=True), a.url, m)
    print(f"Адрес добавлен: {ep.url}")
    print(ds.verification_instructions(ep.id))
    return 0


def _cmd_diag_list(a: argparse.Namespace, ctx: AppContext) -> int:
    ds = DiagnosticsService(ctx.sessions, None)
    for e in ds.endpoints(_project_id(ctx, a.project)):
        state = {"local": "локальный", "verified": "подтверждён", "unverified": "не подтверждён"}[e.state]
        print(f"{e.url}  [{state}{'' if e.usable or e.state != 'verified' else ', подтверждение устарело'}]")
        print(
            f"    маркеры: код {list(e.markers.status)}, содержит {list(e.markers.body_contains)}, "
            f"не содержит {list(e.markers.body_not_contains)}"
            + (f", Location содержит {e.markers.location_contains!r}" if e.markers.location_contains else "")
        )
    return 0


def _cmd_diag_instructions(a: argparse.Namespace, ctx: AppContext) -> int:
    ds, ep = _endpoint(ctx, a.project, a.url)
    print(ds.verification_instructions(ep.id))
    return 0


def _cmd_diag_verify(a: argparse.Namespace, ctx: AppContext) -> int:
    ds, ep = _endpoint(ctx, a.project, a.url)
    ds.verify(ep.id)
    print(f"Владение {ep.host} подтверждено. Теперь можно запускать проверку.")
    return 0


def _cmd_diag_mark(a: argparse.Namespace, ctx: AppContext) -> int:
    CookieService(ctx.sessions).set_test_session(a.ids, not a.unmark)
    print(("Снята отметка" if a.unmark else "Отмечено как тестовая сессия") + f": {len(a.ids)}")
    return 0


def _cmd_diag_cookies(a: argparse.Namespace, ctx: AppContext) -> int:
    ds, ep = _endpoint(ctx, a.project, a.url)
    found = ds.matching_cookies(ep.id)
    if not found:
        print("Нет тестовых сессий для этого адреса. Отметьте cookie: cookie-inspector diag mark ID --project ...")
    for cid, name, domain in found:
        print(f"{cid:>7}  {name}  ({domain})")
    return 0


def _cmd_diag_run(a: argparse.Namespace, ctx: AppContext) -> int:
    ds, ep = _endpoint(ctx, a.project, a.url, _unlock(ctx))
    ids = a.cookie or [c[0] for c in ds.matching_cookies(ep.id)]
    pair = a.pair or (ds.new_pair() if a.phase == "before" else None)
    if a.phase == "after" and not pair:
        raise CliError("Для --phase after укажите --pair из проверки «до»")
    r = ds.run(ep.id, ids, phase=a.phase, pair_id=pair)
    print(f"Результат: {_OUTCOME[r.outcome]}")
    if r.status_code is not None:
        print(f"Код ответа: {r.status_code}, {r.elapsed_ms} мс" + (f", Location: {r.location}" if r.location else ""))
    for c in r.checks:
        print(f"  {'✓' if c.ok else '✗'} {c.marker}: {c.expected}")
    print("Отправлены: " + ", ".join(r.sent_cookies))
    for line in [*r.skipped_cookies, *r.warnings]:
        print(f"  ! {line}")
    if r.set_cookie_names:
        print("Сервер установил cookies: " + ", ".join(r.set_cookie_names))
    if r.error:
        print(f"Ошибка: {r.error}")
    if a.phase == "before":
        print(
            f"\nТеперь выполните действие (например, выйдите из аккаунта на сайте) и запустите:\n"
            f"  cookie-inspector diag run {a.url} --project {a.project} --phase after --pair {pair}"
        )
    if a.phase == "after" and pair:
        verdict = ds.compare_pair(pair)
        print(("\n⚠ " if verdict.problem else "\n") + verdict.verdict)
        return 3 if verdict.problem else 0
    return 0 if r.outcome is Outcome.MATCHED else 1


def _cmd_diag_run_all(a: argparse.Namespace, ctx: AppContext) -> int:
    ds = DiagnosticsService(ctx.sessions, _unlock(ctx))
    rows = ds.run_across_endpoints(_project_id(ctx, a.project))
    if not rows:
        print("В проекте нет адресов диагностики")
        return 0
    for r in rows:
        if r.outcome is not None:
            mark = {Outcome.MATCHED: "СОВПАЛО", Outcome.NOT_MATCHED: "НЕ СОВПАЛО", Outcome.ERROR: "ОШИБКА"}[r.outcome]
            extra = f"код {r.result.status_code}, cookies {len(r.matched_cookie_ids)}" if r.result else ""
        else:
            mark, extra = "ПРОПУЩЕН", r.skipped_reason or ""
        print(f"  [{mark:11}] {r.url}  {extra}")
    checked = sum(1 for r in rows if r.outcome is not None)
    matched = sum(1 for r in rows if r.outcome is Outcome.MATCHED)
    print(f"Итог: адресов {len(rows)}, опрошено {checked}, сессия принята на {matched}")
    return 0


def _cmd_diag_history(a: argparse.Namespace, ctx: AppContext) -> int:
    ds, ep = _endpoint(ctx, a.project, a.url)
    for r in ds.history(ep.id, a.limit):
        print(
            f"#{r.run_id:<5} {r.outcome.value:12} код {r.status_code or '—':<4} {r.phase or '':7} "
            f"{', '.join(r.sent_cookies)}"
        )
    return 0


def _cmd_batch(a: argparse.Namespace, ctx: AppContext) -> int:
    box = _unlock(ctx)
    pid = _project_id(ctx, a.project, create=True)
    bs = BatchService(ctx.sessions, box)
    kind = JobKind.IMPORT if a.no_validate else JobKind.IMPORT_VALIDATE
    opts = ImportOptions(duplicates=DuplicatePolicy(a.duplicates), force_reimport=a.force)
    job_id = bs.create_job(pid, [Path(x) for x in a.paths], kind=kind, options=opts, max_workers=a.workers)
    print(f"Задача #{job_id}: файлов {bs.job(job_id).total}, потоков {a.workers}")

    def progress(p: BatchProgress) -> None:
        if sys.stderr.isatty():
            bar = p.done * 100 // p.total if p.total else 0
            print(f"\r  {bar:3d}%  {p.done}/{p.total}  записей {p.records_ok}", end="", file=sys.stderr, flush=True)

    try:
        summary = bs.run_job(job_id, progress=progress)
    except KeyboardInterrupt:
        bs.cancel(job_id)
        raise
    if sys.stderr.isatty():
        print(file=sys.stderr)
    for t in bs.tasks(job_id):
        mark = {"done": "✓", "failed": "✗", "skipped": "•", "cancelled": "—", "queued": "·", "running": "·"}
        line = f"  {mark.get(t.status.value, '?')} {t.name}: записей {t.records_ok}"
        if t.error:
            line += f" — {t.error}"
        print(line)
    print(
        f"Итог: {summary.status.value}; импортировано {summary.records_ok}, "
        f"дубликатов {summary.duplicates}, файлов с ошибками {summary.failed_tasks}"
    )
    if summary.status is JobStatus.FAILED:
        print(f"Повторить только ошибки: cookie-inspector batch-retry {job_id} --project {a.project}")
        return 1
    return 0


def _cmd_batch_retry(a: argparse.Namespace, ctx: AppContext) -> int:
    box = _unlock(ctx)
    bs = BatchService(ctx.sessions, box)
    n = bs.retry_failed(a.job_id)
    if not n:
        print("Нет файлов с ошибками для повтора")
        return 0
    print(f"Повторная обработка файлов: {n}")
    summary = bs.run_job(a.job_id)
    print(f"Итог: {summary.status.value}; файлов с ошибками {summary.failed_tasks}")
    return 0 if summary.status is not JobStatus.FAILED else 1


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
    dg = sub.add_parser("diag", help="диагностика тестовых сессий на своих адресах").add_subparsers(
        dest="diag_command", required=True
    )
    da = dg.add_parser("add", help="добавить адрес и ожидаемые маркеры")
    da.add_argument("url")
    da.add_argument("--project", required=True)
    da.add_argument("--status", type=int, action="append", help="ожидаемый код ответа (можно несколько)")
    da.add_argument("--contains", action="append", help="текст, который должен быть в ответе")
    da.add_argument("--not-contains", action="append", help="текст, которого не должно быть (например «Войти»)")
    da.add_argument("--location", help="подстрока заголовка Location (для ожидаемых редиректов)")
    da.set_defaults(func=_cmd_diag_add)
    for name, fn, hlp in (("list", _cmd_diag_list, "адреса проекта"),):
        x = dg.add_parser(name, help=hlp)
        x.add_argument("--project", required=True)
        x.set_defaults(func=fn)
    for name, fn, hlp in (
        ("instructions", _cmd_diag_instructions, "как подтвердить владение доменом"),
        ("verify", _cmd_diag_verify, "проверить файл подтверждения на сайте"),
        ("cookies", _cmd_diag_cookies, "тестовые сессии, подходящие к адресу"),
    ):
        x = dg.add_parser(name, help=hlp)
        x.add_argument("url")
        x.add_argument("--project", required=True)
        x.set_defaults(func=fn)
    dm = dg.add_parser("mark", help="отметить cookies как тестовые сессии")
    dm.add_argument("ids", type=int, nargs="+")
    dm.add_argument("--project", required=True)
    dm.add_argument("--unmark", action="store_true")
    dm.set_defaults(func=_cmd_diag_mark)
    dr = dg.add_parser("run", help="проверить тестовую сессию")
    dr.add_argument("url")
    dr.add_argument("--project", required=True)
    dr.add_argument("--cookie", type=int, action="append", help="id cookie (по умолчанию — все подходящие тестовые)")
    dr.add_argument("--phase", choices=["before", "after"])
    dr.add_argument("--pair")
    dr.set_defaults(func=_cmd_diag_run)
    ra = dg.add_parser("run-all", help="прогнать тестовые сессии по всем адресам проекта")
    ra.add_argument("--project", required=True)
    ra.set_defaults(func=_cmd_diag_run_all)
    dh = dg.add_parser("history", help="история проверок адреса")
    dh.add_argument("url")
    dh.add_argument("--project", required=True)
    dh.add_argument("--limit", type=int, default=20)
    dh.set_defaults(func=_cmd_diag_history)

    bt = sub.add_parser("batch", help="пакетная обработка множества файлов")
    bt.add_argument("paths", nargs="+")
    bt.add_argument("--project", required=True)
    bt.add_argument("--workers", type=int, default=4)
    bt.add_argument("--duplicates", choices=[d.value for d in DuplicatePolicy], default=DuplicatePolicy.SKIP.value)
    bt.add_argument("--force", action="store_true")
    bt.add_argument("--no-validate", action="store_true")
    bt.set_defaults(func=_cmd_batch)
    br = sub.add_parser("batch-retry", help="повторить упавшие файлы пакетной задачи")
    br.add_argument("job_id", type=int)
    br.add_argument("--project", required=True)
    br.set_defaults(func=_cmd_batch_retry)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ctx = build_context(migrate=getattr(args, "migrate", True))
    try:
        result: int = args.func(args, ctx)
        return result
    except (CliError, ProjectError, DiagnosticsError, FileNotFoundError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 2
    finally:
        ctx.close()


if __name__ == "__main__":
    sys.exit(main())
