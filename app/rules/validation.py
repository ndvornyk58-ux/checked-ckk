"""Правила проверки корректности (RFC 6265, RFC 6265bis, поведение современных браузеров).

Статусы: INVALID — браузер отвергнет такую cookie; EXPIRED — срок истёк; WARNING — допустимо,
но сомнительно; UNKNOWN — проверку нельзя выполнить по имеющимся данным.
VALID ничего не говорит о том, действует ли сессия на сервере.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

from app.domain import Cookie, Finding, FindingEngine, SameSite, ValidationStatus, ValueState
from app.rules import syntax as sx
from app.rules.base import FuncRule, Rule, RuleContext

S = ValidationStatus


def _f(
    rule_id: str,
    status: ValidationStatus,
    title: str,
    description: str,
    reason: str,
    risk: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        engine=FindingEngine.VALIDATION,
        title=title,
        description=description,
        reason=reason,
        risk=risk,
        recommendation=recommendation,
        status=status,
    )


def name_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    if c.name == "":
        yield _f(
            "name.empty",
            S.WARNING,
            "Пустое имя cookie",
            "Cookie без имени допускается RFC 6265bis, но плохо поддерживается серверами и фреймворками.",
            "Имя cookie — пустая строка.",
            "Значение может быть прочитано не тем обработчиком.",
            "Задайте cookie явное имя.",
        )
        return
    bad = sx.first_non_token(c.name)
    if bad:
        pos, ch = bad
        yield _f(
            "name.invalid-chars",
            S.INVALID,
            "Недопустимый символ в имени",
            "Имя cookie должно быть токеном (RFC 9110): без пробелов, управляющих символов и разделителей.",
            f"{sx.cap(sx.describe_char(ch))} в позиции {pos + 1} имени.",
            "Браузер отвергнет cookie или разберёт заголовок не так, как ожидается.",
            "Используйте в имени только буквы, цифры и символы !#$%&'*+-.^_`|~.",
        )


def value_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    if c.value_state is not ValueState.PRESENT or c.value is None:
        why = (
            "значение зашифровано браузером и не расшифровывается приложением"
            if c.value_state is ValueState.BROWSER_ENCRYPTED
            else "значение отсутствует в источнике"
        )
        yield _f(
            "value.unavailable",
            S.UNKNOWN,
            "Значение недоступно для проверки",
            "Проверки значения (символы, размер) не выполнялись.",
            sx.cap(why) + ".",
            recommendation="Если проверка значения нужна, импортируйте экспорт с значениями.",
        )
        return
    v = c.value.reveal()
    size = len(c.name.encode()) + len(v.encode())
    if size > sx.MAX_NAME_VALUE_BYTES:
        yield _f(
            "size.too-large",
            S.INVALID,
            "Cookie слишком большая",
            f"Браузеры отвергают cookie, у которой имя и значение вместе больше {sx.MAX_NAME_VALUE_BYTES} байт.",
            f"Имя и значение занимают {size} байт.",
            "Cookie не будет сохранена браузером.",
            "Храните данные на сервере, а в cookie — только идентификатор.",
        )
    bad = sx.first_forbidden_in_value(v)
    if bad:
        pos, ch = bad
        yield _f(
            "value.forbidden-chars",
            S.INVALID,
            "Запрещённый символ в значении",
            "Управляющие символы и «;» в значении приводят к отказу браузера или обрезке значения.",
            f"{sx.cap(sx.describe_char(ch))} в позиции {pos + 1} значения.",
            "Значение будет отвергнуто или обрезано.",
            "Кодируйте значение (base64url или URL-encoding).",
        )
        return
    odd = sx.non_rfc_value_chars(v)
    if odd:
        listed = ", ".join(sorted(sx.describe_char(ch) for ch in odd)[:5])
        yield _f(
            "value.non-rfc-chars",
            S.WARNING,
            "Символы вне RFC 6265 в значении",
            "Браузеры принимают такие символы, но часть серверов и прокси разбирает их по-разному.",
            f"Найдено: {listed}.",
            "Несогласованный разбор значения на разных компонентах.",
            "Кодируйте значение (base64url или URL-encoding).",
        )


def domain_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    if not c.domain:
        yield _f(
            "domain.empty",
            S.INVALID,
            "Пустой домен",
            "У сохранённой cookie должен быть домен.",
            "Поле домена пустое.",
            "Невозможно определить, куда браузер отправит cookie.",
            "Проверьте источник данных.",
        )
        return
    err = sx.domain_syntax_error(c.domain)
    if err:
        yield _f(
            "domain.syntax",
            S.INVALID,
            "Некорректный домен",
            "Домен должен быть корректным именем хоста.",
            f"Домен «{c.domain}»: {err}.",
            "Браузер не сопоставит cookie ни с одним сайтом.",
            "Исправьте домен в источнике.",
        )
        return
    if not c.host_only and sx.is_ip(c.domain):
        yield _f(
            "domain.ip-domain-attr",
            S.WARNING,
            "Атрибут Domain для IP-адреса",
            "Для IP-адресов атрибут Domain не имеет смысла: cookie всё равно будет только для этого адреса.",
            f"Доменная cookie для адреса {c.domain}.",
            recommendation="Уберите атрибут Domain.",
        )
    if not c.host_only and c.domain == "localhost":
        yield _f(
            "domain.localhost-domain-attr",
            S.WARNING,
            "Атрибут Domain=localhost",
            "Браузеры по-разному обрабатывают Domain=localhost.",
            "Доменная cookie для localhost.",
            recommendation="Для локальной разработки используйте host-only cookie (без Domain).",
        )
    if not c.host_only and sx.is_public_suffix(c.domain):
        yield _f(
            "domain.public-suffix",
            S.INVALID,
            "Cookie на публичный суффикс",
            "Браузеры отвергают cookie с Domain, равным публичному суффиксу (Public Suffix List).",
            f"«{c.domain}» — публичный суффикс.",
            "Такая cookie была бы доступна всем сайтам в зоне — поэтому браузеры её не принимают.",
            "Укажите домен своего сайта.",
        )


def path_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    if not c.path.startswith("/"):
        yield _f(
            "path.not-absolute",
            S.INVALID,
            "Путь не начинается с «/»",
            "Браузер заменит такой путь путём по умолчанию, поэтому сохранённая cookie с ним некорректна.",
            "Путь не начинается с «/».",
            recommendation="Укажите путь, начинающийся с «/».",
        )
    bad = next(((i, ch) for i, ch in enumerate(c.path) if sx.is_ctl(ch) or ch == ";"), None)
    if bad:
        yield _f(
            "path.forbidden-chars",
            S.INVALID,
            "Запрещённый символ в пути",
            "Управляющие символы и «;» в пути недопустимы.",
            f"{sx.cap(sx.describe_char(bad[1]))} в позиции {bad[0] + 1} пути.",
            recommendation="Исправьте путь в источнике.",
        )
    if len(c.path.encode()) > sx.MAX_ATTRIBUTE_BYTES:
        yield _f(
            "path.too-long",
            S.INVALID,
            "Слишком длинный путь",
            f"Браузеры игнорируют атрибут Path длиннее {sx.MAX_ATTRIBUTE_BYTES} байт.",
            f"Длина пути {len(c.path.encode())} байт.",
            recommendation="Сократите путь.",
        )


def expiry_rules(c: Cookie, ctx: RuleContext) -> Iterator[Finding]:
    if c.expires_at is not None and c.is_expired(ctx.now):
        yield _f(
            "expiry.expired",
            S.EXPIRED,
            "Срок действия истёк",
            "Браузер удаляет cookie после окончания срока и больше её не отправляет.",
            f"Истекла {c.expires_at:%Y-%m-%d %H:%M:%S} UTC.",
            recommendation="Удалите запись или получите актуальную cookie.",
        )
    elif c.expires_at is not None:
        start = c.created_at or ctx.now
        if c.expires_at - start > timedelta(days=sx.MAX_LIFETIME_DAYS):
            days = (c.expires_at - start).days
            yield _f(
                "expiry.over-400-days",
                S.WARNING,
                "Срок больше 400 дней",
                "Современные браузеры (RFC 6265bis) ограничивают срок жизни cookie 400 днями.",
                f"Срок жизни {days} дн.",
                "Фактический срок будет короче заявленного.",
                "Задайте срок не больше 400 дней.",
            )
    skew = ctx.now + timedelta(minutes=5)
    for label, ts in (("создания", c.created_at), ("последнего доступа", c.last_accessed_at)):
        if ts is not None and ts > skew:
            yield _f(
                "timestamps.future",
                S.WARNING,
                "Время в будущем",
                "Отметки времени из будущего обычно означают сбой часов или повреждение данных.",
                f"Время {label}: {ts:%Y-%m-%d %H:%M:%S} UTC.",
                recommendation="Проверьте источник.",
            )


def attribute_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    lower = c.name.lower()
    if lower.startswith("__secure-") and not c.secure:
        yield _f(
            "prefix.secure",
            S.INVALID,
            "Нарушены требования префикса __Secure-",
            "Cookie с префиксом __Secure- браузер примет только с атрибутом Secure.",
            "Нет атрибута Secure.",
            "Браузер отвергнет cookie.",
            "Добавьте Secure или уберите префикс.",
        )
    if lower.startswith("__host-"):
        problems = [
            p
            for ok, p in ((c.secure, "нет Secure"), (c.host_only, "задан Domain"), (c.path == "/", "путь не «/»"))
            if not ok
        ]
        if problems:
            yield _f(
                "prefix.host",
                S.INVALID,
                "Нарушены требования префикса __Host-",
                "Cookie с префиксом __Host- требует Secure, отсутствие Domain и Path=/.",
                "Нарушено: " + ", ".join(problems) + ".",
                "Браузер отвергнет cookie.",
                "Выполните все три требования или уберите префикс.",
            )
    if c.same_site is SameSite.NONE and not c.secure:
        yield _f(
            "samesite.none-insecure",
            S.INVALID,
            "SameSite=None без Secure",
            "Современные браузеры отвергают cookie с SameSite=None без атрибута Secure.",
            "SameSite=None, Secure отсутствует.",
            "Браузер отвергнет cookie.",
            "Добавьте Secure.",
        )
    if c.partitioned and not c.secure:
        yield _f(
            "partitioned.insecure",
            S.INVALID,
            "Partitioned без Secure",
            "Разделённые cookie (CHIPS) требуют атрибут Secure.",
            "Partitioned, Secure отсутствует.",
            "Браузер отвергнет cookie.",
            "Добавьте Secure.",
        )


def duplicate_rule(c: Cookie, ctx: RuleContext) -> Iterator[Finding]:
    if c.identity in ctx.duplicate_identities:
        yield _f(
            "duplicate.identity",
            S.WARNING,
            "Дубликат",
            "В проекте несколько записей с одинаковыми именем, доменом, путём и host-only.",
            "Совпадает ключ cookie (RFC 6265 §5.3) с другой записью.",
            "Браузер хранит только одну такую cookie; какая из записей актуальна — неизвестно.",
            "Оставьте одну запись.",
        )


def build_validation_rules() -> list[Rule]:
    v = FindingEngine.VALIDATION
    return [
        FuncRule("name", v, name_rules),
        FuncRule("value", v, value_rules),
        FuncRule("domain", v, domain_rules),
        FuncRule("path", v, path_rules),
        FuncRule("expiry", v, expiry_rules),
        FuncRule("attributes", v, attribute_rules),
        FuncRule("duplicate", v, duplicate_rule),
    ]
