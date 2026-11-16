"""Правила аудита безопасности cookies.

«Чувствительная» cookie — та, что по имени похожа на сессионную/аутентификационную
или содержит JWT. Это эвристика: она повышает критичность находок, а отчёт об этом сообщает.
"""

from __future__ import annotations

from collections.abc import Iterator

from app.domain import Cookie, Finding, FindingEngine, SameSite, Severity, ValueState
from app.rules import heuristics as hx
from app.rules import syntax as sx
from app.rules.base import FuncRule, Rule, RuleContext

H = "Определено эвристически по имени или содержимому cookie."


def _f(
    rule_id: str, sev: Severity, title: str, description: str, reason: str, risk: str, recommendation: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        engine=FindingEngine.SECURITY,
        title=title,
        description=description,
        reason=reason,
        risk=risk,
        recommendation=recommendation,
        severity=sev,
    )


def _value(c: Cookie) -> str | None:
    return c.value.reveal() if c.value_state is ValueState.PRESENT and c.value is not None else None


def is_sensitive(c: Cookie) -> bool:
    v = _value(c)
    return hx.is_sensitive_name(c.name) or (v is not None and hx.jwt_header(v) is not None)


def flag_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    sens, local = is_sensitive(c), sx.is_local_host(c.domain)
    if not c.secure:
        sev = Severity.INFO if local else (Severity.HIGH if sens else Severity.LOW)
        yield _f(
            "sec.missing-secure",
            sev,
            "Нет атрибута Secure",
            "Без Secure браузер отправляет cookie и по незашифрованному HTTP.",
            "Атрибут Secure отсутствует."
            + (f" {H}" if sens else "")
            + (" Домен локальный — риск снижен." if local else ""),
            "Перехват cookie в открытой сети (Wi-Fi, прокси), а для сессионной — захват сессии.",
            "Установите Secure и отдавайте сайт только по HTTPS (HSTS).",
        )
    if sens and not c.http_only:
        yield _f(
            "sec.missing-httponly",
            Severity.HIGH,
            "Нет атрибута HttpOnly у чувствительной cookie",
            "Без HttpOnly cookie читается JavaScript-кодом страницы.",
            f"HttpOnly отсутствует. {H}",
            "При XSS-уязвимости злоумышленник получит значение cookie и сможет захватить сессию.",
            "Установите HttpOnly для сессионных и аутентификационных cookies.",
        )


def samesite_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    sens = is_sensitive(c)
    if c.same_site is SameSite.NONE:
        yield _f(
            "sec.samesite-none",
            Severity.MEDIUM if sens else Severity.LOW,
            "SameSite=None",
            "Cookie отправляется и при межсайтовых запросах.",
            "SameSite=None." + (f" {H}" if sens else ""),
            "Межсайтовая подделка запросов (CSRF), если нет других мер защиты.",
            "Используйте Lax или Strict, если межсайтовая отправка не требуется.",
        )
    elif c.same_site is SameSite.UNSPECIFIED and sens:
        yield _f(
            "sec.samesite-unspecified",
            Severity.LOW,
            "SameSite не задан у чувствительной cookie",
            "Поведение по умолчанию различается между браузерами (Lax в Chromium, иначе в других).",
            f"Атрибут SameSite отсутствует. {H}",
            "Непредсказуемая защита от CSRF в разных браузерах.",
            "Задайте SameSite=Lax или Strict явно.",
        )


def lifetime_rule(c: Cookie, ctx: RuleContext) -> Iterator[Finding]:
    if c.expires_at is None or c.is_expired(ctx.now) or not is_sensitive(c):
        return
    days = (c.expires_at - (c.created_at or ctx.now)).days
    if days > 30:
        yield _f(
            "sec.excessive-lifetime",
            Severity.MEDIUM,
            "Чрезмерный срок жизни чувствительной cookie",
            "Долгоживущая сессионная cookie расширяет окно для использования украденной сессии.",
            f"Срок жизни {days} дн. {H}",
            "Похищенная cookie остаётся рабочей долгое время.",
            "Ограничьте срок сессии и используйте ротацию/повторную аутентификацию.",
        )


def scope_rules(c: Cookie, ctx: RuleContext) -> Iterator[Finding]:
    sens = is_sensitive(c)
    if sens and not c.host_only:
        yield _f(
            "sec.broad-domain",
            Severity.MEDIUM,
            "Чувствительная cookie доступна поддоменам",
            "С атрибутом Domain cookie отправляется на все поддомены.",
            f"Domain={c.domain}. {H}",
            "Любой поддомен (в т.ч. скомпрометированный или сторонний) получит сессию.",
            "Уберите атрибут Domain или используйте префикс __Host-.",
        )
    if sens and c.secure and c.host_only and c.path == "/" and not c.name.lower().startswith("__host-"):
        yield _f(
            "sec.host-prefix-recommended",
            Severity.INFO,
            "Рекомендуется префикс __Host-",
            "Префикс __Host- гарантирует, что cookie нельзя перезаписать с поддомена или по HTTP.",
            f"Cookie удовлетворяет требованиям __Host-, но префикса нет. {H}",
            "Подмена cookie с поддомена (cookie tossing).",
            "Переименуйте cookie с префиксом __Host-.",
        )
    others = [
        s
        for s in ctx.name_scopes.get(c.name, ())
        if s != (c.domain, c.host_only, c.path)
        and sx.domains_overlap(s[0], c.domain)
        and sx.paths_overlap(s[2], c.path)
    ]
    if others:
        listed = "; ".join(f"{d}{p}" for d, _h, p in others[:3])
        yield _f(
            "sec.cookie-shadowing",
            Severity.MEDIUM if sens else Severity.LOW,
            "Конфликт cookies с одинаковым именем",
            "Несколько cookies с одним именем для пересекающихся доменов и путей отправляются вместе.",
            f"Пересекается с: {listed}.",
            "Сервер может прочитать не ту cookie; возможна подмена (cookie tossing).",
            "Используйте уникальные имена или префикс __Host-.",
        )


def value_rules(c: Cookie, _ctx: RuleContext) -> Iterator[Finding]:
    v = _value(c)
    if v is None:
        return
    header = hx.jwt_header(v)
    if header is not None:
        alg = str(header.get("alg", ""))
        if alg.lower() == "none":
            yield _f(
                "sec.jwt-alg-none",
                Severity.CRITICAL,
                "JWT без подписи (alg=none)",
                "Токен не подписан, его содержимое может изменить кто угодно.",
                "В заголовке JWT указан alg=none.",
                "Подделка токена и повышение привилегий, если сервер принимает такие токены.",
                "Отклоняйте alg=none на сервере и подписывайте токены.",
            )
        if not c.http_only:
            yield _f(
                "sec.jwt-readable",
                Severity.MEDIUM,
                "JWT доступен JavaScript",
                "Токен в cookie без HttpOnly читается скриптами страницы.",
                f"JWT ({alg}) без HttpOnly.",
                "Кража токена при XSS.",
                "Установите HttpOnly.",
            )
        return
    obj = hx.decoded_json_object(v)
    if obj is not None:
        keys = hx.privilege_keys(obj)
        if keys:
            yield _f(
                "sec.client-side-privileges",
                Severity.MEDIUM,
                "Данные о правах в значении cookie",
                "Значение — JSON с полями, похожими на роль или идентификатор пользователя.",
                "Найдены поля: " + ", ".join(sorted(keys)) + ".",
                "Если сервер доверяет этим полям без подписи, клиент может их подменить.",
                "Храните права на сервере или подписывайте данные (HMAC/JWS).",
            )
        return
    if hx.is_sensitive_name(c.name):
        bits = hx.estimated_entropy_bits(v)
        if bits < 64:
            yield _f(
                "sec.weak-session-id",
                Severity.MEDIUM,
                "Слабый идентификатор сессии",
                "Короткий или однообразный идентификатор сессии проще угадать.",
                f"Оценка энтропии ≈{bits:.0f} бит при рекомендуемых ≥64. {H}",
                "Подбор идентификатора чужой сессии.",
                "Генерируйте идентификаторы криптостойким ГСЧ длиной ≥128 бит.",
            )


def build_security_rules() -> list[Rule]:
    s = FindingEngine.SECURITY
    return [
        FuncRule("sec.flags", s, flag_rules),
        FuncRule("sec.samesite", s, samesite_rules),
        FuncRule("sec.lifetime", s, lifetime_rule),
        FuncRule("sec.scope", s, scope_rules),
        FuncRule("sec.value", s, value_rules),
    ]
