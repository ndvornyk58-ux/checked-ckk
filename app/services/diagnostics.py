"""Session Diagnostics — проверка тестовых сессий на собственных endpoints (ADR-0004).

Правила, которые выполняются в коде, а не только в интерфейсе:
* запрос возможен только к endpoint'у проекта со статусом ``local`` (localhost, приватная сеть,
  зоны .test/.local/.localhost) или ``verified`` (владение доменом подтверждено токеном);
* подтверждение устаревает через ``VERIFY_TTL_DAYS`` дней — его нужно повторить;
* для публичных доменов — только HTTPS;
* отправляются только cookies, отмеченные в проекте как тестовые сессии, и только если они
  подходят к адресу (domain-match и path-match по RFC 6265, Secure — только по HTTPS);
* одна проверка за раз, не чаще одного запроса в ``MIN_INTERVAL_S`` секунд на endpoint;
  пакетного режима нет;
* результат — совпадение ответа с маркерами, заданными пользователем. Код 200 сам по себе
  ничего не подтверждает (правило 11 ТЗ).
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.domain import ValueState
from app.infrastructure.crypto import CryptoBox
from app.infrastructure.db.mapping import to_domain
from app.infrastructure.db.models import CookieRow, DiagnosticEndpoint, DiagnosticRun
from app.infrastructure.http import DiagnosticClient, HttpTransportError
from app.services.common import now_ts, record_operation

log = logging.getLogger(__name__)

WELL_KNOWN: Final = "/.well-known/cookie-inspector-verify.txt"
VERIFY_TTL_DAYS: Final = 30
MIN_INTERVAL_S: Final = 1.0
TOKEN_PREFIX: Final = "cookie-inspector-verify="  # noqa: S105 — префикс строки подтверждения, не секрет


class DiagnosticsError(Exception):
    """Проверку нельзя выполнить; текст объясняет, что исправить."""


class Outcome(StrEnum):
    MATCHED = "matched"  # ответ совпал со всеми ожидаемыми маркерами
    NOT_MATCHED = "not_matched"  # хотя бы один маркер не совпал
    ERROR = "error"  # сетевая ошибка, ответа нет


@dataclass(frozen=True, slots=True)
class Markers:
    """Что считается признаком «сессия действует». Нужен хотя бы один маркер помимо кода ответа."""

    status: tuple[int, ...] = (200,)
    body_contains: tuple[str, ...] = ()
    body_not_contains: tuple[str, ...] = ()
    location_contains: str | None = None

    def validate(self) -> None:
        if not (self.body_contains or self.body_not_contains or self.location_contains):
            raise DiagnosticsError(
                "Укажите хотя бы один маркер содержимого: код ответа сам по себе не подтверждает сессию "
                "(многие сайты отвечают 200 и страницей входа)."
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "status": list(self.status),
            "body_contains": list(self.body_contains),
            "body_not_contains": list(self.body_not_contains),
            "location_contains": self.location_contains,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Markers:
        return cls(
            tuple(d.get("status") or (200,)),
            tuple(d.get("body_contains") or ()),
            tuple(d.get("body_not_contains") or ()),
            d.get("location_contains"),
        )


@dataclass(frozen=True, slots=True)
class EndpointInfo:
    id: int
    url: str
    host: str
    state: str
    verification_token: str | None
    verified_at: int | None
    markers: Markers

    @property
    def usable(self) -> bool:
        return self.state == "local" or (self.state == "verified" and not _expired(self.verified_at))

    @property
    def verification_url(self) -> str:
        p = urlsplit(self.url)
        return f"https://{p.netloc}{WELL_KNOWN}"


@dataclass(frozen=True, slots=True)
class MarkerCheck:
    marker: str
    expected: str
    ok: bool


@dataclass(frozen=True, slots=True)
class DiagnosticResult:
    run_id: int
    outcome: Outcome
    status_code: int | None
    elapsed_ms: int | None
    checks: list[MarkerCheck]
    sent_cookies: list[str]
    skipped_cookies: list[str]
    warnings: list[str]
    location: str | None = None
    set_cookie_names: list[str] = field(default_factory=list)
    error: str | None = None
    phase: str | None = None
    pair_id: str | None = None


@dataclass(frozen=True, slots=True)
class Comparison:
    before: Outcome
    after: Outcome
    verdict: str
    problem: bool


def _expired(verified_at: int | None) -> bool:
    return verified_at is None or now_ts() - verified_at > VERIFY_TTL_DAYS * 86400


def classify_host(host: str) -> str:
    """``local`` — локальный/приватный адрес; ``public`` — всё остальное."""
    h = host.strip("[]").lower()
    if h == "localhost" or h.endswith((".localhost", ".test", ".local")):
        return "local"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "public"
    return "local" if (ip.is_loopback or ip.is_private or ip.is_link_local) else "public"


def domain_match(host: str, cookie_domain: str, host_only: bool) -> bool:
    host, cookie_domain = host.lower().strip("[]"), cookie_domain.lower()
    return host == cookie_domain or (not host_only and host.endswith("." + cookie_domain))


def path_match(request_path: str, cookie_path: str) -> bool:
    rp = request_path or "/"
    return rp == cookie_path or (
        rp.startswith(cookie_path) and (cookie_path.endswith("/") or rp[len(cookie_path)] == "/")
    )


def evaluate(markers: Markers, status: int, body: str, location: str | None) -> list[MarkerCheck]:
    checks = [MarkerCheck("status", ", ".join(map(str, markers.status)), status in markers.status)]
    checks += [MarkerCheck("body_contains", s, s in body) for s in markers.body_contains]
    checks += [MarkerCheck("body_not_contains", s, s not in body) for s in markers.body_not_contains]
    if markers.location_contains:
        checks.append(
            MarkerCheck("location_contains", markers.location_contains, markers.location_contains in (location or ""))
        )
    return checks


def compare(before: Outcome, after: Outcome) -> Comparison:
    """Сравнение «до/после» действия (обычно — выхода из аккаунта)."""
    if before is not Outcome.MATCHED:
        return Comparison(
            before,
            after,
            "До действия сессия не подтвердилась — сравнение не имеет смысла. Проверьте маркеры и тестовую cookie.",
            False,
        )
    if after is Outcome.MATCHED:
        return Comparison(
            before,
            after,
            "После действия сессия по-прежнему принимается сервером. Если действием "
            "был выход из аккаунта, сервер не аннулирует сессию — это уязвимость "
            "(похищенная cookie остаётся рабочей).",
            True,
        )
    if after is Outcome.ERROR:
        return Comparison(before, after, "После действия запрос не выполнен — повторите проверку.", False)
    return Comparison(before, after, "После действия сессия больше не принимается — сервер её аннулировал.", False)


class DiagnosticsService:
    def __init__(
        self, sessions: sessionmaker[Session], box: CryptoBox | None, client: DiagnosticClient | None = None
    ) -> None:
        self._sessions = sessions
        self._box = box
        self._client = client or DiagnosticClient()
        self._last_request: dict[int, float] = {}

    # ------------------------------------------------------------------ endpoints
    def add_endpoint(self, project_id: int, url: str, markers: Markers) -> EndpointInfo:
        markers.validate()
        parts = urlsplit(url.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise DiagnosticsError("Адрес должен начинаться с https:// (или http:// для локального сервера)")
        if parts.username or parts.password:
            raise DiagnosticsError("Адрес не должен содержать логин и пароль")
        kind = classify_host(parts.hostname)
        if kind == "public" and parts.scheme != "https":
            raise DiagnosticsError("Для публичного домена допускается только HTTPS")
        state = "local" if kind == "local" else "unverified"
        token = None if kind == "local" else secrets.token_urlsafe(24)
        try:
            with self._sessions.begin() as s:
                ep = DiagnosticEndpoint(
                    project_id=project_id,
                    url=url.strip(),
                    method="GET",
                    verification_state=state,
                    verification_token=token,
                    verified_at=None,
                    expected_markers=markers.to_json(),
                    created_at=now_ts(),
                )
                s.add(ep)
                s.flush()
                record_operation(
                    s,
                    project_id=project_id,
                    kind="diag.endpoint",
                    outcome="ok",
                    summary=f"Добавлен адрес диагностики {parts.hostname}",
                    details={},
                )
                return _info(ep)
        except IntegrityError as e:
            raise DiagnosticsError("Этот адрес уже добавлен в проект") from e

    def endpoints(self, project_id: int) -> list[EndpointInfo]:
        with self._sessions() as s:
            return [
                _info(e)
                for e in s.scalars(
                    select(DiagnosticEndpoint)
                    .where(DiagnosticEndpoint.project_id == project_id)
                    .order_by(DiagnosticEndpoint.id)
                )
            ]

    def update_markers(self, endpoint_id: int, markers: Markers) -> None:
        markers.validate()
        with self._sessions.begin() as s:
            ep = self._get(s, endpoint_id)
            ep.expected_markers = markers.to_json()

    def remove_endpoint(self, endpoint_id: int) -> None:
        with self._sessions.begin() as s:
            s.delete(self._get(s, endpoint_id))

    def verification_instructions(self, endpoint_id: int) -> str:
        with self._sessions() as s:
            info = _info(self._get(s, endpoint_id))
        if info.state == "local":
            return "Локальный адрес — подтверждение владения не требуется."
        return (
            f"Разместите на сайте файл {info.verification_url}\n"
            f"с содержимым (одна строка):\n{TOKEN_PREFIX}{info.verification_token}\n\n"
            "Затем нажмите «Проверить владение». Файл можно удалить после проверки; "
            f"подтверждение действует {VERIFY_TTL_DAYS} дней."
        )

    def verify(self, endpoint_id: int) -> EndpointInfo:
        """Запросить файл подтверждения (без cookies, без редиректов) и сверить токен."""
        with self._sessions() as s:
            info = _info(self._get(s, endpoint_id))
        if info.state == "local":
            return info
        try:
            res = self._client.get(info.verification_url)
        except HttpTransportError as e:
            raise DiagnosticsError(f"Файл подтверждения недоступен: {e}") from e
        expected = f"{TOKEN_PREFIX}{info.verification_token}"
        if res.status != 200:
            raise DiagnosticsError(
                f"Файл подтверждения не найден: сервер ответил {res.status}"
                + (" (редирект — файл должен отдаваться напрямую)" if 300 <= res.status < 400 else "")
            )
        if expected not in res.body.split():
            raise DiagnosticsError("Файл найден, но токен в нём не совпадает. Скопируйте строку целиком.")
        with self._sessions.begin() as s:
            ep = self._get(s, endpoint_id)
            ep.verification_state, ep.verified_at = "verified", now_ts()
            record_operation(
                s,
                project_id=ep.project_id,
                kind="diag.verify",
                outcome="ok",
                summary=f"Подтверждено владение {info.host}",
                details={},
            )
            return _info(ep)

    # ------------------------------------------------------------------ проверка
    def matching_cookies(self, endpoint_id: int) -> list[tuple[int, str, str]]:
        """Тестовые сессии проекта, которые браузер отправил бы на этот адрес: (id, имя, домен)."""
        with self._sessions() as s:
            ep = self._get(s, endpoint_id)
            p = urlsplit(ep.url)
            rows = s.scalars(
                select(CookieRow).where(CookieRow.project_id == ep.project_id, CookieRow.is_test_session.is_(True))
            )
            return [
                (r.id, r.name, r.domain)
                for r in rows
                if domain_match(p.hostname or "", r.domain, r.host_only) and path_match(p.path, r.path)
            ]

    def run(
        self, endpoint_id: int, cookie_ids: list[int], *, phase: str | None = None, pair_id: str | None = None
    ) -> DiagnosticResult:
        if self._box is None:
            raise DiagnosticsError("Хранилище заблокировано — значения тестовых cookies недоступны")
        if phase not in (None, "before", "after"):
            raise DiagnosticsError("Фаза должна быть before или after")
        if not cookie_ids:
            raise DiagnosticsError("Выберите хотя бы одну тестовую cookie")
        with self._sessions() as s:
            ep = self._get(s, endpoint_id)
            info = _info(ep)
            if not info.usable:
                raise DiagnosticsError(
                    "Владение доменом не подтверждено"
                    if info.state != "verified"
                    else "Подтверждение владения устарело — подтвердите домен снова"
                )
            url = urlsplit(ep.url)
            https = url.scheme == "https"
            rows = list(
                s.scalars(select(CookieRow).where(CookieRow.id.in_(cookie_ids), CookieRow.project_id == ep.project_id))
            )
        if len(rows) != len(set(cookie_ids)):
            raise DiagnosticsError("Часть выбранных cookies не найдена в этом проекте")
        sent: list[tuple[str, str]] = []
        sent_names: list[str] = []
        skipped: list[str] = []
        warnings: list[str] = []
        for r in rows:
            label = f"{r.name} ({r.domain})"
            if not r.is_test_session:
                raise DiagnosticsError(f"Cookie {label} не отмечена как тестовая сессия")
            if not (domain_match(url.hostname or "", r.domain, r.host_only) and path_match(url.path, r.path)):
                raise DiagnosticsError(f"Cookie {label} не относится к адресу {url.hostname}{url.path or '/'}")
            if r.secure and not https:
                skipped.append(f"{label}: Secure-cookie не отправляется по HTTP")
                continue
            c = to_domain(r, self._box)
            if c.value_state is not ValueState.PRESENT or c.value is None:
                skipped.append(f"{label}: значение недоступно")
                continue
            if c.is_expired():
                warnings.append(f"Срок {label} истёк — браузер её уже не отправил бы; отправляем для проверки сервера")
            sent.append((c.name, c.value.reveal()))
            sent_names.append(label)
        if not sent:
            raise DiagnosticsError("Нечего отправить: " + "; ".join(skipped))

        wait = MIN_INTERVAL_S - (time.monotonic() - self._last_request.get(endpoint_id, -1e9))
        if wait > 0:
            time.sleep(wait)
        self._last_request[endpoint_id] = time.monotonic()
        started = now_ts()
        markers = info.markers
        try:
            res = self._client.get(info.url, sent)
        except HttpTransportError as e:
            return self._save(
                info,
                cookie_ids,
                started,
                None,
                Outcome.ERROR,
                [],
                sent_names,
                skipped,
                warnings,
                phase,
                pair_id,
                error=str(e),
            )
        location = res.headers.get("location")
        checks = evaluate(markers, res.status, res.body, location)
        if res.truncated:
            warnings.append("Ответ больше 256 КБ — маркеры проверены по первым 256 КБ")
        outcome = Outcome.MATCHED if all(c.ok for c in checks) else Outcome.NOT_MATCHED
        return self._save(
            info, cookie_ids, started, res, outcome, checks, sent_names, skipped, warnings, phase, pair_id
        )

    def new_pair(self) -> str:
        return str(uuid.uuid4())

    def history(self, endpoint_id: int, limit: int = 50) -> list[DiagnosticResult]:
        with self._sessions() as s:
            runs = s.scalars(
                select(DiagnosticRun)
                .where(DiagnosticRun.endpoint_id == endpoint_id)
                .order_by(DiagnosticRun.id.desc())
                .limit(limit)
            )
            return [_result(r) for r in runs]

    def compare_pair(self, pair_id: str) -> Comparison:
        with self._sessions() as s:
            runs = {r.phase: r for r in s.scalars(select(DiagnosticRun).where(DiagnosticRun.pair_id == pair_id))}
        if "before" not in runs or "after" not in runs:
            raise DiagnosticsError("Для сравнения нужны проверки «до» и «после»")
        return compare(Outcome(runs["before"].outcome), Outcome(runs["after"].outcome))

    # ------------------------------------------------------------------ внутреннее
    def _get(self, s: Session, endpoint_id: int) -> DiagnosticEndpoint:
        ep = s.get(DiagnosticEndpoint, endpoint_id)
        if ep is None:
            raise DiagnosticsError("Адрес диагностики не найден")
        return ep

    def _save(
        self,
        info: EndpointInfo,
        cookie_ids: list[int],
        started: int,
        res: Any,
        outcome: Outcome,
        checks: list[MarkerCheck],
        sent: list[str],
        skipped: list[str],
        warnings: list[str],
        phase: str | None,
        pair_id: str | None,
        error: str | None = None,
    ) -> DiagnosticResult:
        meta = {
            "headers": res.headers if res else {},
            "set_cookie_names": res.set_cookie_names if res else [],
            "cookie_ids": cookie_ids,
            "sent": sent,
            "skipped": skipped,
            "warnings": warnings,
        }
        with self._sessions.begin() as s:
            run = DiagnosticRun(
                endpoint_id=info.id,
                cookie_id=cookie_ids[0],
                pair_id=pair_id,
                phase=phase,
                started_at=started,
                duration_ms=res.elapsed_ms if res else None,
                status_code=res.status if res else None,
                outcome=outcome.value,
                matched_markers={"checks": [[c.marker, c.expected, c.ok] for c in checks]},
                response_meta=meta,
                error=error,
            )
            s.add(run)
            s.flush()
            ep = s.get(DiagnosticEndpoint, info.id)
            record_operation(
                s,
                project_id=ep.project_id if ep else None,
                kind="diag.run",
                outcome=outcome.value,
                summary=f"Диагностика {info.host}: {_OUTCOME_TEXT[outcome]}" + (f" ({phase})" if phase else ""),
                details={"run_id": run.id},
            )
            log.info("Диагностика %s: %s, код %s", info.host, outcome.value, res.status if res else "—")
            return _result(run)


_OUTCOME_TEXT = {
    Outcome.MATCHED: "маркеры совпали",
    Outcome.NOT_MATCHED: "маркеры не совпали",
    Outcome.ERROR: "ошибка запроса",
}


def _info(e: DiagnosticEndpoint) -> EndpointInfo:
    return EndpointInfo(
        e.id,
        e.url,
        urlsplit(e.url).hostname or "",
        e.verification_state,
        e.verification_token,
        e.verified_at,
        Markers.from_json(e.expected_markers),
    )


def _result(r: DiagnosticRun) -> DiagnosticResult:
    m = r.response_meta or {}
    return DiagnosticResult(
        run_id=r.id,
        outcome=Outcome(r.outcome),
        status_code=r.status_code,
        elapsed_ms=r.duration_ms,
        checks=[MarkerCheck(a, b, bool(c)) for a, b, c in (r.matched_markers or {}).get("checks", [])],
        sent_cookies=m.get("sent", []),
        skipped_cookies=m.get("skipped", []),
        warnings=m.get("warnings", []),
        location=(m.get("headers") or {}).get("location"),
        set_cookie_names=m.get("set_cookie_names", []),
        error=r.error,
        phase=r.phase,
        pair_id=r.pair_id,
    )
