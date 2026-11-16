"""Session Diagnostics: настоящий локальный HTTP-сервер + подменённый транспорт для публичного домена."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import httpx
import pytest

from app.infrastructure.http import DiagnosticClient
from app.services.diagnostics import (
    DiagnosticsError,
    DiagnosticsService,
    Markers,
    Outcome,
    classify_host,
    domain_match,
    path_match,
)
from tests.conftest import Services

ME = Markers(status=(200,), body_contains=("alice",), body_not_contains=("Войти",))


class _Site(BaseHTTPRequestHandler):
    """Тестовый «сайт»: сессия good-session действует, пока не вызван /logout."""

    valid: ClassVar[set[str]] = {"good-session"}
    forget_logout: ClassVar[bool] = False
    seen_cookie_headers: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        cookie = self.headers.get("Cookie", "")
        type(self).seen_cookie_headers.append(cookie)
        sid = dict(p.split("=", 1) for p in cookie.split("; ") if "=" in p).get("sid")
        if self.path == "/logout":
            if not type(self).forget_logout:
                type(self).valid.discard(sid or "")
            self._send(302, "", {"Location": "/login"})
        elif self.path.startswith("/api/me"):
            if sid in type(self).valid:
                self._send(200, "Привет, alice", {"Set-Cookie": "sid=rotated-secret; HttpOnly"})
            else:
                self._send(302, "", {"Location": "/login"})
        else:
            self._send(200, "<form>Войти</form>")

    def _send(self, code: int, body: str, headers: dict[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_a: object) -> None:
        pass


@pytest.fixture
def site() -> Iterator[str]:
    _Site.valid, _Site.forget_logout, _Site.seen_cookie_headers = {"good-session"}, False, []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _cookie(
    svc: Services,
    tmp_path: Path,
    value: str,
    *,
    domain: str = "127.0.0.1",
    secure: bool = False,
    test: bool = True,
    name: str = "sid",
) -> int:
    p = tmp_path / f"cookie-{len(list(tmp_path.glob('cookie-*')))}.jsonl"  # имя файла без значения cookie
    p.write_text(
        f'{{"name":"{name}","value":"{value}","domain":"{domain}","hostOnly":true,"secure":{str(secure).lower()}}}\n'
    )
    svc.importer.run(svc.project_id, [p])
    cid = max(svc.cookies.ids(svc.project_id))
    if test:
        svc.cookies.set_test_session([cid], True)
    return cid


@pytest.fixture
def diag(svc: Services) -> DiagnosticsService:
    return DiagnosticsService(svc.sessions, svc.box)


def test_session_check_against_real_server(svc: Services, diag: DiagnosticsService, site: str, tmp_path: Path) -> None:
    ep = diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    assert ep.state == "local" and ep.usable
    good = _cookie(svc, tmp_path, "good-session")
    bad = _cookie(svc, tmp_path, "stale-session", name="sid2")
    assert {c[0] for c in diag.matching_cookies(ep.id)} == {good, bad}

    r = diag.run(ep.id, [good])
    assert r.outcome is Outcome.MATCHED and r.status_code == 200 and all(c.ok for c in r.checks)
    assert r.set_cookie_names == ["sid"], "имена новых cookies видны, значения — нет"
    assert _Site.seen_cookie_headers[-1] == "sid=good-session"

    svc.cookies.edit(
        good,
        __import__("app.services.cookies", fromlist=["CookieEdit"]).CookieEdit(
            value=__import__("app.domain", fromlist=["SecretValue"]).SecretValue("wrong")
        ),
    )
    svc.cookies.set_test_session([good], True)
    r2 = diag.run(ep.id, [good])
    assert r2.outcome is Outcome.NOT_MATCHED and r2.status_code == 302 and r2.location == "/login"
    assert [c.marker for c in r2.checks if not c.ok] == ["status", "body_contains"]
    assert [h.run_id for h in diag.history(ep.id)] == [r2.run_id, r.run_id]


def test_status_200_alone_is_not_enough(svc: Services, diag: DiagnosticsService, site: str) -> None:
    with pytest.raises(DiagnosticsError, match="код ответа сам по себе"):
        diag.add_endpoint(svc.project_id, f"{site}/api/me", Markers(status=(200,)))


def test_before_after_logout_detects_missing_invalidation(
    svc: Services, diag: DiagnosticsService, site: str, tmp_path: Path
) -> None:
    ep = diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    cid = _cookie(svc, tmp_path, "good-session")
    # сайт корректно аннулирует сессию
    pair = diag.new_pair()
    assert diag.run(ep.id, [cid], phase="before", pair_id=pair).outcome is Outcome.MATCHED
    httpx.get(f"{site}/logout", cookies={"sid": "good-session"})
    assert diag.run(ep.id, [cid], phase="after", pair_id=pair).outcome is Outcome.NOT_MATCHED
    c = diag.compare_pair(pair)
    assert not c.problem and "аннулировал" in c.verdict
    # сайт «забывает» аннулировать сессию при выходе
    _Site.valid, _Site.forget_logout = {"good-session"}, True
    pair2 = diag.new_pair()
    diag.run(ep.id, [cid], phase="before", pair_id=pair2)
    httpx.get(f"{site}/logout", cookies={"sid": "good-session"})
    diag.run(ep.id, [cid], phase="after", pair_id=pair2)
    bad = diag.compare_pair(pair2)
    assert bad.problem and "уязвимость" in bad.verdict
    with pytest.raises(DiagnosticsError):
        diag.compare_pair(diag.new_pair())


def test_guards(svc: Services, diag: DiagnosticsService, site: str, tmp_path: Path) -> None:
    ep = diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    not_test = _cookie(svc, tmp_path, "good-session", test=False)
    other_host = _cookie(svc, tmp_path, "x", domain="other.example.com", name="o")
    secure = _cookie(svc, tmp_path, "good-session", secure=True, name="s")
    with pytest.raises(DiagnosticsError, match="тестовая"):
        diag.run(ep.id, [not_test])
    with pytest.raises(DiagnosticsError, match="не относится"):
        diag.run(ep.id, [other_host])
    with pytest.raises(DiagnosticsError, match="Secure-cookie не отправляется по HTTP"):
        diag.run(ep.id, [secure])
    with pytest.raises(DiagnosticsError, match="хотя бы одну"):
        diag.run(ep.id, [])
    with pytest.raises(DiagnosticsError, match="заблокировано"):
        DiagnosticsService(svc.sessions, None).run(ep.id, [not_test])
    with pytest.raises(DiagnosticsError, match="уже добавлен"):
        diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    for bad_url, msg in (
        ("ftp://x.test/", "https"),
        ("http://example.com/me", "только HTTPS"),
        ("https://user:pw@example.com/", "логин"),
    ):
        with pytest.raises(DiagnosticsError, match=msg):
            diag.add_endpoint(svc.project_id, bad_url, ME)


def test_network_error_is_recorded(svc: Services, diag: DiagnosticsService, tmp_path: Path) -> None:
    ep = diag.add_endpoint(svc.project_id, "http://127.0.0.1:9/api/me", ME)  # порт discard — закрыт
    cid = _cookie(svc, tmp_path, "good-session")
    r = diag.run(ep.id, [cid])
    assert r.outcome is Outcome.ERROR and r.error and r.status_code is None


def _public_service(svc: Services, handler) -> DiagnosticsService:  # type: ignore[no-untyped-def]
    return DiagnosticsService(svc.sessions, svc.box, DiagnosticClient(httpx.MockTransport(handler)))


def test_public_domain_requires_verification(svc: Services, tmp_path: Path) -> None:
    published: dict[str, str] = {}
    requests: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        requests.append(req)
        if req.url.path == "/.well-known/cookie-inspector-verify.txt":
            return httpx.Response(200, text=published.get("file", "")) if "file" in published else httpx.Response(404)
        if req.headers.get("cookie") == "sid=good-session":
            return httpx.Response(200, text="Привет, alice")
        return httpx.Response(302, headers={"Location": "/login"})

    diag = _public_service(svc, handler)
    ep = diag.add_endpoint(svc.project_id, "https://app.example.com/api/me", ME)
    assert ep.state == "unverified" and not ep.usable and ep.verification_token
    cid = _cookie(svc, tmp_path, "good-session", domain="app.example.com", secure=True)
    with pytest.raises(DiagnosticsError, match="не подтверждено"):
        diag.run(ep.id, [cid])
    assert requests == [], "до подтверждения на домен не уходит ни одного запроса с cookies"

    text = diag.verification_instructions(ep.id)
    line = next(ln for ln in text.splitlines() if ln.startswith("cookie-inspector-verify="))
    with pytest.raises(DiagnosticsError, match="не найден"):
        diag.verify(ep.id)
    published["file"] = "cookie-inspector-verify=wrong-token"
    with pytest.raises(DiagnosticsError, match="не совпадает"):
        diag.verify(ep.id)
    published["file"] = line + "\n"
    assert diag.verify(ep.id).usable
    assert all("cookie" not in r.headers for r in requests), "проверка владения идёт без cookies"

    r = diag.run(ep.id, [cid])
    assert r.outcome is Outcome.MATCHED


def test_verification_expires(svc: Services, monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.diagnostics as d

    diag = _public_service(svc, lambda req: httpx.Response(200, text="x"))
    ep = diag.add_endpoint(svc.project_id, "https://app.example.com/api/me", ME)
    with svc.sessions.begin() as s:
        from app.infrastructure.db.models import DiagnosticEndpoint

        row = s.get(DiagnosticEndpoint, ep.id)
        row.verification_state, row.verified_at = "verified", d.now_ts() - 31 * 86400  # type: ignore[union-attr]
    assert not diag.endpoints(svc.project_id)[0].usable


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("localhost", "local"),
        ("127.0.0.1", "local"),
        ("10.1.2.3", "local"),
        ("192.168.0.5", "local"),
        ("app.test", "local"),
        ("[::1]", "local"),
        ("example.com", "public"),
        ("8.8.8.8", "public"),
    ],
)
def test_classify_host(host: str, kind: str) -> None:
    assert classify_host(host) == kind


def test_rfc6265_matching() -> None:
    assert domain_match("app.example.com", "example.com", host_only=False)
    assert not domain_match("app.example.com", "example.com", host_only=True)
    assert not domain_match("badexample.com", "example.com", host_only=False)
    assert path_match("/api/me", "/api") and path_match("/api/me", "/") and path_match("/api", "/api")
    assert not path_match("/apiv2", "/api") and not path_match("/", "/api")


def test_values_never_reach_logs_or_db(
    svc: Services, diag: DiagnosticsService, site: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    ep = diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    diag.run(ep.id, [_cookie(svc, tmp_path, "good-session")])
    assert "good-session" not in caplog.text and "rotated-secret" not in caplog.text
    db = Path(str(svc.sessions.kw["bind"].url.database))
    for f in (db, Path(str(db) + "-wal")):
        if f.exists():
            raw = f.read_bytes()
            assert b"good-session" not in raw and b"rotated-secret" not in raw


def test_run_across_endpoints_sweeps_only_own_sites(
    svc: Services, diag: DiagnosticsService, site: str, tmp_path: Path
) -> None:
    """Прогон набора cookies по нескольким своим адресам: по локальному — запрос, по
    неподтверждённому публичному — пропуск без обращения к сети."""
    diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    # публичный адрес без подтверждения владения — в сеть за ним не ходим
    diag.add_endpoint(svc.project_id, "https://app.example.com/api/me", ME)
    good = _cookie(svc, tmp_path, "good-session")
    # cookie для другого хоста — не подойдёт ни к одному из адресов 127.0.0.1
    _cookie(svc, tmp_path, "x", domain="other.example.com", name="o")

    rows = diag.run_across_endpoints(svc.project_id)
    by_host = {r.host: r for r in rows}
    assert set(by_host) == {"127.0.0.1", "app.example.com"}

    local = by_host["127.0.0.1"]
    assert local.usable and local.outcome is Outcome.MATCHED
    assert local.matched_cookie_ids == (good,), "отправлена только подходящая тестовая cookie"

    public = by_host["app.example.com"]
    assert not public.usable and public.outcome is None
    assert public.skipped_reason and "не подтверждено" in public.skipped_reason


def test_run_across_endpoints_filters_cookies(
    svc: Services, diag: DiagnosticsService, site: str, tmp_path: Path
) -> None:
    ep = diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    good = _cookie(svc, tmp_path, "good-session")
    stale = _cookie(svc, tmp_path, "stale", name="sid2")
    # ограничиваем набор только устаревшей cookie -> маркеры не совпадут
    rows = diag.run_across_endpoints(svc.project_id, cookie_ids=[stale])
    assert len(rows) == 1 and rows[0].matched_cookie_ids == (stale,)
    assert rows[0].outcome is Outcome.NOT_MATCHED
    # пустой проектный фильтр по подходящим: адрес с cookie, которой нет среди выбранных
    rows2 = diag.run_across_endpoints(svc.project_id, cookie_ids=[good])
    assert rows2[0].outcome is Outcome.MATCHED
    assert ep.id == rows2[0].endpoint_id


def test_run_across_endpoints_reports_no_matching_cookies(svc: Services, diag: DiagnosticsService, site: str) -> None:
    diag.add_endpoint(svc.project_id, f"{site}/api/me", ME)
    rows = diag.run_across_endpoints(svc.project_id)
    assert len(rows) == 1 and rows[0].usable and rows[0].outcome is None
    assert "нет подходящих" in (rows[0].skipped_reason or "")
