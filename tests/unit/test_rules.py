from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.domain import Cookie, Finding, FindingEngine, SameSite, SecretValue, Severity, ValidationStatus, ValueState
from app.rules import FuncRule, RuleContext, RuleEngine, default_engine
from app.rules.heuristics import estimated_entropy_bits, is_sensitive_name, jwt_header

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
ENGINE = default_engine()
STRONG = "Zx8kP2mQv9LrT4wYb6NcHs1Df3Gj5Ka7"


def ck(**kw: Any) -> Cookie:
    base: dict[str, Any] = {
        "name": "pref",
        "domain": "app.example.com",
        "host_only": True,
        "path": "/",
        "value": SecretValue("v"),
        "secure": True,
        "http_only": True,
        "same_site": SameSite.LAX,
    }
    base.update(kw)
    return Cookie(**base)


def ids(c: Cookie, ctx: RuleContext | None = None) -> dict[str, Finding]:
    return {f.rule_id: f for f in ENGINE.evaluate(c, ctx or RuleContext(now=NOW)).findings}


def status(c: Cookie, ctx: RuleContext | None = None) -> ValidationStatus:
    return ENGINE.evaluate(c, ctx or RuleContext(now=NOW)).status


def test_clean_cookie_is_valid_without_findings() -> None:
    ev = ENGINE.evaluate(ck(name="__Host-sid", value=SecretValue(STRONG)), RuleContext(now=NOW))
    assert ev.status is ValidationStatus.VALID and ev.findings == () and ev.max_severity is None


@pytest.mark.parametrize(
    ("kw", "rule", "st"),
    [
        ({"name": ""}, "name.empty", ValidationStatus.WARNING),
        ({"name": "a b"}, "name.invalid-chars", ValidationStatus.INVALID),
        ({"name": "a;b"}, "name.invalid-chars", ValidationStatus.INVALID),
        ({"value": SecretValue("a\x00b")}, "value.forbidden-chars", ValidationStatus.INVALID),
        ({"value": SecretValue("a;b")}, "value.forbidden-chars", ValidationStatus.INVALID),
        ({"value": SecretValue("a b,c")}, "value.non-rfc-chars", ValidationStatus.WARNING),
        ({"value": SecretValue("x" * 4097)}, "size.too-large", ValidationStatus.INVALID),
        ({"domain": ""}, "domain.empty", ValidationStatus.INVALID),
        ({"domain": "bad..example.com"}, "domain.syntax", ValidationStatus.INVALID),
        ({"domain": "-bad.example.com"}, "domain.syntax", ValidationStatus.INVALID),
        ({"domain": "co.uk", "host_only": False}, "domain.public-suffix", ValidationStatus.INVALID),
        ({"domain": "github.io", "host_only": False}, "domain.public-suffix", ValidationStatus.INVALID),
        ({"domain": "10.0.0.1", "host_only": False}, "domain.ip-domain-attr", ValidationStatus.WARNING),
        ({"domain": "localhost", "host_only": False}, "domain.localhost-domain-attr", ValidationStatus.WARNING),
        ({"path": "api"}, "path.not-absolute", ValidationStatus.INVALID),
        ({"path": "/a;b"}, "path.forbidden-chars", ValidationStatus.INVALID),
        ({"path": "/" + "a" * 1100}, "path.too-long", ValidationStatus.INVALID),
        ({"expires_at": NOW - timedelta(seconds=1)}, "expiry.expired", ValidationStatus.EXPIRED),
        ({"expires_at": NOW + timedelta(days=500)}, "expiry.over-400-days", ValidationStatus.WARNING),
        ({"created_at": NOW + timedelta(days=1)}, "timestamps.future", ValidationStatus.WARNING),
        ({"name": "__Secure-x", "secure": False}, "prefix.secure", ValidationStatus.INVALID),
        ({"name": "__host-x", "host_only": False}, "prefix.host", ValidationStatus.INVALID),
        ({"name": "__Host-x", "path": "/app"}, "prefix.host", ValidationStatus.INVALID),
        ({"same_site": SameSite.NONE, "secure": False}, "samesite.none-insecure", ValidationStatus.INVALID),
        ({"partitioned": True, "secure": False}, "partitioned.insecure", ValidationStatus.INVALID),
        ({"value": None, "value_state": ValueState.BROWSER_ENCRYPTED}, "value.unavailable", ValidationStatus.UNKNOWN),
    ],
)
def test_validation_rules(kw: dict[str, Any], rule: str, st: ValidationStatus) -> None:
    found = ids(ck(**kw))
    assert rule in found, f"нет {rule}; есть {list(found)}"
    f = found[rule]
    assert f.status is st and f.title and f.description and f.reason


def test_idn_and_ip_domains_are_valid() -> None:
    for d in ("пример.рф", "xn--e1afmkfd.xn--p1ai", "127.0.0.1", "[::1]", "_dmarc.example.com"):
        assert not {"domain.syntax"} & set(ids(ck(domain=d))), d


def test_findings_never_quote_the_value() -> None:
    secret = "a b\x01;SECRET-TOKEN-VALUE"
    for f in ENGINE.evaluate(
        ck(name="sessionid", value=SecretValue(secret), secure=False), RuleContext(now=NOW)
    ).findings:
        for text in (f.title, f.description, f.reason, f.risk, f.recommendation):
            assert "SECRET-TOKEN-VALUE" not in text


def test_duplicate_requires_context() -> None:
    c = ck(name="dup")
    assert "duplicate.identity" not in ids(c)
    assert "duplicate.identity" in ids(c, RuleContext(now=NOW, duplicate_identities=frozenset({c.identity})))


def test_expired_boundary_and_session() -> None:
    assert status(ck(expires_at=NOW)) is ValidationStatus.EXPIRED
    assert "expiry.expired" not in ids(ck(expires_at=None))


class TestSecurity:
    def test_sensitive_without_flags(self) -> None:
        f = ids(
            ck(
                name="sessionid",
                value=SecretValue(STRONG),
                secure=False,
                http_only=False,
                same_site=SameSite.UNSPECIFIED,
                host_only=False,
                domain="example.com",
            )
        )
        assert f["sec.missing-secure"].severity is Severity.HIGH
        assert f["sec.missing-httponly"].severity is Severity.HIGH
        assert f["sec.samesite-unspecified"].severity is Severity.LOW
        assert f["sec.broad-domain"].severity is Severity.MEDIUM
        assert (
            status(ck(name="sessionid", value=SecretValue(STRONG), http_only=False)) is ValidationStatus.SECURITY_ISSUE
        )
        for x in f.values():
            if x.engine is FindingEngine.SECURITY:
                assert x.risk and x.recommendation

    def test_non_sensitive_is_quiet_and_local_is_downgraded(self) -> None:
        assert ids(ck(name="theme", secure=False))["sec.missing-secure"].severity is Severity.LOW
        assert "sec.missing-httponly" not in ids(ck(name="theme", http_only=False))
        assert (
            ids(ck(name="sid", domain="localhost", secure=False, value=SecretValue(STRONG)))[
                "sec.missing-secure"
            ].severity
            is Severity.INFO
        )
        assert "sec.missing-httponly" not in ids(ck(name="csrftoken", http_only=False))

    def test_samesite_none(self) -> None:
        assert (
            ids(ck(name="sid", same_site=SameSite.NONE, value=SecretValue(STRONG)))["sec.samesite-none"].severity
            is Severity.MEDIUM
        )
        assert ids(ck(same_site=SameSite.NONE))["sec.samesite-none"].severity is Severity.LOW

    def test_lifetime(self) -> None:
        f = ids(ck(name="sid", value=SecretValue(STRONG), expires_at=NOW + timedelta(days=90)))
        assert f["sec.excessive-lifetime"].severity is Severity.MEDIUM
        assert "sec.excessive-lifetime" not in ids(
            ck(name="sid", value=SecretValue(STRONG), expires_at=NOW + timedelta(days=7))
        )

    def test_jwt(self) -> None:
        def jwt(alg: str) -> str:
            h = base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode()).decode().rstrip("=")
            return f"{h}.eyJzdWIiOiIxIn0.sig"

        f = ids(ck(name="data", value=SecretValue(jwt("none")), http_only=False))
        assert f["sec.jwt-alg-none"].severity is Severity.CRITICAL
        assert f["sec.jwt-readable"].severity is Severity.MEDIUM
        assert f["sec.missing-httponly"].severity is Severity.HIGH, "JWT делает cookie чувствительной"
        assert "sec.jwt-alg-none" not in ids(ck(name="data", value=SecretValue(jwt("HS256"))))
        assert jwt_header("not.a.jwt!") is None

    def test_client_side_privileges(self) -> None:
        raw = json.dumps({"user_id": 1, "role": "admin"})
        for v in (raw, base64.b64encode(raw.encode()).decode()):
            f = ids(ck(name="prefs", value=SecretValue(v)))
            assert f["sec.client-side-privileges"].severity is Severity.MEDIUM
            assert "role" in f["sec.client-side-privileges"].reason

    def test_weak_session_id(self) -> None:
        assert ids(ck(name="PHPSESSID", value=SecretValue("1234")))["sec.weak-session-id"].severity is Severity.MEDIUM
        assert "sec.weak-session-id" in ids(ck(name="sessionid", value=SecretValue("a" * 40)))
        assert "sec.weak-session-id" not in ids(ck(name="sessionid", value=SecretValue(STRONG)))

    def test_shadowing(self) -> None:
        c = ck(name="sid", domain="app.example.com", value=SecretValue(STRONG))
        ctx = RuleContext(now=NOW, name_scopes={"sid": [("app.example.com", True, "/"), ("example.com", False, "/")]})
        assert ids(c, ctx)["sec.cookie-shadowing"].severity is Severity.MEDIUM
        ctx2 = RuleContext(now=NOW, name_scopes={"sid": [("app.example.com", True, "/"), ("other.org", False, "/")]})
        assert "sec.cookie-shadowing" not in ids(c, ctx2)

    def test_host_prefix_recommendation(self) -> None:
        assert ids(ck(name="sid", value=SecretValue(STRONG)))["sec.host-prefix-recommended"].severity is Severity.INFO


def test_heuristics() -> None:
    for n in ("sessionid", "PHPSESSID", "JSESSIONID", "connect.sid", "auth_token", "remember_me", "laravel_session"):
        assert is_sensitive_name(n), n
    for n in ("theme", "csrftoken", "XSRF-TOKEN", "_ga", "consent", "lang"):
        assert not is_sensitive_name(n), n
    assert estimated_entropy_bits("") == 0 and estimated_entropy_bits("a" * 32) < 64


def test_crashing_rule_becomes_unknown_finding(caplog: pytest.LogCaptureFixture) -> None:
    def boom(_c: Cookie, _x: RuleContext) -> Iterable[Finding]:
        raise ZeroDivisionError

    eng = RuleEngine([FuncRule("boom", FindingEngine.VALIDATION, boom)], "t")
    ev = eng.evaluate(ck(), RuleContext(now=NOW))
    assert ev.status is ValidationStatus.UNKNOWN and "ZeroDivisionError" in ev.findings[0].reason
    assert "boom" in caplog.text


def test_duplicate_rule_ids_rejected() -> None:
    r = FuncRule("x", FindingEngine.VALIDATION, lambda c, x: [])
    with pytest.raises(ValueError):
        RuleEngine([r, r], "t")
