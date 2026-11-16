from __future__ import annotations

import logging
import pickle
from datetime import UTC, datetime, timedelta

import pytest

from app.domain import (
    MASK,
    Cookie,
    Finding,
    FindingEngine,
    SecretValue,
    Severity,
    ValidationStatus,
    ValueState,
)

SECRET = "s3cr3t-session-token-value"


class TestSecretValue:
    def test_never_leaks_through_string_conversions(self) -> None:
        s = SecretValue(SECRET)
        for rendered in (str(s), repr(s), f"{s}", f"{s!r}", "%s" % s, format(s, ">40")):
            assert SECRET not in rendered
        assert MASK in str(s)

    def test_never_leaks_through_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG)
        logging.getLogger("t").info("value=%s obj=%r", SecretValue(SECRET), SecretValue(SECRET))
        assert SECRET not in caplog.text

    def test_never_leaks_through_containing_cookie_repr(self) -> None:
        c = Cookie(name="sid", domain="example.com", value=SecretValue(SECRET))
        assert SECRET not in repr(c)

    def test_reveal_and_length(self) -> None:
        s = SecretValue(SECRET)
        assert s.reveal() == SECRET
        assert len(s) == len(SECRET)
        assert s.masked(3) == SECRET[:3] + MASK

    def test_immutable(self) -> None:
        with pytest.raises(AttributeError):
            SecretValue("a")._value = "b"  # type: ignore[misc]

    def test_equality_and_pickle_for_process_pool(self) -> None:
        a = SecretValue("x")
        assert a == SecretValue("x") and a != SecretValue("y")
        assert pickle.loads(pickle.dumps(a)) == a

    def test_rejects_non_str(self) -> None:
        with pytest.raises(TypeError):
            SecretValue(b"bytes")  # type: ignore[arg-type]


class TestCookie:
    def test_domain_normalized(self) -> None:
        assert Cookie(name="a", domain="  .Example.COM ", value=SecretValue("v")).domain == "example.com"

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValueError, match="часовой пояс"):
            Cookie(name="a", domain="x.test", value=SecretValue("v"), expires_at=datetime(2030, 1, 1))

    def test_value_state_consistency(self) -> None:
        with pytest.raises(ValueError):
            Cookie(name="a", domain="x.test")  # PRESENT без value
        with pytest.raises(ValueError):
            Cookie(name="a", domain="x.test", value=SecretValue("v"), value_state=ValueState.BROWSER_ENCRYPTED)
        c = Cookie(name="a", domain="x.test", value_state=ValueState.BROWSER_ENCRYPTED)
        assert c.value is None

    def test_expiry_semantics(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        session = Cookie(name="a", domain="x.test", value=SecretValue("v"))
        assert session.is_session and not session.is_expired(now)
        past = Cookie(name="a", domain="x.test", value=SecretValue("v"), expires_at=now - timedelta(seconds=1))
        assert past.is_expired(now)
        boundary = Cookie(name="a", domain="x.test", value=SecretValue("v"), expires_at=now)
        assert boundary.is_expired(now), "момент истечения считается истёкшим"
        future = Cookie(name="a", domain="x.test", value=SecretValue("v"), expires_at=now + timedelta(days=1))
        assert not future.is_expired(now)

    def test_identity_ignores_value(self) -> None:
        a = Cookie(name="sid", domain=".x.test", path="/", value=SecretValue("1"))
        b = Cookie(name="sid", domain="X.test", path="/", value=SecretValue("2"))
        assert a.identity == b.identity
        c = Cookie(name="sid", domain="x.test", path="/app", value=SecretValue("1"))
        assert a.identity != c.identity


class TestEnums:
    def test_worst_status(self) -> None:
        S = ValidationStatus
        assert S.worst([]) is S.VALID
        assert S.worst([S.VALID, S.WARNING]) is S.WARNING
        assert S.worst([S.EXPIRED, S.INVALID, S.WARNING]) is S.INVALID
        assert S.worst([S.INVALID, S.SECURITY_ISSUE]) is S.SECURITY_ISSUE
        assert S.worst([S.VALID, S.UNKNOWN]) is S.UNKNOWN

    def test_severity_order(self) -> None:
        ranks = [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        assert ranks == sorted(ranks) and len(set(ranks)) == 5


class TestFinding:
    def test_requires_engine_specific_field(self) -> None:
        with pytest.raises(ValueError):
            Finding(rule_id="r", engine=FindingEngine.VALIDATION, title="t", description="d", reason="r")
        with pytest.raises(ValueError):
            Finding(rule_id="r", engine=FindingEngine.SECURITY, title="t", description="d", reason="r")
        f = Finding(
            rule_id="sec.no-secure",
            engine=FindingEngine.SECURITY,
            title="t",
            description="d",
            reason="r",
            risk="x",
            recommendation="y",
            severity=Severity.HIGH,
        )
        assert f.severity is Severity.HIGH
