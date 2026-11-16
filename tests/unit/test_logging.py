from __future__ import annotations

import logging
from pathlib import Path

from app.infrastructure.logging import RedactingFilter, redact, setup_logging


def test_redact_patterns() -> None:
    cases = {
        "Cookie: sid=abc123; theme=dark": "abc123",
        "set-cookie: sid=abc123; Path=/": "abc123",
        "Authorization: Bearer eyJhbGciOi.tok.sig": "eyJhbGciOi",
        '{"name": "sid", "value": "abc123"}': "abc123",
        "value=abc123 next": "abc123",
        "token: abc123,": "abc123",
    }
    for text, secret in cases.items():
        assert secret not in redact(text), text
    assert redact("обычная строка без секретов") == "обычная строка без секретов"


def test_filter_redacts_args_and_tracebacks(tmp_path: Path) -> None:
    handler = setup_logging(tmp_path, level=logging.DEBUG)
    log = logging.getLogger("redaction-test")
    try:
        log.info("got %s", "value=TOPSECRET1")
        try:
            raise ValueError("token=TOPSECRET2")
        except ValueError:
            log.exception("failed")
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()
    text = (tmp_path / "app.log").read_text(encoding="utf-8")
    assert "TOPSECRET" not in text
    assert "ValueError" in text and "Traceback" in text, "стек ошибки должен сохраняться"
    assert isinstance(handler.filters[0], RedactingFilter)
