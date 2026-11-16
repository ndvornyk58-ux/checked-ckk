"""Журналирование с защитой от утечки секретов.

Три уровня защиты:
1. ``SecretValue`` маскирует себя при любом форматировании.
2. :class:`RedactingFilter` редактирует уже сформированный текст записи: заголовки
   Cookie / Set-Cookie / Authorization и пары вида ``value=...``, ``token: ...``, ``"value": "..."``.
3. Тест-ловушка проверяет, что маркер из импортированного файла не попадает ни в один журнал.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path
from typing import Final

MASK: Final = "[REDACTED]"
_PATTERNS: Final = (
    re.compile(r"(?im)^((?:set-)?cookie\s*:\s*).+$"),
    re.compile(r"(?i)(authorization\s*:\s*)\S+(?:\s+\S+)?"),
    # заголовки в виде байтовых кортежей: (b'Set-Cookie', b'...') — так их пишут HTTP-библиотеки
    re.compile(r"(?i)(\(b?['\"](?:set-)?cookie['\"],\s*b?['\"])[^'\"]*"),
    re.compile(r"(?i)(\(b?['\"]authorization['\"],\s*b?['\"])[^'\"]*"),
    re.compile(r'(?i)("(?:value|token|password|secret|session(?:id)?|cookie)"\s*:\s*)"(?:[^"\\]|\\.)*"'),
    re.compile(r"(?i)\b((?:value|token|password|passwd|secret|sessionid|session_id|cookie)\s*[=:]\s*)[^\s,;&]+"),
)


def redact(text: str) -> str:
    for pat in _PATTERNS:
        text = pat.sub(lambda m: m.group(1) + MASK, text)
    return text


class RedactingFilter(logging.Filter):
    """Редактирует сообщение записи после подстановки аргументов (и текст исключения)."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        red = redact(msg)
        if red != msg:
            record.msg, record.args = red, None
        if record.exc_info and record.exc_info[1] is not None:
            # Стек сохраняется (ошибки не скрываются), но его текст тоже проходит редактирование.
            tb = logging.Formatter().formatException(record.exc_info)
            record.msg, record.args = f"{record.getMessage()}\n{redact(tb)}", None
            record.exc_info, record.exc_text = None, None
        return True


def setup_logging(logs_dir: Path, *, level: int = logging.INFO) -> logging.Handler:
    """Файловый журнал с ротацией. Возвращает обработчик (удобно снять в тестах)."""
    logs_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        logs_dir / "app.log", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(min(root.level or level, level))
    return handler
