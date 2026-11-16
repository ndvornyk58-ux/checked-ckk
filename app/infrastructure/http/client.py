"""Минимальный HTTP-клиент для диагностики собственных endpoints.

Ограничения заложены в сам клиент, а не только в интерфейс:
* редиректы не выполняются — ответ 3xx возвращается как есть (Location — важный маркер);
* читается не больше ``MAX_BODY`` байт ответа; тело наружу не отдаётся, только проверяется;
* значения Set-Cookie не возвращаются — только имена cookies, которые сервер пытался установить;
* заголовок Cookie собирается здесь и нигде не журналируется.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final

import httpx

from app import __version__

# httpcore в режиме DEBUG пишет заголовки запросов и ответов целиком (включая Cookie и Set-Cookie),
# а httpx в INFO — полный URL. Ни то ни другое не должно попадать в журналы приложения.
for _noisy in ("httpcore", "httpx"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

MAX_BODY: Final = 256 * 1024
TIMEOUT_S: Final = 10.0
USER_AGENT: Final = f"CookieInspectorPro/{__version__} (session-diagnostics)"


class HttpTransportError(Exception):
    """Сетевая ошибка: DNS, TLS, таймаут, отказ соединения. Текст без данных запроса."""


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    elapsed_ms: int
    headers: dict[str, str]
    set_cookie_names: list[str]
    body: str = field(repr=False)  # для проверки маркеров; не сохраняется и не журналируется
    truncated: bool = False


class DiagnosticClient:
    def __init__(self, transport: httpx.BaseTransport | None = None, timeout_s: float = TIMEOUT_S) -> None:
        self._transport = transport
        self._timeout = timeout_s

    def get(self, url: str, cookies: Iterable[tuple[str, str]] = ()) -> HttpResult:
        pairs = list(cookies)
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if pairs:
            headers["Cookie"] = "; ".join(f"{n}={v}" for n, v in pairs)
        started = time.perf_counter()
        try:
            with (
                httpx.Client(
                    transport=self._transport, timeout=self._timeout, follow_redirects=False, trust_env=False
                ) as client,
                client.stream("GET", url, headers=headers) as resp,
            ):
                chunks: list[bytes] = []
                size, truncated = 0, False
                for chunk in resp.iter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY:
                        truncated = True
                        break
                raw = b"".join(chunks)[:MAX_BODY]
                enc = resp.encoding or "utf-8"
                kept = {
                    k.lower(): v
                    for k, v in resp.headers.items()
                    if k.lower() in ("content-type", "location", "content-length", "server", "cache-control")
                }
                names = [c.split("=", 1)[0].strip() for c in resp.headers.get_list("set-cookie")]
                return HttpResult(
                    resp.status_code,
                    int((time.perf_counter() - started) * 1000),
                    kept,
                    names,
                    raw.decode(enc, errors="replace"),
                    truncated,
                )
        except httpx.TimeoutException as e:
            raise HttpTransportError(f"Сервер не ответил за {self._timeout:.0f} с") from e
        except httpx.ConnectError as e:
            raise HttpTransportError(f"Не удалось подключиться: {_short(e)}") from e
        except httpx.HTTPError as e:
            raise HttpTransportError(f"Ошибка HTTP: {type(e).__name__}: {_short(e)}") from e


def _short(e: Exception) -> str:
    text = str(e) or type(e).__name__
    return text[:200]
