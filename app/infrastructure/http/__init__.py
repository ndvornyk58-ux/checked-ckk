"""HTTP-клиент Session Diagnostics, ограниченный allowlist проекта (см. ADR-0004)."""

from app.infrastructure.http.client import DiagnosticClient, HttpResult, HttpTransportError

__all__ = ["DiagnosticClient", "HttpResult", "HttpTransportError"]
