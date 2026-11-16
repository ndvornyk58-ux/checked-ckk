"""Преобразование Cookie ↔ строка таблицы ``cookies``. Здесь значение шифруется и расшифровывается."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from app.domain import Cookie, SameSite, SourceFormat, SourceRef, ValueState
from app.infrastructure.crypto import CryptoBox
from app.infrastructure.db.models import CookieRow


def to_ts(dt: datetime | None) -> int | None:
    return None if dt is None else int(dt.timestamp())


def from_ts(ts: int | None) -> datetime | None:
    return None if ts is None else datetime.fromtimestamp(ts, tz=UTC)


def identity_hash(identity: tuple[str, str, str, bool, bool]) -> bytes:
    """Хеш ключа cookie (имя, домен, путь, host-only, partitioned). Не секрет — обычный SHA-256."""
    return hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).digest()


def to_row_dict(
    c: Cookie, box: CryptoBox, *, project_id: int, batch_id: int | None, source_file_id: int | None, now: int
) -> dict[str, Any]:
    present = c.value_state is ValueState.PRESENT and c.value is not None
    return {
        "project_id": project_id,
        "batch_id": batch_id,
        "source_file_id": source_file_id,
        "source_line": c.source.line,
        "source_format": c.source.fmt,
        "name": c.name,
        "domain": c.domain,
        "path": c.path,
        "host_only": c.host_only,
        "partitioned": c.partitioned,
        "value_state": c.value_state,
        "value_ciphertext": box.encrypt(c.value) if present and c.value is not None else None,
        "value_hmac": box.value_mac(c.value) if present and c.value is not None else None,
        "value_length": len(c.value) if present and c.value is not None else None,
        "expires_at": to_ts(c.expires_at),
        "created_at_source": to_ts(c.created_at),
        "last_accessed_at": to_ts(c.last_accessed_at),
        "secure": c.secure,
        "http_only": c.http_only,
        "same_site": c.same_site,
        "identity_hash": identity_hash(c.identity),
        "is_test_session": False,
        "imported_at": now,
        "updated_at": now,
    }


def to_domain(row: CookieRow, box: CryptoBox | None) -> Cookie:
    """Строка → Cookie. Без ``box`` значение не расшифровывается (value_state сохраняется как ABSENT)."""
    state = ValueState(row.value_state)
    value = None
    if state is ValueState.PRESENT:
        if box is None or row.value_ciphertext is None:
            state = ValueState.ABSENT
        else:
            value = box.decrypt(row.value_ciphertext)
    return Cookie(
        name=row.name,
        domain=row.domain,
        path=row.path,
        value=value,
        value_state=state,
        host_only=row.host_only,
        expires_at=from_ts(row.expires_at),
        secure=row.secure,
        http_only=row.http_only,
        same_site=SameSite(row.same_site),
        partitioned=row.partitioned,
        created_at=from_ts(row.created_at_source),
        last_accessed_at=from_ts(row.last_accessed_at),
        source=SourceRef(path=None, line=row.source_line, fmt=SourceFormat(row.source_format)),
    )
