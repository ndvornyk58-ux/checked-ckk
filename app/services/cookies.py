"""Запросы и действия над сохранёнными cookies (Cookie Manager, Dashboard).

Списки — keyset-пагинация: стоимость страницы не зависит от её номера.
Значения по умолчанию маскированы; раскрытие — отдельный явный вызов.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, cast

from sqlalchemy import ColumnElement, CursorResult, and_, delete, func, or_, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.domain import Cookie, SameSite, SecretValue, Severity, ValidationStatus, ValueState
from app.infrastructure.crypto import CryptoBox
from app.infrastructure.db.mapping import identity_hash, to_domain, to_ts
from app.infrastructure.db.models import CookieRow, FindingRow
from app.services.common import now_ts, record_operation

MAX_PAGE: Final = 1000
_FAR_FUTURE: Final = 1 << 62


class SortKey(StrEnum):
    IMPORTED = "imported"
    NAME = "name"
    DOMAIN = "domain"
    EXPIRES = "expires"


@dataclass(frozen=True, slots=True)
class CookieFilter:
    text: str | None = None
    domain: str | None = None
    name: str | None = None
    statuses: frozenset[ValidationStatus] = frozenset()
    severities: frozenset[Severity] = frozenset()
    expired: bool | None = None
    session_only: bool | None = None
    secure: bool | None = None
    http_only: bool | None = None
    same_site: SameSite | None = None
    batch_id: int | None = None
    test_sessions_only: bool = False
    not_analyzed: bool = False


@dataclass(frozen=True, slots=True)
class CookieListItem:
    id: int
    name: str
    domain: str
    path: str
    host_only: bool
    secure: bool
    http_only: bool
    same_site: str
    expires_at: int | None
    value_state: str
    value_length: int | None
    validation_status: str | None
    max_severity: str | None
    is_test_session: bool


@dataclass(frozen=True, slots=True)
class Page:
    items: list[CookieListItem]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class FindingView:
    rule_id: str
    engine: str
    status: str | None
    severity: str | None
    title: str
    description: str
    reason: str
    risk: str
    recommendation: str


@dataclass(frozen=True, slots=True)
class CookieDetail:
    item: CookieListItem
    source_format: str
    source_line: int | None
    created_at: int | None
    last_accessed_at: int | None
    partitioned: bool
    findings: list[FindingView]
    value: SecretValue | None = None  # заполняется только при reveal=True


@dataclass(frozen=True, slots=True)
class ProjectStats:
    total: int
    domains: int
    by_status: dict[str, int]
    by_severity: dict[str, int]
    expired: int
    session: int
    secure: int
    insecure: int
    http_only: int
    not_analyzed: int


@dataclass(frozen=True, slots=True)
class CookieEdit:
    """Изменения локальной записи; ``None`` — поле не меняется."""

    name: str | None = None
    domain: str | None = None
    path: str | None = None
    value: SecretValue | None = None
    host_only: bool | None = None
    secure: bool | None = None
    http_only: bool | None = None
    same_site: SameSite | None = None
    expires_at: datetime | None = None
    clear_expiry: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _fts_query(s: str) -> str:
    return '"' + s.replace('"', '""') + '"'


def _sort_column(key: SortKey) -> ColumnElement[Any]:
    cols: dict[SortKey, Any] = {
        SortKey.IMPORTED: CookieRow.imported_at,
        SortKey.NAME: CookieRow.name,
        SortKey.DOMAIN: CookieRow.domain,
        SortKey.EXPIRES: func.coalesce(CookieRow.expires_at, _FAR_FUTURE),
    }
    return cast("ColumnElement[Any]", cols[key])


def _encode_cursor(v: Any, i: int) -> str:
    return base64.urlsafe_b64encode(json.dumps([v, i]).encode()).decode()


def _decode_cursor(c: str) -> tuple[Any, int]:
    v, i = json.loads(base64.urlsafe_b64decode(c.encode()))
    return v, int(i)


def _item(r: CookieRow) -> CookieListItem:
    return CookieListItem(
        id=r.id,
        name=r.name,
        domain=r.domain,
        path=r.path,
        host_only=r.host_only,
        secure=r.secure,
        http_only=r.http_only,
        same_site=SameSite(r.same_site).value,
        expires_at=r.expires_at,
        value_state=ValueState(r.value_state).value,
        value_length=r.value_length,
        validation_status=ValidationStatus(r.validation_status).value if r.validation_status else None,
        max_severity=Severity(r.max_severity).value if r.max_severity else None,
        is_test_session=r.is_test_session,
    )


class CookieService:
    def __init__(self, sessions: sessionmaker[Session], box: CryptoBox | None = None) -> None:
        self._sessions = sessions
        self._box = box

    # ------------------------------------------------------------------ фильтр
    def _conditions(self, project_id: int, f: CookieFilter, now: int) -> list[ColumnElement[bool]]:
        c: list[ColumnElement[bool]] = [CookieRow.project_id == project_id]
        if f.text:
            t = f.text.strip()
            if len(t) >= 3:
                c.append(
                    CookieRow.id.in_(
                        select(text("rowid"))
                        .select_from(text("cookies_fts"))
                        .where(text("cookies_fts MATCH :q"))
                        .params(q=_fts_query(t))
                    )
                )
            elif t:
                pat = f"%{_escape_like(t)}%"
                c.append(or_(CookieRow.name.like(pat, escape="\\"), CookieRow.domain.like(pat, escape="\\")))
        if f.domain:
            d = f.domain.strip().lower().lstrip(".")
            c.append(or_(CookieRow.domain == d, CookieRow.domain.like(f"%.{_escape_like(d)}", escape="\\")))
        if f.name:
            c.append(CookieRow.name == f.name)
        if f.statuses:
            c.append(CookieRow.validation_status.in_(f.statuses))
        if f.severities:
            c.append(CookieRow.max_severity.in_(f.severities))
        if f.expired is True:
            c.append(and_(CookieRow.expires_at.is_not(None), CookieRow.expires_at <= now))
        elif f.expired is False:
            c.append(or_(CookieRow.expires_at.is_(None), CookieRow.expires_at > now))
        if f.session_only is not None:
            c.append(CookieRow.expires_at.is_(None) if f.session_only else CookieRow.expires_at.is_not(None))
        for col, val in ((CookieRow.secure, f.secure), (CookieRow.http_only, f.http_only)):
            if val is not None:
                c.append(col.is_(val))
        if f.same_site is not None:
            c.append(CookieRow.same_site == f.same_site)
        if f.batch_id is not None:
            c.append(CookieRow.batch_id == f.batch_id)
        if f.test_sessions_only:
            c.append(CookieRow.is_test_session.is_(True))
        if f.not_analyzed:
            c.append(CookieRow.validation_status.is_(None))
        return c

    def page(
        self,
        project_id: int,
        f: CookieFilter | None = None,
        *,
        sort: SortKey = SortKey.IMPORTED,
        descending: bool = False,
        cursor: str | None = None,
        limit: int = 200,
    ) -> Page:
        limit = max(1, min(limit, MAX_PAGE))
        cond = self._conditions(project_id, f or CookieFilter(), now_ts())
        col = _sort_column(sort)
        if cursor:
            v, i = _decode_cursor(cursor)
            cond.append(
                or_(col < v, and_(col == v, CookieRow.id < i))
                if descending
                else or_(col > v, and_(col == v, CookieRow.id > i))
            )
        order = (col.desc(), CookieRow.id.desc()) if descending else (col.asc(), CookieRow.id.asc())
        with self._sessions() as s:
            rows = list(s.execute(select(CookieRow, col).where(*cond).order_by(*order).limit(limit + 1)))
        has_more = len(rows) > limit
        rows = rows[:limit]
        nxt = _encode_cursor(rows[-1][1], rows[-1][0].id) if has_more and rows else None
        return Page([_item(r) for r, _ in rows], nxt)

    def count(self, project_id: int, f: CookieFilter | None = None) -> int:
        with self._sessions() as s:
            return int(
                s.scalar(
                    select(func.count())
                    .select_from(CookieRow)
                    .where(*self._conditions(project_id, f or CookieFilter(), now_ts()))
                )
                or 0
            )

    def ids(self, project_id: int, f: CookieFilter | None = None) -> list[int]:
        """Все id по фильтру — для массовых операций («выделить всё»)."""
        with self._sessions() as s:
            return list(
                s.scalars(select(CookieRow.id).where(*self._conditions(project_id, f or CookieFilter(), now_ts())))
            )

    def domain_counts(self, project_id: int, f: CookieFilter | None = None, limit: int = 500) -> list[tuple[str, int]]:
        """Группировка по доменам: (домен, число записей), крупные группы первыми."""
        cond = self._conditions(project_id, f or CookieFilter(), now_ts())
        with self._sessions() as s:
            rows = s.execute(
                select(CookieRow.domain, func.count())
                .where(*cond)
                .group_by(CookieRow.domain)
                .order_by(func.count().desc(), CookieRow.domain)
                .limit(limit)
            ).all()
            return [(d, int(n)) for d, n in rows]

    # ------------------------------------------------------------------ детали
    def detail(self, cookie_id: int, *, reveal: bool = False) -> CookieDetail:
        with self._sessions() as s:
            r = s.get(CookieRow, cookie_id)
            if r is None:
                raise LookupError(f"Запись {cookie_id} не найдена")
            fs = [
                FindingView(
                    f.rule_id,
                    f.engine.value,
                    f.status.value if f.status else None,
                    f.severity.value if f.severity else None,
                    f.title,
                    f.description,
                    f.reason,
                    f.risk,
                    f.recommendation,
                )
                for f in s.scalars(select(FindingRow).where(FindingRow.cookie_id == cookie_id).order_by(FindingRow.id))
            ]
            value = None
            if reveal:
                if self._box is None:
                    raise PermissionError("Хранилище заблокировано: значение недоступно")
                value = to_domain(r, self._box).value
                record_operation(
                    s,
                    project_id=r.project_id,
                    kind="value.reveal",
                    outcome="ok",
                    summary=f"Раскрыто значение cookie #{cookie_id}",
                    details={},
                )
                s.commit()
            return CookieDetail(
                _item(r),
                r.source_format.value,
                r.source_line,
                r.created_at_source,
                r.last_accessed_at,
                r.partitioned,
                fs,
                value,
            )

    def stats(self, project_id: int) -> ProjectStats:
        now = now_ts()
        p = CookieRow.project_id == project_id
        with self._sessions() as s:

            def cnt(*c: ColumnElement[bool]) -> int:
                return int(s.scalar(select(func.count()).select_from(CookieRow).where(p, *c)) or 0)

            by_status = {
                str(k): v
                for k, v in s.execute(
                    select(CookieRow.validation_status, func.count())
                    .where(p, CookieRow.validation_status.is_not(None))
                    .group_by(CookieRow.validation_status)
                )
            }
            by_sev = {
                str(k): v
                for k, v in s.execute(
                    select(CookieRow.max_severity, func.count())
                    .where(p, CookieRow.max_severity.is_not(None))
                    .group_by(CookieRow.max_severity)
                )
            }
            total = cnt()
            secure = cnt(CookieRow.secure.is_(True))
            return ProjectStats(
                total=total,
                domains=int(s.scalar(select(func.count(func.distinct(CookieRow.domain))).where(p)) or 0),
                by_status=by_status,
                by_severity=by_sev,
                expired=cnt(CookieRow.expires_at.is_not(None), CookieRow.expires_at <= now),
                session=cnt(CookieRow.expires_at.is_(None)),
                secure=secure,
                insecure=total - secure,
                http_only=cnt(CookieRow.http_only.is_(True)),
                not_analyzed=cnt(CookieRow.validation_status.is_(None)),
            )

    # ------------------------------------------------------------------ изменения
    def edit(self, cookie_id: int, e: CookieEdit) -> Cookie:
        """Изменить локальную запись. Значение перешифровывается; статус сбрасывается до новой проверки."""
        if self._box is None:
            raise PermissionError("Хранилище заблокировано")
        with self._sessions.begin() as s:
            r = s.get(CookieRow, cookie_id)
            if r is None:
                raise LookupError(f"Запись {cookie_id} не найдена")
            cur = to_domain(r, self._box)
            value = e.value if e.value is not None else cur.value
            new = Cookie(
                name=e.name if e.name is not None else cur.name,
                domain=e.domain if e.domain is not None else cur.domain,
                path=e.path if e.path is not None else cur.path,
                value=value,
                value_state=ValueState.PRESENT if value is not None else cur.value_state,
                host_only=e.host_only if e.host_only is not None else cur.host_only,
                expires_at=None if e.clear_expiry else (e.expires_at or cur.expires_at),
                secure=e.secure if e.secure is not None else cur.secure,
                http_only=e.http_only if e.http_only is not None else cur.http_only,
                same_site=e.same_site or cur.same_site,
                partitioned=cur.partitioned,
                created_at=cur.created_at,
                last_accessed_at=cur.last_accessed_at,
                source=cur.source,
            )
            r.name, r.domain, r.path, r.host_only = new.name, new.domain, new.path, new.host_only
            r.secure, r.http_only, r.same_site = new.secure, new.http_only, new.same_site
            r.expires_at = to_ts(new.expires_at)
            if e.value is not None:
                r.value_state = ValueState.PRESENT
                r.value_ciphertext, r.value_hmac = self._box.encrypt(e.value), self._box.value_mac(e.value)
                r.value_length = len(e.value)
            r.identity_hash = identity_hash(new.identity)
            r.validation_status = r.max_severity = r.analyzed_at = None
            r.updated_at = now_ts()
            s.execute(delete(FindingRow).where(FindingRow.cookie_id == cookie_id))
            record_operation(
                s,
                project_id=r.project_id,
                kind="cookie.edit",
                outcome="ok",
                summary=f"Изменена запись #{cookie_id}",
                details={},
            )
            return new

    def set_test_session(self, cookie_ids: list[int], flag: bool) -> None:
        with self._sessions.begin() as s:
            s.execute(update(CookieRow).where(CookieRow.id.in_(cookie_ids)).values(is_test_session=flag))

    def delete(self, project_id: int, cookie_ids: list[int]) -> int:
        with self._sessions.begin() as s:
            n = 0
            for i in range(0, len(cookie_ids), 900):
                res = s.execute(
                    delete(CookieRow).where(
                        CookieRow.project_id == project_id, CookieRow.id.in_(cookie_ids[i : i + 900])
                    )
                )
                n += cast("CursorResult[Any]", res).rowcount
            record_operation(
                s,
                project_id=project_id,
                kind="cookie.delete",
                outcome="ok",
                summary=f"Удалено записей: {n}",
                details={"count": n},
            )
            return n

    def purge_values(self, project_id: int) -> int:
        """Удалить все значения проекта, сохранив метаданные и результаты аудита."""
        with self._sessions.begin() as s:
            res = s.execute(
                update(CookieRow)
                .where(CookieRow.project_id == project_id, CookieRow.value_ciphertext.is_not(None))
                .values(value_ciphertext=None, value_hmac=None, value_state=ValueState.ABSENT, updated_at=now_ts())
            )
            n = cast("CursorResult[Any]", res).rowcount
            record_operation(
                s,
                project_id=project_id,
                kind="values.purge",
                outcome="ok",
                summary=f"Удалены значения у {n} записей",
                details={"count": n},
            )
            return int(n)


def utc(ts: int | None) -> datetime | None:
    return None if ts is None else datetime.fromtimestamp(ts, tz=UTC)
