"""Проверка корректности и безопасности сохранённых cookies.

Обход — чанками по возрастанию id (keyset), каждый чанк в своей транзакции:
GUI видит прогресс, а память не растёт с размером набора. Хранятся находки только
последней проверки каждой cookie; агрегаты всех запусков сохраняются в ``analysis_runs``.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.domain import Finding, FindingEngine, ValidationStatus
from app.infrastructure.crypto import CryptoBox, DecryptionError
from app.infrastructure.db.mapping import to_domain
from app.infrastructure.db.models import AnalysisRun, CookieRow, FindingRow
from app.rules import RuleContext, RuleEngine, default_engine
from app.rules.base import Identity, Scope
from app.services.common import CancelToken, OperationCancelled, now_ts, record_operation

log = logging.getLogger(__name__)
CHUNK: Final = 1000


@dataclass(frozen=True, slots=True)
class ValidationProgress:
    done: int
    total: int


@dataclass(frozen=True, slots=True)
class ValidationReport:
    run_id: int
    status: str
    checked: int
    by_status: dict[str, int]
    by_severity: dict[str, int]


class ValidationService:
    def __init__(
        self, sessions: sessionmaker[Session], box: CryptoBox | None, engine: RuleEngine | None = None
    ) -> None:
        self._sessions = sessions
        self._box = box
        self._engine = engine or default_engine()

    def build_context(self, s: Session, project_id: int, now: datetime) -> RuleContext:
        dup_hashes = (
            select(CookieRow.identity_hash)
            .where(CookieRow.project_id == project_id)
            .group_by(CookieRow.identity_hash)
            .having(func.count() > 1)
        )
        dups: set[Identity] = {
            (n, d, p, bool(h), bool(pt))
            for n, d, p, h, pt in s.execute(
                select(CookieRow.name, CookieRow.domain, CookieRow.path, CookieRow.host_only, CookieRow.partitioned)
                .where(CookieRow.project_id == project_id, CookieRow.identity_hash.in_(dup_hashes))
                .distinct()
            )
        }
        multi_scope_names = (
            select(CookieRow.name)
            .where(CookieRow.project_id == project_id)
            .group_by(CookieRow.name)
            .having(func.count(func.distinct(CookieRow.domain + "|" + CookieRow.path)) > 1)
        )
        scopes: dict[str, list[Scope]] = defaultdict(list)
        for n, d, h, p in s.execute(
            select(CookieRow.name, CookieRow.domain, CookieRow.host_only, CookieRow.path)
            .where(CookieRow.project_id == project_id, CookieRow.name.in_(multi_scope_names))
            .distinct()
        ):
            scopes[n].append((d, bool(h), p))
        return RuleContext(now=now, duplicate_identities=frozenset(dups), name_scopes=dict(scopes))

    def run(
        self,
        project_id: int,
        *,
        batch_id: int | None = None,
        cookie_ids: list[int] | None = None,
        now: datetime | None = None,
        progress: Callable[[ValidationProgress], None] | None = None,
        cancel: CancelToken | None = None,
    ) -> ValidationReport:
        now = now or datetime.now(UTC)
        cancel = cancel or CancelToken()
        cond: list[Any] = [CookieRow.project_id == project_id]
        if batch_id is not None:
            cond.append(CookieRow.batch_id == batch_id)
        if cookie_ids is not None:
            cond.append(CookieRow.id.in_(cookie_ids))

        with self._sessions.begin() as s:
            total = s.scalar(select(func.count()).select_from(CookieRow).where(*cond)) or 0
            ctx = self.build_context(s, project_id, now)
            run = AnalysisRun(
                project_id=project_id,
                engine=FindingEngine.VALIDATION,
                ruleset_version=self._engine.version,
                started_at=now_ts(),
                stats={},
            )
            s.add(run)
            s.flush()
            run_id = run.id

        by_status: Counter[str] = Counter()
        by_sev: Counter[str] = Counter()
        done, last_id, status = 0, 0, "completed"
        try:
            while True:
                cancel.raise_if_cancelled()
                with self._sessions.begin() as s:
                    rows = list(
                        s.scalars(
                            select(CookieRow).where(*cond, CookieRow.id > last_id).order_by(CookieRow.id).limit(CHUNK)
                        )
                    )
                    if not rows:
                        break
                    self._process_chunk(s, rows, ctx, run_id, by_status, by_sev)
                    last_id = rows[-1].id
                    done += len(rows)
                if progress:
                    progress(ValidationProgress(done, total))
        except OperationCancelled:
            status = "cancelled"
        stats = {
            "status": status,
            "checked": done,
            "total": total,
            "by_status": dict(by_status),
            "by_severity": dict(by_sev),
        }
        with self._sessions.begin() as s:
            s.execute(update(AnalysisRun).where(AnalysisRun.id == run_id).values(finished_at=now_ts(), stats=stats))
            record_operation(
                s,
                project_id=project_id,
                kind="validate",
                outcome=status,
                summary=f"Проверено записей: {done} из {total}",
                details={"run_id": run_id, **stats},
            )
        log.info("Проверка %d: %s, %d/%d", run_id, status, done, total)
        return ValidationReport(run_id, status, done, dict(by_status), dict(by_sev))

    def _process_chunk(
        self,
        s: Session,
        rows: list[CookieRow],
        ctx: RuleContext,
        run_id: int,
        by_status: Counter[str],
        by_sev: Counter[str],
    ) -> None:
        ts = now_ts()
        updates: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        for row in rows:
            try:
                ev = self._engine.evaluate(to_domain(row, self._box), ctx)
                fs, st, sev = ev.findings, ev.status, ev.max_severity
            except DecryptionError:
                fs = (
                    Finding(
                        rule_id="storage.decrypt",
                        engine=FindingEngine.VALIDATION,
                        title="Значение не расшифровывается",
                        description="Шифротекст повреждён или зашифрован другим ключом.",
                        reason="Проверка целостности AES-GCM не прошла.",
                        recommendation="Восстановите базу из резервной копии или импортируйте запись заново.",
                        status=ValidationStatus.UNKNOWN,
                    ),
                )
                st, sev = ValidationStatus.UNKNOWN, None
            updates.append({"id": row.id, "validation_status": st, "max_severity": sev, "analyzed_at": ts})
            by_status[st.value] += 1
            if sev is not None:
                by_sev[sev.value] += 1
            findings.extend(
                {
                    "run_id": run_id,
                    "cookie_id": row.id,
                    "rule_id": f.rule_id,
                    "engine": f.engine,
                    "status": f.status,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "reason": f.reason,
                    "risk": f.risk,
                    "recommendation": f.recommendation,
                }
                for f in fs
            )
        s.execute(delete(FindingRow).where(FindingRow.cookie_id.in_([r.id for r in rows])))
        s.expunge_all()
        s.execute(update(CookieRow), updates)
        if findings:
            s.execute(insert(FindingRow), findings)
