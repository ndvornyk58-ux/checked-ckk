"""Журнал операций: последние события и активность по дням (Dashboard, Activity Timeline)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.db.models import Operation


@dataclass(frozen=True, slots=True)
class ActivityItem:
    ts: int
    kind: str
    outcome: str
    summary: str


class ActivityService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def recent(self, project_id: int | None, limit: int = 20) -> list[ActivityItem]:
        """События проекта и общие события (без проекта), новые сверху."""
        cond = or_(Operation.project_id == project_id, Operation.project_id.is_(None))
        with self._sessions() as s:
            rows = s.scalars(
                select(Operation).where(cond).order_by(Operation.ts.desc(), Operation.id.desc()).limit(limit)
            )
            return [ActivityItem(r.ts, r.kind, r.outcome, r.summary) for r in rows]

    def daily_counts(self, project_id: int | None, days: int = 14, today: date | None = None) -> list[tuple[date, int]]:
        """Число операций по дням (UTC) за последние ``days`` дней, включая пустые дни."""
        today = today or datetime.now(UTC).date()
        start = today - timedelta(days=days - 1)
        since = int(datetime(start.year, start.month, start.day, tzinfo=UTC).timestamp())
        counts = {start + timedelta(days=i): 0 for i in range(days)}
        with self._sessions() as s:
            for ts in s.scalars(select(Operation.ts).where(Operation.project_id == project_id, Operation.ts >= since)):
                d = datetime.fromtimestamp(ts, tz=UTC).date()
                if d in counts:
                    counts[d] += 1
        return sorted(counts.items())
