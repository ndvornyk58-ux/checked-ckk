"""Проекты (рабочие пространства)."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.infrastructure.db.models import CookieRow, Project
from app.services.common import now_ts, record_operation


class ProjectError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ProjectInfo:
    id: int
    name: str
    description: str
    created_at: int
    cookie_count: int


class ProjectService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def create(self, name: str, description: str = "") -> ProjectInfo:
        name = name.strip()
        if not name:
            raise ProjectError("Имя проекта не может быть пустым")
        ts = now_ts()
        try:
            with self._sessions.begin() as s:
                p = Project(name=name, description=description, created_at=ts, updated_at=ts, archived=False)
                s.add(p)
                s.flush()
                record_operation(
                    s,
                    project_id=p.id,
                    kind="project.create",
                    outcome="ok",
                    summary=f"Создан проект «{name}»",
                    details={},
                )
                return ProjectInfo(p.id, p.name, p.description, p.created_at, 0)
        except IntegrityError as exc:
            raise ProjectError(f"Проект «{name}» уже существует") from exc

    def list(self) -> list[ProjectInfo]:
        with self._sessions() as s:
            counts = dict(s.execute(select(CookieRow.project_id, func.count()).group_by(CookieRow.project_id)).all())
            return [
                ProjectInfo(p.id, p.name, p.description, p.created_at, counts.get(p.id, 0))
                for p in s.scalars(select(Project).where(Project.archived.is_(False)).order_by(Project.name))
            ]

    def get_by_name(self, name: str) -> ProjectInfo | None:
        return next((p for p in self.list() if p.name == name), None)

    def ensure(self, name: str) -> ProjectInfo:
        return self.get_by_name(name) or self.create(name)

    def rename(self, project_id: int, new_name: str) -> None:
        try:
            with self._sessions.begin() as s:
                p = s.get(Project, project_id)
                if p is None:
                    raise ProjectError("Проект не найден")
                p.name, p.updated_at = new_name.strip(), now_ts()
        except IntegrityError as exc:
            raise ProjectError(f"Проект «{new_name}» уже существует") from exc

    def delete(self, project_id: int) -> None:
        """Удалить проект со всеми данными (каскадно)."""
        with self._sessions.begin() as s:
            p = s.get(Project, project_id)
            if p is None:
                raise ProjectError("Проект не найден")
            name = p.name
            s.delete(p)
            record_operation(
                s, project_id=None, kind="project.delete", outcome="ok", summary=f"Удалён проект «{name}»", details={}
            )
