from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.services.projects import ProjectError, ProjectService


def test_project_lifecycle(sessions: sessionmaker[Session]) -> None:
    ps = ProjectService(sessions)
    a = ps.create("  Alpha ", "desc")
    assert a.name == "Alpha" and ps.ensure("Alpha").id == a.id
    b = ps.ensure("Beta")
    assert [p.name for p in ps.list()] == ["Alpha", "Beta"]
    with pytest.raises(ProjectError, match="уже существует"):
        ps.create("Alpha")
    with pytest.raises(ProjectError, match="пустым"):
        ps.create("   ")
    ps.rename(b.id, "Gamma")
    assert ps.get_by_name("Gamma") is not None and ps.get_by_name("Beta") is None
    with pytest.raises(ProjectError, match="уже существует"):
        ps.rename(b.id, "Alpha")
    with pytest.raises(ProjectError, match="не найден"):
        ps.rename(999, "X")
    ps.delete(a.id)
    with pytest.raises(ProjectError, match="не найден"):
        ps.delete(a.id)
    assert [p.name for p in ps.list()] == ["Gamma"]
