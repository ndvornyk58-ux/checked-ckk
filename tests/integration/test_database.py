from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import IntegrityError

from app.infrastructure.db import migrations
from app.infrastructure.db.alembic_filters import include_name
from app.infrastructure.db.models import Base


def test_upgrade_creates_every_orm_table(migrated_engine: Engine) -> None:
    tables = set(inspect(migrated_engine).get_table_names())
    assert set(Base.metadata.tables) <= tables
    assert "cookies_fts" in tables
    assert migrations.is_up_to_date(migrated_engine)


def test_migration_matches_orm_exactly(migrated_engine: Engine) -> None:
    """Защита от дрейфа: ORM изменили — а миграцию забыли."""
    with migrated_engine.connect() as conn:
        mc = MigrationContext.configure(conn, opts={"include_name": include_name, "compare_type": True})
        diff = compare_metadata(mc, Base.metadata)
    assert diff == [], f"Схема БД расходится с ORM: {diff}"


def test_downgrade_to_base_and_back(migrated_engine: Engine) -> None:
    migrations.downgrade(migrated_engine, "base")
    leftover = set(inspect(migrated_engine).get_table_names()) - {"alembic_version"}
    assert leftover == set()
    migrations.upgrade(migrated_engine)
    migrations.upgrade(migrated_engine)  # повторный upgrade — без ошибок
    assert migrations.is_up_to_date(migrated_engine)


def test_sqlite_pragmas(migrated_engine: Engine) -> None:
    with migrated_engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
        assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"


def _project(conn, name: str = "p") -> int:  # type: ignore[no-untyped-def]
    conn.execute(
        text("INSERT INTO projects(name, description, created_at, updated_at, archived) VALUES (:n, '', 0, 0, 0)"),
        {"n": name},
    )
    return int(conn.execute(text("SELECT id FROM projects WHERE name=:n"), {"n": name}).scalar_one())


def _cookie(conn, pid: int, name: str, domain: str) -> int:  # type: ignore[no-untyped-def]
    conn.execute(
        text(
            "INSERT INTO cookies(project_id, source_format, name, domain, path, host_only, partitioned, value_state,"
            " secure, http_only, same_site, identity_hash, is_test_session, imported_at, updated_at)"
            " VALUES (:p, 'json', :n, :d, '/', 0, 0, 'absent', 0, 0, 'unspecified', x'00', 0, 0, 0)"
        ),
        {"p": pid, "n": name, "d": domain},
    )
    return int(conn.execute(text("SELECT max(id) FROM cookies")).scalar_one())


def _fts(conn, q: str) -> set[int]:  # type: ignore[no-untyped-def]
    rows = conn.execute(text("SELECT rowid FROM cookies_fts WHERE cookies_fts MATCH :q"), {"q": f'"{q}"'})
    return {r[0] for r in rows}


def test_fts_substring_search_stays_in_sync(migrated_engine: Engine) -> None:
    with migrated_engine.begin() as conn:
        pid = _project(conn)
        a = _cookie(conn, pid, "sessionid", "app.example.test")
        b = _cookie(conn, pid, "csrftoken", "admin.example.test")
        assert _fts(conn, "mple.te") == {a, b}  # подстрока домена
        assert _fts(conn, "sionid") == {a}  # подстрока имени
        conn.execute(text("UPDATE cookies SET domain='other.local' WHERE id=:i"), {"i": b})
        assert _fts(conn, "mple.te") == {a}
        conn.execute(text("DELETE FROM cookies WHERE id=:i"), {"i": a})
        assert _fts(conn, "sionid") == set()


def test_project_delete_cascades(migrated_engine: Engine) -> None:
    with migrated_engine.begin() as conn:
        pid = _project(conn)
        _cookie(conn, pid, "a", "x.test")
        conn.execute(text("DELETE FROM projects WHERE id=:i"), {"i": pid})
        assert conn.execute(text("SELECT count(*) FROM cookies")).scalar() == 0


def test_check_constraints_enforced(migrated_engine: Engine) -> None:
    with pytest.raises(IntegrityError), migrated_engine.begin() as conn:
        pid = _project(conn)
        conn.execute(
            text(
                "INSERT INTO import_batches(project_id, started_at, status, options, stats)"
                " VALUES (:p, 0, 'bogus', '{}', '{}')"
            ),
            {"p": pid},
        )
