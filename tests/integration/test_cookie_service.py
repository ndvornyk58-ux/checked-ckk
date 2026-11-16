from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.domain import SameSite, SecretValue, ValidationStatus
from app.services.cookies import CookieEdit, CookieFilter, SortKey
from tests.conftest import TEST_DATA, Services

NOW = datetime(2026, 11, 16, tzinfo=UTC)


@pytest.fixture
def loaded(svc: Services, tmp_path: Path) -> Services:
    lines = []
    for i in range(250):
        exp = "" if i % 5 == 0 else str(1_600_000_000 if i % 7 == 0 else 2_000_000_000 + i)
        lines.append(
            f"{'.' if i % 2 else ''}d{i % 13}.example.test\t{'TRUE' if i % 2 else 'FALSE'}\t/\t"
            f"{'TRUE' if i % 3 else 'FALSE'}\t{exp or 0}\tname_{i:03d}\tv{i}"
        )
    p = tmp_path / "set.txt"
    p.write_text("\n".join(lines) + "\n")
    svc.importer.run(svc.project_id, [p])
    svc.validator.run(svc.project_id, now=NOW)
    return svc


@pytest.mark.parametrize("sort", list(SortKey))
@pytest.mark.parametrize("desc", [False, True])
def test_keyset_paging_visits_every_row_once(loaded: Services, sort: SortKey, desc: bool) -> None:
    seen: list[int] = []
    cursor = None
    while True:
        page = loaded.cookies.page(loaded.project_id, sort=sort, descending=desc, cursor=cursor, limit=37)
        seen += [i.id for i in page.items]
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    assert len(seen) == len(set(seen)) == 250


def test_sort_order(loaded: Services) -> None:
    names = [i.name for i in loaded.cookies.page(loaded.project_id, sort=SortKey.NAME, limit=5).items]
    assert names == sorted(names) and names[0] == "name_000"
    desc = [i.name for i in loaded.cookies.page(loaded.project_id, sort=SortKey.NAME, descending=True, limit=1).items]
    assert desc == ["name_249"]


def test_filters(loaded: Services) -> None:
    c, pid = loaded.cookies, loaded.project_id
    assert c.count(pid) == 250
    assert c.count(pid, CookieFilter(text="name_12")) == 10  # FTS (>=3 символов): name_120..129
    assert c.count(pid, CookieFilter(text="_1")) == 100  # LIKE (<3 символов), «_» экранирован
    assert c.count(pid, CookieFilter(domain="d3.example.test")) == c.count(pid, CookieFilter(text="d3.ex"))
    assert c.count(pid, CookieFilter(domain="example.test")) == 250  # поддомены включены
    assert c.count(pid, CookieFilter(session_only=True)) == 50
    exp = c.count(pid, CookieFilter(expired=True))
    assert exp > 0 and exp + c.count(pid, CookieFilter(expired=False)) == 250
    sec = c.count(pid, CookieFilter(secure=True))
    assert sec + c.count(pid, CookieFilter(secure=False)) == 250
    assert c.count(pid, CookieFilter(statuses=frozenset({ValidationStatus.EXPIRED}))) == exp
    assert c.count(pid, CookieFilter(text='na"me')) == 0  # кавычки в запросе FTS безопасны


def test_stats(loaded: Services) -> None:
    st = loaded.cookies.stats(loaded.project_id)
    assert st.total == 250 and st.domains == 13 and st.session == 50 and st.not_analyzed == 0
    assert st.secure + st.insecure == 250 and sum(st.by_status.values()) == 250


def test_detail_masks_by_default_and_audits_reveal(loaded: Services) -> None:
    cid = loaded.cookies.ids(loaded.project_id)[0]
    d = loaded.cookies.detail(cid)
    assert d.value is None and d.item.value_length == 2 and d.findings
    r = loaded.cookies.detail(cid, reveal=True)
    assert r.value is not None and r.value.reveal() == "v0"
    from sqlalchemy import select

    from app.infrastructure.db.models import Operation

    with loaded.sessions() as s:
        assert "value.reveal" in set(s.scalars(select(Operation.kind)))


def test_edit_reencrypts_and_resets_status(loaded: Services) -> None:
    cid = loaded.cookies.ids(loaded.project_id)[0]
    loaded.cookies.edit(cid, CookieEdit(value=SecretValue("new-value"), same_site=SameSite.STRICT, secure=True))
    d = loaded.cookies.detail(cid, reveal=True)
    assert d.value is not None and d.value.reveal() == "new-value"
    assert d.item.same_site == "strict" and d.item.validation_status is None and d.findings == []
    loaded.validator.run(loaded.project_id, cookie_ids=[cid], now=NOW)
    assert loaded.cookies.detail(cid).item.validation_status is not None


def test_delete_purge_and_test_flag(loaded: Services) -> None:
    c, pid = loaded.cookies, loaded.project_id
    ids = c.ids(pid, CookieFilter(session_only=True))
    c.set_test_session(ids[:3], True)
    assert c.count(pid, CookieFilter(test_sessions_only=True)) == 3
    assert c.delete(pid, ids) == 50 and c.count(pid) == 200
    assert c.purge_values(pid) == 200
    d = c.detail(c.ids(pid)[0], reveal=True)
    assert d.value is None and d.item.value_state == "absent"


def test_locked_storage_refuses_reveal(svc: Services) -> None:
    from app.services.cookies import CookieService

    svc.importer.run(svc.project_id, [TEST_DATA / "valid" / "netscape.txt"])
    locked = CookieService(svc.sessions, None)
    cid = locked.ids(svc.project_id)[0]
    assert locked.detail(cid).item.name
    with pytest.raises(PermissionError):
        locked.detail(cid, reveal=True)
    with pytest.raises(LookupError):
        locked.detail(99999)
