"""Тесты производительности. Запуск: pytest -m perf -s

Размер набора задаётся CIP_PERF_N (по умолчанию 100 000). Пороги — для машины
с 1 CPU; на рабочей машине результат должен быть заметно лучше.
"""

from __future__ import annotations

import os
import resource
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import Services

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from gen_test_data import large

N = int(os.environ.get("CIP_PERF_N", "100000"))
pytestmark = pytest.mark.perf


def _peak_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def test_import_validate_query(svc: Services, tmp_path: Path) -> None:
    from app.services.cookies import CookieFilter, SortKey

    src = large(N, tmp_path)
    t0 = time.perf_counter()
    rep = svc.importer.run(svc.project_id, [src])
    t_import = time.perf_counter() - t0
    assert rep.records_ok == N

    t0 = time.perf_counter()
    vr = svc.validator.run(svc.project_id)
    t_validate = time.perf_counter() - t0
    assert vr.checked == N

    t0 = time.perf_counter()
    page = svc.cookies.page(svc.project_id, sort=SortKey.NAME, limit=200)
    for _ in range(20):
        page = svc.cookies.page(svc.project_id, sort=SortKey.NAME, limit=200, cursor=page.next_cursor)
    t_page = (time.perf_counter() - t0) / 21
    t0 = time.perf_counter()
    hits = svc.cookies.count(svc.project_id, CookieFilter(text="s4242.exam"))
    t_search = time.perf_counter() - t0
    peak = _peak_mb()

    print(
        f"\nN={N}: импорт {t_import:.1f} с ({N / t_import:,.0f} зап/с), проверка {t_validate:.1f} с "
        f"({N / t_validate:,.0f} зап/с), страница {t_page * 1000:.1f} мс, поиск {t_search * 1000:.1f} мс "
        f"({hits} совп.), пик памяти {peak:.0f} МБ"
    )
    scale = N / 100_000
    assert t_import < 30 * scale, "импорт медленнее цели PHASE 2"
    assert t_page < 0.2 and t_search < 0.2
    assert peak < 500
