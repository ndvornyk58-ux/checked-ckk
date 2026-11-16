"""Тест-ловушка: уникальный маркер из импортируемого файла не должен попасть
ни в журналы, ни в файл БД в открытом виде, ни в отчёты об ошибках, ни в журнал операций."""

from __future__ import annotations

import logging
import secrets
from pathlib import Path

from sqlalchemy import select

from app.infrastructure.db.models import ImportErrorRow, Operation
from app.infrastructure.logging import setup_logging
from tests.conftest import Services


def test_values_never_leak(svc: Services, tmp_path: Path) -> None:
    marker = "CANARY" + secrets.token_hex(12)
    logs = tmp_path / "logs"
    handler = setup_logging(logs, level=logging.DEBUG)
    try:
        src = tmp_path / "in"
        src.mkdir()
        (src / "a.txt").write_text(
            f"# Netscape HTTP Cookie File\n.x.test\tTRUE\t/\tFALSE\t0\tsessionid\t{marker}\n"
            f".x.test\tMAYBE\t/\tFALSE\t0\tbroken\t{marker}\n"  # строка с ошибкой тоже содержит маркер
            f".x.test TRUE / FALSE 0 spaces {marker}\n"
        )
        (src / "b.json").write_text(
            f'[{{"name":"t","value":"{marker}","domain":"x.test","secure":"perhaps"}},'
            f'{{"name":"ok","value":"{marker}","domain":"x.test"}}]'
        )
        svc.importer.run(svc.project_id, [src])
        svc.validator.run(svc.project_id)
        cid = svc.cookies.ids(svc.project_id)[0]
        assert svc.cookies.detail(cid, reveal=True).value is not None  # раскрытие тоже журналируется
        logging.getLogger("app").debug("cookie object: %r", svc.cookies.detail(cid))
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()

    for f in logs.iterdir():
        assert marker not in f.read_text(encoding="utf-8"), f"утечка в журнал {f.name}"
    db = Path(str(svc.sessions.kw["bind"].url.database))
    for f in (db, Path(str(db) + "-wal")):
        if f.exists():
            assert marker.encode() not in f.read_bytes(), f"значение в открытом виде в {f.name}"
    with svc.sessions() as s:
        for msg in s.scalars(select(ImportErrorRow.message)):
            assert marker not in msg
        for summary, details in s.execute(select(Operation.summary, Operation.details)):
            assert marker not in summary and marker not in str(details)
