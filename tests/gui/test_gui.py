"""GUI-тесты (pytest-qt, offscreen)."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest
from PySide6.QtCore import QMetaMethod, QTimer
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import QAbstractButton, QApplication, QMessageBox

from app.app_context import Workspace
from app.gui.dialogs.cookie_edit import CookieEditDialog
from app.gui.dialogs.vault import ChangePasswordDialog, VaultDialog
from app.gui.shell.main_window import MainWindow
from tests.conftest import TEST_DATA
from tests.gui.conftest import PASSWORD, settle

pytestmark = pytest.mark.gui
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))


def _connected(obj: QAbstractButton | QAction) -> bool:
    signals = [obj.triggered] if isinstance(obj, QAction) else [obj.clicked, obj.toggled]
    return any(obj.isSignalConnected(QMetaMethod.fromSignal(s)) for s in signals)


def _unconnected(root) -> list[str]:  # type: ignore[no-untyped-def]
    widgets = [*root.findChildren(QAbstractButton), *root.findChildren(QAction)]
    skip = ("qt_", "")  # служебные кнопки Qt (например, кнопка очистки в QLineEdit)
    return [
        f"{type(w).__name__}:{w.text()!r}"
        for w in widgets
        if not _connected(w)
        and w.objectName().startswith(skip[0]) is False
        and w.text()
        and not isinstance(w.parent(), QMessageBox)
        and type(w).__name__ not in ("QCheckBox", "QRadioButton")
    ]


def test_no_button_without_action(window: MainWindow, unlocked: Workspace) -> None:
    unlocked.importer().run(window.project_id, [TEST_DATA / "valid" / "netscape.txt"])
    window.show_page(1)
    detail = unlocked.cookies.detail(unlocked.cookies.ids(window.project_id)[0])
    roots = [window, VaultDialog(unlocked), ChangePasswordDialog(unlocked), CookieEditDialog(detail)]
    missing = [m for r in roots for m in _unconnected(r)]
    assert missing == [], f"Кнопки без обработчика: {missing}"


def test_navigation_and_shortcuts(qtbot, window: MainWindow) -> None:  # type: ignore[no-untyped-def]
    for i, b in enumerate(window.nav_buttons):
        b.click()
        assert window.stack.currentIndex() == i and b.isChecked()
    window.show_page(0)
    window._focus_search()
    assert window.stack.currentIndex() == 1 and window.cookies.search.hasFocus()


def test_vault_setup_and_unlock(qtbot, ws: Workspace) -> None:  # type: ignore[no-untyped-def]
    dlg = VaultDialog(ws)
    qtbot.addWidget(dlg)
    assert dlg.setup_mode
    dlg.use_password.setChecked(True)
    dlg.password.setText("short")
    dlg.confirm.setText("short")
    dlg.ok_btn.click()
    assert "не менее" in dlg.error.text() and not ws.unlocked
    dlg.password.setText(PASSWORD)
    dlg.confirm.setText(PASSWORD + "x")
    dlg.ok_btn.click()
    assert "не совпадают" in dlg.error.text()
    dlg.confirm.setText(PASSWORD)
    with qtbot.waitSignal(dlg.accepted, timeout=10_000):
        dlg.ok_btn.click()
    assert ws.unlocked
    ws.lock()

    dlg2 = VaultDialog(ws)
    qtbot.addWidget(dlg2)
    assert not dlg2.setup_mode and not dlg2.use_password.isVisible()
    dlg2.password.setText("wrong-password")
    dlg2.ok_btn.click()
    qtbot.waitUntil(lambda: "Неверный" in dlg2.error.text(), timeout=10_000)
    assert dlg2.ok_btn.isEnabled() and not ws.unlocked
    dlg2.password.setText(PASSWORD)
    with qtbot.waitSignal(dlg2.accepted, timeout=10_000):
        dlg2.ok_btn.click()
    assert ws.unlocked


def test_import_flow_updates_everything(qtbot, window: MainWindow) -> None:  # type: ignore[no-untyped-def]
    page = window.importer
    window.show_page(2)
    page.add_paths([TEST_DATA / "valid", TEST_DATA / "broken" / "mixed.txt", TEST_DATA / "valid"])
    assert page.queue.count() == 2, "повторно добавленный путь не дублируется"
    page.queue.setCurrentRow(1)
    qtbot.waitUntil(lambda: "netscape" in page.preview_info.text(), timeout=10_000)
    assert page.preview.rowCount() == 2 and "Проблемных строк" in page.preview_info.text()

    page.start_btn.click()
    settle(qtbot, window)
    assert page.report.isVisible() and page.report.rowCount() == 8
    assert "импортировано 15" in page.progress_label.text()
    assert page.queue.count() == 0
    assert "(15)" in window.project_box.currentText()
    window.show_page(0)
    settle(qtbot, window)
    assert window.dashboard.m_total.value.text() == "15" and window.dashboard.spectrum.total() == 15
    assert window.dashboard.empty.isHidden()


def test_import_cancel_rolls_back(qtbot, window: MainWindow, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from gen_test_data import large

    page = window.importer
    page.add_paths([large(20_000, tmp_path)])
    page.start_btn.click()
    page.cancel()
    settle(qtbot, window)
    assert "отменён" in page.progress_label.text()
    assert window.ws.cookies.count(window.project_id) == 0


def test_cookie_manager(
    qtbot,
    window: MainWindow,
    unlocked: Workspace,
    tmp_path: Path,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gen_test_data import large

    unlocked.importer().run(window.project_id, [large(1000, tmp_path)])
    unlocked.validator().run(window.project_id)
    page = window.cookies
    window.show_page(1)
    m = page.model
    assert m.total == 1000 and m.rowCount() == 200, "подгружена только первая страница"
    while m.canFetchMore():
        m.fetchMore()
    assert m.rowCount() == 1000 and len({r.id for r in m.rows}) == 1000
    assert page.domains.item(0).text().endswith("(1000)")

    page.search.setText("sessionid")
    qtbot.waitUntil(lambda: m.total < 1000, timeout=3000)
    assert all("sessionid" in r.name for r in m.rows)
    page.reset_btn.click()
    assert m.total == 1000

    page.status.setCurrentIndex(page.status.findData("expired"))
    assert m.total and all(r.validation_status == "expired" for r in m.rows)
    page.reset_filters()

    page.domains.setCurrentRow(1)
    dom = page.domains.item(1).data(256)
    assert m.total >= 1 and all(r.domain == dom or r.domain.endswith("." + dom) for r in m.rows)
    page.reset_filters()

    from PySide6.QtCore import Qt

    assert page.model.sort_by(2, Qt.SortOrder.AscendingOrder)
    assert not page.model.sort_by(0, Qt.SortOrder.AscendingOrder), "по статусу сортировка не поддерживается"
    names = [r.name for r in m.rows[:50]]
    assert names == sorted(names)

    page.select_row(0)
    it = m.item(0)
    assert page.panel.title.text().startswith(it.name)
    page.panel.reveal_btn.click()
    assert len(page.panel.value.text()) == 32 and page.panel.reveal_btn.text() == "Скрыть"
    page.panel.copy_btn.click()
    assert QGuiApplication.clipboard().text() == page.panel.value.text()

    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    page.delete_btn.click()
    assert m.total == 999 and unlocked.cookies.count(window.project_id) == 999
    assert "(999)" in window.project_box.currentText()


def test_bulk_by_filter(
    qtbot,
    window: MainWindow,
    unlocked: Workspace,
    tmp_path: Path,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gen_test_data import large

    unlocked.importer().run(window.project_id, [large(600, tmp_path)])
    page = window.cookies
    window.show_page(1)
    page.expiry.setCurrentIndex(page.expiry.findData("session"))
    n = page.model.total
    assert n and page.model.rowCount() <= n
    page.all_btn.setChecked(True)
    assert len(page.selected_ids()) == n and page.delete_btn.isEnabled()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    page.delete_btn.click()
    assert unlocked.cookies.count(window.project_id) == 600 - n and not page.all_btn.isChecked()


def test_edit_dialog_roundtrip(qtbot, window: MainWindow, unlocked: Workspace) -> None:  # type: ignore[no-untyped-def]
    unlocked.importer().run(window.project_id, [TEST_DATA / "valid" / "netscape.txt"])
    cid = unlocked.cookies.ids(window.project_id)[0]
    dlg = CookieEditDialog(unlocked.cookies.detail(cid))
    qtbot.addWidget(dlg)
    dlg.value.setText("new-value")
    dlg.secure.setChecked(True)
    dlg.session.setChecked(True)
    e = dlg.edit()
    assert e.value is not None and e.value.reveal() == "new-value" and e.secure and e.clear_expiry
    unlocked.cookies.edit(cid, e)
    assert unlocked.cookies.detail(cid, reveal=True).value.reveal() == "new-value"  # type: ignore[union-attr]


def test_dashboard_legend_opens_filtered_list(qtbot, window: MainWindow, unlocked: Workspace) -> None:  # type: ignore[no-untyped-def]
    unlocked.importer().run(window.project_id, [TEST_DATA / "edge"])
    unlocked.validator().run(window.project_id)
    window.show_page(0)
    settle(qtbot, window)
    assert window.dashboard.legend["invalid"].isEnabled()
    window.dashboard.legend["invalid"].click()
    assert window.stack.currentIndex() == 1
    assert window.cookies.model.total > 0 and all(r.validation_status == "invalid" for r in window.cookies.model.rows)


def test_lock_disables_value_actions(qtbot, window: MainWindow, unlocked: Workspace) -> None:  # type: ignore[no-untyped-def]
    unlocked.importer().run(window.project_id, [TEST_DATA / "valid" / "netscape.txt"])
    window.importer.add_paths([TEST_DATA / "valid" / "selenium.jsonl"])
    window.settings.lock_btn.click()
    assert not unlocked.unlocked and not window.importer.start_btn.isEnabled()
    window.show_page(1)
    window.cookies.select_row(0)
    assert not window.cookies.panel.reveal_btn.isEnabled() and not window.cookies.edit_btn.isEnabled()
    assert window.cookies.model.total == 3, "метаданные доступны и без ключа"
    assert window.vault_btn.text() == "Разблокировать хранилище"


def test_theme_and_project_management(qtbot, window: MainWindow, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    app = QApplication.instance()
    dark = app.styleSheet()  # type: ignore[union-attr]
    window.settings.theme.setCurrentIndex(window.settings.theme.findData("light"))
    assert app.styleSheet() != dark and window.ws.settings.get("theme") == "light"  # type: ignore[union-attr]

    from PySide6.QtWidgets import QInputDialog

    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("Второй", True))
    window.new_project_btn.click()
    assert window.project_box.currentText().startswith("Второй")
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    window.show_page(window.pages.index(window.settings))
    window.settings.delete_btn.click()
    assert window.project_box.count() == 1 and not window.project_box.currentText().startswith("Второй")


def test_gui_stays_responsive_during_import(qtbot, window: MainWindow, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Главный поток не должен замирать, пока импорт идёт в фоне."""
    from gen_test_data import large

    page = window.importer
    page.add_paths([large(30_000, tmp_path)])
    gaps: list[float] = []
    last = [time.perf_counter()]

    def tick() -> None:
        now = time.perf_counter()
        gaps.append(now - last[0])
        last[0] = now

    timer = QTimer()
    timer.setInterval(10)
    timer.timeout.connect(tick)
    timer.start()
    page.start_btn.click()
    settle(qtbot, window)
    timer.stop()
    worst = max(gaps[1:]) * 1000
    print(f"\nмакс. пауза главного потока: {worst:.0f} мс за {len(gaps)} тиков")
    assert worst < 250, f"GUI замирал на {worst:.0f} мс"


def test_drag_and_drop_adds_paths(qtbot, window: MainWindow) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtCore import QMimeData, QPointF, Qt, QUrl
    from PySide6.QtGui import QDragEnterEvent, QDropEvent

    zone = window.importer.drop
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(TEST_DATA / "valid" / "netscape.txt")), QUrl("https://example.com/x")])
    enter = QDragEnterEvent(
        zone.rect().center(), Qt.DropAction.CopyAction, mime, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier
    )
    zone.dragEnterEvent(enter)
    assert enter.isAccepted() and zone.property("active") is True
    drop = QDropEvent(
        QPointF(zone.rect().center()),
        Qt.DropAction.CopyAction,
        mime,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    with qtbot.waitSignal(zone.dropped) as sig:
        zone.dropEvent(drop)
    assert [p.name for p in sig.args[0]] == ["netscape.txt"], "сетевые ссылки отбрасываются"
    assert window.importer.queue.count() == 1 and zone.property("active") is False


def test_diagnostics_page_end_to_end(
    qtbot,
    window: MainWindow,
    unlocked: Workspace,
    tmp_path: Path,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    from http.server import ThreadingHTTPServer

    from tests.integration.test_diagnostics import ME, _Site

    _Site.valid, _Site.forget_logout = {"good-session"}, True  # сайт «забывает» аннулировать сессию
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/api/me"
        src = tmp_path / "c.jsonl"
        src.write_text('{"name":"sid","value":"good-session","domain":"127.0.0.1","hostOnly":true}\n')
        unlocked.importer().run(window.project_id, [src])
        page = window.diagnostics
        window.show_page(window.pages.index(page))
        assert page.ep_title.text().startswith("Добавьте адрес") and not page.run_btn.isEnabled()

        from app.gui.views.diagnostics import EndpointDialog

        def fake_exec(dlg: EndpointDialog) -> int:
            dlg.url.setText(url)
            dlg.contains.setPlainText("alice")
            return 1

        monkeypatch.setattr(EndpointDialog, "exec", fake_exec)
        page.add_btn.click()
        assert page.current() is not None and page.ep_state.text() == "Локальный адрес"
        assert page.no_cookies.isVisible() and not page.run_btn.isEnabled()

        unlocked.cookies.set_test_session(unlocked.cookies.ids(window.project_id), True)
        page.refresh()
        assert page.cookies_list.count() == 1 and page.run_btn.isEnabled()
        page.run_btn.click()
        settle(qtbot, window)
        assert "соответствует действующей сессии" in page.result.toPlainText()

        page.before_btn.click()
        settle(qtbot, window)
        assert page.after_btn.isEnabled() and "Теперь выполните действие" in page.result.toPlainText()
        import httpx

        httpx.get(url.replace("/api/me", "/logout"), cookies={"sid": "good-session"})
        page.after_btn.click()
        settle(qtbot, window)
        assert "уязвимость" in page.result.toPlainText() and not page.after_btn.isEnabled()
        assert page.history.count() == 3
        assert ME.body_contains == ("alice",)
    finally:
        srv.shutdown()


def test_diagnostics_result_not_shown_for_other_endpoint(qtbot, window: MainWindow, unlocked: Workspace) -> None:  # type: ignore[no-untyped-def]
    from app.services.diagnostics import Markers

    ds = unlocked.diagnostics()
    ds.add_endpoint(window.project_id, "http://127.0.0.1:9/a", Markers(body_contains=("x",)))
    ds.add_endpoint(window.project_id, "https://app.example.com/b", Markers(body_contains=("x",)))
    page = window.diagnostics
    window.show_page(window.pages.index(page))
    page.list.setCurrentRow(0)
    page.result.setHtml("<p>результат первого адреса</p>")
    page.pair = "pending"
    page.list.setCurrentRow(1)
    assert page.result.toPlainText() == "" and page.pair is None
    assert page.verify_btn.isVisible() and "cookie-inspector-verify=" in page.instructions.toPlainText()


def test_batch_page_processes_and_reports(
    qtbot,
    window: MainWindow,
    unlocked: Workspace,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    files = []
    for i in range(6):
        p = tmp_path / f"b{i}.jsonl"
        p.write_text(f'{{"name":"c","value":"v","domain":"d{i}.example.test","secure":true}}\n')
        files.append(p)
    bad = tmp_path / "bad.json"
    bad.write_text("{ broken")
    files.append(bad)

    page = window.batch
    window.show_page(window.pages.index(page))
    assert not page.start_btn.isEnabled()
    page.add_paths(files)
    assert page.queue.count() == 7 and page.start_btn.isEnabled()
    page.workers.setValue(3)
    page.start_btn.click()
    settle(qtbot, window)
    assert page.table.rowCount() == 7
    assert "ошибками" in page.status_label.text()
    assert unlocked.cookies.count(window.project_id) == 6
    assert page.retry_btn.isEnabled() and page.job_id is not None

    bad.write_text('{"name":"c","value":"v","domain":"fixed.example.test"}\n')
    page.retry_btn.click()
    settle(qtbot, window)
    assert unlocked.cookies.count(window.project_id) == 7
    assert "Готово" in page.status_label.text() and page.job_id is None


def test_batch_lock_blocks_start(qtbot, window: MainWindow, unlocked: Workspace, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    p = tmp_path / "f.jsonl"
    p.write_text('{"name":"c","value":"v","domain":"x.test"}\n')
    page = window.batch
    window.show_page(window.pages.index(page))
    page.add_paths([p])
    assert page.start_btn.isEnabled()
    window.settings.lock_btn.click()
    assert not page.start_btn.isEnabled() and "заблокировано" in page.start_btn.toolTip()
