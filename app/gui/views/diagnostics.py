"""Session Diagnostics: адреса, подтверждение владения, проверка тестовой сессии, «до/после», история."""

from __future__ import annotations

import html
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from app.app_context import Workspace
from app.gui.tasks import TaskRunner
from app.gui.theming import STATUS_COLORS
from app.gui.views.base import Page
from app.gui.widgets.toast import Notifier
from app.services.diagnostics import (
    Comparison,
    DiagnosticResult,
    EndpointInfo,
    Markers,
    Outcome,
    SweepRow,
)

STATE = {
    "local": ("Локальный адрес", STATUS_COLORS["valid"]),
    "verified": ("Владение подтверждено", STATUS_COLORS["valid"]),
    "unverified": ("Владение не подтверждено", STATUS_COLORS["warning"]),
}
OUTCOME = {
    Outcome.MATCHED: ("Ответ соответствует действующей сессии", STATUS_COLORS["valid"]),
    Outcome.NOT_MATCHED: ("Ответ не соответствует ожидаемому", STATUS_COLORS["warning"]),
    Outcome.ERROR: ("Запрос не выполнен", STATUS_COLORS["invalid"]),
}
MARKER = {
    "status": "Код ответа",
    "body_contains": "Есть в ответе",
    "body_not_contains": "Нет в ответе",
    "location_contains": "Location содержит",
}


def _lines(text: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in text.splitlines() if x.strip())


class EndpointDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Новый адрес диагностики")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        intro = QLabel(
            "Укажите адрес вашего сайта, который отвечает по-разному для вошедшего и не вошедшего "
            "пользователя (например, /api/me или /account), и признаки ответа с действующей сессией."
        )
        intro.setWordWrap(True)
        intro.setProperty("role", "muted")
        lay.addWidget(intro)
        form = QFormLayout()
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://ваш-домен/api/me")
        self.status = QLineEdit("200")
        self.contains = QPlainTextEdit()
        self.contains.setPlaceholderText("Например, ваш логин — по одному тексту на строку")
        self.not_contains = QPlainTextEdit()
        self.not_contains.setPlaceholderText("Например, «Войти» или «Login»")
        self.location = QLineEdit()
        self.location.setPlaceholderText("Необязательно")
        for w in (self.contains, self.not_contains):
            w.setFixedHeight(60)
        form.addRow("Адрес", self.url)
        form.addRow("Ожидаемые коды", self.status)
        form.addRow("Ответ содержит", self.contains)
        form.addRow("Ответ не содержит", self.not_contains)
        form.addRow("Location содержит", self.location)
        lay.addLayout(form)
        self.error = QLabel("")
        self.error.setStyleSheet(f"color:{STATUS_COLORS['invalid']};")
        self.error.setWordWrap(True)
        lay.addWidget(self.error)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel, ok = QPushButton("Отмена"), QPushButton("Добавить")
        ok.setProperty("primary", True)
        row.addWidget(cancel)
        row.addWidget(ok)
        lay.addLayout(row)
        cancel.clicked.connect(self.reject)
        ok.clicked.connect(self._ok)

    def markers(self) -> Markers:
        codes = tuple(int(c) for c in self.status.text().replace(",", " ").split() if c.isdigit())
        return Markers(
            codes or (200,),
            _lines(self.contains.toPlainText()),
            _lines(self.not_contains.toPlainText()),
            self.location.text().strip() or None,
        )

    def _ok(self) -> None:
        try:
            self.markers().validate()
        except Exception as e:  # noqa: BLE001 — показать причину в диалоге
            self.error.setText(str(e))
            return
        if not self.url.text().strip():
            self.error.setText("Укажите адрес.")
            return
        self.accept()


class DiagnosticsPage(Page):
    title = "Диагностика"

    def __init__(self, ws: Workspace, notifier: Notifier, runner: TaskRunner) -> None:
        super().__init__(ws, notifier, runner)
        hint = QLabel(
            "Проверка тестовой сессии на вашем собственном сайте: программа отправляет отмеченные тестовые "
            "cookies на указанный адрес и сравнивает ответ с ожидаемыми признаками. Для публичных доменов "
            "нужно подтвердить владение."
        )
        hint.setWordWrap(True)
        hint.setProperty("role", "muted")
        self.root.addWidget(hint)
        self.pair: str | None = None
        self._busy = False  # только собственные запросы экрана, а не любые фоновые задачи окна
        self._shown_id: int | None = None

        split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.add_btn = QPushButton("Добавить адрес…")
        self.remove_btn = QPushButton("Удалить адрес")
        self.remove_btn.setProperty("danger", True)
        self.sweep_btn = QPushButton("Проверить все мои сайты")
        self.sweep_btn.setToolTip("Прогнать отмеченные тестовые сессии по всем подтверждённым адресам проекта")
        ll.addWidget(self.list, 1)
        ll.addWidget(self.sweep_btn)
        ll.addWidget(self.add_btn)
        ll.addWidget(self.remove_btn)
        split.addWidget(left)

        right = QFrame()
        right.setProperty("card", True)
        rl = QVBoxLayout(right)
        self.ep_title = QLabel("Выберите адрес")
        self.ep_title.setProperty("role", "h2")
        self.ep_title.setWordWrap(True)
        self.ep_state = QLabel("")
        self.instructions = QPlainTextEdit()
        self.instructions.setReadOnly(True)
        self.instructions.setFixedHeight(96)
        self.verify_btn = QPushButton("Проверить владение")
        rl.addWidget(self.ep_title)
        rl.addWidget(self.ep_state)
        rl.addWidget(self.instructions)
        rl.addWidget(self.verify_btn, 0, Qt.AlignmentFlag.AlignLeft)
        cl = QLabel("Тестовые cookies для этого адреса")
        cl.setProperty("role", "h2")
        rl.addWidget(cl)
        self.cookies_list = QListWidget()
        self.cookies_list.setFixedHeight(110)
        self.no_cookies = QLabel(
            "Нет подходящих тестовых сессий. В разделе Cookies выберите cookie вашего сайта и "
            "нажмите «Отметить как тестовую сессию»."
        )
        self.no_cookies.setWordWrap(True)
        self.no_cookies.setProperty("role", "muted")
        rl.addWidget(self.cookies_list)
        rl.addWidget(self.no_cookies)
        row = QHBoxLayout()
        self.run_btn = QPushButton("Проверить сессию")
        self.run_btn.setProperty("primary", True)
        self.before_btn = QPushButton("Проверить «до»")
        self.after_btn = QPushButton("Проверить «после»")
        self.before_btn.setToolTip("Проверка до действия на сайте, например до выхода из аккаунта")
        self.after_btn.setToolTip("Повторная проверка после действия — покажет, аннулировал ли сервер сессию")
        for b in (self.run_btn, self.before_btn, self.after_btn):
            row.addWidget(b)
        row.addStretch(1)
        rl.addLayout(row)
        self.result = QTextBrowser()
        rl.addWidget(self.result, 1)
        hl = QLabel("История проверок")
        hl.setProperty("role", "h2")
        rl.addWidget(hl)
        self.history = QListWidget()
        self.history.setFixedHeight(110)
        rl.addWidget(self.history)
        split.addWidget(right)
        split.setSizes([300, 900])
        self.root.addWidget(split, 1)

        self.list.currentItemChanged.connect(lambda *_: self._show_endpoint())
        self.sweep_btn.clicked.connect(self.run_all)
        self.add_btn.clicked.connect(self.add_endpoint)
        self.remove_btn.clicked.connect(self.remove_endpoint)
        self.verify_btn.clicked.connect(self.verify)
        self.run_btn.clicked.connect(lambda: self.run(None))
        self.before_btn.clicked.connect(lambda: self.run("before"))
        self.after_btn.clicked.connect(lambda: self.run("after"))
        ws.on_lock_change(lambda _u: self._sync())

    # ------------------------------------------------------------------ данные
    def current(self) -> EndpointInfo | None:
        it = self.list.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def refresh(self) -> None:
        if self.project_id is None:
            return
        cur = self.current()
        self.list.blockSignals(True)
        self.list.clear()
        for e in self.ws.diagnostics().endpoints(self.project_id):
            it = QListWidgetItem(f"{e.host}{e.url.split(e.host, 1)[1] if e.host in e.url else ''}")
            it.setData(Qt.ItemDataRole.UserRole, e)
            it.setToolTip(e.url)
            self.list.addItem(it)
            if cur and cur.id == e.id:
                self.list.setCurrentItem(it)
        if self.list.currentRow() < 0 and self.list.count():
            self.list.setCurrentRow(0)
        self.list.blockSignals(False)
        self._show_endpoint()

    def _show_endpoint(self) -> None:
        e = self.current()
        self.cookies_list.clear()
        self.history.clear()
        if (e.id if e else None) != self._shown_id:
            # другой адрес — результат и незавершённая пара «до/после» к нему не относятся
            self._shown_id = e.id if e else None
            self.result.clear()
            self.pair = None
        if e is None:
            self.ep_title.setText("Добавьте адрес своего сайта, чтобы начать")
            for w in (self.ep_state, self.instructions, self.verify_btn):
                w.setVisible(False)
            self._sync()
            return
        ds = self.ws.diagnostics()
        self.ep_title.setText(e.url)
        label, color = STATE[e.state]
        if e.state == "verified" and not e.usable:
            label, color = "Подтверждение устарело — подтвердите владение снова", STATUS_COLORS["warning"]
        self.ep_state.setText(label)
        self.ep_state.setStyleSheet(f"color:{color};")
        self.ep_state.setVisible(True)
        need = e.state != "local"
        self.instructions.setVisible(need and not e.usable)
        self.verify_btn.setVisible(need and not e.usable)
        self.instructions.setPlainText(ds.verification_instructions(e.id))
        for cid, name, domain in ds.matching_cookies(e.id):
            it = QListWidgetItem(f"{name}  ({domain})")
            it.setData(Qt.ItemDataRole.UserRole, cid)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked)
            self.cookies_list.addItem(it)
        for r in ds.history(e.id, 30):
            text, _ = OUTCOME[r.outcome]
            phase = {"before": " (до)", "after": " (после)"}.get(r.phase or "", "")
            self.history.addItem(f"#{r.run_id}{phase}: {text}" + (f", код {r.status_code}" if r.status_code else ""))
        self._sync()

    def checked_cookies(self) -> list[int]:
        return [
            self.cookies_list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.cookies_list.count())
            if self.cookies_list.item(i).checkState() == Qt.CheckState.Checked
        ]

    def _sync(self) -> None:
        e = self.current()
        ready = bool(e and e.usable and self.cookies_list.count() and self.ws.unlocked and not self._busy)
        self.no_cookies.setVisible(bool(e) and self.cookies_list.count() == 0)
        self.remove_btn.setEnabled(e is not None)
        self.sweep_btn.setEnabled(self.list.count() > 0 and self.ws.unlocked and not self._busy)
        self.sweep_btn.setToolTip(
            "Хранилище заблокировано"
            if not self.ws.unlocked
            else "Прогнать отмеченные тестовые сессии по всем подтверждённым адресам проекта"
        )
        self.run_btn.setEnabled(ready)
        self.before_btn.setEnabled(ready)
        self.after_btn.setEnabled(ready and self.pair is not None)
        tip = "" if self.ws.unlocked else "Хранилище заблокировано"
        for b in (self.run_btn, self.before_btn):
            b.setToolTip(tip or b.toolTip())

    # ------------------------------------------------------------------ действия
    def add_endpoint(self) -> None:
        if self.project_id is None:
            return
        dlg = EndpointDialog(self)
        if not dlg.exec():
            return
        try:
            self.ws.diagnostics().add_endpoint(self.project_id, dlg.url.text(), dlg.markers())
        except Exception as e:  # noqa: BLE001
            self.error(e)
            return
        self.notify.show("Адрес добавлен", "success")
        self.refresh()
        self.list.setCurrentRow(self.list.count() - 1)

    def remove_endpoint(self) -> None:
        e = self.current()
        if (
            e
            and QMessageBox.question(self, "Удаление", f"Удалить адрес {e.url} и историю его проверок?")
            == QMessageBox.StandardButton.Yes
        ):
            self.ws.diagnostics().remove_endpoint(e.id)
            self.refresh()

    def verify(self) -> None:
        e = self.current()
        if e is None:
            return
        ds = self.ws.diagnostics()
        self.verify_btn.setEnabled(False)

        def done(_r: Any) -> None:
            self.verify_btn.setEnabled(True)
            self.notify.show(f"Владение {e.host} подтверждено", "success")
            self.refresh()

        def fail(exc: Exception) -> None:
            self.verify_btn.setEnabled(True)
            self.error(exc)

        self.runner.start(lambda _p: ds.verify(e.id), on_done=done, on_error=fail)

    def run_all(self) -> None:
        if self.project_id is None or self.list.count() == 0:
            return
        ds = self.ws.diagnostics()
        pid = self.project_id
        self._busy = True
        self._sync()

        self.runner.start(
            lambda _p: ds.run_across_endpoints(pid), on_done=self._show_sweep, on_error=self._sweep_failed
        )

    def _sweep_failed(self, exc: Exception) -> None:
        self._busy = False
        self._sync()
        self.error(exc)

    def _show_sweep(self, rows: list[SweepRow]) -> None:
        self._busy = False
        self._sync()
        self.refresh()
        SweepDialog(rows, self).exec()
        checked = sum(1 for r in rows if r.outcome is not None)
        matched = sum(1 for r in rows if r.outcome is Outcome.MATCHED)
        self.notify.show(f"Проверено адресов: {checked}, сессия принята на {matched}", "info")

    def run(self, phase: str | None) -> None:
        e = self.current()
        ids = self.checked_cookies()
        if e is None or not ids:
            self.notify.show("Отметьте хотя бы одну cookie в списке", "warning")
            return
        ds = self.ws.diagnostics()
        if phase == "before":
            self.pair = ds.new_pair()
        pair = self.pair if phase else None
        self.result.setHtml("<p>Выполняется запрос…</p>")
        self._busy = True
        self._sync()

        def job(_p: Any) -> tuple[DiagnosticResult, Comparison | None]:
            r = ds.run(e.id, ids, phase=phase, pair_id=pair)
            return r, (ds.compare_pair(pair) if phase == "after" and pair else None)

        self.runner.start(job, on_done=self._show_result, on_error=self._failed)

    def _failed(self, exc: Exception) -> None:
        self._busy = False
        self.result.setHtml(f"<p>{html.escape(str(exc))}</p>")
        self.error(exc)
        self._sync()

    def _show_result(self, data: tuple[DiagnosticResult, Comparison | None]) -> None:
        r, cmp = data
        self._busy = False
        text, color = OUTCOME[r.outcome]
        if r.phase:
            text = ("До действия: " if r.phase == "before" else "После действия: ") + text[0].lower() + text[1:]
        if cmp is not None:
            color = STATUS_COLORS["security_issue"] if cmp.problem else STATUS_COLORS["valid"]
        out = [f'<h3 style="color:{color}">{text}</h3>']
        if r.status_code is not None:
            out.append(
                f"<p>Код ответа {r.status_code}, {r.elapsed_ms} мс"
                + (f", Location: {html.escape(r.location)}" if r.location else "")
                + "</p>"
            )
        if r.checks:
            out.append(
                "<ul>"
                + "".join(
                    f"<li>{'✓' if c.ok else '✗'} {MARKER.get(c.marker, c.marker)}: {html.escape(c.expected)}</li>"
                    for c in r.checks
                )
                + "</ul>"
            )
        out.append(f"<p>Отправлены: {html.escape(', '.join(r.sent_cookies))}</p>")
        for w in (*r.skipped_cookies, *r.warnings):
            out.append(f"<p>⚠ {html.escape(w)}</p>")
        if r.set_cookie_names:
            out.append(f"<p>Сервер установил cookies: {html.escape(', '.join(r.set_cookie_names))}</p>")
        if r.error:
            out.append(f"<p>{html.escape(r.error)}</p>")
        if r.phase == "before":
            out.append(
                "<p><b>Теперь выполните действие на сайте</b> (например, выйдите из аккаунта) "
                "и нажмите «Проверить «после»».</p>"
            )
        if cmp is not None:
            c = STATUS_COLORS["security_issue"] if cmp.problem else STATUS_COLORS["valid"]
            out.append(f'<p style="color:{c}"><b>{html.escape(cmp.verdict)}</b></p>')
            self.pair = None
        out.append(
            "<p style='color:gray'>Совпадение маркеров показывает, как сервер ответил на эти cookies "
            "сейчас, а не гарантирует поведение в будущем.</p>"
        )
        self.result.setHtml("".join(out))
        self._show_endpoint()


class SweepDialog(QDialog):
    """Сводка прогона тестовых сессий по всем адресам проекта."""

    def __init__(self, rows: list[SweepRow], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Проверка всех моих сайтов")
        self.setMinimumSize(720, 420)
        lay = QVBoxLayout(self)
        checked = sum(1 for r in rows if r.outcome is not None)
        matched = sum(1 for r in rows if r.outcome is Outcome.MATCHED)
        head = QLabel(f"Адресов в проекте: {len(rows)}. Опрошено: {checked}. Сессия принята сервером на: {matched}.")
        head.setWordWrap(True)
        lay.addWidget(head)
        table = QTableWidget(len(rows), 4)
        table.setHorizontalHeaderLabels(["Адрес", "Результат", "Код", "Отправлено cookies / причина"])
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        table.setColumnWidth(1, 150)
        table.setColumnWidth(2, 60)
        for row, r in enumerate(rows):
            if r.outcome is not None:
                label = {
                    Outcome.MATCHED: "Принята",
                    Outcome.NOT_MATCHED: "Не принята",
                    Outcome.ERROR: "Ошибка запроса",
                }[r.outcome]
                color = OUTCOME[r.outcome][1]
                detail = f"{len(r.matched_cookie_ids)} шт."
            else:
                label, color = (r.skipped_reason or "пропущен", STATUS_COLORS["unknown"])
                detail = r.skipped_reason or ""
            code = str(r.result.status_code) if r.result and r.result.status_code is not None else "—"
            for col, (text, c) in enumerate(((r.url, None), (label, color), (code, None), (detail, None))):
                it = QTableWidgetItem(text)
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if c:
                    it.setForeground(QColor(c))
                if col == 0:
                    it.setToolTip(r.url)
                table.setItem(row, col, it)
        lay.addWidget(table, 1)
        note = QLabel(
            "Совпадение маркеров показывает, как каждый сервер ответил на эти cookies сейчас. "
            "Неподтверждённые адреса не опрашивались."
        )
        note.setWordWrap(True)
        note.setProperty("role", "muted")
        lay.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        lay.addWidget(buttons)
