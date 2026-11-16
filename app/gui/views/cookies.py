"""Cookie Manager: поиск, фильтры, группировка по доменам, детали, массовые действия."""

from __future__ import annotations

import html
from typing import Any, Final

from PySide6.QtCore import QItemSelectionModel, QModelIndex, Qt, QTimer
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTextBrowser,
    QVBoxLayout,
)

from app.app_context import Workspace
from app.domain import SameSite, Severity, ValidationStatus
from app.gui.dialogs.cookie_edit import CookieEditDialog
from app.gui.models.cookie_table import STATUS_SHORT, CookieTableModel, flags, fmt_expiry, value_text
from app.gui.tasks import TaskRunner
from app.gui.theming import SEVERITY_COLORS, SEVERITY_LABELS, STATUS_COLORS, STATUS_LABELS
from app.gui.views.base import Page
from app.gui.widgets.toast import Notifier
from app.services.cookies import CookieDetail, CookieFilter

CLIPBOARD_CLEAR_MS: Final = 30_000


def _combo(items: list[tuple[str, Any]]) -> QComboBox:
    c = QComboBox()
    for label, data in items:
        c.addItem(label, data)
    return c


class DetailPanel(QFrame):
    """Подробности записи. Значение скрыто, пока его явно не раскроют."""

    def __init__(self, page: CookiesPage) -> None:
        super().__init__()
        self.page = page
        self.setProperty("card", True)
        self.detail: CookieDetail | None = None
        lay = QVBoxLayout(self)
        self.title = QLabel("Выберите запись")
        self.title.setProperty("role", "h2")
        self.title.setWordWrap(True)
        lay.addWidget(self.title)
        row = QHBoxLayout()
        self.value = QLineEdit()
        self.value.setReadOnly(True)
        self.value.setEchoMode(QLineEdit.EchoMode.Password)
        self.reveal_btn = QPushButton("Показать")
        self.copy_btn = QPushButton("Копировать")
        row.addWidget(self.value, 1)
        row.addWidget(self.reveal_btn)
        row.addWidget(self.copy_btn)
        lay.addLayout(row)
        self.body = QTextBrowser()
        self.body.setOpenLinks(False)
        lay.addWidget(self.body, 1)
        self.reveal_btn.clicked.connect(self.toggle_reveal)
        self.copy_btn.clicked.connect(self.copy_value)
        self.show_detail(None)

    def show_detail(self, d: CookieDetail | None) -> None:
        self.detail = d
        self.value.clear()
        self.value.setEchoMode(QLineEdit.EchoMode.Password)
        self.reveal_btn.setText("Показать")
        has_value = d is not None and d.item.value_state == "present"
        self.reveal_btn.setEnabled(has_value and self.page.ws.unlocked)
        self.copy_btn.setEnabled(has_value and self.page.ws.unlocked)
        self.value.setPlaceholderText(value_text(d.item) if d else "")
        if d is None:
            self.title.setText("Выберите запись")
            self.body.setHtml("<p>Выберите строку в таблице, чтобы увидеть атрибуты и найденные проблемы.</p>")
            return
        it = d.item
        self.title.setText(f"{it.name or '(без имени)'} — {it.domain}")
        st = it.validation_status
        rows = [
            ("Статус", f'<span style="color:{STATUS_COLORS[st]}">{STATUS_SHORT[st]}</span>' if st else "Не проверена"),
            ("Путь", html.escape(it.path)),
            ("Истекает", fmt_expiry(it.expires_at)),
            ("Флаги", flags(it)),
            ("SameSite", it.same_site),
            ("Partitioned", "да" if d.partitioned else "нет"),
            ("Источник", f"{d.source_format}" + (f", строка {d.source_line}" if d.source_line else "")),
            ("Тестовая сессия", "да" if it.is_test_session else "нет"),
        ]
        out = ["<table cellspacing='0' cellpadding='3'>"]
        out += [f"<tr><td style='color:gray'>{k}</td><td>{v}</td></tr>" for k, v in rows]
        out.append("</table>")
        if d.findings:
            out.append(f"<h3>Находки ({len(d.findings)})</h3>")
            for f in d.findings:
                if f.severity:
                    tag = f'<span style="color:{SEVERITY_COLORS[f.severity]}">{SEVERITY_LABELS[f.severity]}</span>'
                else:
                    tag = (
                        f'<span style="color:{STATUS_COLORS[f.status or "unknown"]}">'
                        f"{STATUS_LABELS[f.status or 'unknown']}</span>"
                    )
                out.append(
                    f"<p><b>{html.escape(f.title)}</b> · {tag}<br>{html.escape(f.description)}<br>"
                    f"<i>Причина:</i> {html.escape(f.reason)}"
                )
                if f.risk:
                    out.append(f"<br><i>Риск:</i> {html.escape(f.risk)}")
                if f.recommendation:
                    out.append(f"<br><i>Рекомендация:</i> {html.escape(f.recommendation)}")
                out.append("</p>")
        elif st:
            out.append(
                "<p>Проблем не найдено. Это проверка структуры и настроек, а не подтверждение того, "
                "что сессия действует на сервере.</p>"
            )
        self.body.setHtml("".join(out))

    def _reveal(self) -> str | None:
        if self.detail is None:
            return None
        try:
            d = self.page.ws.cookies.detail(self.detail.item.id, reveal=True)
        except (PermissionError, LookupError) as e:
            self.page.error(e)
            return None
        return d.value.reveal() if d.value is not None else None

    def toggle_reveal(self) -> None:
        if self.value.echoMode() == QLineEdit.EchoMode.Normal:
            self.value.clear()
            self.value.setEchoMode(QLineEdit.EchoMode.Password)
            self.reveal_btn.setText("Показать")
            return
        v = self._reveal()
        if v is not None:
            self.value.setText(v)
            self.value.setEchoMode(QLineEdit.EchoMode.Normal)
            self.reveal_btn.setText("Скрыть")

    def copy_value(self) -> None:
        v = self._reveal()
        if v is None:
            return
        cb = QGuiApplication.clipboard()
        cb.setText(v)
        QTimer.singleShot(CLIPBOARD_CLEAR_MS, lambda: cb.clear() if cb.text() == v else None)
        self.page.notify.show("Значение скопировано. Буфер обмена очистится через 30 секунд.", "info")


class CookiesPage(Page):
    title = "Cookies"

    def __init__(self, ws: Workspace, notifier: Notifier, runner: TaskRunner) -> None:
        super().__init__(ws, notifier, runner)
        self.domain: str | None = None

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск по имени или домену")
        self.search.setClearButtonEnabled(True)
        self.status = _combo(
            [("Любой статус", None), ("Не проверены", "none")]
            + [(STATUS_LABELS[s.value], s.value) for s in ValidationStatus]
        )
        self.severity = _combo(
            [("Любая критичность", None)] + [(SEVERITY_LABELS[s.value], s.value) for s in reversed(Severity)]
        )
        self.expiry = _combo(
            [("Любой срок", None), ("Действующие", "active"), ("Истекшие", "expired"), ("Сессионные", "session")]
        )
        self.secure = _combo([("Secure: любой", None), ("С Secure", True), ("Без Secure", False)])
        self.samesite = _combo([("SameSite: любой", None)] + [(s.value, s.value) for s in SameSite])
        self.reset_btn = QPushButton("Сбросить фильтры")
        bar.addWidget(self.search, 2)
        for w in (self.status, self.severity, self.expiry, self.secure, self.samesite):
            bar.addWidget(w)
        bar.addWidget(self.reset_btn)
        self.root.addLayout(bar)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.domains = QListWidget()
        self.domains.setMinimumWidth(170)
        self.model = CookieTableModel(ws, ws.settings.get("table.page_size") or 200)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.horizontalHeader().setSectionsClickable(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        for col, width in enumerate((125, 120, 170, 200, 70, 125, 150, 80)):
            self.table.setColumnWidth(col, width)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.panel = DetailPanel(self)
        split.addWidget(self.domains)
        split.addWidget(self.table)
        split.addWidget(self.panel)
        split.setSizes([180, 760, 360])
        self.root.addWidget(split, 1)

        foot = QHBoxLayout()
        self.counter = QLabel("")
        self.counter.setProperty("role", "muted")
        self.all_btn = QPushButton("Применять ко всем по фильтру")
        self.all_btn.setCheckable(True)
        self.all_btn.setToolTip("Действия ниже затронут все записи по текущему фильтру, а не только выделенные")
        self.validate_btn = QPushButton("Проверить")
        self.edit_btn = QPushButton("Изменить")
        self.test_btn = QPushButton("Отметить как тестовую сессию")
        self.delete_btn = QPushButton("Удалить")
        self.delete_btn.setProperty("danger", True)
        foot.addWidget(self.counter, 1)
        for b in (self.all_btn, self.validate_btn, self.test_btn, self.edit_btn, self.delete_btn):
            foot.addWidget(b)
        self.root.addLayout(foot)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(250)
        self._debounce.timeout.connect(self.apply_filters)
        self.search.textChanged.connect(lambda _t: self._debounce.start())
        for c in (self.status, self.severity, self.expiry, self.secure, self.samesite):
            c.currentIndexChanged.connect(lambda _i: self.apply_filters())
        self.reset_btn.clicked.connect(lambda: self.reset_filters())
        self.domains.currentItemChanged.connect(self._domain_selected)
        self.table.horizontalHeader().sectionClicked.connect(self._sort_clicked)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._selection_changed())
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.validate_btn.clicked.connect(self.revalidate)
        self.edit_btn.clicked.connect(self.edit_selected)
        self.test_btn.clicked.connect(self.toggle_test_session)
        self.delete_btn.clicked.connect(self.delete_selected)
        self.all_btn.toggled.connect(lambda _on: self._selection_changed())
        delete_action = QAction("Удалить", self.table)
        delete_action.setShortcut(QKeySequence.StandardKey.Delete)
        delete_action.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        delete_action.triggered.connect(self.delete_selected)
        self.table.addAction(delete_action)
        self._selection_changed()

    # ------------------------------------------------------------------ фильтры
    def current_filter(self, *, with_domain: bool = True) -> CookieFilter:
        st, sev, exp = self.status.currentData(), self.severity.currentData(), self.expiry.currentData()
        ss = self.samesite.currentData()
        return CookieFilter(
            text=self.search.text().strip() or None,
            domain=self.domain if with_domain else None,
            statuses=frozenset({ValidationStatus(st)}) if st and st != "none" else frozenset(),
            not_analyzed=st == "none",
            severities=frozenset({Severity(sev)}) if sev else frozenset(),
            expired=True if exp == "expired" else (False if exp == "active" else None),
            session_only=True if exp == "session" else None,
            secure=self.secure.currentData(),
            same_site=SameSite(ss) if ss else None,
        )

    def set_filter(self, spec: dict[str, Any]) -> None:
        """Открыть экран с фильтром (например, по клику на статус на обзоре)."""
        self.reset_filters(reload=False)
        if "status" in spec:
            self.status.setCurrentIndex(self.status.findData(spec["status"]))
        self.apply_filters()

    def reset_filters(self, reload: bool = True) -> None:
        for c in (self.status, self.severity, self.expiry, self.secure, self.samesite):
            c.blockSignals(True)
            c.setCurrentIndex(0)
            c.blockSignals(False)
        self.search.blockSignals(True)
        self.search.clear()
        self.search.blockSignals(False)
        self.domain = None
        if reload:
            self.apply_filters()

    def apply_filters(self) -> None:
        if self.project_id is None:
            return
        try:
            self.model.reload(self.project_id, self.current_filter())
            self._load_domains()
        except Exception as e:  # noqa: BLE001 — ошибка запроса показывается пользователю
            self.error(e)
        self.panel.show_detail(None)
        self._selection_changed()

    def refresh(self) -> None:
        self.apply_filters()

    def _load_domains(self) -> None:
        if self.project_id is None:
            return
        groups = self.ws.cookies.domain_counts(self.project_id, self.current_filter(with_domain=False), limit=300)
        self.domains.blockSignals(True)
        self.domains.clear()
        total = self.ws.cookies.count(self.project_id, self.current_filter(with_domain=False))
        first = QListWidgetItem(f"Все домены  ({total})")
        first.setToolTip(f"Показаны крупнейшие группы: {len(groups)}" if len(groups) >= 300 else "")
        first.setData(Qt.ItemDataRole.UserRole, None)
        self.domains.addItem(first)
        for d, n in groups:
            it = QListWidgetItem(f"{d}  ({n})")
            it.setData(Qt.ItemDataRole.UserRole, d)
            self.domains.addItem(it)
            if d == self.domain:
                self.domains.setCurrentItem(it)
        if self.domain is None:
            self.domains.setCurrentRow(0)
        self.domains.blockSignals(False)

    def _domain_selected(self, cur: QListWidgetItem | None, _prev: QListWidgetItem | None) -> None:
        self.domain = cur.data(Qt.ItemDataRole.UserRole) if cur else None
        if self.project_id is not None:
            self.model.reload(self.project_id, self.current_filter())
            self.panel.show_detail(None)
            self._selection_changed()

    def _sort_clicked(self, col: int) -> None:
        h = self.table.horizontalHeader()
        if self.model.sort_by(
            col,
            Qt.SortOrder.AscendingOrder
            if h.sortIndicatorOrder() == Qt.SortOrder.DescendingOrder
            else Qt.SortOrder.DescendingOrder,
        ):
            h.setSortIndicatorShown(True)
            h.setSortIndicator(
                col, Qt.SortOrder.DescendingOrder if self.model.descending else Qt.SortOrder.AscendingOrder
            )
        else:
            self.notify.show("Сортировка доступна по имени, домену и сроку.", "info")

    # ------------------------------------------------------------------ выбор и детали
    def selected_ids(self) -> list[int]:
        if self.all_btn.isChecked() and self.project_id is not None:
            return self.ws.cookies.ids(self.project_id, self.current_filter())
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        return [self.model.item(r).id for r in rows]

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        n_sel = self.model.total if self.all_btn.isChecked() else len(rows)
        self.counter.setText(f"Найдено: {self.model.total}" + (f"; выбрано: {n_sel}" if n_sel else ""))
        unlocked = self.ws.unlocked
        for b in (self.validate_btn, self.delete_btn, self.test_btn):
            b.setEnabled(n_sel > 0)
        self.validate_btn.setEnabled(n_sel > 0 and unlocked)
        self.edit_btn.setEnabled(len(rows) == 1 and not self.all_btn.isChecked() and unlocked)
        if len(rows) == 1:
            try:
                self.panel.show_detail(self.ws.cookies.detail(self.model.item(rows[0].row()).id))
            except LookupError:
                self.panel.show_detail(None)
        elif not rows:
            self.panel.show_detail(None)

    def select_row(self, row: int) -> None:
        self.table.selectionModel().select(
            self.model.index(row, 0),
            QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows,
        )

    def _context_menu(self, pos: Any) -> None:
        idx: QModelIndex = self.table.indexAt(pos)
        if not idx.isValid():
            return
        it = self.model.item(idx.row())
        m = QMenu(self)
        m.addAction("Копировать имя", lambda: QGuiApplication.clipboard().setText(it.name))
        m.addAction("Копировать домен", lambda: QGuiApplication.clipboard().setText(it.domain))
        m.addAction("Показать только этот домен", lambda: self._focus_domain(it.domain))
        m.addSeparator()
        for b in (self.validate_btn, self.edit_btn, self.test_btn, self.delete_btn):
            a = m.addAction(b.text(), b.click)
            a.setEnabled(b.isEnabled())
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _focus_domain(self, domain: str) -> None:
        self.domain = domain
        self.apply_filters()

    # ------------------------------------------------------------------ действия
    def _changed(self, message: str) -> None:
        self.notify.show(message, "success")
        self.apply_filters()
        self.on_data_changed()

    def revalidate(self) -> None:
        ids, pid = self.selected_ids(), self.project_id
        if not ids or pid is None:
            return
        validator = self.ws.validator()
        self.validate_btn.setEnabled(False)
        self.runner.start(
            lambda _p: validator.run(pid, cookie_ids=ids),
            on_done=lambda r: self._changed(f"Проверено записей: {r.checked}"),
            on_error=self.error,
        )

    def edit_selected(self) -> None:
        ids = self.selected_ids()
        if len(ids) != 1 or self.project_id is None:
            return
        dlg = CookieEditDialog(self.ws.cookies.detail(ids[0]), self)
        if dlg.exec():
            try:
                self.ws.cookies.edit(ids[0], dlg.edit())
                self.ws.validator().run(self.project_id, cookie_ids=ids)
            except Exception as e:  # noqa: BLE001 — показать причину пользователю
                self.error(e)
                return
            self._changed("Изменения сохранены, запись проверена заново")

    def toggle_test_session(self) -> None:
        ids = self.selected_ids()
        if not ids:
            return
        details = [self.ws.cookies.detail(i) for i in ids[:1]]
        flag = not details[0].item.is_test_session
        self.ws.cookies.set_test_session(ids, flag)
        self._changed(("Отмечено" if flag else "Снята отметка") + f" тестовой сессии: {len(ids)}")

    def delete_selected(self) -> None:
        ids = self.selected_ids()
        if not ids or self.project_id is None:
            return
        answer = QMessageBox.question(
            self,
            "Удаление",
            f"Удалить записей: {len(ids)}? Действие необратимо.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            n = self.ws.cookies.delete(self.project_id, ids)
            self.all_btn.setChecked(False)
            self._changed(f"Удалено записей: {n}")
