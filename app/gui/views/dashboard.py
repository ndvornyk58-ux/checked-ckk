"""Обзор проекта: распределение статусов, ключевые показатели, активность."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.gui.tasks import TaskRunner
from app.gui.theming import SEVERITY_COLORS, SEVERITY_LABELS, STATUS_COLORS, STATUS_LABELS
from app.gui.views.base import Page
from app.gui.widgets.charts import STATUS_ORDER, ActivityChart, SpectrumBar
from app.gui.widgets.toast import Notifier
from app.services.workspace import Workspace

KIND_LABELS = {
    "import": "Импорт",
    "validate": "Проверка",
    "cookie.edit": "Изменение",
    "cookie.delete": "Удаление",
    "values.purge": "Очистка значений",
    "value.reveal": "Раскрытие значения",
    "project.create": "Проект",
    "project.delete": "Проект",
    "key.init": "Хранилище",
    "key.protection": "Хранилище",
    "diag.endpoint": "Диагностика",
    "diag.verify": "Диагностика",
    "diag.run": "Диагностика",
}


def _n(v: int) -> str:
    return f"{v:,}".replace(",", " ")


class Metric(QWidget):
    """Показатель без собственной рамки — все показатели живут в одной панели."""

    def __init__(self, label: str, color: str | None = None, tip: str = "") -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 8, 16, 8)
        self.value = QLabel("—")
        self.value.setProperty("role", "metric")
        if color:
            self.value.setStyleSheet(f"color:{color};")
        cap = QLabel(label)
        cap.setProperty("role", "muted")
        lay.addWidget(self.value)
        lay.addWidget(cap)
        self.setToolTip(tip)

    def set(self, v: int) -> None:
        self.value.setText(_n(v))


class DashboardPage(Page):
    title = "Обзор"
    open_cookies = Signal(object)  # dict фильтра для Cookie Manager
    open_import = Signal()

    def __init__(self, ws: Workspace, notifier: Notifier, runner: TaskRunner) -> None:
        super().__init__(ws, notifier, runner)
        self.summary = QLabel("")
        self.summary.setProperty("role", "muted")
        self.root.addWidget(self.summary)
        self.spectrum = SpectrumBar()
        self.root.addWidget(self.spectrum)
        legend = QHBoxLayout()
        self.legend: dict[str, QPushButton] = {}
        for key in STATUS_ORDER:
            b = QPushButton(STATUS_LABELS[key])
            b.setFlat(True)
            b.setStyleSheet(
                f"QPushButton{{border:none;color:{STATUS_COLORS[key]};padding:2px 6px;text-align:left}}"
                "QPushButton:hover{text-decoration:underline}"
            )
            b.setToolTip("Показать эти записи")
            b.clicked.connect(lambda _=False, k=key: self.open_cookies.emit({"status": k}))
            legend.addWidget(b)
            self.legend[key] = b
        legend.addStretch(1)
        self.root.addLayout(legend)

        panel = QFrame()
        panel.setProperty("card", True)
        grid = QGridLayout(panel)
        grid.setContentsMargins(0, 6, 0, 6)
        grid.setHorizontalSpacing(0)
        self.m_total, self.m_domains = Metric("Всего записей"), Metric("Доменов")
        self.m_expired = Metric(
            "Со сроком в прошлом",
            STATUS_COLORS["expired"],
            "Все записи с прошедшим сроком. В спектре выше запись учитывается один раз — "
            "по самому серьёзному статусу, поэтому числа могут различаться.",
        )
        self.m_invalid = Metric("Некорректных", STATUS_COLORS["invalid"])
        self.m_security = Metric("С проблемами безопасности", STATUS_COLORS["security_issue"])
        self.m_secure, self.m_insecure = Metric("С флагом Secure"), Metric("Без Secure")
        self.m_session = Metric("Сессионных")
        metrics = (
            self.m_total,
            self.m_domains,
            self.m_invalid,
            self.m_security,
            self.m_expired,
            self.m_session,
            self.m_secure,
            self.m_insecure,
        )
        for i, m in enumerate(metrics):
            grid.addWidget(m, i // 4, (i % 4) * 2)
            if i % 4:
                line = QFrame()
                line.setProperty("divider", True)
                line.setFixedWidth(1)
                grid.addWidget(line, i // 4, (i % 4) * 2 - 1)
        self.root.addWidget(panel)

        lower = QHBoxLayout()
        lower.setSpacing(12)
        left = QFrame()
        left.setProperty("card", True)
        ll = QVBoxLayout(left)
        h = QLabel("Критичность находок")
        h.setProperty("role", "h2")
        ll.addWidget(h)
        self.sev_labels: dict[str, QLabel] = {}
        for key in ("critical", "high", "medium", "low", "informational"):
            row = QHBoxLayout()
            name = QLabel(SEVERITY_LABELS[key])
            name.setStyleSheet(f"color:{SEVERITY_COLORS[key]};")
            val = QLabel("0")
            val.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(name)
            row.addWidget(val)
            ll.addLayout(row)
            self.sev_labels[key] = val
        h2 = QLabel("Операции за 14 дней")
        h2.setProperty("role", "h2")
        ll.addSpacing(8)
        ll.addWidget(h2)
        self.chart = ActivityChart()
        ll.addWidget(self.chart, 1)
        lower.addWidget(left, 1)

        right = QFrame()
        right.setProperty("card", True)
        rl = QVBoxLayout(right)
        h3 = QLabel("Последние операции")
        h3.setProperty("role", "h2")
        rl.addWidget(h3)
        self.activity = QListWidget()
        rl.addWidget(self.activity)
        lower.addWidget(right, 2)
        self.root.addLayout(lower, 1)

        self.empty = QFrame()
        self.empty.setProperty("card", True)
        el = QVBoxLayout(self.empty)
        msg = QLabel("В проекте пока нет cookies. Импортируйте файлы, чтобы проверить их корректность и безопасность.")
        msg.setWordWrap(True)
        go = QPushButton("Импортировать файлы")
        go.setProperty("primary", True)
        go.clicked.connect(self.open_import.emit)
        el.addWidget(msg)
        el.addWidget(go, 0, Qt.AlignmentFlag.AlignLeft)
        self.root.insertWidget(2, self.empty)

    def refresh(self) -> None:
        if self.project_id is None:
            return
        pid = self.project_id

        def load(_p: Any) -> tuple[Any, Any, Any]:
            return (self.ws.cookies.stats(pid), self.ws.activity.recent(pid, 30), self.ws.activity.daily_counts(pid))

        self.runner.start(load, on_done=self._show, on_error=self.error)

    def _show(self, data: tuple[Any, Any, Any]) -> None:
        st, recent, daily = data
        self.empty.setVisible(st.total == 0)
        self.spectrum.set_data(st.by_status, st.not_analyzed)
        for key, b in self.legend.items():
            n = st.by_status.get(key, 0)
            b.setText(f"{STATUS_LABELS[key]}  {_n(n)}")
            b.setEnabled(n > 0)
        self.summary.setText(
            f"{_n(st.total)} записей, {_n(st.domains)} доменов"
            + (f"; не проверено: {_n(st.not_analyzed)}" if st.not_analyzed else "")
        )
        self.m_total.set(st.total)
        self.m_domains.set(st.domains)
        self.m_expired.set(st.expired)
        self.m_invalid.set(st.by_status.get("invalid", 0))
        self.m_security.set(st.by_status.get("security_issue", 0))
        self.m_session.set(st.session)
        self.m_secure.set(st.secure)
        self.m_insecure.set(st.insecure)
        for key, lbl in self.sev_labels.items():
            lbl.setText(_n(st.by_severity.get(key, 0)))
        self.chart.set_data(daily)
        self.activity.clear()
        for a in recent:
            when = datetime.fromtimestamp(a.ts, tz=UTC).astimezone().strftime("%d.%m %H:%M")
            self.activity.addItem(f"{when}   {KIND_LABELS.get(a.kind, a.kind)}: {a.summary}")
        if not recent:
            self.activity.addItem("Операций ещё не было")
