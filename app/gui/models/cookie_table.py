"""Модель таблицы cookies.

Строки подгружаются страницами по мере прокрутки (canFetchMore/fetchMore), страница —
один keyset-запрос (~5 мс на 500 тыс. записей). В памяти — только просмотренные строки.
Значения не загружаются вовсе: в таблице только метаданные и длина значения.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QColor

from app.app_context import Workspace
from app.gui.theming import SEVERITY_COLORS, SEVERITY_LABELS, STATUS_COLORS, STATUS_LABELS
from app.services.cookies import CookieFilter, CookieListItem, SortKey

Index = QModelIndex | QPersistentModelIndex

COLUMNS: Final = ("Статус", "Критичность", "Имя", "Домен", "Путь", "Истекает", "Флаги", "SameSite", "Значение")
SORTABLE: Final = {2: SortKey.NAME, 3: SortKey.DOMAIN, 5: SortKey.EXPIRES}
STATUS_SHORT: Final = {
    "valid": "Корректна",
    "warning": "Замечания",
    "expired": "Истекла",
    "invalid": "Некорректна",
    "security_issue": "Безопасность",
    "unknown": "Не определено",
}


def fmt_expiry(ts: int | None) -> str:
    return "Сессия" if ts is None else datetime.fromtimestamp(ts, tz=UTC).strftime("%d.%m.%Y %H:%M")


def flags(i: CookieListItem) -> str:
    parts = [n for n, on in (("Secure", i.secure), ("HttpOnly", i.http_only), ("Host-only", i.host_only)) if on]
    return ", ".join(parts) or "—"


def value_text(i: CookieListItem) -> str:
    if i.value_state == "browser_encrypted":
        return "Зашифровано браузером"
    if i.value_state == "absent" or i.value_length is None:
        return "Нет значения"
    return f"•••••• ({i.value_length} симв.)"


class CookieTableModel(QAbstractTableModel):
    def __init__(self, ws: Workspace, page_size: int = 200) -> None:
        super().__init__()
        self.ws = ws
        self.page_size = page_size
        self.project_id: int | None = None
        self.filter = CookieFilter()
        # Не «sort»: это имя виртуального метода QAbstractItemModel.sort, его нельзя перекрывать.
        self.sort_key = SortKey.IMPORTED
        self.descending = True
        self.rows: list[CookieListItem] = []
        self._cursor: str | None = None
        self._exhausted = True
        self.total = 0

    # ------------------------------------------------------------------ загрузка
    def reload(self, project_id: int | None = None, f: CookieFilter | None = None) -> None:
        if project_id is not None:
            self.project_id = project_id
        if f is not None:
            self.filter = f
        self.beginResetModel()
        self.rows, self._cursor, self._exhausted = [], None, self.project_id is None
        self.total = self.ws.cookies.count(self.project_id, self.filter) if self.project_id is not None else 0
        self.endResetModel()
        if not self._exhausted:
            self.fetchMore(QModelIndex())

    def canFetchMore(self, parent: Index = QModelIndex()) -> bool:  # noqa: B008
        return not parent.isValid() and not self._exhausted

    def fetchMore(self, parent: Index = QModelIndex()) -> None:  # noqa: B008
        if parent.isValid() or self._exhausted or self.project_id is None:
            return
        page = self.ws.cookies.page(
            self.project_id,
            self.filter,
            sort=self.sort_key,
            descending=self.descending,
            cursor=self._cursor,
            limit=self.page_size,
        )
        if page.items:
            self.beginInsertRows(QModelIndex(), len(self.rows), len(self.rows) + len(page.items) - 1)
            self.rows.extend(page.items)
            self.endInsertRows()
        self._cursor = page.next_cursor
        self._exhausted = page.next_cursor is None

    def sort_by(self, column: int, order: Qt.SortOrder) -> bool:
        key = SORTABLE.get(column)
        if key is None:
            return False
        self.sort_key, self.descending = key, order == Qt.SortOrder.DescendingOrder
        self.reload()
        return True

    # ------------------------------------------------------------------ модель
    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.ToolTipRole:
            return "Нажмите для сортировки" if section in SORTABLE else None
        return None

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        it = self.rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return (
                STATUS_SHORT.get(it.validation_status or "", "Не проверена"),
                SEVERITY_LABELS.get(it.max_severity or "", "—"),
                it.name,
                it.domain,
                it.path,
                fmt_expiry(it.expires_at),
                flags(it),
                it.same_site if it.same_site != "unspecified" else "—",
                value_text(it),
            )[col]
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 0 and it.validation_status:
                return QColor(STATUS_COLORS[it.validation_status])
            if col == 1 and it.max_severity:
                return QColor(SEVERITY_COLORS[it.max_severity])
        if role == Qt.ItemDataRole.ToolTipRole and col == 0 and it.validation_status:
            return STATUS_LABELS[it.validation_status]
        if role == Qt.ItemDataRole.UserRole:
            return it.id
        return None

    def item(self, row: int) -> CookieListItem:
        return self.rows[row]
