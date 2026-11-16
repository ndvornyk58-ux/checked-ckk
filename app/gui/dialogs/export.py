"""Диалог экспорта: формат, столбцы, выгрузка значений (по умолчанию выключена)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from app.services.export import COLUMN_LABELS, DEFAULT_COLUMNS, Column, ExportFormat, ExportOptions

FORMAT_LABELS = {
    ExportFormat.CSV: "CSV (Excel, таблицы)",
    ExportFormat.XLSX: "Excel (.xlsx)",
    ExportFormat.JSON: "JSON",
    ExportFormat.JSONL: "JSON Lines",
    ExportFormat.HTML: "HTML-отчёт",
    ExportFormat.PDF: "PDF-отчёт",
}


class ExportDialog(QDialog):
    def __init__(self, count: int, unlocked: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Экспорт")
        self.setMinimumWidth(460)
        self._path: Path | None = None
        lay = QVBoxLayout(self)
        info = QLabel(f"Будет выгружено записей по текущему фильтру: {count}.")
        info.setProperty("role", "muted")
        lay.addWidget(info)

        form = QFormLayout()
        self.format = QComboBox()
        for fmt, label in FORMAT_LABELS.items():
            self.format.addItem(label, fmt.value)
        self.title = QLineEdit("Отчёт по cookies")
        form.addRow("Формат", self.format)
        form.addRow("Заголовок отчёта", self.title)
        lay.addLayout(form)

        box = QGroupBox("Столбцы")
        grid = QGridLayout(box)
        self.columns: dict[Column, QCheckBox] = {}
        for i, col in enumerate(Column):
            cb = QCheckBox(COLUMN_LABELS[col])
            cb.setChecked(col in DEFAULT_COLUMNS)
            if col is Column.VALUE:
                cb.setChecked(False)
                cb.setEnabled(False)  # включается только вместе с «показать значения»
            self.columns[col] = cb
            grid.addWidget(cb, i // 3, i % 3)
        lay.addWidget(box)

        self.reveal = QCheckBox("Выгрузить значения cookies в открытом виде")
        self.reveal.setEnabled(unlocked)
        self.reveal_note = QLabel(
            "Значения по умолчанию маскируются. Открытая выгрузка записывается в журнал операций; "
            "храните такой файл как секрет."
            if unlocked
            else "Чтобы выгрузить значения, разблокируйте хранилище."
        )
        self.reveal_note.setWordWrap(True)
        self.reveal_note.setProperty("role", "muted")
        lay.addWidget(self.reveal)
        lay.addWidget(self.reveal_note)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Выбрать файл и экспортировать")
        lay.addWidget(buttons)
        buttons.accepted.connect(self._choose)
        buttons.rejected.connect(self.reject)
        self.reveal.toggled.connect(self._reveal_toggled)

    def _reveal_toggled(self, on: bool) -> None:
        self.columns[Column.VALUE].setEnabled(on)
        self.columns[Column.VALUE].setChecked(on)

    def _selected_format(self) -> ExportFormat:
        return ExportFormat(self.format.currentData())

    def _choose(self) -> None:
        fmt = self._selected_format()
        filters = {
            ExportFormat.CSV: "CSV (*.csv)",
            ExportFormat.XLSX: "Excel (*.xlsx)",
            ExportFormat.JSON: "JSON (*.json)",
            ExportFormat.JSONL: "JSON Lines (*.jsonl)",
            ExportFormat.HTML: "HTML (*.html)",
            ExportFormat.PDF: "PDF (*.pdf)",
        }
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить экспорт", f"cookies{fmt.extension}", filters[fmt])
        if path:
            self._path = Path(path)
            self.accept()

    def result_path(self) -> Path | None:
        return self._path

    def options(self) -> ExportOptions:
        cols = tuple(c for c, cb in self.columns.items() if cb.isChecked() and cb.isEnabled()) or DEFAULT_COLUMNS
        return ExportOptions(
            fmt=self._selected_format(),
            columns=cols,
            reveal_values=self.reveal.isChecked(),
            title=self.title.text().strip() or "Отчёт по cookies",
        )
