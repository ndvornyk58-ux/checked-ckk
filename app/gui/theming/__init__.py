"""Дизайн-токены и генерация QSS.

Принцип палитры: интерактивный акцент (бирюзовый) используется только для того, что
можно нажать или что выбрано. Тёплые и красные тона зарезервированы за статусами
проверки — цвет в интерфейсе всегда что-то означает.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.domain.presentation import (
    SEVERITY_COLORS as SEVERITY_COLORS,
)
from app.domain.presentation import (
    SEVERITY_LABELS as SEVERITY_LABELS,
)
from app.domain.presentation import (
    STATUS_COLORS as STATUS_COLORS,
)
from app.domain.presentation import (
    STATUS_LABELS as STATUS_LABELS,
)


@dataclass(frozen=True, slots=True)
class Palette:
    name: str
    base: str  # фон окна
    surface: str  # панели
    raised: str  # поля ввода, строки при наведении
    border: str
    text: str
    muted: str
    accent: str  # интерактивное
    accent_text: str  # текст на акценте
    selection: str


DARK: Final = Palette(
    "dark", "#1B2129", "#232B35", "#2C3642", "#3A4654", "#DCE3EA", "#8A97A6", "#4FB3BF", "#0E2A2E", "#2F5560"
)
LIGHT: Final = Palette(
    "light", "#EEF1F4", "#FFFFFF", "#F5F7F9", "#C9D1DA", "#1D2733", "#5C6B7A", "#1F7F8B", "#FFFFFF", "#CDE9EC"
)
THEMES: Final = {"dark": DARK, "light": LIGHT}

# Цвета статусов одинаковы по смыслу в обеих темах; подобраны для контраста на обоих фонах.
FONT_STACK: Final = '"Segoe UI", "Inter", "Noto Sans", "Helvetica Neue", Arial, sans-serif'


def stylesheet(p: Palette) -> str:
    """QSS приложения. Селекторы по objectName/свойствам — без каскадных конфликтов."""
    return f"""
* {{ font-family: {FONT_STACK}; font-size: 10pt; color: {p.text}; }}
QMainWindow, QDialog {{ background: {p.base}; }}
QWidget#page {{ background: {p.base}; }}
QLabel[role="muted"] {{ color: {p.muted}; }}
QLabel[role="h1"] {{ font-size: 17pt; font-weight: 600; }}
QLabel[role="h2"] {{ font-size: 12pt; font-weight: 600; }}
QLabel[role="metric"] {{ font-size: 20pt; font-weight: 600; }}

QFrame#sidebar {{ background: {p.surface}; border-right: 1px solid {p.border}; }}
QLabel#brand {{ font-size: 12pt; font-weight: 600; padding: 18px 16px 14px 16px; }}
QPushButton[nav="true"] {{
    text-align: left; padding: 9px 16px; border: none; border-left: 3px solid transparent;
    background: transparent; color: {p.muted}; border-radius: 0;
}}
QPushButton[nav="true"]:hover {{ color: {p.text}; background: {p.raised}; }}
QPushButton[nav="true"]:checked {{ color: {p.text}; border-left-color: {p.accent}; background: {p.raised}; }}
QPushButton[nav="true"]:focus:!checked {{ border-left-color: transparent; color: {p.text}; }}

QFrame#topbar {{ background: {p.base}; border-bottom: 1px solid {p.border}; }}
QFrame[card="true"] {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 6px; }}

QPushButton {{
    background: {p.raised}; border: 1px solid {p.border}; border-radius: 4px; padding: 6px 14px;
}}
QPushButton:hover {{ border-color: {p.accent}; }}
QPushButton:focus {{ border-color: {p.accent}; }}
QPushButton:disabled {{ color: {p.muted}; border-color: {p.border}; }}
QPushButton[primary="true"] {{ background: {p.accent}; color: {p.accent_text}; border-color: {p.accent};
    font-weight: 600; }}
QPushButton[primary="true"]:disabled {{ background: {p.raised}; color: {p.muted}; border-color: {p.border}; }}
QPushButton[danger="true"] {{ color: {STATUS_COLORS["invalid"]}; }}

QTextBrowser {{ background: {p.surface}; border: none; color: {p.text}; }}
QLineEdit, QComboBox, QSpinBox, QDateTimeEdit, QPlainTextEdit {{
    background: {p.raised}; border: 1px solid {p.border}; border-radius: 4px; padding: 5px 8px;
    selection-background-color: {p.selection};
}}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QDateTimeEdit:focus {{ border-color: {p.accent}; }}
QComboBox QAbstractItemView {{ background: {p.surface}; border: 1px solid {p.border};
    selection-background-color: {p.selection}; }}
QCheckBox {{ spacing: 8px; }}

QTableView, QListWidget, QTreeWidget {{
    background: {p.surface}; alternate-background-color: {p.raised}; border: 1px solid {p.border};
    border-radius: 4px; gridline-color: transparent; selection-background-color: {p.selection};
    selection-color: {p.text};
}}
QHeaderView::section {{ background: {p.surface}; color: {p.muted}; border: none;
    border-bottom: 1px solid {p.border}; padding: 6px 8px; font-weight: 600; }}
QTableView::item {{ padding: 4px 8px; }}
QListWidget::item {{ padding: 4px 8px; }}
QFrame[divider="true"] {{ background: {p.border}; }}

QProgressBar {{ background: {p.raised}; border: 1px solid {p.border}; border-radius: 4px; height: 8px;
    text-align: center; color: transparent; }}
QProgressBar::chunk {{ background: {p.accent}; border-radius: 3px; }}

QSplitter::handle {{ background: {p.border}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; }}
QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 4px; min-height: 24px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; }}
QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 4px; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QStatusBar {{ background: {p.surface}; color: {p.muted}; border-top: 1px solid {p.border}; }}
QToolTip {{ background: {p.surface}; color: {p.text}; border: 1px solid {p.border}; padding: 4px; }}
QMenu {{ background: {p.surface}; border: 1px solid {p.border}; padding: 4px; }}
QMenu::item {{ padding: 6px 20px; }}
QMenu::item:selected {{ background: {p.selection}; }}
QFrame#toast {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: 6px; }}
QFrame#dropzone {{ background: {p.surface}; border: 2px dashed {p.border}; border-radius: 8px; }}
QFrame#dropzone[active="true"] {{ border-color: {p.accent}; background: {p.raised}; }}
"""
