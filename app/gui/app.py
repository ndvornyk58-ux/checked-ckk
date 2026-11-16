"""Запуск графического интерфейса."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication, QMessageBox

from app.app_context import Workspace
from app.gui.dialogs.vault import VaultDialog, unlock_without_dialog
from app.gui.shell.main_window import MainWindow
from app.gui.theming import THEMES, stylesheet


def build_palette(name: str) -> QPalette:
    """Палитра Qt из токенов темы: её используют виджеты, которых не касается QSS (HTML, флажки)."""
    t = THEMES.get(name, THEMES["dark"])
    qp = QPalette()
    roles = {
        QPalette.ColorRole.Window: t.base,
        QPalette.ColorRole.WindowText: t.text,
        QPalette.ColorRole.Base: t.surface,
        QPalette.ColorRole.AlternateBase: t.raised,
        QPalette.ColorRole.Text: t.text,
        QPalette.ColorRole.Button: t.raised,
        QPalette.ColorRole.ButtonText: t.text,
        QPalette.ColorRole.Highlight: t.selection,
        QPalette.ColorRole.HighlightedText: t.text,
        QPalette.ColorRole.ToolTipBase: t.surface,
        QPalette.ColorRole.ToolTipText: t.text,
        QPalette.ColorRole.PlaceholderText: t.muted,
        QPalette.ColorRole.Mid: t.border,
        QPalette.ColorRole.Link: t.accent,
        QPalette.ColorRole.BrightText: t.text,
        QPalette.ColorRole.Light: t.raised,
        QPalette.ColorRole.Dark: t.border,
        QPalette.ColorRole.Shadow: t.base,
    }
    for role, color in roles.items():
        qp.setColor(role, QColor(color))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.WindowText, QPalette.ColorRole.ButtonText):
        qp.setColor(QPalette.ColorGroup.Disabled, role, QColor(t.muted))
    return qp


def apply_theme(app: QApplication, name: str) -> None:
    app.setPalette(build_palette(name))
    app.setStyleSheet(stylesheet(THEMES.get(name, THEMES["dark"])))


def create_app(argv: list[str] | None = None) -> QApplication:
    app = QApplication.instance() or QApplication(argv or sys.argv)
    if not isinstance(app, QApplication):
        raise RuntimeError("Уже создан QCoreApplication без поддержки окон")
    app.setApplicationName("Cookie Inspector Pro")
    app.setStyle("Fusion")
    f = QFont()
    f.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(f)
    return app


def open_vault(ws: Workspace) -> bool:
    """Разблокировать хранилище: молча через keyring или через диалог. False — пользователь вышел."""
    error = unlock_without_dialog(ws)
    if ws.unlocked:
        return True
    if error:
        QMessageBox.warning(
            None,
            "Cookie Inspector Pro",
            f"Не удалось получить ключ из системного хранилища: {error}\n\nРабота со значениями cookies недоступна.",
        )
        return False
    return bool(VaultDialog(ws).exec())


def run_gui(ws: Workspace) -> int:
    app = create_app()
    apply_theme(app, ws.settings.get("theme") or "dark")
    if not open_vault(ws):
        return 1
    win = MainWindow(ws, apply_theme=lambda name: apply_theme(app, name))
    win.show()
    return app.exec()


__all__ = ["Qt", "apply_theme", "create_app", "run_gui"]
