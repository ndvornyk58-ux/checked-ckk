"""Неблокирующие уведомления в правом нижнем углу окна."""

from __future__ import annotations

from typing import Final

import shiboken6
from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer
from PySide6.QtWidgets import QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QWidget

from app.gui.theming import SEVERITY_COLORS, STATUS_COLORS

KIND_COLORS: Final = {
    "info": "#4FB3BF",
    "success": STATUS_COLORS["valid"],
    "warning": STATUS_COLORS["warning"],
    "error": SEVERITY_COLORS["critical"],
}


class Toast(QFrame):
    def __init__(self, parent: QWidget, text: str, kind: str, timeout_ms: int) -> None:
        super().__init__(parent)
        self.setObjectName("toast")
        self.kind = kind
        self.text = text
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 14, 0)
        bar = QFrame(self)
        bar.setFixedWidth(4)
        bar.setStyleSheet(f"background:{KIND_COLORS.get(kind, KIND_COLORS['info'])};border-radius:2px;")
        lay.addWidget(bar)
        label = QLabel(text, self)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        label.setContentsMargins(10, 10, 0, 10)
        lay.addWidget(label, 1)
        self.setMaximumWidth(420)
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        QTimer.singleShot(timeout_ms, self.dismiss)

    def appear(self) -> None:
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self.show()
        self._anim.start()

    def dismiss(self) -> None:
        self._anim.setStartValue(self._effect.opacity())
        self._anim.setEndValue(0.0)
        self._anim.finished.connect(self.deleteLater)
        self._anim.start()


class Notifier:
    """Стопка уведомлений поверх окна. Ошибки висят дольше, чем информационные сообщения."""

    def __init__(self, host: QWidget) -> None:
        self._host = host
        self._toasts: list[Toast] = []
        self.history: list[tuple[str, str]] = []

    def show(self, text: str, kind: str = "info") -> None:
        self.history.append((kind, text))
        timeout = 9000 if kind == "error" else 4500
        t = Toast(self._host, text, kind, timeout)
        t.destroyed.connect(lambda *_: self._forget(t))
        self._toasts.append(t)
        t.adjustSize()
        self.relayout()
        t.appear()

    def _forget(self, t: Toast) -> None:
        if t in self._toasts:
            self._toasts.remove(t)
        self.relayout()

    def relayout(self) -> None:
        if not shiboken6.isValid(self._host):
            return  # окно уже закрыто — уведомления удаляются вместе с ним
        y = self._host.height() - 44
        for t in reversed(self._toasts):
            t.adjustSize()
            y -= t.height()
            t.move(self._host.width() - t.width() - 20, y)
            t.raise_()
            y -= 8
