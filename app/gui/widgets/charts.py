"""Графики, нарисованные QPainter: без зависимостей и одинаково в обеих темах."""

from __future__ import annotations

from datetime import date

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter, QPaintEvent
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from app.gui.theming import STATUS_COLORS, STATUS_LABELS

STATUS_ORDER = ("valid", "warning", "expired", "invalid", "security_issue", "unknown")


class SpectrumBar(QWidget):
    """Полоса долей статусов — главный визуальный элемент обзора.

    Ширина сегмента пропорциональна числу записей; наведение показывает подпись.
    Записи без проверки показываются отдельным приглушённым сегментом.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.counts: dict[str, int] = {}
        self.not_analyzed = 0
        self.setMinimumHeight(28)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMouseTracking(True)
        self._segments: list[tuple[QRectF, str]] = []

    def set_data(self, counts: dict[str, int], not_analyzed: int) -> None:
        self.counts, self.not_analyzed = counts, not_analyzed
        self.update()

    def sizeHint(self) -> QSize:
        return QSize(400, 28)

    def total(self) -> int:
        return sum(self.counts.values()) + self.not_analyzed

    def paintEvent(self, _e: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0, 4, 0, -4)
        muted = self.palette().mid().color()
        total = self.total()
        self._segments = []
        if total == 0:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(muted)
            p.drawRoundedRect(r, 4, 4)
            return
        x = r.left()
        items = [(k, self.counts.get(k, 0)) for k in STATUS_ORDER] + [("not_analyzed", self.not_analyzed)]
        items = [(k, n) for k, n in items if n]
        for i, (key, n) in enumerate(items):
            w = r.width() * n / total if i < len(items) - 1 else r.right() - x
            seg = QRectF(x, r.top(), max(w, 2.0), r.height())
            color = QColor(STATUS_COLORS.get(key, muted.name()))
            if key == "not_analyzed":
                color = muted
            p.fillRect(seg.adjusted(0, 0, -1 if i < len(items) - 1 else 0, 0), color)
            self._segments.append((seg, key))
            x += w

    def segment_at(self, x: float) -> str | None:
        return next((k for rect, k in self._segments if rect.left() <= x <= rect.right()), None)

    def mouseMoveEvent(self, e) -> None:  # type: ignore[no-untyped-def]
        key = self.segment_at(e.position().x())
        if key is None:
            QToolTip.hideText()
            return
        n = self.not_analyzed if key == "not_analyzed" else self.counts.get(key, 0)
        label = "Не проверены" if key == "not_analyzed" else STATUS_LABELS[key]
        QToolTip.showText(
            e.globalPosition().toPoint(), f"{label}: {n:,} ({n * 100 / self.total():.1f} %)".replace(",", " "), self
        )


class ActivityChart(QWidget):
    """Столбики операций по дням."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.points: list[tuple[date, int]] = []
        self.setMinimumHeight(90)
        self.accent = QColor("#4FB3BF")

    def set_data(self, points: list[tuple[date, int]]) -> None:
        self.points = points
        self.setToolTip("\n".join(f"{d:%d.%m}: {n}" for d, n in points if n) or "За период операций не было")
        self.update()

    def paintEvent(self, _e: QPaintEvent) -> None:
        if not self.points:
            return
        p = QPainter(self)
        r = QRectF(self.rect()).adjusted(0, 4, 0, -18)
        peak = max(n for _, n in self.points) or 1
        step = r.width() / len(self.points)
        muted = self.palette().mid().color()
        text = self.palette().placeholderText().color()
        for i, (d, n) in enumerate(self.points):
            h = max(2.0, r.height() * n / peak) if n else 2.0
            bar = QRectF(r.left() + i * step + step * 0.2, r.bottom() - h, step * 0.6, h)
            p.fillRect(bar, self.accent if n else muted)
            if i in (0, len(self.points) - 1):
                p.setPen(text)
                p.drawText(
                    QRectF(bar.left() - 10, r.bottom() + 2, bar.width() + 20, 14),
                    Qt.AlignmentFlag.AlignHCenter,
                    f"{d:%d.%m}",
                )
