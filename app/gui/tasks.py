"""Фоновые задачи для GUI: тяжёлые вызовы сервисов никогда не выполняются в главном потоке.

Результат, ошибка и прогресс приходят в главный поток через сигналы Qt (queued connection).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

log = logging.getLogger(__name__)


class _Signals(QObject):
    progress = Signal(object)
    finished = Signal(object)
    failed = Signal(object)


class Task(QRunnable):
    """Выполняет ``fn(progress=emit)`` в пуле потоков. ``fn`` получает функцию для отчёта о прогрессе."""

    def __init__(self, fn: Callable[[Callable[[Any], None]], Any]) -> None:
        super().__init__()
        self.signals = _Signals()
        self._fn = fn
        self.setAutoDelete(False)  # Python держит ссылку до завершения (см. TaskRunner)

    def run(self) -> None:
        try:
            result = self._fn(self.signals.progress.emit)
        except Exception as exc:
            log.exception("Фоновая задача завершилась ошибкой")
            self.signals.failed.emit(exc)
        else:
            self.signals.finished.emit(result)


class TaskRunner(QObject):
    """Запуск задач с удержанием ссылок до завершения."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pool = QThreadPool.globalInstance()
        self._active: set[Task] = set()

    def start(
        self,
        fn: Callable[[Callable[[Any], None]], Any],
        *,
        on_done: Callable[[Any], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
        on_progress: Callable[[Any], None] | None = None,
    ) -> Task:
        task = Task(fn)
        self._active.add(task)

        def done(result: Any) -> None:
            self._active.discard(task)
            if on_done:
                on_done(result)

        def fail(exc: Exception) -> None:
            self._active.discard(task)
            if on_error:
                on_error(exc)

        task.signals.finished.connect(done)
        task.signals.failed.connect(fail)
        if on_progress:
            task.signals.progress.connect(on_progress)
        self._pool.start(task)
        return task

    @property
    def busy(self) -> bool:
        return bool(self._active)

    def wait(self, msecs: int = 30000) -> bool:
        return self._pool.waitForDone(msecs)
