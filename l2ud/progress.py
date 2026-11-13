"""Progresso por etapa e cancelamento seguro (cooperativo) para análises longas."""
from __future__ import annotations

import threading
import time
from typing import Callable


class Cancelled(Exception):
    """Levantada por `CancelToken.check()` quando o usuário cancelou. Nenhum estado parcial é gravado."""


class CancelToken:
    """Cancelamento cooperativo: o código longo chama `check()` entre unidades de trabalho (nunca no meio de uma
    gravação em banco), então cancelar é sempre seguro."""

    def __init__(self) -> None:
        self._ev = threading.Event()

    def cancel(self) -> None:
        self._ev.set()

    @property
    def cancelled(self) -> bool:
        return self._ev.is_set()

    def check(self) -> None:
        if self._ev.is_set():
            raise Cancelled()


NO_CANCEL = CancelToken()


class Progress:
    """Relatório de progresso: `callback(stage, done, total, message)`. `total` pode ser 0 (desconhecido)."""

    def __init__(self, callback: Callable[[str, int, int, str], None] | None = None,
                 cancel: CancelToken | None = None) -> None:
        self.cb = callback
        self.cancel = cancel or NO_CANCEL
        self.stage_name = ""
        self.total = 0
        self.done = 0
        self.timings: dict[str, float] = {}
        self._t0 = time.time()

    def stage(self, name: str, total: int = 0, message: str = "") -> None:
        self.cancel.check()
        if self.stage_name:
            self.timings[self.stage_name] = self.timings.get(self.stage_name, 0.0) + time.time() - self._t0
        self.stage_name, self.total, self.done, self._t0 = name, total, 0, time.time()
        self._emit(message or name)

    def step(self, message: str = "", n: int = 1) -> None:
        self.cancel.check()
        self.done += n
        self._emit(message)

    def finish(self) -> None:
        if self.stage_name:
            self.timings[self.stage_name] = self.timings.get(self.stage_name, 0.0) + time.time() - self._t0
            self.stage_name = ""

    def _emit(self, message: str) -> None:
        if self.cb:
            self.cb(self.stage_name, self.done, self.total, message)
