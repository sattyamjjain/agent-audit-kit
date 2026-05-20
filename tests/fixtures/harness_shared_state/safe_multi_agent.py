"""Safe: 2 Agent classes mutate shared dict but both acquire a Lock."""
from __future__ import annotations

import threading


_SHARED: dict = {}
_LOCK = threading.Lock()


class ReaderAgent:
    def push(self, key: str, value: str) -> None:
        with _LOCK:
            _SHARED[key] = value


class WriterAgent:
    def update(self, key: str, value: str) -> None:
        with _LOCK:
            _SHARED.update({key: value})
