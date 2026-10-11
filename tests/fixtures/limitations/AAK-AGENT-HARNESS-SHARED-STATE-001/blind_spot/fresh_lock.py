import threading

_SHARED: dict = {}


class ReaderAgent:
    def push(self, key: str, value: str) -> None:
        with threading.Lock():
            _SHARED[key] = value


class WriterAgent:
    def update(self, key: str, value: str) -> None:
        with threading.Lock():
            _SHARED.update({key: value})
