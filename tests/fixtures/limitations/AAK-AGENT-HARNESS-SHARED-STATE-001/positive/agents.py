_SHARED: dict = {}


class ReaderAgent:
    def push(self, key: str, value: str) -> None:
        _SHARED[key] = value


class WriterAgent:
    def update(self, key: str, value: str) -> None:
        _SHARED.update({key: value})
