_SHARED: dict = {}


class Researcher:
    def push(self, key: str, value: str) -> None:
        _SHARED[key] = value


class Writer:
    def update(self, key: str, value: str) -> None:
        _SHARED.update({key: value})
