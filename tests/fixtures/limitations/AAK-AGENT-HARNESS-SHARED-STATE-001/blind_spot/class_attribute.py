class BaseAgent:
    registry: dict = {}


class ReaderAgent(BaseAgent):
    def push(self, key: str, value: str) -> None:
        self.registry[key] = value


class WriterAgent(BaseAgent):
    def update(self, key: str, value: str) -> None:
        self.registry.update({key: value})
