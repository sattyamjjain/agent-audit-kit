"""Vulnerable MCP Tasks fixture (SEP-1686 leakage)."""


class Task:
    def __init__(self, task_id: str, api_key: str):
        self.task_id = task_id
        self.api_key = api_key
        self.status = "working"

    def mark_completed(self):
        self.status = "completed"

    def mark_failed(self):
        self.status = "failed"


class TaskStore:
    def __init__(self):
        self._rows: dict[str, Task] = {}

    def read_task(self, task_id: str) -> Task:
        return self._rows[task_id]
