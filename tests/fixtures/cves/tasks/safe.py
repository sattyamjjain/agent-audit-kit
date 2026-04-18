"""Safe MCP Tasks fixture: owner checks, TTL, cancel path, zeroization."""

from datetime import datetime, timedelta


class Task:
    def __init__(self, task_id: str, owner: str, api_key: str):
        self.task_id = task_id
        self.owner = owner
        self.api_key = api_key
        self.status = "working"
        self.expires_at = datetime.utcnow() + timedelta(hours=1)

    def mark_completed(self):
        self.status = "completed"
        self.api_key = None  # zeroize on terminal state

    def cancel_task(self):
        self.status = "cancelled"
        self.api_key = None


class TaskStore:
    def __init__(self):
        self._rows: dict[str, Task] = {}

    def read_task(self, task_id: str, caller_id: str) -> Task:
        task = self._rows[task_id]
        if task.owner != caller_id:
            raise PermissionError("not owner")
        return task
