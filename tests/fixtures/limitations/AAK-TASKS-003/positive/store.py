class TaskStore:
    def __init__(self):
        self.items = {}

    def add(self, task_id, payload):
        self.items[task_id] = payload
