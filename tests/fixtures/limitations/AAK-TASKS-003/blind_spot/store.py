class TaskStore:
    def __init__(self, cache):
        self.items = {}
        self.cache = cache

    def add(self, task_id, payload):
        self.items[task_id] = payload
        self.cache.set(task_id, payload, ttl=60)
