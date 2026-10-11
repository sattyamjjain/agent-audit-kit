class TaskStore:
    def __init__(self, api_key):
        self.api_key = api_key
        self.state = "running"

    def reset(self):
        self.api_key = None

    def finish(self):
        self.state = "completed"
