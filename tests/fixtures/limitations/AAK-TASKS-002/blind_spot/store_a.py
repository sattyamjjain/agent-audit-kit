class TaskStore:
    def __init__(self, access_token):
        self.access_token = access_token
        self.state = "running"

    def finish(self):
        self.state = "completed"
