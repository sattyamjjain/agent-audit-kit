class TaskStore:
    def __init__(self):
        self.items = {}


def create_task(store, payload):
    store.items[len(store.items)] = payload

# TODO: add a per-caller quota
