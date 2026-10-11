class TaskStore {
  items = new Map<number, unknown>();
}

export function createTask(store: TaskStore, payload: unknown) {
  store.items.set(store.items.size, payload);
}
