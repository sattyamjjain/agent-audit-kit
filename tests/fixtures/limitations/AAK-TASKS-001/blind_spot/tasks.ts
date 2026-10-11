const tasks = new Map<string, unknown>();

export async function getTask(taskId: string) {
  return tasks.get(taskId);
}

export const route = "/tasks/:task_id";
