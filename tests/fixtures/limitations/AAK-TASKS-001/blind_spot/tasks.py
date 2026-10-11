TASKS = {}


def get_task(task_id):
    task = TASKS[task_id]
    return {"id": task_id, "owner": task["owner"], "state": task["state"]}
