"""Safe: @skill mutates persistent state AND records outcome."""
from __future__ import annotations

from pathlib import Path


def skill(fn):
    return fn


def record_outcome(**kwargs) -> None:
    return None


@skill
def execute(task_id: str, output_path: str) -> str:
    Path(output_path).write_text(f"result for {task_id}\n")
    record_outcome(skill_id="execute", outcome="success", signals={"task_id": task_id})
    return "done"
