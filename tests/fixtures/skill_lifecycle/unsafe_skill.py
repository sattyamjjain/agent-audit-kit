"""Vulnerable: @skill mutates persistent state but emits no outcome record."""
from __future__ import annotations

from pathlib import Path


def skill(fn):
    """Stub decorator — fixture only."""
    return fn


@skill
def execute(task_id: str, output_path: str) -> str:
    Path(output_path).write_text(f"result for {task_id}\n")
    return "done"
