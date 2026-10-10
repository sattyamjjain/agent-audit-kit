"""The docs only name pre-commit hook ids that .pre-commit-hooks.yaml defines.

docs/ci-cd.md told users to add `id: agent-audit-kit-strict`, a hook this repo
never defined, so `pre-commit install` failed for anyone who copied the block.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

# An active (uncommented) `- id: agent-audit-kit...` line in a hooks list.
_HOOK_ID_RE = re.compile(r"^\s*-\s*id:\s*(agent-audit-kit[\w-]*)\s*$", re.MULTILINE)


def _defined_ids() -> set[str]:
    hooks = yaml.safe_load((REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    return {hook["id"] for hook in hooks}


def _documents() -> list[Path]:
    docs = [
        REPO_ROOT / "README.md",
        *sorted((REPO_ROOT / "docs").rglob("*.md")),
        *sorted((REPO_ROOT / "examples").rglob("*.yaml")),
        *sorted((REPO_ROOT / "examples").rglob("*.yml")),
    ]
    return [doc for doc in docs if doc.is_file()]


def test_every_documented_hook_id_exists() -> None:
    defined = _defined_ids()
    unknown = [
        f"{doc.relative_to(REPO_ROOT)}: {match.group(1)}"
        for doc in _documents()
        for match in _HOOK_ID_RE.finditer(doc.read_text(encoding="utf-8"))
        if match.group(1) not in defined
    ]
    assert not unknown, f"hook ids missing from .pre-commit-hooks.yaml: {unknown}"


def test_the_docs_name_at_least_one_hook() -> None:
    """Guard the guard: a regex that matches nothing would pass the test above."""
    assert any(_HOOK_ID_RE.search(doc.read_text(encoding="utf-8")) for doc in _documents())
