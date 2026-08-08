"""Guard: the rendered GitHub repo description carries the live RULE_COUNT.

The repo `description` field is the highest-traffic surface this project has, and it
was the one place the rule count was never guarded — it drifted to "271 rules" while
the code said 274. `scripts/render_repo_metadata.py` renders it from
`agent_audit_kit.RULE_COUNT` via `.github/repo-metadata.yml`; this test fails the
build if the rendered string ever carries a rule count other than RULE_COUNT.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

from agent_audit_kit import RULE_COUNT

_REPO = Path(__file__).resolve().parent.parent


def _render() -> str:
    spec = importlib.util.spec_from_file_location(
        "render_repo_metadata", _REPO / "scripts" / "render_repo_metadata.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.render()


def test_rendered_description_carries_current_rule_count() -> None:
    desc = _render()
    assert f"{RULE_COUNT} rules" in desc, (
        f"rendered repo description does not say {RULE_COUNT!r} rules:\n  {desc}"
    )
    # No OTHER `<N> rules` may appear — a future drift (274 -> 275 in code but the
    # template/description left at the old number) must fail loudly.
    counts = re.findall(r"(\d+)\s+rules", desc)
    assert counts == [str(RULE_COUNT)], (
        f"rendered repo description carries a rule count other than {RULE_COUNT}: "
        f"found {counts}. Re-render with `python scripts/render_repo_metadata.py` "
        "and paste into repo Settings (CONTRIBUTING.md 'Release checklist')."
    )
