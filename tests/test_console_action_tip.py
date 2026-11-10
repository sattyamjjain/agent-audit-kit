"""The console footer's GitHub Action tip must name a ref the repository has.

Through 0.6.32 every console scan ended with `uses: sattyamjjain/agent-audit-kit@v1`.
The repository never had a `v1` tag or branch, so a workflow copied from the tip
failed with "unable to resolve action". The tip now names the running release's
tag, the same ref the README's workflow snippet pins.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit import __version__
from agent_audit_kit.models import ScanResult
from agent_audit_kit.output import console

REPO_ROOT = Path(__file__).resolve().parent.parent
_TIP_RE = re.compile(r"GitHub Action: uses: sattyamjjain/agent-audit-kit@(\S+?)(?:\x1b\[0m)?$", re.M)


def _tip_ref() -> str:
    text = console.format_results(ScanResult())
    refs = _TIP_RE.findall(text)
    assert len(refs) == 1, text
    return refs[0]


def test_action_tip_names_this_release() -> None:
    assert _tip_ref() == f"v{__version__}"


def test_action_tip_matches_the_readme_snippet() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    pinned = re.findall(r"^\s*- uses: sattyamjjain/agent-audit-kit@(\S+)$", readme, re.M)
    assert pinned, "README.md lost its workflow snippet"
    assert _tip_ref() in pinned


def test_action_tip_is_not_the_missing_v1_ref() -> None:
    assert _tip_ref() != "v1"
