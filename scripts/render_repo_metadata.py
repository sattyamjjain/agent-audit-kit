#!/usr/bin/env python3
"""Render the GitHub repo description from ``RULE_COUNT``.

Reads ``.github/repo-metadata.yml``'s ``description_template`` and substitutes the
live ``agent_audit_kit.RULE_COUNT`` into it, printing the final string to stdout.
This is the machine-readable source of truth for the repo description so the count
on github.com can never drift from the code again (it drifted to 271 while the code
said 274).

Dependency-free on purpose (no PyYAML): the template is a single ``>-`` folded
block scalar, which we fold by hand so this runs in any clean checkout.

    python scripts/render_repo_metadata.py

We do NOT write the description to GitHub from here — that needs repo-admin rights a
CI token does not have. Paste the printed string into repo Settings when RULE_COUNT
changes (CONTRIBUTING.md "Release checklist").
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_METADATA = _REPO / ".github" / "repo-metadata.yml"


def load_description_template(text: str) -> str:
    """Extract the ``description_template`` ``>-`` folded block scalar, folded.

    A ``>-`` scalar folds each run of non-empty, more-indented lines into a single
    space-joined line and chomps the trailing newline — which for a one-paragraph
    template is exactly ``" ".join(stripped_non_empty_lines)``.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^description_template:\s*>-\s*$", line):
            block: list[str] = []
            for cont in lines[i + 1:]:
                if cont.strip() == "":
                    break
                if not cont.startswith((" ", "\t")):  # dedent ends the block
                    break
                block.append(cont.strip())
            if not block:
                break
            return " ".join(block)
    raise SystemExit(
        f"description_template (a `>-` block scalar) not found in {_METADATA}"
    )


def render() -> str:
    """The final repo description with ``{RULE_COUNT}`` substituted."""
    from agent_audit_kit import RULE_COUNT

    template = load_description_template(_METADATA.read_text(encoding="utf-8"))
    return template.replace("{RULE_COUNT}", str(RULE_COUNT))


def main() -> int:
    sys.stdout.write(render() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
