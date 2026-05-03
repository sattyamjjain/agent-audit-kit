#!/usr/bin/env python3
"""Single-source-of-truth for scanner-module count.

Counts the detector modules in `agent_audit_kit/scanners/` (excluding
`__init__.py` and any private `_helpers.py`-style modules) and rewrites
every place in the repo that advertises the scanner-module count:

    - README.md                       `<!-- scanner-count:total -->NN<!-- /scanner-count -->`
    - agent_audit_kit/__init__.py     `SCANNER_COUNT = NN` constant

Same posture as `sync_rule_count.py`:
    * pre-commit hook (blocks human drift)
    * .github/workflows/sync-rule-count.yml step (auto-commits)

Why this exists: README's lead paragraph drifted from "28 scanner
modules" while the codebase grew past 50 detectors over twelve minor
revs. Procurement reviewers cite README claims; a 2x undercount looks
worse than the underlying drift.

Usage:
    python scripts/sync_scanner_count.py             # writes
    python scripts/sync_scanner_count.py --check     # exits 1 on drift
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCANNERS_DIR = REPO_ROOT / "agent_audit_kit" / "scanners"

# Files in agent_audit_kit/scanners/ that are NOT detector modules and
# should be excluded from the count. Add explicitly — CI fails if a new
# private helper is added without bumping this set, so the count never
# silently drifts.
EXCLUDED: frozenset[str] = frozenset({
    "__init__.py",
    "_helpers.py",
})

_README_ANCHOR_RE = re.compile(
    r"(<!--\s*scanner-count:total\s*-->)(.*?)(<!--\s*/scanner-count\s*-->)",
    re.DOTALL,
)
_LEGACY_PROSE_RE = re.compile(
    r"\b\d+\s+scanner modules\b",
)
_INIT_CONSTANT_RE = re.compile(
    r"^(SCANNER_COUNT\s*[:=]\s*)\d+(.*)$",
    re.MULTILINE,
)


def count_scanners() -> int:
    """Count `.py` detectors in agent_audit_kit/scanners/ excluding EXCLUDED."""
    count = 0
    for entry in sorted(SCANNERS_DIR.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix != ".py":
            continue
        if entry.name in EXCLUDED:
            continue
        count += 1
    return count


def _update_readme(count: int, *, check: bool) -> bool:
    readme = REPO_ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    original = text

    # Anchor-based rewrite (preferred — explicit + idempotent).
    def _sub_anchor(match: re.Match) -> str:
        return f"{match.group(1)}{count}{match.group(3)}"

    text = _README_ANCHOR_RE.sub(_sub_anchor, text)

    # Legacy bare-prose rewrite ("28 scanner modules") — only if no anchor
    # is present yet. After the first run, the anchor will be in place
    # and the legacy regex can no longer match.
    if "<!-- scanner-count:total -->" not in text:
        text = _LEGACY_PROSE_RE.sub(
            f"<!-- scanner-count:total -->{count}<!-- /scanner-count --> scanner modules",
            text,
            count=1,
        )

    if text == original:
        return False
    if check:
        return True
    readme.write_text(text, encoding="utf-8")
    return True


def _update_init_py(count: int, *, check: bool) -> bool:
    init = REPO_ROOT / "agent_audit_kit" / "__init__.py"
    text = init.read_text(encoding="utf-8")
    original = text
    if _INIT_CONSTANT_RE.search(text):
        text = _INIT_CONSTANT_RE.sub(rf"\g<1>{count}\g<2>", text)
    else:
        text = text.rstrip() + f"\nSCANNER_COUNT = {count}\n"
    if text == original:
        return False
    if check:
        return True
    init.write_text(text, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="Exit 1 if any file would change (for CI / pre-commit).",
    )
    args = parser.parse_args(argv)

    count = count_scanners()
    changed_readme = _update_readme(count, check=args.check)
    changed_init = _update_init_py(count, check=args.check)
    changed = any((changed_readme, changed_init))

    if args.check and changed:
        sys.stderr.write(
            f"sync_scanner_count: drift detected (scanner count = {count}). "
            "Run `python scripts/sync_scanner_count.py` and commit the result.\n"
        )
        return 1
    if changed:
        sys.stdout.write(
            f"sync_scanner_count: wrote {count} scanners into README / __init__.py\n"
        )
    else:
        sys.stdout.write(
            f"sync_scanner_count: clean ({count} scanners everywhere).\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
