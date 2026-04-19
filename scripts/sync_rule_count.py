#!/usr/bin/env python3
"""Single-source-of-truth for rule count.

Reads the current signed bundle (or rebuilds it if missing) and rewrites
every place in the repo that advertises a specific rule count:

    - README.md            shields.io badge
    - action.yml           description:
    - agent_audit_kit/__init__.py  RULE_COUNT constant

Idempotent. Exits 0 when nothing needs changing, 0 when files were updated.
Exits 1 if the bundle can't be read or the regex anchor isn't found.

Runs as:
    * pre-commit hook (blocks human drift)
    * .github/workflows/sync-rule-count.yml (auto-commits after rules.json changes)

Usage:
    python scripts/sync_rule_count.py                # uses ./rules.json
    python scripts/sync_rule_count.py --bundle PATH  # explicit
    python scripts/sync_rule_count.py --regenerate   # (re)build bundle first
    python scripts/sync_rule_count.py --check        # fail if drift detected
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BUNDLE = REPO_ROOT / "rules.json"

_README_BADGE_RE = re.compile(
    r"(img\.shields\.io/badge/rules-)\d+(-[a-z]+\.svg)"
)
# HTML-comment anchors are the canonical place the badge/phrase/total
# writes hit. Anything NOT inside an anchor is manual prose that we will
# not silently rewrite (the A2A "12 rules" cell on README line 320
# collided with the old phrase regex — we are not doing that again).
_README_ANCHOR_RE = re.compile(
    r"(<!--\s*rule-count:total\s*-->)(.*?)(<!--\s*/rule-count\s*-->)",
    re.DOTALL,
)
_INIT_CONSTANT_RE = re.compile(
    r"^(RULE_COUNT\s*[:=]\s*)\d+(.*)$",
    re.MULTILINE,
)


def _load_rule_count(bundle: pathlib.Path, regenerate: bool) -> int:
    """Read rule count from the bundle (or regenerate then read)."""
    if regenerate or not bundle.is_file():
        # Prefer a clean rebuild via the public API — keeps the bundle in
        # lockstep with the code even if the on-disk rules.json is stale.
        from agent_audit_kit.bundle import write_bundle
        write_bundle(bundle)
    data = json.loads(bundle.read_text(encoding="utf-8"))
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise SystemExit(f"Invalid rule bundle at {bundle}: missing 'rules' list")
    return len(rules)


def _update_readme(count: int, *, check: bool) -> bool:
    """Rewrite the badge URL + every `<!-- rule-count:total -->...<!-- /rule-count -->`
    anchor. Also keep the shields alt-text in lockstep with the badge."""
    readme = REPO_ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    original = text
    text = _README_BADGE_RE.sub(rf"\g<1>{count}\g<2>", text)
    text = re.sub(r"alt=\"Rules:\s*\d+\"", f'alt="Rules: {count}"', text)

    def _sub_anchor(match: re.Match) -> str:
        return f"{match.group(1)}{count}{match.group(3)}"

    text = _README_ANCHOR_RE.sub(_sub_anchor, text)
    if text == original:
        return False
    if check:
        return True
    readme.write_text(text, encoding="utf-8")
    return True


def _update_action_yml(count: int, *, check: bool) -> bool:
    action = REPO_ROOT / "action.yml"
    text = action.read_text(encoding="utf-8")
    original = text
    new_desc = (
        f"'AgentAuditKit — MCP Security Scan ({count} rules, "
        "OWASP Agentic Top 10 + MCP Top 10)'"
    )
    # Only rewrite the top-level `description:` line (the first one we see).
    pattern = re.compile(r"^description:\s*.+$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        raise SystemExit("Could not find a top-level 'description:' line in action.yml")
    text = pattern.sub(f"description: {new_desc}", text, count=1)
    if text == original:
        return False
    if check:
        return True
    action.write_text(text, encoding="utf-8")
    return True


def _update_init_py(count: int, *, check: bool) -> bool:
    init = REPO_ROOT / "agent_audit_kit" / "__init__.py"
    text = init.read_text(encoding="utf-8")
    original = text
    if _INIT_CONSTANT_RE.search(text):
        text = _INIT_CONSTANT_RE.sub(rf"\g<1>{count}\g<2>", text)
    else:
        text = text.rstrip() + f"\nRULE_COUNT = {count}\n"
    if text == original:
        return False
    if check:
        return True
    init.write_text(text, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", default=str(DEFAULT_BUNDLE), help="Path to rules.json")
    parser.add_argument(
        "--regenerate", action="store_true",
        help="(Re)build the bundle from agent_audit_kit.rules.builtin before reading it.",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Exit 1 if any file would change (for CI / pre-commit).",
    )
    args = parser.parse_args()
    bundle = pathlib.Path(args.bundle)

    count = _load_rule_count(bundle, args.regenerate)
    changed_readme = _update_readme(count, check=args.check)
    changed_action = _update_action_yml(count, check=args.check)
    changed_init = _update_init_py(count, check=args.check)

    changed = any((changed_readme, changed_action, changed_init))
    if args.check and changed:
        sys.stderr.write(
            f"sync_rule_count: drift detected (rule count = {count}). "
            "Run `python scripts/sync_rule_count.py` and commit the result.\n"
        )
        return 1
    if changed:
        sys.stdout.write(f"sync_rule_count: wrote {count} rules into README / action.yml / __init__.py\n")
    else:
        sys.stdout.write(f"sync_rule_count: clean ({count} rules everywhere).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
