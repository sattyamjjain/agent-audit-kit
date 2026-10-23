#!/usr/bin/env python3
"""Regenerate, or check, the committed standards crosswalk page.

`docs/crosswalk/nsa-csi-owasp-agentic.md` is what `agent_audit_kit.output.crosswalk.
render_markdown()` writes: every rule in the registry against the NSA MCP CSI
controls and the OWASP Agentic Top-10 ids its compliance mappings give it, with
the rule and mapped counts in its first line. It is generated, so it rots the
moment a rule is added, retired or remapped and nobody runs the generator;
#1040 regenerated it by hand, and nothing checked it until #1060 row 7. This is
the check, the class of guard the counts job exists for.

Usage:
    python scripts/sync_crosswalk.py            # rewrite the page from the registry
    python scripts/sync_crosswalk.py --check    # exit 1 if the committed page differs

Callers: `make crosswalk` / `make crosswalk-check`, the `counts` job in ci.yml, and
`tests/test_crosswalk.py`, which asserts the same equality on every pytest run.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGE = REPO_ROOT / "docs" / "crosswalk" / "nsa-csi-owasp-agentic.md"


def rendered() -> str:
    sys.path.insert(0, str(REPO_ROOT))
    from agent_audit_kit.output.crosswalk import render_markdown

    return render_markdown()


def check(page: Path) -> int:
    """0 when `page` holds exactly what the generator writes, else 1 with the first
    differing lines and the command that regenerates it."""
    want = rendered()
    try:
        have = page.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"crosswalk-check: cannot read {page}: {exc}")
        return 1
    if have == want:
        print(f"crosswalk-check: {page.relative_to(REPO_ROOT) if page.is_relative_to(REPO_ROOT) else page} "
              "matches its generator.")
        return 0
    diff = list(difflib.unified_diff(
        have.splitlines(), want.splitlines(), "committed", "generated", lineterm="", n=0,
    ))
    shown = [line for line in diff if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
    print(f"crosswalk-check: {page} differs from what the generator writes "
          f"({len(shown)} changed line(s)); run `make crosswalk` and commit the result.")
    for line in shown[:12]:
        print(f"  {line}")
    if len(shown) > 12:
        print(f"  ... {len(shown) - 12} more")
    return 1


def write(page: Path) -> int:
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(rendered(), encoding="utf-8")
    print(f"wrote {page}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="Fail if the committed page is stale.")
    parser.add_argument("--path", type=Path, default=PAGE, help=f"The page to write or check (default: {PAGE}).")
    args = parser.parse_args(argv)
    return check(args.path) if args.check else write(args.path)


if __name__ == "__main__":
    raise SystemExit(main())
