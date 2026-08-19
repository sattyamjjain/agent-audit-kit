#!/usr/bin/env python3
"""Repo-wide guard: no stale current-state count in any tracked ``*.md``.

The `<!-- rule-count:total -->` / `<!-- scanner-count:total -->` markers and the
`test_no_stale_hardcoded_counts_in_prose` fence only covered README / CLAUDE /
docs / launch. Counts drifted exactly where nothing looked: `DEEP_ANALYSIS.md`,
`ROADMAP_2026.md`, `CLAUDE_PROMPT.md`, `research/**`, `launch/owasp-outreach.md`.

This widens the scan to every tracked markdown file, excluding the changelogs and
a small set of dated / historical / frozen artifacts whose "N rules / N scanner
modules" is a measurement pinned to a past version, not a current-state claim —
each of those carries an in-file dated note or explicit version label.

Single source of truth for three callers:
    - tests/test_rule_count_sync.py::test_no_stale_hardcoded_counts_in_prose
    - .github/workflows/release.yml  (fails the release on a mismatch)
    - `make count-check`

Usage:
    python scripts/check_counts.py            # exit 1 on any mismatch, prints file:line
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Historical entries stay historical (task exclusion). Dated / frozen artifacts:
# the number is a measurement of a named past version, not a claim about the
# current build. Every entry here carries an in-file dated note or version label
# so a human reading the file is not misled.
EXCLUDE_EXACT: frozenset[str] = frozenset({
    "CHANGELOG.md",
    "CHANGELOG.cves.md",
    # DEEP_ANALYSIS.md and ROADMAP_2026.md are exempted by their dated banner
    # (see HISTORICAL_BANNER_RE below), not by name — so if a future file drops its
    # banner while keeping a stale count, or a new snapshot file forgets to add one,
    # it gets caught instead of silently sliding under a hard-coded name list.
    "launch/blog-50-mcp-servers.md",               # dated note: a v0.3.x 225-rule run
    "launch/state-of-mcp-security-2026.md",        # inline "v0.3.41, 225 rules", self-labelled superseded
    "docs/research/mcp-security-baseline-v1.0.md",  # frozen baseline: "0.3.56 - 262 rules"
    "research/state-of-mcp-2026/blackhat-briefings-abstract.md",  # dated CFP skeleton (2026-07-19 scan)
    "launch/MARKET-RESEARCH-2026-04-12.md",        # header: "Date: April 12, 2026 | Version: v0.2.0"
})
EXCLUDE_PREFIX: tuple[str, ...] = (
    "docs/changelog/archive/",   # frozen changelog history
    "docs/presets/",             # "shipped in vX" dated preset facts
    "releases/",                 # per-version release notes (releases/v0.3.N.md); count is that version's
)

# Headline-total phrasings only, so per-category tables ("**12 rules**"), per-language
# counts ("2 scanners"), and quoted historical numbers never trip. This tuple is the
# single source: tests/test_rule_count_sync.py imports find_stale_counts() instead of
# keeping a second copy, so there is no mirror to update alongside it.
#
# The guard matches PHRASES, not numbers: a count written in a phrasing absent from this
# tuple is never looked at, and rots silently while `make count-check` reports clean.
# When prose needs a new count phrasing, reuse one below or add it here.
PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\*\*(\d+)\s+(?:deterministic |detection )?rules?\*\*\s+across", re.I), "rules"),
    (re.compile(r"\ball (\d+) rules\b", re.I), "rules"),
    (re.compile(r"\b(\d+)\s+RuleDefinition entries\b"), "rules"),
    (re.compile(r"\b(\d+)\s+deterministic rules\b", re.I), "rules"),
    (re.compile(r"\brule\s*\((\d+)\s+total\b", re.I), "rules"),
    (re.compile(r"\b(\d+)\s+rules across (\d+)\s+scanners?\b", re.I), "rules+scanners"),
    (re.compile(r"\b(\d+)\s+detection rules\b", re.I), "rules"),
    (re.compile(r"with (\d+) rules\b", re.I), "rules"),
    # "understand the N existing rules" (CLAUDE_PROMPT.md) — the phrasing that
    # drifted to 289 two rules after the v0.3.72 sweep, because no pattern matched it.
    (re.compile(r"\b(\d+)\s+existing rules?\b", re.I), "rules"),
    (re.compile(r"\b(\d+)\s+scanner modules?\b", re.I), "scanners"),
    # "N registered scanners" (CLAUDE.md architecture block) — sat at 89 while the
    # registry moved to 92, because "scanner modules" was the only scanner phrasing
    # covered. Same failure as the "N existing rules" drift above: guard clean, count
    # wrong. Deliberately requires the "registered" qualifier, so the per-language
    # "2 scanners" counts in README stay out of scope.
    (re.compile(r"\b(\d+)\s+registered scanners?\b", re.I), "scanners"),
    (re.compile(r"\b(\d+)\s+CLI commands?\b", re.I), "commands"),
    (re.compile(r"entry point\s*\((\d+)\s+commands?\)", re.I), "commands"),
    (re.compile(r"\*\*(\d+)\s+frameworks\*\*", re.I), "frameworks"),
    (re.compile(r"\((\d+)\s+frameworks\)", re.I), "frameworks"),
    (re.compile(r"\bmapped to (\d+) frameworks\b", re.I), "frameworks"),
    (re.compile(r"\b(\d+)\s+compliance frameworks\b", re.I), "frameworks"),
    (re.compile(r"\*\*(\d+)\s+agent platforms\*\*", re.I), "platforms"),
    (re.compile(r"\b(\d+)\s+agent platforms\b", re.I), "platforms"),
    # Category count. Unguarded until v0.3.84, when Category gained COMPOSITION --
    # the third instance of the phrase-based blind spot, after "N existing rules"
    # and "N registered scanners".
    #
    # Anchored on the headline "rules ... across N categories" form, which is how
    # every current-state claim in the tree is actually written. A bare
    # "N categories" pattern was tried first and is wrong: it matches "10/10
    # categories" in the OWASP coverage pages (that 10 is the OWASP taxonomy's
    # size, not AAK's), "all 11 security categories" in examples/, and
    # "9 of 11 security categories" in a case study -- three statements about
    # different things that a guard would have "fixed" into being false.
    (re.compile(r"rules\*{0,2}\s+across\s+(\d+)\s+(?:security\s+)?categor(?:y|ies)", re.I), "categories"),
)


def canonical_counts() -> dict[str, int]:
    """The numbers current-state prose may claim, each computed from code."""
    from agent_audit_kit import SCANNER_COUNT, discovery
    from agent_audit_kit.cli import cli
    from agent_audit_kit.models import Category
    from agent_audit_kit.output import pdf_report
    from agent_audit_kit.rules.builtin import RULES

    return {
        "rules": len(RULES),
        "scanners": SCANNER_COUNT,
        "commands": len(cli.commands),
        "frameworks": len(pdf_report._FRAMEWORK_TITLES),
        "platforms": len(discovery.AGENT_CONFIGS),
        "categories": len(list(Category)),
    }


def _tracked_markdown() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "*.md"],
        capture_output=True, text=True, check=True,
    )
    return [line for line in out.stdout.splitlines() if line]


# A dated historical-snapshot banner near the top of a file declares that its
# counts describe a named past version, not the current build. DEEP_ANALYSIS.md
# opens with "Historical snapshot - v0.2.0"; ROADMAP_2026.md opens with
# "Starting point (Apr 2026): v0.2.0 - 77 rules". Either form exempts the file;
# a file that states a live count without such a banner is checked.
HISTORICAL_BANNER_RE = re.compile(
    r"historical snapshot|starting point \(\w+\.? 20\d\d\)", re.I
)
_BANNER_HEAD_CHARS = 800


def has_historical_banner(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8")[:_BANNER_HEAD_CHARS]
    except OSError:
        return False
    return bool(HISTORICAL_BANNER_RE.search(head))


def is_excluded(rel: str) -> bool:
    return rel in EXCLUDE_EXACT or any(rel.startswith(p) for p in EXCLUDE_PREFIX)


def find_stale_counts() -> list[str]:
    """Return ``path:line: ...`` strings for every current-state count that
    disagrees with the live registry, across all tracked markdown minus the
    changelog / historical exclusions."""
    counts = canonical_counts()
    failures: list[str] = []
    for rel in _tracked_markdown():
        if is_excluded(rel):
            continue
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        if has_historical_banner(path):
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for pattern, key in PATTERNS:
                for m in pattern.finditer(line):
                    keys = key.split("+")
                    for idx, k in enumerate(keys):
                        claimed = int(m.group(idx + 1))
                        if claimed != counts[k]:
                            failures.append(
                                f"{rel}:{lineno}: {m.group(0).strip()!r} claims "
                                f"{claimed} {k}; canonical is {counts[k]}"
                            )
    return failures


def main() -> int:
    failures = find_stale_counts()
    if failures:
        sys.stderr.write(
            "count-check: stale count(s) outside the changelog / historical exclusions "
            "(fix the file, or add a dated note and exclude it in scripts/check_counts.py):\n  "
            + "\n  ".join(failures) + "\n"
        )
        return 1
    sys.stdout.write(f"count-check: clean ({canonical_counts()}).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
