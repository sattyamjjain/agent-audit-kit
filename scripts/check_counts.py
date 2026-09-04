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
    # "`Category` (12 members)" in CLAUDE.md's Code Conventions block -- the
    # fourth instance of the phrase blind spot, after "N existing rules",
    # "N registered scanners" and the category count itself. The pattern above
    # is anchored on the headline "rules ... across N categories" form, so it
    # never looked at this one, and the corroboration sweep does not either --
    # that sweep reads README.md and docs/**, and this claim lives in CLAUDE.md.
    # The result was one file asserting "330 rules across 14 security
    # categories" on line 8 and "Category (12 members)" on line 137 while
    # count-check reported clean. Anchored on the backticked symbol so it only
    # ever matches a claim about the enum itself, never a prose category count.
    (re.compile(r"`Category`\s*\((\d+)\s+members?\)", re.I), "categories"),
    # "(97 .py files on disk - the registry is authoritative)" in CLAUDE.md. This
    # phrasing was unguarded and had drifted to 97 while the directory held 96 --
    # a count wrong in the one file that tells the next reader the counts are
    # guarded. It is a different number from `scanners` (which counts what the
    # engine registers), so it needs its own canonical entry rather than reusing
    # one.
    (re.compile(r"\b(\d+)\s+\.py files on disk\b", re.I), "scanner_files"),
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
        # Non-private modules in scanners/: registered scanners plus the
        # back-compat shims. scanners.json states the same invariant.
        "scanner_files": len([
            p for p in (REPO_ROOT / "agent_audit_kit" / "scanners").glob("*.py")
            if not p.stem.startswith("_")
        ]),
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


# ---------------------------------------------------------------------------
# Corroboration sweep (v0.3.86)
#
# `find_stale_counts` above matches PHRASES. That is why it kept missing things:
# a count written in a phrasing absent from PATTERNS is never looked at, and the
# CHANGELOG records the same blind spot being found three separate times
# (v0.3.72 "N existing rules", v0.3.81 "N registered scanners", v0.3.84 the
# category count). Each fix added one more phrase, which fixes one instance and
# leaves the class.
#
# This sweep inverts the question. Instead of "does this known phrasing hold?"
# it asks, of EVERY "<n> rules" and "<n> scanners" in README.md and docs/**:
# does that number correspond to anything real in the registry? A claim is
# corroborated when it equals the total, or equals the count of a category named
# on the same line, or sits inside a generated marker. Anything else is a number
# nobody can source, which is what "A2A protocol scanning | 12 rules" was while
# the registry said 13 and `make count-check` reported clean.
#
# It cannot be phrase-blind, because it does not read phrases.
# ---------------------------------------------------------------------------

_SWEEP_ROOTS: tuple[str, ...] = ("README.md", "docs")

_RULE_CLAIM_RE = re.compile(
    r"(?<![\d.])(\d[\d,]*)\s+(?:[A-Za-z][\w-]*\s+){0,2}rules?\b", re.I
)
_SCANNER_CLAIM_RE = re.compile(
    r"(?<![\d.])(\d[\d,]*)\s+(?:[A-Za-z][\w-]*\s+){0,2}scanners?\b", re.I
)

# Inside a generated marker the number is written by scripts/sync_rule_count.py,
# so it cannot drift by hand and re-checking it here only duplicates that owner.
_MARKER_RE = re.compile(r"<!--\s*[\w:-]+\s*-->\s*\d[\d,]*\s*<!--\s*/[\w:-]+\s*-->")

# Numbers that are legitimately not a registry count, each with the reason it is
# exempt. Keyed by (relative path, the matched text). Enumerating EXEMPTIONS
# rather than obligations means a new unsourced number fails closed.
SWEEP_ALLOW: dict[tuple[str, str], str] = {
    ("README.md", "2 scanners"):
        "per-language pattern-scanner count (TypeScript + Rust), not the registry total",
    ("docs/RELEASING.md", "77 rules"):
        "narrative quoting the v0.2.0-era numbers a past drift left behind; the "
        "sentence exists to describe that bug, so correcting it would erase the point",
    ("docs/RELEASING.md", "13 scanners"):
        "same sentence as above",
}

# A number introduced by a threshold operator states a bar, not a count:
# "Full = >=3 rules", "with >= 1 deterministic rule". Recognised as a shape
# rather than allow-listed one by one, because writing a new threshold is
# ordinary and should not require editing this file.
_THRESHOLD_RE = re.compile(
    r"(?:>=|≥|>|at least|minimum of|min\.?|no fewer than|each with)\s*$", re.I
)

# Phrases whose number is a claim about something other than AAK's own registry.
_NOT_OUR_COUNT_RE = re.compile(
    r"\b(?:new|added|shipped|net-new|mapped|reference|other|competing|their|its)\b",
    re.I,
)


def _category_counts() -> dict[str, int]:
    """Category display + enum name -> rule count, for same-line corroboration."""
    from collections import Counter

    from agent_audit_kit.rules.builtin import RULES

    by_enum = Counter(r.category.name for r in RULES.values())
    out: dict[str, int] = {}
    for enum_name, n in by_enum.items():
        out[enum_name.lower()] = n
        out[enum_name.replace("_", " ").lower()] = n
        out[enum_name.replace("_", "-").lower()] = n
    return out


def _sweep_files() -> list[str]:
    out: list[str] = []
    for rel in _tracked_markdown():
        if not any(rel == root or rel.startswith(root + "/") for root in _SWEEP_ROOTS):
            continue
        if is_excluded(rel):
            continue
        out.append(rel)
    return out


def find_uncorroborated_counts() -> list[str]:
    """Every "<n> rules"/"<n> scanners" in README.md and docs/** that matches no
    real registry number.

    Corroboration, in order: the generated-marker owner, the explicit allow-list,
    a phrase that is plainly about someone else's count, the registry total, or a
    category named on the same line.
    """
    counts = canonical_counts()
    categories = _category_counts()
    failures: list[str] = []

    for rel in _sweep_files():
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        if has_historical_banner(path):
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            marker_spans = [m.span() for m in _MARKER_RE.finditer(line)]
            lowered = line.lower()
            for rx, key in ((_RULE_CLAIM_RE, "rules"), (_SCANNER_CLAIM_RE, "scanners")):
                for m in rx.finditer(line):
                    text = m.group(0).strip()
                    if any(a <= m.start() and m.end() <= b for a, b in marker_spans):
                        continue
                    if SWEEP_ALLOW.get((rel, text)):
                        continue
                    if _NOT_OUR_COUNT_RE.search(text):
                        continue
                    if _THRESHOLD_RE.search(line[: m.start()]):
                        continue
                    claimed = int(m.group(1).replace(",", ""))
                    if claimed == counts[key]:
                        continue
                    if key == "rules" and any(
                        name in lowered and claimed == n for name, n in categories.items()
                    ):
                        continue
                    expected = counts[key]
                    hint = ""
                    if key == "rules":
                        near = sorted(
                            {n for name, n in categories.items() if name in lowered}
                        )
                        if near:
                            hint = f" (a category on this line has {near[0]})"
                    failures.append(
                        f"{rel}:{lineno}: {text!r} matches no registry number"
                        f"{hint}; total is {expected}. Fix it, wrap it in a generated "
                        f"marker, or add it to SWEEP_ALLOW with a reason."
                    )
    return failures


def find_manifest_arithmetic_faults() -> list[str]:
    """``count + unregistered_shims == files on disk`` in ``scanners.json``.

    94 registered against 96 files on disk is defensible -- two of those files
    are back-compat re-exports -- but until v0.3.86 nothing in the tree said so,
    and anyone who counted files got a number the manifest contradicted. This
    turns "defensible" into "asserted": if a module is added and not registered,
    or a shim is deleted, the arithmetic stops working and says which.
    """
    import json

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from sync_scanner_count import scanner_module_files, unregistered_shims

    manifest_path = REPO_ROOT / "scanners.json"
    if not manifest_path.is_file():
        return ["scanners.json is missing"]
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"scanners.json is unreadable: {exc}"]

    failures: list[str] = []
    declared_shims = data.get("unregistered_shims")
    if declared_shims is None:
        return [
            "scanners.json has no `unregistered_shims` key, so its `count` cannot be "
            "reconciled with the files on disk"
        ]

    actual_shims = unregistered_shims()
    if sorted(declared_shims) != sorted(actual_shims):
        failures.append(
            f"scanners.json lists shims {sorted(declared_shims)} but the engine leaves "
            f"{sorted(actual_shims)} unregistered. Run scripts/sync_scanner_count.py."
        )

    on_disk = scanner_module_files()
    total = int(data.get("count", 0)) + len(declared_shims)
    if total != len(on_disk):
        missing = sorted(set(on_disk) - {e["module"] for e in data.get("scanners", [])}
                         - set(declared_shims))
        failures.append(
            f"scanners.json: count {data.get('count')} + {len(declared_shims)} shim(s) "
            f"= {total}, but {len(on_disk)} non-private modules are on disk"
            + (f"; unaccounted: {missing}" if missing else "")
            + ". Register the module, or record it as a shim."
        )
    return failures


def main() -> int:
    failures = (
        find_stale_counts()
        + find_uncorroborated_counts()
        + find_manifest_arithmetic_faults()
    )
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
