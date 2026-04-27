#!/usr/bin/env python3
"""Audit pass: every rule whose docs cite a CVE must also have it in
metadata.cve_references on the registered RuleDefinition.

Reads docs/rules/*.md, extracts CVE-NNNN-NNNN tokens, then verifies the
corresponding rule object's `cve_references`. Reports drift; exits
non-zero if any drift is found.

Usage: python scripts/backfill_cve_property.py [--check|--write]

`--check` (default) prints drift, exits 1.
`--write` would patch builtin.py in place — kept off by default since
hand-editing the rule registry from a script is risky.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs" / "rules"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Stop scanning at the first cross-link section header — sister rule
# docs cite each other's CVEs under "## Sister rule" / "## See also"
# and those should not count as the rule's own CVE.
_CROSSLINK_HEADER_RE = re.compile(
    r"^##\s*(Sister rules?|See also|Related|Cross-link)\b",
    re.IGNORECASE | re.MULTILINE,
)


def _doc_cves() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    if not DOCS_DIR.is_dir():
        return out
    for path in DOCS_DIR.glob("AAK-*.md"):
        rule_id = path.stem
        text = path.read_text(encoding="utf-8")
        m = _CROSSLINK_HEADER_RE.search(text)
        scan_text = text[: m.start()] if m else text
        cves = set(_CVE_RE.findall(scan_text))
        if cves:
            out[rule_id] = cves
    return out


def _registry_cves() -> dict[str, set[str]]:
    from agent_audit_kit.rules.builtin import RULES
    return {rid: set(r.cve_references) for rid, r in RULES.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Default mode — report drift, exit 1 on any.")
    parser.add_argument("--write", action="store_true", help="(Reserved for future use; rule registry is hand-curated.)")
    args = parser.parse_args(argv if argv is not None else [])

    if args.write:
        sys.stderr.write("--write is intentionally not implemented; rule registry edits are hand-curated.\n")
        return 1

    docs = _doc_cves()
    reg = _registry_cves()
    drift_found = False

    for rule_id, doc_cves in docs.items():
        if rule_id not in reg:
            sys.stderr.write(f"  doc cites unknown rule_id {rule_id!r}\n")
            drift_found = True
            continue
        missing = doc_cves - reg[rule_id]
        if missing:
            drift_found = True
            sys.stderr.write(
                f"  {rule_id}: docs cite {sorted(missing)} but registry lacks them\n"
            )
    if drift_found:
        sys.stderr.write("\nFix by editing agent_audit_kit/rules/builtin.py manually.\n")
        return 1
    sys.stdout.write(f"  CVE-property check passed across {len(docs)} doc page(s).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
