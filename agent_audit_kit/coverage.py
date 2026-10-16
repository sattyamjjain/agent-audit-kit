"""OX-disclosed CVE coverage manifest reader + summary helpers.

Powers `aak coverage --source ox`, the README badge endpoint and the
2026-04-28 GitHub Actions workflow that publishes the coverage badge.

The manifest lives at agent_audit_kit/data/ox-cve-manifest.json and is
hand-curated from OX Security's MCP supply-chain disclosure timeline
(license: CC-BY-4.0). Each entry maps a CVE identifier to a list of
covering AAK rule IDs.

Only a registered rule covers anything. Until 2026-10-17 the summary counted
an entry as covered on the strength of its `covered` flag and listed whatever
ids it named, and three of the 19 entries named only ids no rule ever had
(wrong names for real rules, written by hand when the manifest was). The
published figure happened to be right because the real rules existed, but
nothing would have noticed if they had not. `tests/test_coverage_maps.py`
keeps the manifest's ids registered.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_audit_kit.rules.builtin import RULES


_DATA_DIR = Path(__file__).resolve().parent / "data"


def load_manifest(source: str) -> list[dict[str, Any]]:
    """Load the OX-disclosed CVE manifest entries.

    Args:
        source: Manifest source ID. Only "ox" is supported.

    Returns:
        List of manifest entry dicts.

    Raises:
        ValueError: If `source` is not a known manifest source.
    """
    if source != "ox":
        raise ValueError(f"Unknown coverage source: {source}")
    text = (_DATA_DIR / "ox-cve-manifest.json").read_text(encoding="utf-8")
    data = json.loads(text)
    return list(data.get("entries", []))


def summarize(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute coverage summary from manifest entries.

    Args:
        entries: List of entry dicts as returned by `load_manifest`.

    Returns:
        Summary dict with `total`, `covered`, `coverage_pct`, and the
        entries (sorted by CVE). An entry's `rules` keeps only registered
        rule ids, and it counts as covered when the manifest says so and at
        least one of those remains.
    """
    rows = []
    for e in entries:
        rules = [rule for rule in e.get("rules", []) if rule in RULES]
        rows.append({
            "cve": e["cve"],
            "title": e.get("title", ""),
            "covered": bool(e.get("covered")) and bool(rules),
            "rules": rules,
        })
    total = len(rows)
    covered = sum(1 for row in rows if row["covered"])
    pct = round((covered / total * 100), 1) if total else 0.0
    return {
        "total": total,
        "covered": covered,
        "coverage_pct": pct,
        "entries": sorted(rows, key=lambda x: x["cve"]),
    }


__all__ = ["load_manifest", "summarize"]
