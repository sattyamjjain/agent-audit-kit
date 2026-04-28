"""OX-disclosed CVE coverage manifest reader + summary helpers.

Powers `aak coverage --source ox`, the README badge endpoint and the
2026-04-28 GitHub Actions workflow that publishes the coverage badge.

The manifest lives at agent_audit_kit/data/ox-cve-manifest.json and is
hand-curated from OX Security's MCP supply-chain disclosure timeline
(license: CC-BY-4.0). Each entry maps a CVE identifier to a list of
covering AAK rule IDs.
"""
from __future__ import annotations

import json
from importlib import resources
from typing import Any


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
    text = resources.files("agent_audit_kit.data").joinpath(
        "ox-cve-manifest.json"
    ).read_text(encoding="utf-8")
    data = json.loads(text)
    return list(data.get("entries", []))


def summarize(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute coverage summary from manifest entries.

    Args:
        entries: List of entry dicts as returned by `load_manifest`.

    Returns:
        Summary dict with `total`, `covered`, `coverage_pct`, and
        the original `entries` list (sorted by CVE).
    """
    total = len(entries)
    covered = sum(1 for e in entries if e.get("covered"))
    pct = round((covered / total * 100), 1) if total else 0.0
    return {
        "total": total,
        "covered": covered,
        "coverage_pct": pct,
        "entries": sorted(
            (
                {
                    "cve": e["cve"],
                    "title": e.get("title", ""),
                    "covered": bool(e.get("covered")),
                    "rules": list(e.get("rules", [])),
                }
                for e in entries
            ),
            key=lambda x: x["cve"],
        ),
    }


__all__ = ["load_manifest", "summarize"]
