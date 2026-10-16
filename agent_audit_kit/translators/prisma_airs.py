"""Prisma AIRS catalog coverage mapper, behind `aak coverage --source prisma-airs`.

Reads the curated catalog + AAK map from `agent_audit_kit/data/` and
produces a coverage summary similar to `aak coverage --source ox`.

Public Prisma AIRS catalog only — entries flagged
`status: catalog-private` are intentionally absent. `runtime-only`
entries are listed but excluded from the covered/total math (AAK is
static-only by design; runtime engines like Prisma AIRS are the
canonical detector).

Only a registered rule covers an attack, the rule `coverage.summarize` follows
for the OX manifest. The map was written by hand and, until 2026-10-17, named
three ids no rule ever had; PA-AIRS-018 rested on one of them alone and was
counted as covered all the same, because any listed id counted.
`tests/test_coverage_maps.py` keeps the map's ids registered.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_audit_kit.rules.builtin import RULES


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_NOT_STATIC = frozenset({"runtime-only", "catalog-private"})


def load_catalog() -> list[dict[str, Any]]:
    text = (_DATA_DIR / "prisma-airs-catalog.json").read_text(encoding="utf-8")
    return list(json.loads(text).get("attacks", []))


def load_map() -> list[dict[str, Any]]:
    text = (_DATA_DIR / "prisma-airs-aak-map.json").read_text(encoding="utf-8")
    return list(json.loads(text).get("map", []))


def _registered(rule_ids: list[str] | None) -> list[str]:
    """The ids in `rule_ids` that are rules in the registry, in their order."""
    return [rule for rule in rule_ids or [] if rule in RULES]


def map_airs_attack_to_rule(attack: dict[str, Any], mapping: list[dict[str, Any]] | None = None) -> list[str]:
    mapping = mapping or load_map()
    target = attack.get("airs_attack_id")
    for entry in mapping:
        if entry.get("airs_attack_id") == target:
            return _registered(entry.get("aak_rule_ids"))
    return []


def summarize(
    catalog: list[dict[str, Any]] | None = None,
    mapping: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Coverage of the catalog, from the shipped files unless both are given.

    A static attack is covered when its map entry lists at least one registered
    rule, and its row says `covered` or `uncovered` accordingly, whatever status
    the map wrote; `runtime-only` and `catalog-private` rows keep their status
    and stay out of the totals.
    """
    catalog = load_catalog() if catalog is None else catalog
    mapping = load_map() if mapping is None else mapping
    by_id: dict[str, dict[str, Any]] = {e["airs_attack_id"]: e for e in mapping}
    total_static = 0
    covered = 0
    rows: list[dict[str, Any]] = []
    for attack in catalog:
        aid = attack["airs_attack_id"]
        entry = by_id.get(aid, {"aak_rule_ids": [], "status": "uncovered"})
        status = entry.get("status") or attack.get("status") or "uncovered"
        rules = _registered(entry.get("aak_rule_ids"))
        if status not in _NOT_STATIC:
            total_static += 1
            status = "covered" if rules else "uncovered"
            if rules:
                covered += 1
        rows.append({
            "airs_attack_id": aid,
            "title": attack.get("title", ""),
            "category": attack.get("category", ""),
            "status": status,
            "aak_rule_ids": rules,
        })
    pct = round((covered / total_static * 100), 1) if total_static else 0.0
    return {
        "total_static": total_static,
        "covered": covered,
        "coverage_pct": pct,
        "entries": sorted(rows, key=lambda r: r["airs_attack_id"]),
    }


__all__ = ["load_catalog", "load_map", "map_airs_attack_to_rule", "summarize"]
