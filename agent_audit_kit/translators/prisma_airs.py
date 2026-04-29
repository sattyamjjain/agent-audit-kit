"""AAK-PRISMA-AIRS-COVERAGE-001 — Prisma AIRS catalog coverage mapper.

Reads the curated catalog + AAK map from `agent_audit_kit/data/` and
produces a coverage summary similar to `aak coverage --source ox`.

Public Prisma AIRS catalog only — entries flagged
`status: catalog-private` are intentionally absent. `runtime-only`
entries are listed but excluded from the covered/total math (AAK is
static-only by design; runtime engines like Prisma AIRS are the
canonical detector).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_catalog() -> list[dict[str, Any]]:
    text = (_DATA_DIR / "prisma-airs-catalog.json").read_text(encoding="utf-8")
    return list(json.loads(text).get("attacks", []))


def load_map() -> list[dict[str, Any]]:
    text = (_DATA_DIR / "prisma-airs-aak-map.json").read_text(encoding="utf-8")
    return list(json.loads(text).get("map", []))


def map_airs_attack_to_rule(attack: dict[str, Any], mapping: list[dict[str, Any]] | None = None) -> list[str]:
    mapping = mapping or load_map()
    target = attack.get("airs_attack_id")
    for entry in mapping:
        if entry.get("airs_attack_id") == target:
            return list(entry.get("aak_rule_ids", []) or [])
    return []


def summarize() -> dict[str, Any]:
    catalog = load_catalog()
    mapping = load_map()
    by_id: dict[str, dict[str, Any]] = {e["airs_attack_id"]: e for e in mapping}
    total_static = 0
    covered = 0
    rows: list[dict[str, Any]] = []
    for attack in catalog:
        aid = attack["airs_attack_id"]
        entry = by_id.get(aid, {"aak_rule_ids": [], "status": "uncovered"})
        status = entry.get("status") or attack.get("status") or "uncovered"
        is_static = status not in {"runtime-only", "catalog-private"}
        if is_static:
            total_static += 1
            if entry.get("aak_rule_ids"):
                covered += 1
        rows.append({
            "airs_attack_id": aid,
            "title": attack.get("title", ""),
            "category": attack.get("category", ""),
            "status": status,
            "aak_rule_ids": entry.get("aak_rule_ids", []) or [],
        })
    pct = round((covered / total_static * 100), 1) if total_static else 0.0
    return {
        "total_static": total_static,
        "covered": covered,
        "coverage_pct": pct,
        "entries": sorted(rows, key=lambda r: r["airs_attack_id"]),
    }


__all__ = ["load_catalog", "load_map", "map_airs_attack_to_rule", "summarize"]
