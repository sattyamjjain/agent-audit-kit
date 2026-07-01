#!/usr/bin/env python3
"""State of MCP Security 2026 — reproducible research harness.

Scans a corpus of public MCP server configs with AgentAuditKit and aggregates
the findings into a grade distribution (A–F), per-rule-category hit rates, and
the top-N most-common misconfigurations.

This harness does NOT contain a scanner. It REUSES:
  - ``agent_audit_kit.engine.run_scan``      — the scan entrypoint (engine.py)
  - ``agent_audit_kit.scoring.compute_score`` — the same penalty-based A–F
                                                grade the MCP Security Index /
                                                ``aak score`` uses (scoring/__init__.py)
  - ``agent_audit_kit.rules.builtin.RULES``   — rule titles for the top-N table

Corpus acquisition is delegated to the existing crawler,
``benchmarks/crawler.py`` (GitHub Code Search → downloaded ``.mcp.json`` files),
seeded to match the official MCP Registry export + mcp.so top-N. Point
``--corpus`` at its output directory (default ``benchmarks/data``).

Reproduce:
    export GITHUB_TOKEN=$(gh auth token)
    python benchmarks/crawler.py --limit 500 --output benchmarks/results.json
    python research/state-of-mcp-2026/run_report.py \
        --corpus benchmarks/data \
        --out research/state-of-mcp-2026/results.json

Output is deterministic for a fixed corpus (offline, no network, no LLM).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scoring import compute_score

# Findings AAK reports that are advisory *posture* signals, not exploitable
# misconfigurations. Excluded from the "top misconfigurations" headline so the
# story isn't inflated (documented in REPORT.md).
_ADVISORY_RULES = frozenset({"AAK-MCP-ATTEST-001", "AAK-MCP-007"})


def _iter_configs(corpus: Path) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for pattern in ("*.json",):
        for p in sorted(corpus.rglob(pattern)):
            if p.is_file() and p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _content_key(path: Path) -> str | None:
    """Stable sha256 of the normalised JSON so byte-identical configs that
    differ only in formatting dedupe to one sample."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (ValueError, OSError):
        return None
    blob = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _scan_one(path: Path) -> Any:
    """Scan a single config in isolation by copying it into a temp project root
    and reusing engine.run_scan + scoring.compute_score."""
    tmp = Path(tempfile.mkdtemp(prefix="aak-somcp-"))
    try:
        shutil.copy(path, tmp / path.name)
        result = run_scan(tmp)
        compute_score(result)
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def aggregate(corpus: Path) -> dict[str, Any]:
    configs = _iter_configs(corpus)
    seen_keys: set[str] = set()

    total = 0
    duplicates = 0
    unparseable = 0
    grades: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    category_configs: Counter[str] = Counter()  # configs with >=1 finding in cat
    rule_configs: Counter[str] = Counter()       # configs with >=1 finding of rule
    owasp_mcp_configs: Counter[str] = Counter()  # configs with >=1 finding mapped to MCPxx
    has_critical = 0
    has_high = 0

    for path in configs:
        key = _content_key(path)
        if key is None:
            unparseable += 1
            continue
        if key in seen_keys:
            duplicates += 1
            continue
        seen_keys.add(key)

        result = _scan_one(path)
        total += 1
        grades[result.grade or "?"] += 1

        cats_here: set[str] = set()
        rules_here: set[str] = set()
        sev_here: set[str] = set()
        owasp_here: set[str] = set()
        for f in result.findings:
            sev = f.severity.value
            severities[sev] += 1
            sev_here.add(sev)
            cats_here.add(f.category.value)
            rules_here.add(f.rule_id)
            rule = RULES.get(f.rule_id)
            if rule:
                owasp_here.update(rule.owasp_mcp_references)
        for c in cats_here:
            category_configs[c] += 1
        for r in rules_here:
            rule_configs[r] += 1
        for o in owasp_here:
            owasp_mcp_configs[o] += 1
        if "critical" in sev_here:
            has_critical += 1
        if "high" in sev_here:
            has_high += 1

    def _pct(n: int) -> float:
        return round(100.0 * n / total, 1) if total else 0.0

    top_misconfig = [
        {
            "rule_id": rid,
            "title": RULES[rid].title if rid in RULES else rid,
            "severity": RULES[rid].severity.value if rid in RULES else "?",
            "configs": n,
            "config_pct": _pct(n),
        }
        for rid, n in rule_configs.most_common()
        if rid not in _ADVISORY_RULES
    ][:5]

    return {
        "tool": "agent-audit-kit",
        "corpus": str(corpus),
        "corpus_total_files": len(configs),
        "distinct_configs_scanned": total,
        "duplicates_removed": duplicates,
        "unparseable_removed": unparseable,
        "grade_distribution": dict(sorted(grades.items())),
        "configs_with_critical": has_critical,
        "configs_with_critical_pct": _pct(has_critical),
        "configs_with_high": has_high,
        "configs_with_high_pct": _pct(has_high),
        "severity_totals": dict(severities),
        "category_hit_rate": {
            cat: {"configs": n, "pct": _pct(n)}
            for cat, n in category_configs.most_common()
        },
        "owasp_mcp_hit_rate": {
            code: {"configs": n, "pct": _pct(n)}
            for code, n in owasp_mcp_configs.most_common()
        },
        "top_misconfigurations": top_misconfig,
        "excluded_advisory_rules": sorted(_ADVISORY_RULES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus", default="benchmarks/data",
        help="Directory of downloaded MCP configs (default: benchmarks/data).",
    )
    parser.add_argument(
        "--out", default="research/state-of-mcp-2026/results.json",
        help="Where to write the aggregate results JSON.",
    )
    args = parser.parse_args()

    corpus = Path(args.corpus)
    if not corpus.is_dir():
        raise SystemExit(
            f"Corpus dir {corpus} not found. Populate it first:\n"
            "  export GITHUB_TOKEN=$(gh auth token)\n"
            "  python benchmarks/crawler.py --limit 500 --output benchmarks/results.json"
        )

    data = aggregate(corpus)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    g = data["grade_distribution"]
    print(
        f"scanned {data['distinct_configs_scanned']} distinct configs "
        f"({data['duplicates_removed']} dup, {data['unparseable_removed']} unparseable removed)\n"
        f"grades: {g}\n"
        f"critical: {data['configs_with_critical']} ({data['configs_with_critical_pct']}%) "
        f"| high: {data['configs_with_high']} ({data['configs_with_high_pct']}%)\n"
        f"wrote {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
