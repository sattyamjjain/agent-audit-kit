#!/usr/bin/env python3
"""False-positive benchmark — scan a BENIGN SLICE and bucket the findings.

Runs the **real AAK engine** (`agent_audit_kit.engine.run_scan`, the same
entrypoint the `scan` CLI drives) over the benign slice derived in `corpus.py`,
buckets findings by severity and rule family, and surfaces the top-30
HIGH/CRITICAL findings for MANUAL adjudication (see `triage.md`). It does NOT
label anything true/false itself — the false-positive *rate* is computed from the
human adjudication, not here.

Reuses (no scanning/scoring reimplemented):
  - `agent_audit_kit.engine.run_scan`      — the scan entrypoint
  - `agent_audit_kit.rules.builtin.RULES`  — rule titles + severity/family
  - `benchmarks.false_positive.corpus`     — the benign-slice predicate

Deterministic: output uses `sort_keys=True`, stable tie-breaks, and a
finding-set SHA-256 digest — no wall-clock in the persisted result. Offline, no
network, no LLM. Run:

    python benchmarks/false_positive/run.py            # print summary + top-30
    python benchmarks/false_positive/run.py --write     # (re)write results.json
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

from corpus import PREDICATE, benign_slice  # type: ignore[import-not-found]

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[1]
RESULTS_JSON = _HERE / "results.json"

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_HIGH_CRIT = frozenset({"critical", "high"})
TOP_N = 30


def _family(rule_id: str) -> str:
    parts = rule_id.split("-")
    return "-".join(parts[:2]) if len(parts) >= 2 else rule_id


def _scan_config(name: str, config_json: str) -> list[dict[str, str]]:
    """Scan one benign config in isolation via engine.run_scan; return findings."""
    tmp = Path(tempfile.mkdtemp(prefix="aak-fp-"))
    try:
        (tmp / "config.mcp.json").write_text(config_json, encoding="utf-8")
        result = run_scan(tmp)
        return [
            {
                "rule_id": f.rule_id,
                "config": name,
                "severity": f.severity.value,
                "evidence": (f.evidence or "").strip(),
            }
            for f in result.findings
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _ranked(counter: Counter[str]) -> list[tuple[str, int]]:
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def run_benchmark(servers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    slice_servers: list[dict[str, Any]] = benign_slice() if servers is None else servers
    n = len(slice_servers)

    all_findings: list[dict[str, str]] = []
    for s in slice_servers:
        all_findings.extend(_scan_config(str(s.get("name")), json.dumps(s.get("config"))))

    severity = Counter(f["severity"] for f in all_findings)
    hc = [f for f in all_findings if f["severity"] in _HIGH_CRIT]
    configs_with_hc = {f["config"] for f in hc}

    family = Counter(_family(f["rule_id"]) for f in all_findings)
    by_rule = Counter(f["rule_id"] for f in all_findings)
    top_rules_overall = [
        {
            "rule_id": rid,
            "title": RULES[rid].title if rid in RULES else rid,
            "severity": RULES[rid].severity.value if rid in RULES else "?",
            "findings": cnt,
        }
        for rid, cnt in _ranked(by_rule)
    ][:5]
    hc_by_rule = Counter(f["rule_id"] for f in hc)
    top_noisy = [
        {
            "rule_id": rid,
            "title": RULES[rid].title if rid in RULES else rid,
            "severity": RULES[rid].severity.value if rid in RULES else "?",
            "high_critical_findings": cnt,
        }
        for rid, cnt in _ranked(hc_by_rule)
    ][:5]

    # Deterministic top-N HIGH/CRITICAL for manual triage: stable multi-key sort.
    hc_sorted = sorted(
        hc,
        key=lambda f: (_SEV_RANK[f["severity"]], f["rule_id"], f["config"], f["evidence"]),
    )
    top30 = hc_sorted[:TOP_N]

    # Finding-set digest — the determinism invariant (order-independent).
    digest_rows = sorted(
        [f["rule_id"], f["config"], f["severity"], f["evidence"]] for f in all_findings
    )
    digest = hashlib.sha256(
        json.dumps(digest_rows, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    return {
        "tool": "agent-audit-kit",
        "benign_slice_predicate": PREDICATE,
        "benign_slice_n": n,
        "total_findings": len(all_findings),
        "findings_per_config": round(len(all_findings) / n, 2) if n else 0.0,
        "severity_buckets": {k: severity.get(k, 0) for k in _SEV_RANK},
        "high_critical_findings": len(hc),
        "configs_with_high_critical": len(configs_with_hc),
        "high_critical_config_rate": round(len(configs_with_hc) / n, 4) if n else 0.0,
        "rule_family_buckets": dict(_ranked(family)),
        "top_rules_overall": top_rules_overall,
        "top_noisy_high_critical_rules": top_noisy,
        "finding_set_digest": digest,
        "top30_high_critical": top30,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="(Re)write results.json.")
    args = ap.parse_args()

    data = run_benchmark()
    blob = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.write:
        RESULTS_JSON.write_text(blob, encoding="utf-8")
        print(f"wrote {RESULTS_JSON.relative_to(_REPO)}")

    print(
        f"benign slice n = {data['benign_slice_n']} | "
        f"total findings = {data['total_findings']} "
        f"({data['findings_per_config']}/config)\n"
        f"severity = {data['severity_buckets']}\n"
        f"HIGH+CRITICAL findings = {data['high_critical_findings']} "
        f"across {data['configs_with_high_critical']} configs "
        f"({data['high_critical_config_rate'] * 100:.1f}% of slice)\n"
        f"digest = {data['finding_set_digest'][:16]}…"
    )
    print("\ntop HIGH/CRITICAL for triage:")
    for i, f in enumerate(data["top30_high_critical"], 1):
        print(f"  {i:2d}. [{f['severity']:8}] {f['rule_id']:34} {f['config'][:40]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
