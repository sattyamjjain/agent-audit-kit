#!/usr/bin/env python3
"""State of MCP Security 2026 — reproducible research harness.

Scans a corpus of public MCP server configs with AgentAuditKit and aggregates
the findings into a grade distribution (A–F), per-rule-category hit rates, the
top-N most-common misconfigurations, and the 2026-07-28 / 2027-07-28 migration
exposure metrics.

This harness does NOT contain a scanner. It REUSES:
  - ``agent_audit_kit.engine.run_scan``       — the scan entrypoint (engine.py)
  - ``agent_audit_kit.scoring.compute_score``  — the same penalty-based A–F grade
                                                 ``aak score`` / the Security Index use
  - ``agent_audit_kit.rules.builtin.RULES``    — rule titles + families
  - ``agent_audit_kit.scanners.oauth_misconfig`` regexes — the RFC 9728 PRM /
                                                 inline-credential detection that
                                                 backs AAK-OAUTH-008

Corpus = two provenance-tracked sources, deduped by config content:
  1. ``benchmarks/data`` — GitHub-crawled ``.mcp.json`` files (existing).
  2. ``research/state-of-mcp-2026/corpus/registry-manifest.json`` — official MCP
     Registry latest-version servers (see ``fetch_registry.py``).

Reproduce (offline, deterministic — no network, no LLM):
    python research/state-of-mcp-2026/run_report.py \
        --corpus benchmarks/data \
        --registry-manifest research/state-of-mcp-2026/corpus/registry-manifest.json \
        --out research/state-of-mcp-2026/results.json
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
from agent_audit_kit.scanners.oauth_misconfig import (
    _MCP_INLINE_AUTH_RE,
    _MCP_REMOTE_RE,
    _PRM_DISCOVERY_RE,
)
from agent_audit_kit.scoring import compute_score

# Findings AAK reports that are advisory *posture* signals, not exploitable
# misconfigurations. Excluded from the "top misconfigurations" headline so the
# story isn't inflated (documented in REPORT.md).
_ADVISORY_RULES = frozenset({"AAK-MCP-ATTEST-001", "AAK-MCP-007"})

# The remote MCP server "no authentication" rule.
_NO_AUTH_RULE = "AAK-MCP-001"
# Deprecated SSE transport — the measurable proxy for the 2026-07-28 stateless
# transport break (SEP-2567 removes Mcp-Session-Id; the SSE session model goes).
_SSE_DEPRECATED_RULE = "AAK-TRANSPORT-003"
# 2027-07-28 removal-clock features (Roots/Sampling/Logging + DCR). These are
# runtime/server-code capabilities, largely NOT expressible in a client
# ``.mcp.json`` config — reported with an explicit coverage denominator.
_REMOVAL_CLOCK_RULES = frozenset({
    "AAK-MCP-DEPRECATED-001", "AAK-MCP-DEPRECATED-002", "AAK-MCP-DEPRECATED-003",
    "AAK-MCP-STATELESS-001", "AAK-MCP-STATELESS-002",
    "AAK-MCP-STATELESS-003", "AAK-MCP-STATELESS-004",
})


def _iter_files(corpus: Path) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for p in sorted(corpus.rglob("*.json")):
        if p.is_file() and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _config_sources(corpus: Path, registry_manifest: Path | None) -> list[tuple[str, str, str]]:
    """Unified (identifier, text, provenance-source) list from both corpora."""
    sources: list[tuple[str, str, str]] = []
    for p in _iter_files(corpus):
        try:
            sources.append((str(p), p.read_text(encoding="utf-8", errors="ignore"), "crawl"))
        except OSError:
            continue
    if registry_manifest and registry_manifest.is_file():
        data = json.loads(registry_manifest.read_text(encoding="utf-8"))
        for s in data.get("servers", []) or []:
            cfg = s.get("config")
            if cfg is None:
                continue
            sources.append((s.get("name", "?"), json.dumps(cfg), "registry"))
    return sources


def _content_key(text: str) -> str | None:
    try:
        raw = json.loads(text)
    except ValueError:
        return None
    blob = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _scan_text(text: str) -> Any:
    """Scan one config in isolation via engine.run_scan + scoring.compute_score."""
    tmp = Path(tempfile.mkdtemp(prefix="aak-somcp-"))
    try:
        (tmp / "config.mcp.json").write_text(text, encoding="utf-8")
        result = run_scan(tmp)
        compute_score(result)
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _transport_of_entry(entry: Any) -> str:
    if not isinstance(entry, dict):
        return "unknown"
    t = str(entry.get("type") or entry.get("transport") or "").lower()
    if "streamable" in t or t == "http":
        return "streamable-http"
    if t == "sse":
        return "sse"
    if entry.get("command"):
        return "stdio"
    if entry.get("url"):
        return "streamable-http"
    return "unknown"


def _transport_signals(text: str) -> tuple[Counter[str], bool]:
    """Per-server-entry transport counts + whether the config declares a remote server."""
    counts: Counter[str] = Counter()
    remote = False
    try:
        raw = json.loads(text)
    except ValueError:
        return counts, remote
    servers = raw.get("mcpServers") or raw.get("servers") or {}
    if isinstance(servers, dict):
        for entry in servers.values():
            tr = _transport_of_entry(entry)
            counts[tr] += 1
            if tr in ("streamable-http", "sse"):
                remote = True
    return counts, remote


def _family(rule_id: str) -> str:
    parts = rule_id.split("-")
    return "-".join(parts[:2]) if len(parts) >= 2 else rule_id


def _ranked(counter: Counter[str]) -> list[tuple[str, int]]:
    """Stable rank: by count desc, then key asc — so ties never flip between
    runs (set-iteration order is not hash-stable). This is what keeps
    results.json byte-identical across runs."""
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def aggregate(corpus: Path, registry_manifest: Path | None) -> dict[str, Any]:
    sources = _config_sources(corpus, registry_manifest)
    seen_keys: set[str] = set()

    total = 0
    duplicates = 0
    unparseable = 0
    src_counts: Counter[str] = Counter()
    grades: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    category_configs: Counter[str] = Counter()
    rule_configs: Counter[str] = Counter()
    owasp_mcp_configs: Counter[str] = Counter()
    family_configs: Counter[str] = Counter()
    transport_entries: Counter[str] = Counter()
    has_critical = 0
    has_high = 0

    # Auth-profile (2026-07-28) metrics.
    no_auth = 0
    prm_discovery = 0
    remote_configs = 0
    remote_auth_configs = 0
    static_cred_configs = 0
    sse_deprecated = 0
    removal_clock = 0

    for _, text, src in sources:
        key = _content_key(text)
        if key is None:
            unparseable += 1
            continue
        if key in seen_keys:
            duplicates += 1
            continue
        seen_keys.add(key)

        result = _scan_text(text)
        total += 1
        src_counts[src] += 1
        grades[result.grade or "?"] += 1

        tr_counts, is_remote = _transport_signals(text)
        transport_entries.update(tr_counts)
        if is_remote:
            remote_configs += 1
        has_prm = bool(_PRM_DISCOVERY_RE.search(text))
        if has_prm:
            prm_discovery += 1
        has_inline_auth = bool(_MCP_INLINE_AUTH_RE.search(text)) and bool(_MCP_REMOTE_RE.search(text))
        if has_inline_auth:
            remote_auth_configs += 1
            if not has_prm:
                static_cred_configs += 1

        rules_here: set[str] = set()
        cats_here: set[str] = set()
        sev_here: set[str] = set()
        owasp_here: set[str] = set()
        for f in result.findings:
            severities[f.severity.value] += 1
            sev_here.add(f.severity.value)
            cats_here.add(f.category.value)
            rules_here.add(f.rule_id)
            rule = RULES.get(f.rule_id)
            if rule:
                owasp_here.update(rule.owasp_mcp_references)
        for c in cats_here:
            category_configs[c] += 1
        fams_here: set[str] = set()
        for r in rules_here:
            rule_configs[r] += 1
            fams_here.add(_family(r))
        for fam in fams_here:  # configs with >=1 finding in the family (<=100%)
            family_configs[fam] += 1
        for o in owasp_here:
            owasp_mcp_configs[o] += 1
        if _NO_AUTH_RULE in rules_here:
            no_auth += 1
        if _SSE_DEPRECATED_RULE in rules_here or tr_counts.get("sse"):
            sse_deprecated += 1
        if rules_here & _REMOVAL_CLOCK_RULES:
            removal_clock += 1
        if "critical" in sev_here:
            has_critical += 1
        if "high" in sev_here:
            has_high += 1

    def _pct(n: int, d: int = total) -> float:
        return round(100.0 * n / d, 1) if d else 0.0

    def _metric(n: int, d: int) -> dict[str, Any]:
        return {"n": n, "denominator": d, "pct": _pct(n, d)}

    top_misconfig = [
        {
            "rule_id": rid,
            "title": RULES[rid].title if rid in RULES else rid,
            "severity": RULES[rid].severity.value if rid in RULES else "?",
            "configs": n,
            "config_pct": _pct(n),
        }
        for rid, n in _ranked(rule_configs)
        if rid not in _ADVISORY_RULES
    ][:10]

    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    return {
        "tool": "agent-audit-kit",
        "corpus": str(corpus),
        "corpus_sources": dict(sorted(src_counts.items())),
        "corpus_total_candidates": len(sources),
        "distinct_configs_scanned": total,
        "duplicates_removed": duplicates,
        "unparseable_removed": unparseable,
        "grade_distribution": dict(sorted(grades.items())),
        "configs_with_critical": has_critical,
        "configs_with_critical_pct": _pct(has_critical),
        "configs_with_high": has_high,
        "configs_with_high_pct": _pct(has_high),
        "severity_totals": dict(sorted(severities.items(), key=lambda kv: _sev_order.get(kv[0], 9))),
        "transport_distribution": dict(_ranked(transport_entries)),
        "rule_family_distribution": {
            fam: {"configs": n, "pct": _pct(n)} for fam, n in _ranked(family_configs)
        },
        "category_hit_rate": {
            cat: {"configs": n, "pct": _pct(n)} for cat, n in _ranked(category_configs)
        },
        "owasp_mcp_hit_rate": {
            code: {"configs": n, "pct": _pct(n)} for code, n in _ranked(owasp_mcp_configs)
        },
        "auth_profile_2026_07_28": {
            "no_authentication": _metric(no_auth, total),
            "rfc9728_prm_discovery": _metric(prm_discovery, total),
            "remote_configs": _metric(remote_configs, total),
            "remote_auth_static_credential": _metric(static_cred_configs, remote_auth_configs),
            "sse_transport_stateless_break_proxy": _metric(sse_deprecated, total),
            "removal_clock_features_measured_from_config": _metric(removal_clock, total),
        },
        "top_misconfigurations": top_misconfig,
        "excluded_advisory_rules": sorted(_ADVISORY_RULES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="benchmarks/data",
                        help="Directory of crawled MCP configs (default: benchmarks/data).")
    parser.add_argument("--registry-manifest",
                        default="research/state-of-mcp-2026/corpus/registry-manifest.json",
                        help="MCP Registry corpus manifest (see fetch_registry.py).")
    parser.add_argument("--out", default="research/state-of-mcp-2026/results.json",
                        help="Where to write the aggregate results JSON.")
    args = parser.parse_args()

    corpus = Path(args.corpus)
    if not corpus.is_dir():
        raise SystemExit(f"Corpus dir {corpus} not found. Populate benchmarks/data first.")
    reg = Path(args.registry_manifest) if args.registry_manifest else None

    data = aggregate(corpus, reg)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    ap = data["auth_profile_2026_07_28"]
    print(
        f"scanned {data['distinct_configs_scanned']} distinct configs "
        f"(sources={data['corpus_sources']}; "
        f"{data['duplicates_removed']} dup, {data['unparseable_removed']} unparseable removed)\n"
        f"grades: {data['grade_distribution']}\n"
        f"critical: {data['configs_with_critical']} ({data['configs_with_critical_pct']}%)\n"
        f"no-auth: {ap['no_authentication']['n']} ({ap['no_authentication']['pct']}%) | "
        f"PRM: {ap['rfc9728_prm_discovery']['n']} ({ap['rfc9728_prm_discovery']['pct']}%) | "
        f"static-cred: {ap['remote_auth_static_credential']['n']}/"
        f"{ap['remote_auth_static_credential']['denominator']}\n"
        f"wrote {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
