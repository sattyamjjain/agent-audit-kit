#!/usr/bin/env python3
"""AAK-MCP-001 measurement, Steps 0 and 1: offline, deterministic, no LLM.

``AAK-MCP-001`` fires CRITICAL on every URL server whose config carries no
recognized auth header. It is also the State of MCP report's headline: in report
v1.0, 1,201 of 2,303 configs, all of them among the 1,213 (52.7%) that carry a
critical finding. A hosted server that follows the MCP authorization specification puts
no credential in the config at all, because the client runs OAuth at connect
time, so its correct config fires too. This module measures how much of the
headline rests on that. It does not change the rule.

Step 0 re-derives the published numbers from a fresh scan of the same corpus
the report used, iterated exactly as ``run_report.aggregate`` iterates it (its
own ``_config_sources``, ``_content_key`` and ``_scan_text`` are imported, not
copied), checks them against the committed ``results.json``, and recomputes the
critical headline under five counterfactuals: every hit wrong, loopback hosts
exempt, private hosts exempt as well, an https URL without a header downgraded
below critical, and loopback exempt with https downgraded.

Step 1 classifies every hit by what its URL says: host class (loopback,
private, public, placeholder, template), scheme, transport, whether the URL
itself carries a credential, and whether the config carries an auth-looking
header the rule does not recognize. A hit is one ``AAK-MCP-001`` finding, that
is one (config, server entry) pair; ``hits_for`` re-derives them with the
rule's own predicate and every config's hits are checked, evidence string for
evidence string, against the findings the engine actually emitted, so the
population cannot drift from the rule.

What it writes:

* ``results.json`` (committed, ``--write``): aggregates only. ``--check`` diffs
  a fresh run against it. Both need the gitignored ``benchmarks/data`` crawl.
* ``probe-headline.json`` (committed, ``--write`` with ``--probe-raw``): the
  headline joined with what the servers answered, by evidence class. Counts
  only; it needs the probe's raw log, which is never committed, so it is
  regenerated with the probe rather than checked in CI.
* ``population.jsonl`` (``--population-out``, never committed): one redacted
  record per hit for the labeler. It is checked for secret patterns before it
  is written and refused if any survive redaction.

The live probe of the public https endpoints is a separate, opt-in network
step: ``probe.py --probe``. Its raw log is read here with ``--probe-raw``;
nothing in this module touches the network.

Run (from the repo root):

    python benchmarks/aak_mcp_001/measure.py              # print Step 0 / Step 1
    python benchmarks/aak_mcp_001/measure.py --write      # (re)write results.json
    python benchmarks/aak_mcp_001/measure.py --check      # drift guard
    python benchmarks/aak_mcp_001/measure.py \\
        --population-out /path/outside/repo/population.jsonl \\
        --probe-raw /path/outside/repo/probe-raw.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
# Import this tree's package, never another checkout's editable install.
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from agent_audit_kit.redaction import redact_evidence  # noqa: E402
from agent_audit_kit.scanners import mcp_config  # noqa: E402
from agent_audit_kit.scanners._helpers import is_loopback_url, iter_mcp_servers  # noqa: E402

RESEARCH = REPO / "research" / "state-of-mcp-2026"
DEFAULT_MANIFEST = RESEARCH / "corpus" / "registry-manifest.json"
DEFAULT_CACHE = RESEARCH / "cache"
REPORT_RESULTS = RESEARCH / "results.json"
RESULTS_JSON = HERE / "results.json"

RULE = "AAK-MCP-001"
_EVIDENCE = "Server '{name}' URL: {url} — no authentication headers"
_MAX_CONFIG_BYTES = 1_000_000  # mcp_config.scan skips anything larger


def default_corpus() -> Path:
    """``$AAK_MCP001_CORPUS`` if set (a worktree has no crawl of its own), else
    the gitignored ``benchmarks/data`` in this checkout."""
    env = os.environ.get("AAK_MCP001_CORPUS")
    return Path(env) if env else REPO / "benchmarks" / "data"


def default_cache() -> Path:
    """``$AAK_MCP001_REGISTRY_CACHE`` if set, else the gitignored raw registry
    pages ``fetch_registry.py`` cached beside the manifest."""
    env = os.environ.get("AAK_MCP001_REGISTRY_CACHE")
    return Path(env) if env else DEFAULT_CACHE


def load_module(name: str, path: Path) -> ModuleType:
    """Import a file by path under a unique name, registered before it runs.

    research/ and benchmarks/ are not packages, and the benchmark directories
    reuse module names (``corpus``, ``run``), so a sys.path import could pick up
    the wrong one. Registering first keeps dataclasses and repeat loads working.
    """
    key = f"aak_mcp_001_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


endpoints = load_module("endpoints", HERE / "endpoints.py")


def run_report() -> ModuleType:
    return load_module("run_report", RESEARCH / "run_report.py")


class MeasurementError(RuntimeError):
    """The measurement disagrees with the engine or the published data."""


def _pct(n: int, d: int) -> float:
    """Same rounding as run_report: one decimal, of 100 * n / d."""
    return round(100.0 * n / d, 1) if d else 0.0


def _metric(n: int, d: int) -> dict[str, Any]:
    return {"n": n, "denominator": d, "pct": _pct(n, d)}


def hit_id(content_key: str, server_name: str) -> str:
    """Stable, opaque id for one hit: re-derivable from the corpus, and
    identifying nothing without it."""
    return hashlib.sha256(f"{content_key}\x00{server_name}".encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Hits: the rule's own predicate, checked against the engine's findings
# ---------------------------------------------------------------------------


def hits_for(text: str) -> list[tuple[str, dict[str, Any], str]]:
    """``(server_name, entry, url)`` for every entry AAK-MCP-001 fires on.

    Uses the rule's own helpers (`mcp_config._as_str`, `_server_declares_auth`,
    `is_loopback_url`) on the server maps the scanner reads
    (`iter_mcp_servers`: `mcpServers`, then VS Code's `servers`), so this is the
    predicate, not a copy. The rule has exempted a loopback host since report
    v1.1; without that exemption here the population held hits the engine no
    longer emits, and the run stopped on the mismatch below.
    """
    if len(text) > _MAX_CONFIG_BYTES:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: list[tuple[str, dict[str, Any], str]] = []
    for name, entry in iter_mcp_servers(data):
        url = mcp_config._as_str(entry.get("url", ""))
        if (url and not is_loopback_url(url)
                and not mcp_config._server_declares_auth(entry.get("headers", {}))):
            out.append((name, entry, url))
    return out


def _header_auth(headers: Any) -> tuple[str, list[dict[str, str]]]:
    """Why a header block did not count as auth, when it looks like it should.

    ``unrecognized-name``: a header whose name says credential (``token``,
    ``context7_api_key``) but which the rule's recognizer does not match.
    ``literal-value``: a recognized custom auth header holding a hardcoded
    literal, which the rule fires on by design (the credential is exposed in
    the config). Header VALUES are never returned, only their kind.
    """
    if not isinstance(headers, dict) or not headers:
        return "none", []
    status = "none"
    shapes: list[dict[str, str]] = []
    for name, value in headers.items():
        lname = str(name).lower()
        kind = "reference" if mcp_config._is_credential_reference(str(value)) else "literal"
        shapes.append({"name": endpoints.redact_text(str(name), 80), "value_kind": kind})
        recognized = (
            lname in mcp_config._KNOWN_AUTH_HEADERS
            or bool(mcp_config._CUSTOM_AUTH_HEADER_RE.match(lname))
        )
        if mcp_config._NON_AUTH_TOKEN_HEADERS.match(lname):
            continue
        if recognized and kind == "literal":
            status = "literal-value" if status == "none" else status
        elif not recognized and endpoints.credential_name(lname):
            status = "unrecognized-name"
    return status, sorted(shapes, key=lambda s: s["name"])


def hit_features(entry: dict[str, Any], url: str) -> dict[str, Any]:
    """Deterministic Step 1 features of one hit. No network."""
    rr = run_report()
    cu = endpoints.classify_url(url)
    cred = endpoints.url_credential(url)
    header_status, header_shapes = _header_auth(entry.get("headers"))
    declared = entry.get("type", entry.get("transport", ""))
    return {
        "scheme": cu["scheme"] or "none",
        "host": cu["host"],
        "host_class": cu["host_class"],
        "url_has_template": bool(cu["has_template"]),
        "url_credential": cred["status"],
        "url_credential_where": cred["where"],
        "transport": rr._transport_of_entry(entry),
        "declared_type": declared if isinstance(declared, str) else type(declared).__name__,
        "header_auth": header_status,
        "headers": header_shapes,
    }


def scan_corpus(corpus: Path, manifest: Path | None) -> list[dict[str, Any]]:
    """One record per distinct config, in the report's order, with its hits.

    Iterates exactly as ``run_report.aggregate`` does: its source order, its
    content-key dedup (first occurrence wins, so a config in both the crawl and
    the registry counts as crawl), its unparseable skip, and one isolated
    ``_scan_text`` per config.
    """
    rr = run_report()
    seen: set[str] = set()
    configs: list[dict[str, Any]] = []
    for ident, text, src in rr._config_sources(corpus, manifest):
        key = rr._content_key(text)
        if key is None or key in seen:
            continue
        seen.add(key)
        result = rr._scan_text(text)
        derived = hits_for(text)
        # The engine masks credentials in evidence (agent_audit_kit.redaction),
        # so the derived strings go through the same mask before comparing.
        expected = Counter(
            redact_evidence(_EVIDENCE.format(name=n, url=u)) for n, _, u in derived
        )
        actual = Counter(f.evidence for f in result.findings if f.rule_id == RULE)
        if expected != actual:
            raise MeasurementError(
                f"{RULE} hits re-derived for one {src} config disagree with the "
                f"engine ({sum(expected.values())} derived vs {sum(actual.values())} "
                f"emitted); the population would not be the rule's"
            )
        config_id = Path(ident).name if src == "crawl" else ident
        configs.append({
            "config_id": config_id,
            "source": src,
            "content_key": key,
            "rule_ids": sorted({f.rule_id for f in result.findings}),
            "critical_rules": sorted(
                {f.rule_id for f in result.findings if f.severity.value == "critical"}
            ),
            "hits": [
                {
                    "hit_id": hit_id(key, name),
                    "server_name": name,
                    "url": url,  # raw: in memory only, redacted before any write
                    "entry": entry,  # raw: in memory only
                    **hit_features(entry, url),
                }
                for name, entry, url in derived
            ],
        })
    return configs


# ---------------------------------------------------------------------------
# Step 0: the published numbers, and the headline under counterfactuals
# ---------------------------------------------------------------------------


def _other_critical(config: dict[str, Any]) -> bool:
    return bool(set(config["critical_rules"]) - {RULE})


# Each scenario keeps an AAK-MCP-001 hit at CRITICAL only when its predicate
# holds. "https downgraded" keeps a hit whose scheme is not known to be https,
# so a templated URL (scheme unknown) stays critical.
SCENARIOS: tuple[tuple[str, str, Callable[[dict[str, Any]], bool]], ...] = (
    ("as-published", "the rule as shipped", lambda h: True),
    ("every-hit-wrong", "every AAK-MCP-001 hit is a false positive", lambda h: False),
    ("loopback-exempt", "loopback hosts exempt", lambda h: h["host_class"] != "loopback"),
    (
        "loopback-and-private-exempt",
        "loopback and private-network hosts exempt",
        lambda h: h["host_class"] not in ("loopback", "private"),
    ),
    (
        "https-downgraded",
        "https without a header downgraded below critical",
        lambda h: h["scheme"] != "https",
    ),
    (
        "loopback-exempt-and-https-downgraded",
        "loopback exempt and https downgraded",
        lambda h: h["host_class"] != "loopback" and h["scheme"] != "https",
    ),
)


def scenario_table(configs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total = len(configs)
    rows = []
    for key, label, keep in SCENARIOS:
        still = sum(1 for c in configs if any(keep(h) for h in c["hits"]))
        crit = sum(1 for c in configs if _other_critical(c) or any(keep(h) for h in c["hits"]))
        rows.append({
            "scenario": key,
            "description": label,
            "configs_with_critical": _metric(crit, total),
            "configs_where_aak_mcp_001_stays_critical": _metric(still, total),
        })
    return rows


def step0(configs: list[dict[str, Any]], published: dict[str, Any] | None) -> dict[str, Any]:
    total = len(configs)
    with_hit = [c for c in configs if c["hits"]]
    with_crit = [c for c in configs if c["critical_rules"]]
    other = [c for c in configs if _other_critical(c)]
    other_rules: Counter[str] = Counter()
    for c in other:
        other_rules.update(set(c["critical_rules"]) - {RULE})
    per_config = Counter(len(c["hits"]) for c in with_hit)
    fresh = {
        "distinct_configs_scanned": total,
        "aak_mcp_001_configs": len(with_hit),
        "configs_with_critical": len(with_crit),
        "configs_with_critical_pct": _pct(len(with_crit), total),
    }
    checks: dict[str, Any] = {}
    if published is not None:
        pub = {
            "distinct_configs_scanned": published.get("distinct_configs_scanned"),
            "aak_mcp_001_configs":
                published.get("auth_profile_2026_07_28", {}).get("no_authentication", {}).get("n"),
            "configs_with_critical": published.get("configs_with_critical"),
            "configs_with_critical_pct": published.get("configs_with_critical_pct"),
        }
        checks = {k: {"published": pub[k], "fresh": fresh[k], "equal": pub[k] == fresh[k]}
                  for k in fresh}
    return {
        "published_check": checks,
        "distinct_configs_scanned": total,
        "aak_mcp_001": {
            "configs": _metric(len(with_hit), total),
            "findings": sum(len(c["hits"]) for c in with_hit),
            "findings_per_config": {str(k): v for k, v in sorted(per_config.items())},
            "configs_also_carrying_critical": sum(1 for c in with_hit if c["critical_rules"]),
        },
        "configs_with_critical": _metric(len(with_crit), total),
        "configs_with_critical_but_no_aak_mcp_001": sum(1 for c in with_crit if not c["hits"]),
        "configs_with_a_critical_other_than_aak_mcp_001": _metric(len(other), total),
        "configs_with_aak_mcp_001_and_another_critical": sum(1 for c in other if c["hits"]),
        "other_critical_rules_by_config": dict(
            sorted(other_rules.items(), key=lambda kv: (-kv[1], kv[0]))
        ),
        "scenarios": scenario_table(configs),
    }


# ---------------------------------------------------------------------------
# Step 1: deterministic classification of every hit
# ---------------------------------------------------------------------------


def probe_candidate(hit: dict[str, Any]) -> str | None:
    """None when the probe may send to this hit's URL, else the skip reason.

    The probe adds two runtime gates of its own (DNS must resolve to public
    addresses only; the query must be plain), but a hit that fails here is never
    handed to it.
    """
    if hit["host_class"] in ("loopback", "private"):
        return "non-public host"
    if hit["host_class"] in ("template", "placeholder", "invalid"):
        return f"{hit['host_class']} host"
    if hit["scheme"] != "https":
        return "not https"
    if hit["url_credential"] != "none":
        return "credential in URL"
    if hit["url_has_template"]:
        return "template in URL"
    if not endpoints.query_is_plain(hit["url"]):
        # Not provably a credential, not provably safe: a long or non-plain query
        # value, or a 64+ character path segment. Counted apart so the
        # conservative skips are visible, never sent.
        return "credential in URL (suspected)"
    return None


def _ranked(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def step1(configs: list[dict[str, Any]], manifest: Path | None) -> dict[str, Any]:
    hits = [(c, h) for c in configs for h in c["hits"]]
    auth_modes = _manifest_auth_modes(manifest)
    by_source: Counter[str] = Counter()
    host_scheme: Counter[str] = Counter()
    host_cls: Counter[str] = Counter()
    scheme: Counter[str] = Counter()
    transport: Counter[str] = Counter()
    declared: Counter[str] = Counter()
    cred: Counter[str] = Counter()
    cred_where: Counter[str] = Counter()
    header: Counter[str] = Counter()
    reg_auth: Counter[str] = Counter()
    skip: Counter[str] = Counter()
    candidate_endpoints: set[str] = set()
    candidate_hosts: set[str] = set()
    public_https_hosts: set[str] = set()
    for c, h in hits:
        by_source[c["source"]] += 1
        host_cls[h["host_class"]] += 1
        scheme[h["scheme"]] += 1
        host_scheme[f"{h['host_class']}/{h['scheme']}"] += 1
        transport[h["transport"]] += 1
        declared[h["declared_type"] or "(none)"] += 1
        cred[h["url_credential"]] += 1
        for w in h["url_credential_where"]:
            cred_where[w] += 1
        header[h["header_auth"]] += 1
        if c["source"] == "registry":
            reg_auth[auth_modes.get(c["config_id"], "(not in manifest)")] += 1
        if h["host_class"] == "public" and h["scheme"] == "https":
            public_https_hosts.add(h["host"])
        reason = probe_candidate(h)
        if reason is None:
            candidate_endpoints.add(endpoints.endpoint_key(h["url"]))
            candidate_hosts.add(h["host"])
        else:
            skip[reason] += 1
    return {
        "hits": len(hits),
        "hits_by_source": _ranked(by_source),
        "host_class": _ranked(host_cls),
        "scheme": _ranked(scheme),
        "host_class_by_scheme": _ranked(host_scheme),
        "transport": _ranked(transport),
        "declared_type": _ranked(declared),
        "url_credential": _ranked(cred),
        "url_credential_where": _ranked(cred_where),
        "header_auth": _ranked(header),
        "registry_auth_mode": _ranked(reg_auth),
        "public_https_distinct_hosts": len(public_https_hosts),
        "probe_plan": {
            "candidate_hits": len(hits) - sum(skip.values()),
            "candidate_distinct_endpoints": len(candidate_endpoints),
            "candidate_distinct_hosts": len(candidate_hosts),
            "skipped_hits": _ranked(skip),
        },
    }


def _manifest_auth_modes(manifest: Path | None) -> dict[str, str]:
    if manifest is None or not manifest.is_file():
        return {}
    data = json.loads(manifest.read_text(encoding="utf-8"))
    return {str(s.get("name")): str(s.get("auth_mode")) for s in data.get("servers", []) or []}


def build_results(corpus: Path, manifest: Path | None,
                  configs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The committed aggregate. Deterministic: no clock, no paths, sorted keys."""
    configs = scan_corpus(corpus, manifest) if configs is None else configs
    published = (
        json.loads(REPORT_RESULTS.read_text(encoding="utf-8")) if REPORT_RESULTS.is_file() else None
    )
    src = Counter(c["source"] for c in configs)
    return {
        "tool": "agent-audit-kit",
        "rule": RULE,
        "corpus": {
            "same_as": "research/state-of-mcp-2026/results.json (run_report.py iteration order)",
            "distinct_configs": len(configs),
            "by_source": dict(sorted(src.items())),
        },
        "unit": "hit = one AAK-MCP-001 finding = one (config, server entry) pair",
        "step0": step0(configs, published),
        "step1": step1(configs, manifest),
    }


# ---------------------------------------------------------------------------
# Population (Step 2 input): redacted, one record per hit, never committed
# ---------------------------------------------------------------------------


def load_registry_cache(cache_dir: Path, manifest: Path | None) -> dict[str, dict[str, Any]]:
    """Raw registry records for the manifest's servers, keyed by name.

    The manifest keeps only provenance; the cached raw pages from the same
    2026-07-26 crawl carry the title, description and every remote. The record
    whose version matches the manifest's is used (the pages hold every version).
    Missing cache: empty dict, and the population falls back to the manifest.
    """
    if not cache_dir.is_dir():
        return {}
    want: dict[str, str] = {}
    if manifest is not None and manifest.is_file():
        for s in json.loads(manifest.read_text(encoding="utf-8")).get("servers", []) or []:
            want[str(s.get("name"))] = str(s.get("version"))
    out: dict[str, dict[str, Any]] = {}
    for page in sorted(cache_dir.glob("page-*.json")):
        try:
            data = json.loads(page.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for e in data.get("servers", []) or []:
            server = e.get("server") or {}
            name = str(server.get("name") or "")
            if name in want and str(server.get("version")) == want[name]:
                out[name] = server
    return out


def _redact_registry(server: dict[str, Any] | None, manifest_row: dict[str, Any] | None) -> dict[str, Any]:
    r: dict[str, Any] = {}
    if manifest_row:
        r.update({
            "name": manifest_row.get("name"),
            "version": manifest_row.get("version"),
            "auth_mode": manifest_row.get("auth_mode"),
            "transport": manifest_row.get("transport"),
            "registry_status": manifest_row.get("registry_status"),
            "published_at": manifest_row.get("published_at"),
            "source_url": endpoints.redact_url(str(manifest_row.get("source_url") or "")),
        })
    if server:
        repo_raw = server.get("repository")
        repo: dict[str, Any] = repo_raw if isinstance(repo_raw, dict) else {}
        remotes = []
        for rem in server.get("remotes") or []:
            if not isinstance(rem, dict):
                continue
            headers = []
            for hdr in rem.get("headers") or []:
                if not isinstance(hdr, dict):
                    continue
                value = hdr.get("value")
                headers.append({
                    "name": endpoints.redact_text(str(hdr.get("name") or ""), 80),
                    "is_secret": bool(hdr.get("isSecret")),
                    "is_required": bool(hdr.get("isRequired")),
                    "has_value": value is not None,
                    "value_kind": (
                        "none" if value is None
                        else "template" if endpoints.TEMPLATE_RE.search(str(value))
                        else "literal"
                    ),
                    "description": endpoints.redact_text(str(hdr.get("description") or ""), 300),
                })
            remotes.append({
                "type": rem.get("type"),
                "url": endpoints.redact_url(str(rem.get("url") or "")),
                "headers": headers,
                "variables": sorted(str(k) for k in (rem.get("variables") or {})),
            })
        r.update({
            "title": endpoints.redact_text(str(server.get("title") or ""), 200),
            "description": endpoints.redact_text(str(server.get("description") or ""), 1000),
            "website_url": endpoints.redact_url(str(server.get("websiteUrl") or "")) or None,
            "repository_url": endpoints.redact_url(str(repo.get("url") or "")) or None,
            "remotes": remotes,
            "has_packages": bool(server.get("packages")),
        })
    return r


def _entry_shape(entry: dict[str, Any]) -> dict[str, Any]:
    """The server entry's structure without its values: key names, and the
    sub-keys of any object (an ``oauth`` / ``auth`` block is evidence)."""
    shape: dict[str, Any] = {}
    for k, v in entry.items():
        key = endpoints.redact_text(str(k), 80)
        if isinstance(v, dict):
            shape[key] = sorted(endpoints.redact_text(str(sk), 80) for sk in v)
        elif k in ("type", "transport") and isinstance(v, str):
            shape[key] = v
        else:
            shape[key] = type(v).__name__
    return shape


def population_records(
    configs: list[dict[str, Any]],
    manifest: Path | None,
    cache_dir: Path | None,
    probe_by_endpoint: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    if manifest is not None and manifest.is_file():
        for s in json.loads(manifest.read_text(encoding="utf-8")).get("servers", []) or []:
            rows[str(s.get("name"))] = s
    raw = load_registry_cache(cache_dir, manifest) if cache_dir is not None else {}
    probe_by_endpoint = probe_by_endpoint or {}
    out = []
    for c in configs:
        for h in c["hits"]:
            skip = probe_candidate(h)
            endpoint = endpoints.endpoint_key(h["url"]) if skip is None else None
            rec = {
                "hit_id": h["hit_id"],
                "config_id": endpoints.redact_text(c["config_id"], 200),
                "source": c["source"],
                "server_name": endpoints.redact_text(h["server_name"], 200),
                "url": endpoints.redact_url(h["url"]),
                "scheme": h["scheme"],
                "host": h["host"],
                "host_class": h["host_class"],
                "transport": h["transport"],
                "declared_type": h["declared_type"],
                "url_credential": h["url_credential"],
                "url_credential_where": h["url_credential_where"],
                "header_auth": h["header_auth"],
                "headers": h["headers"],
                "entry_shape": _entry_shape(h["entry"]),
                "config_hits": len(c["hits"]),
                "config_other_rules": [r for r in c["rule_ids"] if r != RULE],
                "config_other_critical": _other_critical(c),
                "registry": (
                    _redact_registry(raw.get(c["config_id"]), rows.get(c["config_id"]))
                    if c["source"] == "registry" else None
                ),
                "probe": (
                    probe_by_endpoint.get(endpoint)
                    if endpoint is not None
                    else {"status": "not probed", "reason": skip}
                ),
            }
            out.append(rec)
    return out


def write_population(records: list[dict[str, Any]], path: Path) -> int:
    """Write JSONL after proving no secret pattern survived redaction."""
    blob = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in records)
    leaks = endpoints.leak_report(blob)
    if leaks:
        raise MeasurementError(
            f"refusing to write the population: {len(leaks)} secret-pattern match(es) "
            f"survived redaction ({', '.join(sorted(set(leaks)))})"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(blob, encoding="utf-8")
    return len(records)


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Step 1, joined: what the URL says plus what the server answered
# ---------------------------------------------------------------------------

PROBE_HEADLINE_JSON = HERE / "probe-headline.json"

# Evidence classes, from what was observed, never from a judgement. "refused"
# means the server turned an unauthenticated client away; "accepted" means it
# answered the initialize with a JSON-RPC result. Neither is a verdict: a
# refusing server can still be misconfigured, and an accepting one can be
# public by design. That call is Step 3's.
EVIDENCE_CLASSES = (
    "non-public host",
    "unresolvable host",
    "not probed: credential or template in URL",
    "refused: HTTP 401/403",
    "refused: HTTP 402",
    "accepted unauthenticated initialize",
    "no DNS answer",
    "no HTTP answer (timeout or TLS)",
    "other HTTP answer",
    "not in probe log",
)


def evidence_class(hit: dict[str, Any], probe_by_endpoint: dict[str, dict[str, Any]]) -> str:
    skip = probe_candidate(hit)
    if skip == "non-public host":
        return "non-public host"
    if skip in ("template host", "placeholder host", "invalid host"):
        return "unresolvable host"
    if skip is not None:
        return "not probed: credential or template in URL"
    p = probe_by_endpoint.get(endpoints.endpoint_key(hit["url"]))
    if not p:
        return "not in probe log"
    if p.get("status") != "probed":
        # Resolved, but to a private address: as non-public as a literal one.
        return "non-public host" if "non-public" in str(p.get("skip_reason")) else "no DNS answer"
    outcome = (p.get("initialize") or {}).get("outcome", "")
    if outcome == "auth-required":
        return "refused: HTTP 401/403"
    if outcome == "payment-required":
        return "refused: HTTP 402"
    if outcome == "accepted":
        return "accepted unauthenticated initialize"
    if outcome.startswith("error:"):
        return "no HTTP answer (timeout or TLS)"
    return "other HTTP answer"


# Which hits keep the config critical, per scenario. Facts, not verdicts: these
# bound the headline before anyone decides what "public by design" covers.
PROBE_SCENARIOS: tuple[tuple[str, str, Callable[[str], bool]], ...] = (
    ("as-published", "every hit counts", lambda e: True),
    ("refused-exempt", "a hit on a server that refused the unauthenticated client does not count",
     lambda e: not e.startswith("refused")),
    ("refused-and-non-public-exempt", "neither does a hit on a loopback or private host",
     lambda e: not e.startswith("refused") and e != "non-public host"),
    ("only-accepted-count", "only a hit on a server that accepted the unauthenticated initialize counts",
     lambda e: e == "accepted unauthenticated initialize"),
)


def probe_headline(configs: list[dict[str, Any]], probe_by_endpoint: dict[str, dict[str, Any]],
                   probe_dates: list[str]) -> dict[str, Any]:
    """The headline joined with the probe. Aggregates only."""
    total = len(configs)
    hits: Counter[str] = Counter()
    hits_by_source: dict[str, Counter[str]] = {}
    classes: list[tuple[dict[str, Any], list[str]]] = []
    for c in configs:
        ev = [evidence_class(h, probe_by_endpoint) for h in c["hits"]]
        classes.append((c, ev))
        hits.update(ev)
        hits_by_source.setdefault(c["source"], Counter()).update(ev)
    rows = []
    for key, label, keep in PROBE_SCENARIOS:
        crit = sum(1 for c, ev in classes if _other_critical(c) or any(keep(e) for e in ev))
        still = sum(1 for _, ev in classes if any(keep(e) for e in ev))
        rows.append({
            "scenario": key,
            "description": label,
            "configs_with_critical": _metric(crit, total),
            "configs_where_aak_mcp_001_stays_critical": _metric(still, total),
        })
    n_hits = sum(hits.values())
    return {
        "rule": RULE,
        "probe_dates_utc": probe_dates,
        "distinct_configs": total,
        "hits": n_hits,
        "hits_by_evidence": {k: _metric(hits.get(k, 0), n_hits) for k in EVIDENCE_CLASSES},
        "hits_by_evidence_and_source": {
            src: {k: v for k, v in sorted(cnt.items())} for src, cnt in sorted(hits_by_source.items())
        },
        "scenarios": rows,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _summary(data: dict[str, Any]) -> str:
    s0, s1 = data["step0"], data["step1"]
    lines = [
        f"configs {s0['distinct_configs_scanned']} | {RULE} configs "
        f"{s0['aak_mcp_001']['configs']['n']} ({s0['aak_mcp_001']['configs']['pct']}%) | "
        f"findings {s0['aak_mcp_001']['findings']} | critical configs "
        f"{s0['configs_with_critical']['n']} ({s0['configs_with_critical']['pct']}%)",
        "published check: " + ", ".join(
            f"{k}={'ok' if v['equal'] else 'MISMATCH'}" for k, v in s0["published_check"].items()
        ),
        f"critical other than {RULE}: {s0['configs_with_a_critical_other_than_aak_mcp_001']['n']} "
        f"configs {s0['other_critical_rules_by_config']}",
    ]
    for row in s0["scenarios"]:
        m = row["configs_with_critical"]
        lines.append(f"  {row['scenario']:40} critical {m['n']:5} ({m['pct']}%)")
    lines.append(f"hits {s1['hits']} | host class {s1['host_class']} | scheme {s1['scheme']}")
    lines.append(f"url credential {s1['url_credential']} | header auth {s1['header_auth']}")
    lines.append(f"probe plan {s1['probe_plan']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, default=None,
                    help="crawl directory (default: $AAK_MCP001_CORPUS or benchmarks/data)")
    ap.add_argument("--registry-manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--registry-cache", type=Path, default=None,
                    help="raw registry pages from the same crawl, for the population's titles and "
                         "descriptions (default: $AAK_MCP001_REGISTRY_CACHE or the research cache)")
    ap.add_argument("--write", action="store_true", help="(re)write results.json")
    ap.add_argument("--check", action="store_true", help="exit 1 if results.json is stale")
    ap.add_argument("--out", type=Path, default=None, help="write the aggregate here instead")
    ap.add_argument("--population-out", type=Path, default=None,
                    help="write the redacted per-hit population (JSONL; must be outside the repo)")
    ap.add_argument("--probe-raw", type=Path, default=None,
                    help="raw probe log from probe.py --probe: merged into the population, and "
                         "with --write also joined into probe-headline.json")
    args = ap.parse_args(argv)

    corpus = args.corpus or default_corpus()
    if not corpus.is_dir() or not any(corpus.glob("*.json")):
        print(f"corpus {corpus} not found; set --corpus or AAK_MCP001_CORPUS", file=sys.stderr)
        return 2
    configs = scan_corpus(corpus, args.registry_manifest)
    data = build_results(corpus, args.registry_manifest, configs)
    blob = json.dumps(data, indent=2, sort_keys=True) + "\n"

    if args.check:
        current = RESULTS_JSON.read_text(encoding="utf-8") if RESULTS_JSON.is_file() else ""
        if current != blob:
            print("benchmarks/aak_mcp_001/results.json is stale - run measure.py --write")
            return 1
        print("benchmarks/aak_mcp_001/results.json is up to date")
    if args.out:
        args.out.write_text(blob, encoding="utf-8")
        print(f"wrote {args.out}")
    elif args.write:
        RESULTS_JSON.write_text(blob, encoding="utf-8")
        print(f"wrote {RESULTS_JSON.relative_to(REPO)}")
    mismatches = [k for k, v in data["step0"]["published_check"].items() if not v["equal"]]
    probe = None
    if args.probe_raw:
        probe_mod = load_module("probe", HERE / "probe.py")
        raw = probe_mod.read_raw(args.probe_raw)
        probe = probe_mod.summarize_by_endpoint(raw)
        dates = probe_mod.build_summary(raw)["probe"]["run_dates_utc"]
        joined = probe_headline(configs, probe, dates)
        jblob = json.dumps(joined, indent=2, sort_keys=True) + "\n"
        if endpoints.leak_report(jblob) or "://" in jblob:
            print("refusing: the joined aggregate would carry a URL or a secret", file=sys.stderr)
            return 2
        if args.write:
            PROBE_HEADLINE_JSON.write_text(jblob, encoding="utf-8")
            print(f"wrote {PROBE_HEADLINE_JSON.relative_to(REPO)}")
        for row in joined["scenarios"]:
            m = row["configs_with_critical"]
            print(f"  probe: {row['scenario']:32} critical {m['n']:5} ({m['pct']}%)")
    if args.population_out:
        if _inside_repo(args.population_out):
            print("refusing to write third-party records inside the repository", file=sys.stderr)
            return 2
        cache = args.registry_cache or default_cache()
        if not cache.is_dir():
            print(f"note: no registry cache at {cache}; registry titles and descriptions omitted",
                  file=sys.stderr)
        records = population_records(configs, args.registry_manifest, cache, probe)
        n = write_population(records, args.population_out)
        print(f"wrote {n} redacted records to {args.population_out} (0 secret-pattern matches)")
    print(_summary(data))
    if mismatches:
        print(f"MISMATCH vs research/state-of-mcp-2026/results.json: {mismatches}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
