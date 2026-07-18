#!/usr/bin/env python3
"""Reproduce the numbers in docs/reports/mcp-2026-07-28-readiness.md.

Runs the `mcp-2026-07-28` auth-profile rules (AAK-OAUTH-006/007/008) across the
public-MCP config corpus under benchmarks/data/ and prints the breakdown used in
the readiness report. Deterministic, offline — the same corpus yields the same
counts every run.

Usage:
    python scripts/mcp_2026_07_28_readiness.py            # human-readable
    python scripts/mcp_2026_07_28_readiness.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from agent_audit_kit.scanners.oauth_misconfig import (
    _MCP_INLINE_AUTH_RE,
    _MCP_REMOTE_RE,
    _PRM_DISCOVERY_RE,
    _check_file,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "benchmarks" / "data"
PROFILE_RULES = ("AAK-OAUTH-006", "AAK-OAUTH-007", "AAK-OAUTH-008")


@dataclass
class Readiness:
    corpus_configs: int = 0
    server_entries: int = 0
    remote_entries: int = 0
    configs_with_remote_server: int = 0
    remote_configs_with_inline_credential: int = 0
    configs_referencing_rfc9728_prm: int = 0
    hits: dict[str, int] = field(default_factory=dict)


def compute() -> Readiness:
    files = sorted(CORPUS.glob("*.mcp.json"))
    r = Readiness(corpus_configs=len(files))
    rule_hits: Counter[str] = Counter()

    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
            servers = data.get("mcpServers") or data.get("servers") or {}
            if isinstance(servers, dict):
                r.server_entries += len(servers)
                for cfg in servers.values():
                    if isinstance(cfg, dict) and _MCP_REMOTE_RE.search(json.dumps(cfg)):
                        r.remote_entries += 1
        except (json.JSONDecodeError, ValueError):
            pass

        if _MCP_REMOTE_RE.search(text):
            r.configs_with_remote_server += 1
            if _MCP_INLINE_AUTH_RE.search(text):
                r.remote_configs_with_inline_credential += 1
        if _PRM_DISCOVERY_RE.search(text):
            r.configs_referencing_rfc9728_prm += 1

        for rid in {x.rule_id for x in _check_file(f, CORPUS) if x.rule_id in PROFILE_RULES}:
            rule_hits[rid] += 1

    r.hits = {rid: rule_hits[rid] for rid in PROFILE_RULES}
    return r


def _pct(num: int, den: int) -> str:
    return f"{100 * num / den:.1f}%" if den else "n/a"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    r = compute()
    if args.json:
        print(json.dumps(asdict(r), indent=2))
        return 0

    print(f"corpus: {r.corpus_configs} public MCP configs (benchmarks/data/*.mcp.json)")
    print(f"server entries: {r.server_entries} | remote (http/sse/url): {r.remote_entries}")
    print(f"configs with a remote server: {r.configs_with_remote_server} "
          f"({_pct(r.configs_with_remote_server, r.corpus_configs)})")
    print(f"  of those, inline credential: {r.remote_configs_with_inline_credential} "
          f"({_pct(r.remote_configs_with_inline_credential, r.configs_with_remote_server)} of remote)")
    print(f"configs referencing RFC 9728 PRM discovery: {r.configs_referencing_rfc9728_prm} "
          f"({_pct(r.configs_referencing_rfc9728_prm, r.corpus_configs)})")
    for rid in PROFILE_RULES:
        h = r.hits[rid]
        print(f"  {rid}: {h} files ({_pct(h, r.corpus_configs)} of all, "
              f"{_pct(h, r.remote_configs_with_inline_credential)} of remote-auth)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
