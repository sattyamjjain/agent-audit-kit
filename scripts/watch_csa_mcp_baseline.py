#!/usr/bin/env python3
"""Poll for the CSA MCP Security Baseline v0.1 RC drop.

CSA announced the "MCP Security Baseline" (coming soon) in the MCP
Security Resource Center post:
https://cloudsecurityalliance.org/blog/2025/08/20/securing-the-agentic-ai-control-plane-announcing-the-mcp-security-resource-center

When the RC1 lands, we want to:
1. Open a tracking issue labelled `csa-mcp-baseline` with the canonical URL.
2. (Human follow-up) tag the relevant AAK-MCP-*, AAK-A2A-*, AAK-STDIO-*
   rules with `csa_mcp_baseline_references`.

This script is meant to run weekly via the existing `.github/workflows/
cve-watcher.yml` cron or a sibling workflow. It records previously seen
version strings in `.aak/csa-mcp-baseline-state.json` so it only opens
one issue per drop.

Exit codes:
    0 — nothing new, or new version found and issue filed.
    1 — network / parsing error.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import urllib.error
import urllib.request


_SOURCES = (
    "https://cloudsecurityalliance.org/artifacts/",
    "https://cloudsecurityalliance.org/research/working-groups/ai-controls",
    "https://modelcontextprotocol-security.io",
)

_VERSION_RE = re.compile(
    r"MCP\s+Security\s+Baseline\s+v?(?P<version>\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)*)",
    re.IGNORECASE,
)

_DEFAULT_STATE_PATH = pathlib.Path(".aak/csa-mcp-baseline-state.json")

_USER_AGENT = "agent-audit-kit csa-baseline-watch/0.3.2"


def _fetch(url: str, timeout: int = 30) -> str | None:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": _USER_AGENT},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"watcher: GET {url} failed: {exc}\n")
        return None


def _load_state(state_path: pathlib.Path) -> dict:
    if state_path.is_file():
        try:
            return json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_state(state_path: pathlib.Path, state: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _detect_versions(sources: list[str]) -> set[str]:
    out: set[str] = set()
    for url in sources:
        text = _fetch(url)
        if not text:
            continue
        for m in _VERSION_RE.finditer(text):
            out.add(m.group("version"))
    return out


def _file_issue(version: str, owner_repo: str, gh_token: str | None) -> None:
    title = f"CSA MCP Security Baseline v{version} is available"
    body = (
        "CSA has published the MCP Security Baseline. When the published "
        "artifact URL is public, add a `csa_mcp_baseline_references` "
        "field to `RuleDefinition` and tag the AAK-MCP-*, AAK-A2A-*, "
        "AAK-STDIO-*, AAK-MCPWN-* rules with their control IDs.\n\n"
        "Sources polled by the watcher:\n"
        + "\n".join(f"- {u}" for u in _SOURCES)
        + "\n\n"
        f"Detected version string: **v{version}**.\n\n"
        "See also the tracking TODO in `agent_audit_kit/rules/builtin.py`.\n"
    )
    if not gh_token:
        sys.stdout.write(
            f"watcher: would file issue {title!r} on {owner_repo} (no $GITHUB_TOKEN set)\n"
        )
        return
    api = f"https://api.github.com/repos/{owner_repo}/issues"
    payload = json.dumps({"title": title, "body": body, "labels": ["csa-mcp-baseline"]}).encode()
    req = urllib.request.Request(
        api,
        data=payload,
        headers={
            "Authorization": f"Bearer {gh_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": _USER_AGENT,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            sys.stdout.write(f"watcher: filed issue {data.get('html_url')}\n")
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"watcher: POST issue failed: {exc}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sources", nargs="*", default=list(_SOURCES),
        help="Override the default source URL list (primarily for tests).",
    )
    parser.add_argument(
        "--owner-repo",
        default=os.environ.get("GITHUB_REPOSITORY", "sattyamjjain/agent-audit-kit"),
        help="Repo to file the tracking issue on.",
    )
    parser.add_argument(
        "--state",
        default=str(_DEFAULT_STATE_PATH),
        help="Path to the watcher state file.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Detect versions but do not file issues or write state.",
    )
    args = parser.parse_args(argv)

    state_path = pathlib.Path(args.state)

    detected = _detect_versions(args.sources)
    if not detected:
        sys.stdout.write("watcher: no version strings detected\n")
        return 0

    state = _load_state(state_path)
    known: set[str] = set(state.get("seen_versions", []))
    new_versions = detected - known
    if not new_versions:
        sys.stdout.write(
            f"watcher: no new versions (already seen: {sorted(known)})\n"
        )
        return 0

    gh_token = os.environ.get("GITHUB_TOKEN")
    for version in sorted(new_versions):
        if args.dry_run:
            sys.stdout.write(f"watcher: dry-run — would file issue for v{version}\n")
        else:
            _file_issue(version, args.owner_repo, gh_token)

    if not args.dry_run:
        state["seen_versions"] = sorted(known | new_versions)
        _save_state(state_path, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
