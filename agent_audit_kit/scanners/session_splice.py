"""Session-scoped instruction-splice check (AAK-AGENT-COMPOSE-002).

`AAK-AGENT-COMPOSE-001` covers the capability UNION across a set of skills. It does
not cover instruction splicing: one intent fragmented across N compliant tool calls
in a single session, where each call is individually allowed but the concatenation
of their arguments reconstructs something a single call would have been denied for.
That is the GhostSplice / cross-channel trust-fragmentation shape disclosed by the
ASSET Research Group (https://asset-group.github.io/disclosures/ghostsplice/).

This rule was written from that public disclosure, not from a reproduction we ran.

Given an ordered transcript of tool calls (a `*.session.json` file, or JSON under
`.aak/sessions/`, shaped `{"calls": [{"tool": ..., "arguments": {...}}, ...]}` or a
bare list of calls), it reassembles the arguments of consecutive same-tool calls and
flags two narrow cases only:

  - file-path reassembly: the concatenation matches a sensitive-path pattern
    (`id_rsa`, `.env`, `.aws/credentials`, ...) that no single fragment matched.
  - URL reassembly: the concatenation is a URL whose host is not on the egress
    allowlist, and no single fragment was itself a complete non-allowlisted URL.

It reuses AAK-AGENT-COMPOSE-001's config (`.aak/composition-boundaries.yaml`):
`session_reassembly.sensitive_path_patterns` and the shared `egress_allowlist`. It
defaults to WARN (MEDIUM), not fail, because it WILL raise false positives on
legitimate chunked work (a large file uploaded in path-sized pieces reassembles the
same way). Treat a finding as a prompt to look, not a verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, make_finding
from agent_audit_kit.scanners.skill_composition import (
    _DEFAULT_BOUNDARIES,
    _PROJECT_OVERRIDE,
    _as_list,
    _host,
)

_RULE_ID = "AAK-AGENT-COMPOSE-002"
_MAX_FILE_BYTES = 1_000_000

_FILE_TOOLS = frozenset({
    "read_file", "read", "cat", "open", "load_file", "get_file", "fs_read", "view",
    "write_file", "write", "edit", "append_file", "save",
})
_NET_TOOLS = frozenset({
    "web_fetch", "webfetch", "fetch", "http_get", "http", "curl", "get_url",
    "request", "download", "post", "upload",
})
_PATH_KEYS = ("path", "file", "filename", "filepath", "target", "name", "arg")
_URL_KEYS = ("url", "uri", "endpoint", "href", "link", "destination", "arg")

_DEFAULT_SENSITIVE = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".aws/credentials", ".env",
    ".netrc", ".pgpass", ".npmrc", ".pem", ".kube/config",
)


def _load_session_config(project_root: Path) -> tuple[list[str], set[str]]:
    """Reuse AAK-AGENT-COMPOSE-001's config file for the session_reassembly section."""
    override = project_root / _PROJECT_OVERRIDE
    src = override if override.is_file() else _DEFAULT_BOUNDARIES
    try:
        data = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    raw_session = data.get("session_reassembly")
    session = raw_session if isinstance(raw_session, dict) else {}
    patterns = _as_list(session.get("sensitive_path_patterns")) or list(_DEFAULT_SENSITIVE)
    allowlist = {h.lower() for h in _as_list(data.get("egress_allowlist"))}
    return patterns, allowlist


def _calls(raw: object) -> list[dict]:
    if isinstance(raw, dict) and isinstance(raw.get("calls"), list):
        seq = raw["calls"]
    elif isinstance(raw, list):
        seq = raw
    else:
        return []
    return [c for c in seq if isinstance(c, dict) and c.get("tool")]


def _transcripts(project_root: Path) -> list[tuple[str, list[dict]]]:
    out: list[tuple[str, list[dict]]] = []
    seen: set[Path] = set()
    for path in project_root.rglob("*.session.json"):
        seen.add(path)
    sessions_dir = project_root / ".aak" / "sessions"
    if sessions_dir.is_dir():
        for path in sessions_dir.rglob("*.json"):
            seen.add(path)
    for path in sorted(seen):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        calls = _calls(raw)
        if calls:
            out.append((path.relative_to(project_root).as_posix(), calls))
    return out


def _primary_arg(arguments: object, keys: tuple[str, ...]) -> str:
    if not isinstance(arguments, dict):
        return arguments if isinstance(arguments, str) else ""
    for k in keys:
        v = arguments.get(k)
        if isinstance(v, str) and v:
            return v
    for v in arguments.values():
        if isinstance(v, str) and v:
            return v
    return ""


def _same_tool_runs(calls: list[dict]) -> list[list[tuple[int, dict]]]:
    """Maximal runs of >=2 consecutive calls to the same tool."""
    runs: list[list[tuple[int, dict]]] = []
    cur: list[tuple[int, dict]] = []
    last: str | None = None
    for i, c in enumerate(calls):
        tool = str(c.get("tool"))
        if tool == last:
            cur.append((i, c))
        else:
            if len(cur) >= 2:
                runs.append(cur)
            cur = [(i, c)]
            last = tool
    if len(cur) >= 2:
        runs.append(cur)
    return runs


def _complete_external_url(frag: str, allowlist: set[str]) -> bool:
    if "://" not in frag:
        return False
    host = _host(frag)
    return bool(host) and "." in host and not host.endswith(".") and host not in allowlist


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan session transcripts for spliced file-path / URL reassembly (AAK-AGENT-COMPOSE-002)."""
    findings: list[Finding] = []
    evaluated = {_RULE_ID}

    sensitive, allowlist = _load_session_config(project_root)

    for rel, calls in _transcripts(project_root):
        for run in _same_tool_runs(calls):
            tool = str(run[0][1].get("tool")).lower()
            if tool in _FILE_TOOLS:
                frags = [_primary_arg(c.get("arguments"), _PATH_KEYS) for _, c in run]
            elif tool in _NET_TOOLS:
                frags = [_primary_arg(c.get("arguments"), _URL_KEYS) for _, c in run]
            else:
                continue
            frags = [f for f in frags if f]
            if len(frags) < 2:
                continue
            reassembled = "".join(frags)

            if tool in _FILE_TOOLS:
                hit = next(
                    (p for p in sensitive if p in reassembled and not any(p in f for f in frags)),
                    None,
                )
                if hit:
                    findings.append(_finding(rel, run, tool, reassembled, f"sensitive path token {hit!r}", frags))
            else:  # net
                if "://" not in reassembled:
                    continue
                host = _host(reassembled)
                if not host or "." not in host or host.endswith(".") or host in allowlist:
                    continue
                if any(_complete_external_url(f, allowlist) and _host(f) == host for f in frags):
                    continue
                findings.append(_finding(rel, run, tool, reassembled, f"non-allowlisted host {host!r}", frags))

    return findings, evaluated


def _finding(rel: str, run: list[tuple[int, dict]], tool: str, reassembled: str, why: str, frags: list[str]) -> Finding:
    related = [
        {"file_path": rel, "line_number": None, "message": f"call #{i} ({tool}) fragment: {frag!r}"}
        for (i, _), frag in zip(run, frags)
    ]
    idxs = ", ".join(f"#{i}" for i, _ in run)
    evidence = (
        f"Session transcript `{rel}`: {len(run)} consecutive `{tool}` calls ({idxs}) whose "
        f"arguments concatenate to {reassembled!r}, which crosses a boundary ({why}) that no "
        f"single call requested. Fragments: {frags}. This is the GhostSplice / cross-channel "
        f"trust-fragmentation shape; each call is individually compliant."
    )
    return make_finding(_RULE_ID, rel, evidence, run[0][0] + 1, related_locations=related)
