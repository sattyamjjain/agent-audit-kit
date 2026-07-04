"""Static audit of remote MCP Server Cards — SEP-1649 (`/.well-known/mcp/server-card.json`).

SEP-1649 (superseded-in-draft by SEP-2127; MCP spec discovery track) has servers
publish a **server card** at ``/.well-known/mcp/server-card.json`` — a JSON
document with ``serverInfo``, ``transport`` (``type`` + ``endpoint``),
``capabilities``, ``authentication`` (``required`` + ``schemes``), and a summary
of ``tools`` (each with a ``description``). A client fetches the card *before*
connecting and trusts what it declares, so the card itself is an attack surface.

This scanner statically audits a server card (from a committed file, or an
opt-in fetch via ``discover``) and emits four deterministic rules:

- **AAK-MCP-CARD-001** — tool-description poisoning / imperative-injection in a
  ``tools[].description``. Reuses the ``tool_poisoning`` detectors (invisible
  Unicode, prompt-injection, cross-tool reference, encoded payloads) — the same
  regexes AAK-POISON-001..006 use; nothing duplicated.
- **AAK-MCP-CARD-002** — declared-transport vs advertised-capability mismatch
  (e.g. a network transport that declares ``authentication.required: false``, or
  a ``stdio`` transport advertising a remote ``endpoint`` URL).
- **AAK-MCP-CARD-003** — missing / invalid signature or provenance (no
  ``signature`` / ``provenance`` / ``attestation`` / ``publisher`` field, or one
  present but empty/placeholder). An unsigned card's self-declared tool list is
  trusted with no origin proof.
- **AAK-MCP-CARD-004** — over-broad capability claims (wildcard tool/scope
  claims, ``capabilities`` asserting everything, or ``authentication.required``
  true with an empty ``schemes`` list).

stdlib-only. Fetching is **opt-in and offline-by-default** (``fetch_url`` /
``AAK_FETCH_SERVER_CARDS=1``) per the zero-cloud guardrail — the default scan
path makes zero network calls.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

# Reuse the tool-poisoning detectors — do NOT duplicate the regexes.
from agent_audit_kit.scanners.tool_poisoning import (
    _BASE64_RE,
    _CROSS_TOOL_RE,
    _HEX_SEQUENCE_RE,
    _PROMPT_INJECTION_RE,
    _has_invisible_unicode,
)

_CARD_POISON = "AAK-MCP-CARD-001"
_CARD_MISMATCH = "AAK-MCP-CARD-002"
_CARD_UNSIGNED = "AAK-MCP-CARD-003"
_CARD_BROAD = "AAK-MCP-CARD-004"

# A file is a server card if it is named like one, or its JSON carries the
# SEP-1649 shape (serverInfo + tools/capabilities).
_CARD_NAME_RE = re.compile(
    r"server-card\.json$|server_card\.json$|\.well-known[/\\]mcp[/\\]",
    re.IGNORECASE,
)
_STDIO_TRANSPORTS = {"stdio", "local"}
_REMOTE_TRANSPORTS = {"http", "https", "sse", "streamable-http", "streamable_http", "ws", "wss"}
_PROVENANCE_FIELDS = ("signature", "signatures", "provenance", "attestation",
                      "publisher", "publisherId", "publisher_id", "verified")
_PLACEHOLDER = {"", "todo", "changeme", "none", "null", "unsigned", "n/a",
                "placeholder", "xxx", "example"}
_WILDCARD_SCOPES = {"*", "all", "any", "full", "admin", "root", "*:*"}

_JSON_SUFFIXES = (".json",)


def _looks_like_card(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if "serverInfo" in data or "server_info" in data:
        return True
    # tools + at least one of the SEP-1649 sibling fields
    if "tools" in data and any(k in data for k in ("capabilities", "transport", "protocolVersion", "authentication")):
        return True
    return False


def _get(data: dict, *keys: str) -> Any:
    for k in keys:
        if k in data:
            return data[k]
    return None


def _audit_card(data: dict, rel_path: str, raw_text: str) -> list[Finding]:
    findings: list[Finding] = []

    # ---- (a) AAK-MCP-CARD-001: tool-description poisoning (reused detectors)
    tools = data.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", "?"))
            desc = tool.get("description")
            if not isinstance(desc, str):
                continue
            reasons: list[str] = []
            if _has_invisible_unicode(desc):
                reasons.append("invisible-unicode")
            if _PROMPT_INJECTION_RE.search(desc):
                reasons.append("prompt-injection")
            if _CROSS_TOOL_RE.search(desc):
                reasons.append("cross-tool-reference")
            if _BASE64_RE.search(desc) or _HEX_SEQUENCE_RE.search(desc):
                reasons.append("encoded-payload")
            if reasons:
                findings.append(make_finding(
                    _CARD_POISON,
                    rel_path,
                    (
                        f"Server-card tool '{name}' description is poisoned "
                        f"({', '.join(reasons)}) — a client that trusts the card "
                        f"ingests the injected instructions before connecting."
                    ),
                    find_line_number(raw_text, name),
                ))

    # ---- (b) AAK-MCP-CARD-002: transport vs capability/auth mismatch
    transport = data.get("transport")
    ttype = ""
    endpoint = ""
    if isinstance(transport, dict):
        ttype = str(transport.get("type", "")).lower()
        endpoint = str(transport.get("endpoint", "") or transport.get("url", ""))
    elif isinstance(transport, str):
        ttype = transport.lower()
    auth = data.get("authentication")
    auth_required = auth.get("required") if isinstance(auth, dict) else None
    is_remote = ttype in _REMOTE_TRANSPORTS or endpoint.startswith(("http://", "https://", "ws"))
    if is_remote and auth_required is False:
        findings.append(make_finding(
            _CARD_MISMATCH,
            rel_path,
            (
                f"Server card advertises a remote transport ('{ttype or endpoint}') "
                f"but declares `authentication.required: false` — an "
                f"anyone-can-connect network endpoint."
            ),
            find_line_number(raw_text, "authentication") or find_line_number(raw_text, "transport"),
        ))
    if ttype in _STDIO_TRANSPORTS and endpoint.startswith(("http://", "https://", "ws")):
        findings.append(make_finding(
            _CARD_MISMATCH,
            rel_path,
            (
                f"Server card declares a `stdio`/local transport but advertises a "
                f"remote endpoint '{endpoint}' — declared transport and advertised "
                f"capability disagree."
            ),
            find_line_number(raw_text, "endpoint"),
        ))

    # ---- (c) AAK-MCP-CARD-003: missing / invalid signature or provenance
    prov_val = _get(data, *_PROVENANCE_FIELDS)
    prov_present = any(k in data for k in _PROVENANCE_FIELDS)
    prov_empty = prov_present and (
        prov_val in (None, [], {}, False)
        or (isinstance(prov_val, str) and prov_val.strip().lower() in _PLACEHOLDER)
    )
    if not prov_present or prov_empty:
        why = "no signature/provenance field" if not prov_present else "empty/placeholder signature"
        findings.append(make_finding(
            _CARD_UNSIGNED,
            rel_path,
            (
                f"Server card has {why} — its self-declared tool list and "
                f"endpoint are trusted with no origin proof (SEP-1649 cards are "
                f"fetched and trusted before connecting)."
            ),
            find_line_number(raw_text, "serverInfo") or 1,
        ))

    # ---- (d) AAK-MCP-CARD-004: over-broad capability claims
    caps = data.get("capabilities")
    broad_reason = ""
    if isinstance(caps, dict):
        # every capability enabled with no constraint object
        enabled = [k for k, v in caps.items() if v is True]
        if len(enabled) >= 3:
            broad_reason = f"all capabilities asserted ({', '.join(sorted(enabled)[:4])}...)"
    scopes = None
    if isinstance(auth, dict):
        scopes = auth.get("scopes") or auth.get("scope")
    scope_list = scopes if isinstance(scopes, list) else ([scopes] if scopes else [])
    if any(isinstance(s, str) and s.strip().lower() in _WILDCARD_SCOPES for s in scope_list):
        broad_reason = "wildcard auth scope (`*`/`all`)"
    if isinstance(auth, dict) and auth.get("required") is True:
        schemes = auth.get("schemes")
        if isinstance(schemes, list) and not schemes:
            broad_reason = "authentication.required is true but `schemes` is empty (no enforceable method)"
    if broad_reason:
        findings.append(make_finding(
            _CARD_BROAD,
            rel_path,
            (
                f"Server card makes over-broad capability/auth claims: "
                f"{broad_reason}. Scope the card to what the server actually "
                f"exposes."
            ),
            find_line_number(raw_text, "capabilities") or find_line_number(raw_text, "authentication"),
        ))

    return findings


# ---------------------------------------------------------------------------
# Optional opt-in fetch (offline by default)
# ---------------------------------------------------------------------------


def fetch_card(base_url: str, timeout: int = 15) -> dict | None:
    """Fetch a server card from ``<base_url>/.well-known/mcp/server-card.json``.

    Network op — callers must opt in (``discover --fetch-cards`` /
    ``AAK_FETCH_SERVER_CARDS=1``). Never called in the default scan path.
    """
    url = base_url.rstrip("/") + "/.well-known/mcp/server-card.json"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (opt-in)
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan committed MCP server-card JSON files (offline).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _JSON_SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        rel = str(path.relative_to(project_root))
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Only parse JSON that is named like a card or clearly shaped like one.
        named = bool(_CARD_NAME_RE.search(rel.replace("\\", "/")))
        if not named and "serverInfo" not in raw and '"tools"' not in raw:
            continue
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        if not (named and isinstance(data, dict)) and not _looks_like_card(data):
            continue

        card_findings = _audit_card(data, rel, raw)
        if card_findings:
            scanned_files.add(rel)
            findings.extend(card_findings)

    # Optional opt-in fetch of a single explicitly-configured card URL.
    fetch_url = os.environ.get("AAK_FETCH_SERVER_CARD_URL")
    if fetch_url:
        data = fetch_card(fetch_url)
        if isinstance(data, dict):
            rel = f"<fetched:{fetch_url}>"
            scanned_files.add(rel)
            findings.extend(_audit_card(data, rel, json.dumps(data, indent=2)))

    return findings, scanned_files
