from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    find_line_number,
    in_skip_dir,
    loads_json,
    make_finding,
    placed,
    read_text_capped,
    url_readings,
)

# ---- Known file names and patterns for A2A Agent Cards ----
_AGENT_CARD_FILES: list[str] = [
    "agent-card.json",
    ".well-known/agent.json",
]

# ---- AAK-A2A-001: Internal / privileged capability keywords ----
_INTERNAL_CAPABILITIES = re.compile(
    r"\b(admin|system|internal|debug|root)\b",
    re.IGNORECASE,
)

# ---- AAK-A2A-004: HTTP (not HTTPS) endpoint ----
_HTTP_URL_RE = re.compile(r"^http://", re.IGNORECASE)


def _is_http(value: str) -> bool:
    """True when a client would reach `value` over cleartext http.

    `^http://` alone missed what a WHATWG client (Node's `fetch`, a browser)
    still reads as http: a leading space, `http:/host`, `http:\\\\host`, a tab
    in the scheme. `url_readings` reads those; the regex still answers first.
    """
    return bool(_HTTP_URL_RE.match(value)) or any(
        reading.scheme == "http" for reading in url_readings(value)
    )


def _find_agent_cards(project_root: Path) -> list[Path]:
    """Discover A2A Agent Card files in the project."""
    found: list[Path] = []

    # Explicit known locations
    for rel in _AGENT_CARD_FILES:
        p = project_root / rel
        if p.is_file():
            found.append(p)

    # Glob for *agent-card*.json anywhere in the tree
    for p in project_root.rglob("*agent-card*.json"):
        if in_skip_dir(p, project_root):
            continue
        if p.is_file() and p not in found:
            found.append(p)

    return found


def _check_capabilities(
    data: dict[str, Any],
    rel_path: str,
) -> list[tuple[Finding, str]]:
    """AAK-A2A-001: Check capabilities for internal / admin keywords; each finding
    comes with the key its line is found by (see `placed`)."""
    findings: list[tuple[Finding, str]] = []
    capabilities = data.get("capabilities", [])
    if isinstance(capabilities, list):
        for cap in capabilities:
            if isinstance(cap, str) and _INTERNAL_CAPABILITIES.search(cap):
                findings.append((make_finding(
                    "AAK-A2A-001",
                    rel_path,
                    f"Internal capability exposed: {cap}",
                ), cap))
    elif isinstance(capabilities, dict):
        for cap_name in capabilities:
            if isinstance(cap_name, str) and _INTERNAL_CAPABILITIES.search(cap_name):
                findings.append((make_finding(
                    "AAK-A2A-001",
                    rel_path,
                    f"Internal capability exposed: {cap_name}",
                ), cap_name))
    return findings


def _check_authentication(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-002: Check for missing or none-type authentication."""
    findings: list[Finding] = []
    auth = data.get("authentication", data.get("auth"))

    if auth is None:
        # No auth field at all
        findings.append(make_finding(
            "AAK-A2A-002",
            rel_path,
            "Agent Card has no authentication field",
            find_line_number(raw_text, "capabilities") or 1,
        ))
    elif isinstance(auth, dict):
        auth_type = auth.get("type", "")
        if isinstance(auth_type, str) and auth_type.lower() == "none":
            findings.append(make_finding(
                "AAK-A2A-002",
                rel_path,
                "Authentication type is 'none'",
                find_line_number(raw_text, "none"),
            ))
    elif isinstance(auth, str) and auth.lower() == "none":
        findings.append(make_finding(
            "AAK-A2A-002",
            rel_path,
            "Authentication is 'none'",
            find_line_number(raw_text, auth),
        ))

    return findings


def _check_skills(
    data: dict[str, Any],
    rel_path: str,
) -> list[tuple[Finding, str]]:
    """AAK-A2A-003: Check for missing inputSchema in skill definitions; each finding
    comes with the key its line is found by (see `placed`)."""
    findings: list[tuple[Finding, str]] = []
    skills = data.get("skills", [])
    if not isinstance(skills, list):
        return findings

    for skill in skills:
        if not isinstance(skill, dict):
            continue
        skill_name = skill.get("name", skill.get("id", "<unnamed>"))
        input_schema = skill.get("inputSchema")
        if input_schema is None:
            findings.append((make_finding(
                "AAK-A2A-003",
                rel_path,
                f"Skill '{skill_name}' has no inputSchema",
            ), str(skill_name)))
        elif isinstance(input_schema, dict) and not input_schema:
            findings.append((make_finding(
                "AAK-A2A-003",
                rel_path,
                f"Skill '{skill_name}' has empty inputSchema",
            ), str(skill_name)))

    return findings


def _check_endpoints(
    data: dict[str, Any],
    rel_path: str,
) -> list[tuple[Finding, str]]:
    """AAK-A2A-004: Check url/endpoint fields for HTTP (not HTTPS); each finding
    comes with the key its line is found by (see `placed`)."""
    findings: list[tuple[Finding, str]] = []

    # Check top-level url/endpoint fields
    for key in ("url", "endpoint", "baseUrl", "base_url"):
        val = data.get(key, "")
        if isinstance(val, str) and _is_http(val):
            findings.append((make_finding(
                "AAK-A2A-004",
                rel_path,
                f"Field '{key}' uses HTTP: {val}",
            ), val))

    # Check nested skills for endpoints
    skills = data.get("skills", [])
    if isinstance(skills, list):
        for skill in skills:
            if not isinstance(skill, dict):
                continue
            skill_name = skill.get("name", skill.get("id", "<unnamed>"))
            for key in ("url", "endpoint"):
                val = skill.get(key, "")
                if isinstance(val, str) and _is_http(val):
                    findings.append((make_finding(
                        "AAK-A2A-004",
                        rel_path,
                        f"Skill '{skill_name}' {key} uses HTTP: {val}",
                    ), val))

    return findings


_LIFETIME_KEYS: list[str] = [
    "tokenLifetime", "token_lifetime", "expiresIn", "expires_in",
]

_DURATION_RE = re.compile(r"^(\d+)\s*h$", re.IGNORECASE)


def _parse_lifetime_seconds(value: Any) -> int | None:
    """Attempt to interpret a lifetime value as seconds.

    Handles:
      - int / float (treated as seconds)
      - str digits (treated as seconds)
      - str like "2h" (treated as hours -> seconds)
    """
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        value_stripped = value.strip()
        if value_stripped.isdigit():
            return int(value_stripped)
        m = _DURATION_RE.match(value_stripped)
        if m:
            return int(m.group(1)) * 3600
    return None


def _objects_depth_first(data: object) -> Iterator[dict[str, Any]]:
    """`data` and every object under it, in the order the JWT checks met them
    when they recursed: an object, then each object value, or each object
    directly inside a list value, with everything under it, before the next.
    A list inside a list is not entered, as it never was.

    One frame per level took an agent card nested past the recursion limit,
    which JSON's parser reads on Python 3.12 and later (about 10,000 levels),
    down with the whole scanner and its findings on every other card. The
    walk keeps its own stack.
    """
    stack: list[object] = [data]
    while stack:
        obj = stack.pop()
        if not isinstance(obj, dict):
            continue
        yield obj
        children: list[object] = []
        for value in obj.values():
            if isinstance(value, dict):
                children.append(value)
            elif isinstance(value, list):
                children.extend(value)
        stack.extend(reversed(children))


def _check_jwt_lifetime(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-005: Check for JWT token lifetime > 1 hour."""
    findings: list[Finding] = []
    for obj in _objects_depth_first(data):
        for key in _LIFETIME_KEYS:
            if key in obj:
                seconds = _parse_lifetime_seconds(obj[key])
                if seconds is not None and seconds > 3600:
                    findings.append(make_finding(
                        "AAK-A2A-005",
                        rel_path,
                        f"JWT lifetime '{key}' is {seconds}s (>{3600}s)",
                        find_line_number(raw_text, key),
                    ))
    return findings


def _check_jwt_validation(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-006: Check for weak JWT validation settings."""
    findings: list[Finding] = []
    for obj in _objects_depth_first(data):
        # Check verifySignature / verify_signature == false
        for key in ("verifySignature", "verify_signature"):
            val = obj.get(key)
            if val is False or (isinstance(val, str) and val.lower() == "false"):
                findings.append(make_finding(
                    "AAK-A2A-006",
                    rel_path,
                    f"'{key}' is disabled",
                    find_line_number(raw_text, key),
                ))
        # Check algorithms list for "none"
        algorithms = obj.get("algorithms", [])
        if isinstance(algorithms, list):
            for alg in algorithms:
                if isinstance(alg, str) and alg.lower() == "none":
                    findings.append(make_finding(
                        "AAK-A2A-006",
                        rel_path,
                        "JWT algorithms include 'none'",
                        find_line_number(raw_text, alg),
                    ))
    return findings


def _check_impersonation(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-007: Check for agent impersonation risk.

    Flags when:
    - Agent card has neither 'id' nor 'identity' field, OR
    - Any top-level URL/endpoint field uses HTTP.
    """
    findings: list[Finding] = []

    has_id = "id" in data or "identity" in data
    if not has_id:
        findings.append(make_finding(
            "AAK-A2A-007",
            rel_path,
            "Agent Card has no 'id' or 'identity' field",
            1,
        ))

    for key in ("url", "endpoint", "baseUrl", "base_url"):
        val = data.get(key, "")
        if isinstance(val, str) and _is_http(val):
            findings.append(make_finding(
                "AAK-A2A-007",
                rel_path,
                f"Agent uses HTTP endpoint '{key}': {val}",
                find_line_number(raw_text, val),
            ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan A2A Agent Card files for protocol security issues.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for card_path in _find_agent_cards(project_root):
        try:
            raw_text = read_text_capped(card_path, CONFIG_MAX_BYTES, errors="replace")
            if len(raw_text) > 1_000_000:
                continue
            data = loads_json(raw_text, card_path)
        except (json.JSONDecodeError, OSError):
            continue

        if not isinstance(data, dict):
            continue

        rel_path = (
            str(card_path.relative_to(project_root))
            if card_path.is_relative_to(project_root)
            else str(card_path)
        )
        scanned_files.add(rel_path)

        # The checks that report one finding per capability or skill find their
        # lines in one pass over the card each, not one search of it per finding.
        findings.extend(placed(raw_text, _check_capabilities(data, rel_path)))
        findings.extend(_check_authentication(data, rel_path, raw_text))
        findings.extend(placed(raw_text, _check_skills(data, rel_path)))
        findings.extend(placed(raw_text, _check_endpoints(data, rel_path)))
        findings.extend(_check_jwt_lifetime(data, rel_path, raw_text))
        findings.extend(_check_jwt_validation(data, rel_path, raw_text))
        findings.extend(_check_impersonation(data, rel_path, raw_text))
        findings.extend(_check_2026_gaps(data, rel_path, raw_text))

    return findings, scanned_files


# ---------------------------------------------------------------------------
# 2026 gaps — AAK-A2A-008..012
# ---------------------------------------------------------------------------


def _check_2026_gaps(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """Fire AAK-A2A-008..012 (mutual auth, delegation, transitive, replay, schema)."""
    findings: list[Finding] = []

    auth_section = data.get("authentication") or {}
    if isinstance(auth_section, dict):
        scheme = str(auth_section.get("scheme", "")).lower()
        mutual = bool(
            auth_section.get("mutual") or auth_section.get("mutual_tls")
            or "mtls" in scheme or "mutual" in scheme
        )
        if not mutual and ("bearer" in scheme or "oauth" in scheme):
            findings.append(
                make_finding(
                    "AAK-A2A-008",
                    rel_path,
                    f"Auth scheme {scheme!r} does not declare mutual authentication",
                    line_number=find_line_number(raw_text, "authentication"),
                )
            )

    delegation = data.get("delegation")
    if isinstance(delegation, dict) and delegation:
        max_hops = delegation.get("max_depth") or delegation.get("max_hops")
        if max_hops is None:
            findings.append(
                make_finding(
                    "AAK-A2A-009",
                    rel_path,
                    "Delegation block present but max_depth/max_hops is not set",
                    line_number=find_line_number(raw_text, "delegation"),
                )
            )

    trust = data.get("trust") or {}
    if isinstance(trust, dict) and trust.get("accepts_relayed_claims") is True:
        findings.append(
            make_finding(
                "AAK-A2A-010",
                rel_path,
                "Agent Card advertises accepts_relayed_claims=true (transitive trust)",
                line_number=find_line_number(raw_text, "accepts_relayed_claims"),
            )
        )

    tokens = data.get("tokens")
    if isinstance(tokens, dict) and tokens:
        has_antireplay = any(k in tokens for k in ("jti", "nonce", "require_jti", "replay_window"))
        if not has_antireplay:
            findings.append(
                make_finding(
                    "AAK-A2A-011",
                    rel_path,
                    "Agent Card token config has no jti/nonce/replay_window",
                    line_number=find_line_number(raw_text, "tokens"),
                )
            )

    # Only demand schema_version on Agent Cards that actually look 2026-era
    # (i.e. have the newer tokens/delegation sections). Legacy skill-only
    # cards from 2024/2025 should not be flagged.
    has_new_sections = any(k in data for k in ("tokens", "delegation", "trust"))
    if has_new_sections and "schema_version" not in data and "a2a_version" not in data and "apiVersion" not in data:
        findings.append(
            make_finding(
                "AAK-A2A-012",
                rel_path,
                "Agent Card has no schema_version/a2a_version discriminator",
                line_number=1,
            )
        )

    return findings
