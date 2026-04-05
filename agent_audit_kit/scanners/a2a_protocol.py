from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

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
        if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        if p.is_file() and p not in found:
            found.append(p)

    return found


def _check_capabilities(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-001: Check capabilities for internal / admin keywords."""
    findings: list[Finding] = []
    capabilities = data.get("capabilities", [])
    if isinstance(capabilities, list):
        for cap in capabilities:
            if isinstance(cap, str) and _INTERNAL_CAPABILITIES.search(cap):
                findings.append(make_finding(
                    "AAK-A2A-001",
                    rel_path,
                    f"Internal capability exposed: {cap}",
                    find_line_number(raw_text, cap),
                ))
    elif isinstance(capabilities, dict):
        for cap_name in capabilities:
            if isinstance(cap_name, str) and _INTERNAL_CAPABILITIES.search(cap_name):
                findings.append(make_finding(
                    "AAK-A2A-001",
                    rel_path,
                    f"Internal capability exposed: {cap_name}",
                    find_line_number(raw_text, cap_name),
                ))
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
                f"Authentication type is 'none'",
                find_line_number(raw_text, "none"),
            ))
    elif isinstance(auth, str) and auth.lower() == "none":
        findings.append(make_finding(
            "AAK-A2A-002",
            rel_path,
            f"Authentication is 'none'",
            find_line_number(raw_text, auth),
        ))

    return findings


def _check_skills(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-003: Check for missing inputSchema in skill definitions."""
    findings: list[Finding] = []
    skills = data.get("skills", [])
    if not isinstance(skills, list):
        return findings

    for skill in skills:
        if not isinstance(skill, dict):
            continue
        skill_name = skill.get("name", skill.get("id", "<unnamed>"))
        input_schema = skill.get("inputSchema")
        if input_schema is None:
            findings.append(make_finding(
                "AAK-A2A-003",
                rel_path,
                f"Skill '{skill_name}' has no inputSchema",
                find_line_number(raw_text, str(skill_name)),
            ))
        elif isinstance(input_schema, dict) and not input_schema:
            findings.append(make_finding(
                "AAK-A2A-003",
                rel_path,
                f"Skill '{skill_name}' has empty inputSchema",
                find_line_number(raw_text, str(skill_name)),
            ))

    return findings


def _check_endpoints(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-004: Check url/endpoint fields for HTTP (not HTTPS)."""
    findings: list[Finding] = []

    # Check top-level url/endpoint fields
    for key in ("url", "endpoint", "baseUrl", "base_url"):
        val = data.get(key, "")
        if isinstance(val, str) and _HTTP_URL_RE.match(val):
            findings.append(make_finding(
                "AAK-A2A-004",
                rel_path,
                f"Field '{key}' uses HTTP: {val}",
                find_line_number(raw_text, val),
            ))

    # Check nested skills for endpoints
    skills = data.get("skills", [])
    if isinstance(skills, list):
        for skill in skills:
            if not isinstance(skill, dict):
                continue
            skill_name = skill.get("name", skill.get("id", "<unnamed>"))
            for key in ("url", "endpoint"):
                val = skill.get(key, "")
                if isinstance(val, str) and _HTTP_URL_RE.match(val):
                    findings.append(make_finding(
                        "AAK-A2A-004",
                        rel_path,
                        f"Skill '{skill_name}' {key} uses HTTP: {val}",
                        find_line_number(raw_text, val),
                    ))

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


def _check_jwt_lifetime(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-005: Check for JWT token lifetime > 1 hour."""
    findings: list[Finding] = []

    def _inspect(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
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
        # Recurse into nested dicts
        for v in obj.values():
            if isinstance(v, dict):
                _inspect(v)
            elif isinstance(v, list):
                for item in v:
                    _inspect(item)

    _inspect(data)
    return findings


def _check_jwt_validation(
    data: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """AAK-A2A-006: Check for weak JWT validation settings."""
    findings: list[Finding] = []

    def _inspect(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
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
        # Recurse into nested dicts
        for v in obj.values():
            if isinstance(v, dict):
                _inspect(v)
            elif isinstance(v, list):
                for item in v:
                    _inspect(item)

    _inspect(data)
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
        if isinstance(val, str) and _HTTP_URL_RE.match(val):
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
            raw_text = card_path.read_text(encoding="utf-8")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
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

        findings.extend(_check_capabilities(data, rel_path, raw_text))
        findings.extend(_check_authentication(data, rel_path, raw_text))
        findings.extend(_check_skills(data, rel_path, raw_text))
        findings.extend(_check_endpoints(data, rel_path, raw_text))
        findings.extend(_check_jwt_lifetime(data, rel_path, raw_text))
        findings.extend(_check_jwt_validation(data, rel_path, raw_text))
        findings.extend(_check_impersonation(data, rel_path, raw_text))

    return findings, scanned_files
