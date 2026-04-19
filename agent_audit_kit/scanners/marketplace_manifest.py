"""Scanner for `.claude-plugin/marketplace.json` and related plugin manifests.

Fires AAK-MARKETPLACE-001..004:
- 001 unsigned manifest (no signature / integrity field)
- 002 broad permission set (fs:*, shell:exec, network:*)
- 003 typosquat against a well-known package name
- 004 mutable git ref (branch/tag without commit SHA)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_KNOWN_UPSTREAMS = frozenset(
    {
        "anthropic",
        "claude",
        "claude-code",
        "claude-agent-sdk",
        "mcp",
        "model-context-protocol",
        "langchain",
        "langchain-core",
        "langgraph",
        "openai",
        "openai-agents-sdk",
        "gemini",
        "google-adk",
    }
)
_BROAD_PERMISSIONS = (
    "fs:*",
    "shell:exec",
    "network:*",
    "credentials:*",
    "env:*",
    "*:*",
)
_COMMIT_SHA_RE = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{7,40}$")


def _iter_manifests(project_root: Path) -> list[Path]:
    results: list[Path] = []
    for path in project_root.rglob("marketplace.json"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            results.append(path)
    return results


def _edit_distance_le_1(a: str, b: str) -> bool:
    """Return True if a and b differ by at most one insert/delete/substitute
    OR an adjacent transposition (Damerau-Levenshtein distance <= 1)."""
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            return a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
        return False
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(short)):
        if short[i] != long_[i]:
            return short[i:] == long_[i + 1 :]
    return True


def _is_typosquat(name: str) -> bool:
    lowered = name.lower()
    if lowered in _KNOWN_UPSTREAMS:
        return False
    for trusted in _KNOWN_UPSTREAMS:
        if _edit_distance_le_1(lowered, trusted):
            return True
    return False


def _check_plugin_entry(
    entry: dict,
    manifest_path: Path,
    project_root: Path,
    raw_text: str,
) -> list[Finding]:
    findings: list[Finding] = []
    rel = str(manifest_path.relative_to(project_root))
    name = entry.get("name", "")

    has_sig = any(
        key in entry
        for key in ("signature", "integrity", "sha256", "sigstore", "publicKey")
    )
    if not has_sig:
        findings.append(
            make_finding(
                "AAK-MARKETPLACE-001",
                rel,
                f"Plugin {name!r} has no signature/integrity field",
                line_number=find_line_number(raw_text, f'"name": "{name}"'),
            )
        )

    permissions = entry.get("permissions") or []
    if isinstance(permissions, list):
        broad = [p for p in permissions if p in _BROAD_PERMISSIONS]
        if broad:
            findings.append(
                make_finding(
                    "AAK-MARKETPLACE-002",
                    rel,
                    f"Plugin {name!r} declares broad permissions: {', '.join(broad)}",
                    line_number=find_line_number(raw_text, f'"name": "{name}"'),
                )
            )

    if name and _is_typosquat(name):
        findings.append(
            make_finding(
                "AAK-MARKETPLACE-003",
                rel,
                f"Plugin name {name!r} is within edit distance 1 of a well-known upstream",
                line_number=find_line_number(raw_text, f'"name": "{name}"'),
            )
        )

    source = entry.get("source") or {}
    if isinstance(source, dict):
        ref = str(source.get("ref") or source.get("branch") or source.get("tag") or "")
        if ref and not _COMMIT_SHA_RE.fullmatch(ref):
            findings.append(
                make_finding(
                    "AAK-MARKETPLACE-004",
                    rel,
                    f"Plugin {name!r} pins to mutable ref {ref!r} (not a commit SHA)",
                    line_number=find_line_number(raw_text, ref),
                )
            )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for manifest_path in _iter_manifests(project_root):
        rel = str(manifest_path.relative_to(project_root))
        scanned.add(rel)
        try:
            raw = manifest_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue
        plugins = data.get("plugins")
        if not isinstance(plugins, list):
            continue
        for entry in plugins:
            if isinstance(entry, dict):
                findings.extend(_check_plugin_entry(entry, manifest_path, project_root, raw))

    # AAK-SEC-MD-001: MCP-server repos should ship SECURITY.md / security_contact.
    findings.extend(_check_mcp_security_md(project_root, scanned))
    return findings, scanned


def _check_mcp_security_md(
    project_root: Path,
    scanned: set[str],
) -> list[Finding]:
    """Fire AAK-SEC-MD-001 if this repo advertises itself as an MCP server
    but has no SECURITY.md + no security_contact manifest field."""
    import tomllib

    # Detect whether this repo identifies as an MCP server.
    name = ""
    keywords: list[str] = []
    security_contact_declared = False

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        scanned.add("pyproject.toml")
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            project = data.get("project", {})
            name = str(project.get("name") or name)
            keywords = [str(k) for k in project.get("keywords", []) if k]
            urls = project.get("urls") or {}
            if any("security" in str(k).lower() for k in urls):
                security_contact_declared = True
            if "security-contact" in project or "security_contact" in project:
                security_contact_declared = True
        except Exception:  # noqa: BLE001
            pass

    pkg_json = project_root / "package.json"
    if pkg_json.is_file():
        scanned.add("package.json")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            if not name:
                name = str(data.get("name") or "")
            keywords = keywords or [str(k) for k in data.get("keywords", []) if k]
            if "security_contact" in data or "securityContact" in data:
                security_contact_declared = True
        except json.JSONDecodeError:
            pass

    marketplace = project_root / ".claude-plugin" / "marketplace.json"
    if marketplace.is_file():
        try:
            data = json.loads(marketplace.read_text(encoding="utf-8"))
            if data.get("security_contact") or data.get("securityContact"):
                security_contact_declared = True
            if not name:
                name = str(data.get("name") or "")
            keywords = keywords or [str(k) for k in data.get("keywords", []) if k]
        except json.JSONDecodeError:
            pass

    advertises_mcp = "mcp" in name.lower() or any("mcp" in k.lower() for k in keywords)
    if not advertises_mcp:
        return []

    has_security_md = (project_root / "SECURITY.md").is_file() or (
        project_root / ".github" / "SECURITY.md"
    ).is_file()
    if has_security_md or security_contact_declared:
        return []

    anchor_path = "SECURITY.md"
    return [
        make_finding(
            "AAK-SEC-MD-001",
            anchor_path,
            f"Repo advertises itself as MCP (name={name!r}, keywords={keywords!r}) "
            "but ships no SECURITY.md and no security_contact manifest field",
        )
    ]
