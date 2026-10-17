"""Scanner for `.claude-plugin/marketplace.json` and related plugin manifests.

Fires AAK-MARKETPLACE-001..005:
- 001 unsigned manifest (no signature / integrity field)
- 002 broad permission set (fs:*, shell:exec, network:*)
- 003 typosquat against a well-known package name
- 004 mutable git ref (branch/tag without commit SHA)
- 005 a manifest that could not be read (not JSON, not UTF-8, not an object),
  so 001..004 could not judge it
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    MANIFEST_MAX_BYTES,
    find_line_number,
    in_skip_dir,
    loads_json,
    loads_toml,
    make_finding,
    read_text_capped,
)


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
# The grants AAK-MARKETPLACE-002 calls broad, as (scope, action). A permission is
# reported when it covers one of them, not when it equals one: the six strings
# were compared exactly, so `shell:*` and a bare `*`, both broader than
# `shell:exec`, passed while `shell:exec` was flagged, and so did `SHELL:EXEC`.
_BROAD_GRANTS: tuple[tuple[str, str], ...] = (
    ("fs", "*"),
    ("shell", "exec"),
    ("network", "*"),
    ("credentials", "*"),
    ("env", "*"),
    ("*", "*"),
)
_COMMIT_SHA_RE = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{7,40}$")
# Where GitHub reads a SECURITY.md from: `.github/`, the root, then `docs/`, the
# precedence its docs give for a community health file that can sit in more than
# one place (https://docs.github.com/en/communities/setting-up-your-project-for-
# healthy-contributions/creating-a-default-community-health-file). Only the root
# and `.github/` were read, so a repository that kept its policy in `docs/` was
# told it shipped none.
_SECURITY_MD_FOLDERS = (".github", ".", "docs")


def _iter_manifests(project_root: Path) -> list[Path]:
    results: list[Path] = []
    for path in project_root.rglob("marketplace.json"):
        if in_skip_dir(path, project_root):
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


def _string_grant(item: str) -> tuple[str, str, str] | None:
    """(as written, scope, action) of one `scope:action` string, a bare `*`
    being every scope and action, or None for a string with no colon."""
    if item.strip() == "*":
        return item, "*", "*"
    scope, colon, action = item.partition(":")
    if not colon:
        return None
    return item, scope.strip().lower(), action.strip().lower()


def _grants(permissions: object) -> list[tuple[str, str, str]]:
    """(as written, scope, action) for each grant a `permissions` value makes.

    A list holds `scope:action` strings, and one string alone is one grant. An
    object maps a scope to an action, a list of actions, or `true`, which is
    every action (`{"fs": "*"}`, `{"shell": true}`); `false` grants nothing.
    Scope and action are compared without case or surrounding space. A string
    with no colon other than `*`, and a value of any other type, grants nothing
    this reads.
    """
    found: list[tuple[str, str, str]] = []
    if isinstance(permissions, str):
        permissions = [permissions]
    if isinstance(permissions, list):
        for item in permissions:
            grant = _string_grant(item) if isinstance(item, str) else None
            if grant is not None:
                found.append(grant)
    elif isinstance(permissions, dict):
        for scope, value in permissions.items():
            if not isinstance(scope, str):
                continue
            if value is True:
                found.append((f"{scope}: true", scope.strip().lower(), "*"))
                continue
            for action in value if isinstance(value, list) else [value]:
                if isinstance(action, str):
                    found.append((f"{scope}:{action}", scope.strip().lower(),
                                  action.strip().lower()))
    return found


def _covers(scope: str, action: str) -> bool:
    """Does a grant reach at least as far as one of the broad grants? A `*` on
    either side stands for every scope or every action."""
    return any(
        scope in ("*", broad_scope) and action in ("*", broad_action)
        for broad_scope, broad_action in _BROAD_GRANTS
    )


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

    broad = [shown for shown, scope, action in _grants(entry.get("permissions"))
             if _covers(scope, action)]
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


def _unreadable(rel: str, why: str, line_number: int | None = None) -> Finding:
    return make_finding(
        "AAK-MARKETPLACE-005",
        rel,
        f"{rel} {why}, so its plugins were not checked for a signature, "
        "permissions, a typosquat or a mutable ref",
        line_number=line_number,
    )


def _load_manifest(manifest_path: Path, rel: str) -> tuple[object, str, Finding | None]:
    """(parsed manifest, raw text, None), or (None, "", an AAK-MARKETPLACE-005 finding).

    A manifest that failed to parse used to be skipped without a word, so a
    file AAK could not read reported as clean. `utf-8-sig` drops a byte-order
    mark, which a strict UTF-8 decode left in front of the JSON, where it failed.
    """
    try:
        raw = read_text_capped(manifest_path, CONFIG_MAX_BYTES, encoding="utf-8-sig")
    except UnicodeDecodeError:
        return None, "", _unreadable(rel, "is not UTF-8 text")
    except OSError as exc:
        return None, "", _unreadable(rel, f"could not be read ({exc.strerror or exc})")
    try:
        return loads_json(raw, manifest_path), raw, None
    except json.JSONDecodeError as exc:
        why = f"is not valid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})"
        return None, "", _unreadable(rel, why, line_number=exc.lineno)


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for manifest_path in _iter_manifests(project_root):
        rel = str(manifest_path.relative_to(project_root))
        scanned.add(rel)
        data, raw, failure = _load_manifest(manifest_path, rel)
        if failure is not None:
            findings.append(failure)
            continue
        if not isinstance(data, dict):
            # Valid JSON, but not an object: `data.get` raised here before.
            findings.append(_unreadable(rel, "is JSON but not an object"))
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
    # Detect whether this repo identifies as an MCP server.
    name = ""
    keywords: list[str] = []
    security_contact_declared = False

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        scanned.add("pyproject.toml")
        try:
            data = loads_toml(read_text_capped(pyproject, MANIFEST_MAX_BYTES, errors="replace"), pyproject)
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
            data = loads_json(read_text_capped(pkg_json, MANIFEST_MAX_BYTES, errors="replace"), pkg_json)
            if not isinstance(data, dict):
                data = {}
            if not name:
                name = str(data.get("name") or "")
            keywords = keywords or [str(k) for k in data.get("keywords", []) if k]
            if "security_contact" in data or "securityContact" in data:
                security_contact_declared = True
        except (json.JSONDecodeError, OSError):
            pass

    marketplace = project_root / ".claude-plugin" / "marketplace.json"
    if marketplace.is_file():
        market: object = None
        try:
            market = loads_json(read_text_capped(marketplace, CONFIG_MAX_BYTES, encoding="utf-8-sig"), marketplace)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            pass  # AAK-MARKETPLACE-005 already reports a manifest that cannot be read.
        if isinstance(market, dict):
            if market.get("security_contact") or market.get("securityContact"):
                security_contact_declared = True
            if not name:
                name = str(market.get("name") or "")
            keywords = keywords or [str(k) for k in market.get("keywords", []) if k]

    advertises_mcp = "mcp" in name.lower() or any("mcp" in k.lower() for k in keywords)
    if not advertises_mcp:
        return []

    has_security_md = any(
        (project_root / folder / "SECURITY.md").is_file() for folder in _SECURITY_MD_FOLDERS
    )
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
