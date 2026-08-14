"""Microsoft UFO mobile MCP servers exposed without auth (CVE-2026-73296).

Microsoft UFO — the open-source framework for intelligent automation across
devices and platforms — before 3.0.8 exposes two Streamable-HTTP MCP services
from ``ufo/client/mcp/http_servers/mobile_mcp_server.py``:

  - ``create_mobile_data_collection_server``  (TCP 8020)
  - ``create_mobile_action_server``           (TCP 8021)

Neither applies inbound authentication. An unauthenticated remote attacker who
can reach either port invokes ``capture_screenshot``, ``get_ui_tree``, ``tap``,
``swipe``, ``type_text``, ``launch_app``, ``press_key`` and ``click_control``
against the ADB-connected Android device — disclosing screen and device data and
modifying device state (CVE-2026-73296, CVSS 9.4). Fixed in 3.0.8.

UFO is distributed as a git checkout, not a PyPI or npm artifact (``ufo`` on npm
is unjs's unrelated URL library), so this CVE gets a detection rule rather than a
row in the ``mcp_cve_pins_2026_07`` pin table — the same disposition the pin
scanner's docstring records for other non-pinnable CVEs.

Three detection paths, matching how a UFO deployment actually shows up in a repo:

  1. vendored / forked UFO server source that constructs either mobile server,
  2. an MCP client config, compose file or Dockerfile wired to the 8020/8021
     mobile endpoints,
  3. a dependency reference to the UFO git source unpinned or below 3.0.8.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73296
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding

_RULE_ID = "AAK-MCP-UFO-CVE-2026-73296-001"
_FIX = (3, 0, 8)
_MAX_FILE_BYTES = 1_000_000

# UFO's own factory symbols — specific enough that a match means UFO's mobile
# MCP surface, not a generic MCP server.
_UFO_SERVER_RE = re.compile(
    r"create_mobile_data_collection_server"
    r"|create_mobile_action_server"
    r"|mobile_mcp_server"
)

# UFO identity, for the weaker config/dependency signals that need corroboration.
_UFO_CTX_RE = re.compile(
    r"\bUFO\b"
    r"|microsoft/UFO"
    r"|ufo\.client\.mcp"
    r"|ufo/client/mcp"
    r"|mobile_mcp",
    re.IGNORECASE,
)

# The two ADB-backed device-control tools the CVE names. Their presence next to
# an MCP surface is the exploit's payload set.
_UFO_TOOLS_RE = re.compile(
    r"capture_screenshot|get_ui_tree|click_control|launch_app"
    r"|\btap\b|\bswipe\b|type_text|press_key"
)

_UFO_PORT_RE = re.compile(r"\b(?:8020|8021)\b")

# Inbound-auth markers. Deliberately broad: any credible inbound credential
# check clears the finding, because the CVE is specifically "no authentication".
_AUTH_RE = re.compile(
    r"Authorization"
    r"|[Bb]earer\b"
    r"|api[-_]?key|apiKey"
    r"|require_auth|requireAuth"
    r"|verify_token|authenticate|auth_middleware"
    r"|BearerAuth|TokenVerifier"
    r"|x-admin-key",
    re.IGNORECASE,
)

# Loopback-only binds are not remotely reachable, so they are out of scope.
_LOOPBACK_RE = re.compile(r"127\.0\.0\.1|\blocalhost\b|::1")
_BIND_ALL_RE = re.compile(r"0\.0\.0\.0|\[::\]|\"::\"|'::'")

# A UFO git dependency, with an optional tag/ref we can compare to the fix.
_UFO_GIT_RE = re.compile(
    r"(?:git\+)?https?://(?:www\.)?github\.com/microsoft/UFO(?:\.git)?"
    r"(?:@|/tree/|#egg=[^\s]*@)?(v?\d+\.\d+(?:\.\d+)?)?",
    re.IGNORECASE,
)

_SOURCE_SUFFIXES = (".py",)
_CONFIG_SUFFIXES = (".json", ".yaml", ".yml", ".toml", ".txt")
_DEP_NAMES = ("requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "uv.lock")


def _ver(raw: str) -> tuple[int, int, int] | None:
    """Parse ``v3.0.8`` / ``3.0`` into a comparable triple."""
    m = re.match(r"v?(\d+)\.(\d+)(?:\.(\d+))?$", raw.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _is_dep_file(path: Path) -> bool:
    name = path.name.lower()
    return name in {n.lower() for n in _DEP_NAMES} or name.startswith("requirements")


def _is_config_file(path: Path) -> bool:
    return path.suffix.lower() in _CONFIG_SUFFIXES or path.name.lower().startswith("dockerfile")


def _scan_source(raw: str) -> str | None:
    """Vendored UFO mobile MCP server source with no inbound auth."""
    if not _UFO_SERVER_RE.search(raw):
        return None
    if _AUTH_RE.search(raw):
        return None
    # A server pinned to loopback with no bind-all anywhere is not remotely
    # reachable — the CVE's precondition fails.
    if _LOOPBACK_RE.search(raw) and not _BIND_ALL_RE.search(raw):
        return None
    return (
        "vendored UFO mobile MCP server source constructs the Streamable-HTTP "
        "mobile server(s) with no inbound authentication"
    )


def _scan_config(raw: str) -> str | None:
    """An MCP config / compose / Dockerfile wired to the 8020/8021 endpoints."""
    if not _UFO_CTX_RE.search(raw):
        return None
    if not (_UFO_PORT_RE.search(raw) or _UFO_SERVER_RE.search(raw)):
        return None
    # Require a second UFO-mobile signal so a bare "8020" in an unrelated file
    # cannot carry the finding on its own.
    if not (_UFO_SERVER_RE.search(raw) or _UFO_TOOLS_RE.search(raw)):
        return None
    if _AUTH_RE.search(raw):
        return None
    if _LOOPBACK_RE.search(raw) and not _BIND_ALL_RE.search(raw):
        return None
    return (
        "MCP config wires the UFO mobile data-collection / action servers "
        "(TCP 8020/8021) with no inbound authentication"
    )


def _scan_dependency(raw: str) -> str | None:
    """A UFO git dependency unpinned or below the 3.0.8 fix."""
    m = _UFO_GIT_RE.search(raw)
    if not m:
        return None
    ref = m.group(1)
    if ref is None:
        return "UFO git dependency is unpinned, so it resolves to whatever HEAD serves"
    parsed = _ver(ref)
    if parsed is None:
        return f"UFO git dependency pinned to non-version ref {ref!r}"
    if parsed >= _FIX:
        return None
    return f"UFO git dependency pinned at {ref}, below the 3.0.8 fix"


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for UFO mobile MCP servers exposed without authentication.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of evaluated rule IDs).
    """
    findings: list[Finding] = []
    evaluated = {_RULE_ID}
    seen: set[str] = set()

    for path in sorted(project_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue

        is_source = path.suffix in _SOURCE_SUFFIXES
        is_dep = _is_dep_file(path)
        is_config = _is_config_file(path)
        if not (is_source or is_dep or is_config):
            continue

        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        why = None
        if is_dep:
            why = _scan_dependency(raw)
        if why is None and is_source:
            why = _scan_source(raw)
        if why is None and is_config:
            why = _scan_config(raw)
        if why is None:
            continue

        rel = path.relative_to(project_root).as_posix()
        if rel in seen:
            continue
        seen.add(rel)

        anchor = (
            find_line_number(raw, "create_mobile_action_server")
            or find_line_number(raw, "create_mobile_data_collection_server")
            or find_line_number(raw, "8020")
            or find_line_number(raw, "8021")
            or find_line_number(raw, "UFO")
        )
        findings.append(make_finding(
            _RULE_ID,
            rel,
            (
                f"Microsoft UFO before 3.0.8: {why}. The mobile data-collection "
                f"(8020) and mobile action (8021) Streamable-HTTP MCP services "
                f"accept unauthenticated callers, who can then invoke "
                f"capture_screenshot, get_ui_tree, tap, swipe, type_text, "
                f"launch_app, press_key and click_control against the "
                f"ADB-connected Android device — reading screen contents and "
                f"changing device state (CVE-2026-73296, CVSS 9.4). Upgrade to "
                f"UFO >= 3.0.8, bind the mobile MCP servers to 127.0.0.1, and "
                f"require an inbound credential."
            ),
            anchor,
        ))

    return findings, evaluated
