from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding, Severity
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    codex_home,
    find_line_number,
    find_line_numbers,
    is_loopback_url,
    loads_json,
    loads_toml,
    make_finding,
    placed,
    read_text_capped,
    url_host,
)

# Patterns for API URL override env vars
API_URL_PATTERNS = re.compile(
    r"(_BASE_URL|_API_URL|_ENDPOINT)$", re.IGNORECASE
)

# Wildcard/broad permission patterns
BROAD_PERMISSION_PATTERNS = re.compile(
    r"^(\*+|mcp__\*|Bash\(\*\)|Edit\(\*\*\)|Read\(\*\*\)|Write\(\*\*\))$"
)

SETTINGS_FILES = [
    ".claude/settings.json",
    ".claude/settings.local.json",
]


def _find_settings(project_root: Path, include_user_config: bool = False) -> list[Path]:
    found: list[Path] = []
    for name in SETTINGS_FILES:
        p = project_root / name
        if p.is_file():
            found.append(p)
    if include_user_config:
        user_settings = Path.home() / ".claude" / "settings.json"
        if user_settings.is_file():
            found.append(user_settings)
    return found


_find_line_number = find_line_number
_make_finding = make_finding

_ANTHROPIC_DOMAIN = "anthropic.com"


def _is_anthropic_endpoint(value: str) -> bool:
    """True when ANTHROPIC_BASE_URL's host is anthropic.com or a subdomain of it.

    This was ``"anthropic.com" in value``, a substring test, so any URL that
    merely contained the text passed as Anthropic's own endpoint:
    ``https://anthropic.com.attacker.example/v1`` (a lookalike under somebody
    else's domain), ``https://evil.example/?next=anthropic.com`` (the text in the
    query), ``https://anthropic.com@evil.example/v1`` (the text as userinfo) and
    ``https://evilanthropic.com/v1`` (no dot before it). The redirect AAK-TRUST-002
    exists to catch, CVE-2026-21852, went through any of them unreported.

    The comparison is on the parsed host, dot-bounded, as agent_config's
    ``_is_safe_host`` does. ``url_host`` returns a host only when Node and
    urlsplit/httpx read the same one, so a backslash cannot make either see
    Anthropic where the other connects elsewhere: Claude Code reads
    ``https://api.anthropic.com\\@evil.example/v1`` as Anthropic, and the Python
    SDK (httpx), reading the same variable, sends its key to evil.example. The
    scheme is not compared: a cleartext
    ``http://`` URL to an Anthropic host passes, as it always did, and is stated
    as a limitation.
    """
    host = url_host(value)
    if host is None:
        return False
    return host == _ANTHROPIC_DOMAIN or host.endswith("." + _ANTHROPIC_DOMAIN)


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()
    settings_files = _find_settings(project_root, include_user_config)

    for settings_path in settings_files:
        try:
            raw_text = read_text_capped(settings_path, CONFIG_MAX_BYTES, errors="replace")
            if len(raw_text) > 1_000_000:
                continue
            data = loads_json(raw_text, settings_path)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = str(settings_path.relative_to(project_root)) if settings_path.is_relative_to(project_root) else str(settings_path)
        scanned_files.add(rel_path)
        if not isinstance(data, dict):
            continue

        # AAK-TRUST-001: enableAllProjectMcpServers
        if data.get("enableAllProjectMcpServers") is True:
            findings.append(_make_finding(
                "AAK-TRUST-001", rel_path,
                "enableAllProjectMcpServers: true",
                _find_line_number(raw_text, "enableAllProjectMcpServers"),
            ))

        # AAK-TRUST-002: ANTHROPIC_BASE_URL override
        env = data.get("env", {})
        if isinstance(env, dict):
            anthropic_url = env.get("ANTHROPIC_BASE_URL", "")
            if anthropic_url and isinstance(anthropic_url, str):
                if not _is_anthropic_endpoint(anthropic_url):
                    findings.append(_make_finding(
                        "AAK-TRUST-002", rel_path,
                        f"ANTHROPIC_BASE_URL = {anthropic_url}",
                        _find_line_number(raw_text, "ANTHROPIC_BASE_URL"),
                    ))

            # AAK-TRUST-005: Custom API base URL for any provider
            unplaced: list[tuple[Finding, str]] = []
            for key, value in env.items():
                if key == "ANTHROPIC_BASE_URL":
                    continue  # Already handled by AAK-TRUST-002
                if API_URL_PATTERNS.search(key) and isinstance(value, str) and value:
                    unplaced.append((_make_finding(
                        "AAK-TRUST-005", rel_path,
                        f"{key} = {value}",
                    ), key))
            # Every reported variable's line in one pass over the file, not one search of it per variable.
            findings.extend(placed(raw_text, unplaced))

        # Check permissions
        permissions = data.get("permissions", {})
        if isinstance(permissions, dict):
            allow_list = permissions.get("allow", [])
            deny_list = permissions.get("deny", [])

            # AAK-TRUST-003: Wildcard permissions
            if isinstance(allow_list, list):
                for pattern in allow_list:
                    if isinstance(pattern, str) and BROAD_PERMISSION_PATTERNS.match(pattern):
                        findings.append(_make_finding(
                            "AAK-TRUST-003", rel_path,
                            f"Broad permission allow: {pattern}",
                            _find_line_number(raw_text, pattern),
                        ))

            # AAK-TRUST-004: No deny rules
            if allow_list and (not deny_list or deny_list == []):
                findings.append(_make_finding(
                    "AAK-TRUST-004", rel_path,
                    "permissions.allow has entries but permissions.deny is empty/missing",
                    _find_line_number(raw_text, "allow"),
                ))

            # AAK-TRUST-006: Project settings may override user denys
            if isinstance(allow_list, list) and len(allow_list) > 0:
                # Check for potentially shadow-capable allows
                has_tool_allows = any(
                    isinstance(p, str) and ("Bash" in p or "Edit" in p or "Write" in p or "Read" in p or "mcp__" in p)
                    for p in allow_list
                )
                if has_tool_allows and not deny_list:
                    findings.append(_make_finding(
                        "AAK-TRUST-006", rel_path,
                        f"Project allows tool access ({len(allow_list)} rules) with no deny rules to prevent override",
                        _find_line_number(raw_text, "allow"),
                    ))

        # AAK-TRUST-007: No MCP server allowlist configured. A present key is the
        # allowlist, an empty list included: `[]` approves no server, the strictest
        # allowlist there is, and it is what `aak fix` writes. Reading `[]` as absent
        # (through 0.6.24) made the fix report a change that cleared nothing (#1060).
        if "enabledMcpjsonServers" not in data and data.get("enableAllProjectMcpServers") is not True:
            # Only flag if there's an .mcp.json in the project (servers exist to allowlist)
            mcp_json = project_root / ".mcp.json"
            if mcp_json.is_file():
                findings.append(_make_finding(
                    "AAK-TRUST-007", rel_path,
                    "No enabledMcpjsonServers allowlist configured",
                    1,  # the key is absent whenever this fires
                ))

        findings.extend(_proxy_ca_findings(settings_path, rel_path, raw_text, data.get("env")))

    findings.extend(_codex_findings(project_root, include_user_config, scanned_files))
    return findings, scanned_files


_CODEX_RULE = "AAK-TRUST-009"
_CODEX_DEFAULT_PROVIDER = "openai"
_OPENAI_DOMAIN = "openai.com"
_AZURE_OPENAI_SUFFIX = ".openai.azure.com"


def _is_openai_or_local(value: str) -> bool:
    """True when a Codex provider URL reaches OpenAI, Azure OpenAI or this machine.

    By host, as `_is_anthropic_endpoint` judges, so `api.openai.com.gateway.example.net`
    and `api.openai.com@gateway.example.net` are the gateway's. `url_host` has no answer
    for an IPv6 literal, and `is_loopback_url` does, so `http://[::1]:11434` passes.
    """
    if is_loopback_url(value):
        return True
    host = url_host(value)
    if host is None:
        return False
    return host == _OPENAI_DOMAIN or host.endswith(("." + _OPENAI_DOMAIN, _AZURE_OPENAI_SUFFIX))


def _selected_providers(config: dict[str, Any]) -> list[str]:
    """The provider ids a Codex config can run: its top-level one and each profile's."""
    selected = [config.get("model_provider", _CODEX_DEFAULT_PROVIDER)]
    profiles = config.get("profiles")
    if isinstance(profiles, dict):
        selected.extend(p.get("model_provider") for p in profiles.values() if isinstance(p, dict))
    return list(dict.fromkeys(name for name in selected if isinstance(name, str)))


def _provider_urls(config: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(provider, key, URL) for the URLs the selected providers use.

    A provider nothing selects is left out. `openai_base_url` is how OpenAI's config
    reference re-points the built-in `openai` provider, which needs no table.
    """
    declared = config.get("model_providers")
    tables = declared if isinstance(declared, dict) else {}
    override = config.get("openai_base_url")
    urls: list[tuple[str, str, str]] = []
    for provider in _selected_providers(config):
        table = tables.get(provider)
        url = table.get("base_url") if isinstance(table, dict) else None
        if isinstance(url, str):
            urls.append((provider, "base_url", url))
        if provider == _CODEX_DEFAULT_PROVIDER and isinstance(override, str):
            urls.append((provider, "openai_base_url", override))
    return urls


def _codex_provider_findings(
    raw: str, rel_path: str, config: dict[str, Any], is_user_file: bool,
) -> list[Finding]:
    """One finding per selected provider URL off the allowlist, naming its host, never its URL."""
    foreign = [item for item in _provider_urls(config) if not _is_openai_or_local(item[2])]
    if not foreign:
        return []
    lines = find_line_numbers(raw, [item[2] for item in foreign] + ["base_url", "openai_base_url"])
    findings: list[Finding] = []
    for provider, key, url in foreign:
        host = url_host(url)
        where = f"host {host}" if host else "a host that could not be read"
        evidence = f"{rel_path}: provider {provider[:100]!r} {key} has {where}"
        line = lines[url] or lines[key]
        if is_user_file:
            evidence += "; this is your user config, so you may have set it on purpose"
            findings.append(dataclasses.replace(
                make_finding(_CODEX_RULE, rel_path, evidence, line), severity=Severity.HIGH,
            ))
        else:
            findings.append(make_finding(_CODEX_RULE, rel_path, evidence, line))
    return findings


def _codex_config_files(project_root: Path, include_user_config: bool) -> list[tuple[Path, bool]]:
    """(path, is the user's own config). A CODEX_HOME that is the project's own `.codex` is read once."""
    project = project_root / ".codex" / "config.toml"
    found = [(project, False)] if project.is_file() else []
    if include_user_config:
        user = codex_home() / "config.toml"
        if user.is_file() and user.resolve() != project.resolve():
            found.append((user, True))
    return found


def _codex_findings(
    project_root: Path, include_user_config: bool, scanned_files: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for path, is_user_file in _codex_config_files(project_root, include_user_config):
        try:
            raw = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
            config = loads_toml(raw, path)
        except (OSError, ValueError):  # TOMLDecodeError and RefusedTOML are ValueErrors
            continue
        rel_path = str(path.relative_to(project_root)) if path.is_relative_to(project_root) else str(path)
        scanned_files.add(rel_path)
        findings.extend(_codex_provider_findings(raw, rel_path, config, is_user_file))
    return findings


# ---------------------------------------------------------------------------
# AAK-TRUST-008: a proxy or certificate-authority override in a project's
# settings `env`.
#
# Claude Code applies a settings file's `env` "for every session and for the
# subprocesses Claude Code starts from it" (settings reference, `env`), from
# project and local settings once the folder is trusted and at startup in `-p`
# mode. Its network configuration page says the proxy and CA variables "can
# also be configured in settings.json", and that only a Claude Desktop session
# whose connection the app manages ignores them in a repository's own settings
# files, "so a checked-out repository can't redirect the TLS or proxy path";
# every other session reads them "from every settings scope, like any terminal
# session". The names: the proxies Claude Code reads (`HTTPS_PROXY`,
# `HTTP_PROXY`, lower case too) and `ALL_PROXY`, which curl and other programs
# a session starts read; the CA bundles of Node (`NODE_EXTRA_CA_CERTS`),
# OpenSSL-based clients (`SSL_CERT_FILE`) and Python requests
# (`REQUESTS_CA_BUNDLE`); and Node's switch that turns certificate checking off,
# which takes effect only for the string "0".
#
# The user's own settings file is where the docs put these variables, so it
# is skipped even when `include_user_config` reads it, and when the scanned
# root is the home directory and its `.claude/settings.json` is that file.
# ---------------------------------------------------------------------------

_PROXY_VARS = frozenset({"https_proxy", "http_proxy", "all_proxy"})  # compared lower-cased
_CA_VARS = frozenset({"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"})
_TLS_CHECK_VAR = "NODE_TLS_REJECT_UNAUTHORIZED"


def _is_user_settings(path: Path) -> bool:
    """Whether `path` is the user's own `~/.claude/settings.json`.

    False when the home directory is unknown: Path.home() raises KeyError on 3.9
    when HOME is unset and the uid has no passwd entry, and RuntimeError on later
    releases, and either one escaping here lost every TRUST-* finding of the scan.
    """
    try:
        return path.resolve() == (Path.home() / ".claude" / "settings.json").resolve()
    except (OSError, RuntimeError, KeyError):
        return False


def _overrides_network(name: str, value: object) -> bool:
    """Whether one `env` entry reroutes or unpins TLS for the session."""
    if name == _TLS_CHECK_VAR:
        return value == "0" or (type(value) is int and value == 0)
    if name.lower() in _PROXY_VARS or name in _CA_VARS:
        return isinstance(value, str) and bool(value.strip())
    return False


def _proxy_ca_findings(settings_path: Path, rel_path: str, raw_text: str, env: object) -> list[Finding]:
    """One AAK-TRUST-008 finding for each proxy or CA override in a project's `env`."""
    if not isinstance(env, dict) or _is_user_settings(settings_path):
        return []
    return [
        _make_finding(
            "AAK-TRUST-008", rel_path,
            f"{name} = {value}",
            _find_line_number(raw_text, f'"{name}"'),
        )
        for name, value in env.items()
        if isinstance(name, str) and _overrides_network(name, value)
    ]
