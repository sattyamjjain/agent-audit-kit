from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.redaction import shown_arg
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    ZCODE_SERVER_KEY,
    find_line_number,
    host_ip,
    in_skip_dir,
    is_loopback_url,
    is_zcode_workspace_config,
    loads_json,
    loads_jsonc,
    make_finding,
    mcp_server_maps,
    placed,
    read_text_capped,
    strip_vscode_variables,
    url_hosts,
    zcode_workspace_configs,
)
from agent_audit_kit.scanners._launchers import launch_evidence

# Patterns for secret-like keys in MCP server env blocks
SECRET_KEY_PATTERNS = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|ANTHROPIC|OPENAI|AWS_)", re.IGNORECASE
)

# Shell metacharacters indicating shell expansion risk
SHELL_METACHARACTERS = re.compile(r"[|;&`$()]")
SHELL_WRAPPERS = ("sh -c", "bash -c", "cmd /c", "cmd.exe /c")

# npx-like package fetchers
PACKAGE_FETCHERS = ("npx", "uvx", "bunx", "pnpx")

# Well-known binaries that are acceptable without absolute paths
KNOWN_BINARIES = frozenset({
    "node", "python", "python3", "npx", "uvx", "bunx", "pnpx",
    "docker", "deno", "bun", "cargo", "go", "java", "ruby",
})

# Internal / localhost patterns
INTERNAL_URL_PATTERNS = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|\.local\b)",
    re.IGNORECASE,
)
# The private ranges INTERNAL_URL_PATTERNS spells out, for a host read as an
# address (`_is_internal_url`).
_INTERNAL_NETWORKS = tuple(
    ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _is_internal_url(url: str) -> bool:
    """AAK-MCP-009's test: the URL names an RFC 1918 address or a `.local` host.

    The regex reads the URL's text, so it missed every other way a client reads
    one of those addresses: `http://10.1/`, `http://0xa.0.0.5/`,
    `http://167772165/`, `http://012.0.0.5/` and `http://%31%30.0.0.5/` all
    reach 10.0.0.x, and so does 10.0.0.5 written with ideographic full stops
    (U+3002), which Node maps to dots. Each host `url_hosts` reads is now
    tested as well, as an address or a `.local` name; the regex still answers
    first, so nothing it reported is lost.
    """
    if INTERNAL_URL_PATTERNS.search(url):
        return True
    for host in url_hosts(url):
        address = host_ip(host)
        if address is None:
            if host.rstrip(".").endswith(".local"):
                return True
        elif address.version == 4 and any(address in net for net in _INTERNAL_NETWORKS):
            return True
    return False


# --- AAK-MCP-001 authentication-header recognition (#475) --------------------
# Header names historically recognized as auth. Kept NAME-only (value not
# inspected) for backward compatibility: a hardcoded literal in one of these is
# a secret-exposure concern (AAK-MCP-003 / AAK-SECRET-*), not "no authentication".
_KNOWN_AUTH_HEADERS = frozenset({"authorization", "bearer", "x-api-key", "api-key"})

# Headers that carry a *token* but are not authentication. `X-CSRF-Token` and
# `X-XSRF-Token` prove the request came from your own page, not that the caller
# is anyone in particular, so a server whose only header is one of these really
# is unauthenticated. Checked before the family below, which would otherwise
# swallow them via the `-token` suffix.
_NON_AUTH_TOKEN_HEADERS = re.compile(r"^x-(?:csrf|xsrf)-token$", re.IGNORECASE)

# Custom credential / access-control header family: vendor-prefixed secrets
# (X-<Vendor>-Key / -Token / -Secret, *-API-Key, *-API-Token, *-Access-Key), bare
# apikey / token header variants, and the x402 `X-PAYMENT` pay-to-access header
# (access control, not identity auth, but the endpoint is not openly reachable).
#
# #475 introduced this family for the `-key` suffix after two benign-slice false
# positives. The 2026-08-24 re-measurement produced two more from the same root
# cause one step out — `X-Velarion-Agent-Token` and `X-SignDocs-Client-Secret` —
# because that fix generalised exactly one suffix and stopped. The suffix
# alternation below is the generalisation it should have been.
#
# `-id` is deliberately NOT in the family. A bare `client_id` is a public
# identifier, not a credential; `X-SignDocs-Client-Id` is recognized only because
# its companion `X-SignDocs-Client-Secret` is. Adding `-id` would also swallow
# `X-Request-Id` / `X-Trace-Id` / `X-Correlation-Id`, which authenticate nothing.
#
# A third step out, 2026-10-12, on 190 real `.vscode/mcp.json` files: 8 servers
# that send a key under a name the family required hyphens for, or that carries
# no `x-` / `-api-key` affix, were reported "without authentication":
# `CONTEXT7_API_KEY` (underscores) and Azure API Management's
# `Ocp-Apim-Subscription-Key`. Any name ending in an API key spelling, and the
# `-subscription-key` suffix, now count, still only with a referenced value.
_CUSTOM_AUTH_HEADER_RE = re.compile(
    r"^(?:"
    # X-Nefesh-Key, X-Goog-Api-Key, X-Velarion-Agent-Token, X-SignDocs-Client-Secret
    r"x-[a-z0-9]+(?:-[a-z0-9]+)*-(?:key|token|secret)"
    r"|[a-z0-9-]+-api-key"               # *-api-key
    r"|[a-z0-9_-]*(?:api_key|apikey)"    # CONTEXT7_API_KEY, ServiceApiKey, apikey
    r"|[a-z0-9-]+-api-token"             # *-api-token
    r"|[a-z0-9-]+-access-key"            # *-access-key
    r"|[a-z0-9-]+-client-secret"         # OAuth client-credentials pair
    r"|[a-z0-9_-]+[-_]subscription[-_]key"  # Ocp-Apim-Subscription-Key
    r"|x-auth-token|x-access-token"
    r"|x-payment"                        # x402 pay-to-access gate
    r")$",
    re.IGNORECASE,
)

# A header VALUE that references a credential indirectly — env var, template, or
# an obvious placeholder — rather than baking a literal secret into the config.
# Only such a value counts as a genuine declared scheme for the custom family; a
# hardcoded literal in a custom auth header still trips AAK-MCP-001 because the
# credential is exposed in the config, so the endpoint is effectively unprotected.
#
# Each bracketed arm stops reading at the next opener of its own kind (`${`,
# `{{`, or a `<` that has something before its `>`), which reaches the same
# closer itself, so a value is a reference exactly when it was. With `[^}]*`
# and `[^>]+` every opener that has no closer rescanned to the end of the value:
# 200,000 characters of `{{` took 12.6 seconds, four times the
# 100,000-character time. Ending each read at the next opener makes it linear.
# Leaving the opener's first character out of the class (`[^{}]`, `[^<>]`) is
# also linear but matches less: `${a{b}` and `<<>` are references here and to
# `[^}]` and `[^>]`, and were not to it. AAK-MCP-003's literal check below
# reuses the same arms.
_REFERENCE_ARMS = (
    r"\$\{(?:(?!\$\{)[^}])*\}"     # ${VAR}
    r"|\{\{(?:(?!\{\{)[^}])*\}\}"  # {{VAR}}
    r"|<(?:(?!<[^>])[^>])+>"       # <your-key>
)
_PLACEHOLDER_ARMS = (
    r"your[_\- ]?\w*"     # YOUR_API_KEY, your-key
    r"|change[_\- ]?me|changeme|placeholder|redacted|dummy|\bexample\b|\bsample\b"
    r"|_here\b|x{4,}"
)
_CREDENTIAL_REF_RE = re.compile(
    _REFERENCE_ARMS
    + r"|\$[A-Za-z_]\w*"  # $VAR
    + r"|%[A-Za-z_]\w*%"  # %VAR%
    + "|" + _PLACEHOLDER_ARMS,
    re.IGNORECASE,
)


# --- AAK-MCP-003: is a literal under a secret-looking name a secret? -----------
# The key pattern (KEY, SECRET, TOKEN, ...) is wide on purpose, so it also
# names settings: on 190 real `.vscode/mcp.json` files the rule reported
# `AWS_DOCUMENTATION_PARTITION=aws`, `PROXMOX_TOKEN_NAME`, `ROBOTMCP_TOKENIZER`,
# `ROBOTMCP_MAX_INLINE_TOKENS`, and demo literals such as a password containing
# "password", as hardcoded secrets (HIGH). Its three true positives were 44 to
# 139 characters with no marker. A key that names a setting, a value too short to
# be a credential, a reference or placeholder, and a short demo string are not
# reported. A UUID is deliberately NOT exempt, although the measurement proposed
# it: no row needed it, and some services issue UUID API keys (Heroku's are).
_SETTING_KEY_RE = re.compile(r"(?:_NAME|_ID|_TOKENS)$|TOKENIZER", re.IGNORECASE)
_PLACEHOLDER_VALUE_RE = re.compile(_REFERENCE_ARMS + "|" + _PLACEHOLDER_ARMS, re.IGNORECASE)
_DEMO_MARKERS = ("test", "demo", "password", "1234", "abcd")


def _could_be_credential(key: str, value: str) -> bool:
    """Whether an env literal under a secret-looking `key` can be a credential.

    The demo markers apply only below 40 characters, so a long real key that
    happens to contain one (`sk_test_...`, a hash with `abcd` in it) still
    fires; the placeholder pattern is the header check's without its `$VAR`
    and `%VAR%` arms, because a literal password may well contain a `$` or `%`.
    """
    if _SETTING_KEY_RE.search(key):
        return False
    v = value.strip()
    if len(v) < 6 or _PLACEHOLDER_VALUE_RE.search(v):
        return False
    return not (len(v) < 40 and any(m in v.lower() for m in _DEMO_MARKERS))


def _is_credential_reference(value: str) -> bool:
    """True when a header value is empty or an env/template/placeholder reference
    (i.e. not a hardcoded literal secret baked into the config)."""
    v = (value or "").strip()
    if not v:
        return True
    return bool(_CREDENTIAL_REF_RE.search(v))


def _server_declares_auth(headers: Any) -> bool:
    """Whether a server's ``headers`` block declares an authentication or
    access-control scheme, so AAK-MCP-001 ("without authentication") should not
    fire. Recognizes the historical exact names (name-only) plus the custom
    credential-header family (value-aware — a hardcoded literal does not count)."""
    if not isinstance(headers, dict):
        return False
    for name, value in headers.items():
        lname = str(name).lower()
        if lname in _KNOWN_AUTH_HEADERS:
            return True
        if _NON_AUTH_TOKEN_HEADERS.match(lname):
            continue
        if _CUSTOM_AUTH_HEADER_RE.match(lname) and _is_credential_reference(str(value)):
            return True
    return False

MCP_CONFIG_FILES = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    ".windsurf/mcp.json",
    ".continue/config.json",
    ".roo/mcp.json",
    ".kiro/mcp.json",
    "mcp.json",
]

# Config files that use a different key structure or format
_YAML_CONFIG_FILES = [
    ".config/goose/config.yaml",
]

# Gemini uses a settings.json that may contain MCP config
_SETTINGS_CONFIG_FILES = [
    ".gemini/settings.json",
]


def _find_mcp_configs(project_root: Path, include_user_config: bool = False) -> list[Path]:
    found: list[Path] = []
    for name in MCP_CONFIG_FILES:
        p = project_root / name
        if p.is_file():
            found.append(p)
    # Check settings-style configs (Gemini)
    for name in _SETTINGS_CONFIG_FILES:
        p = project_root / name
        if p.is_file() and p not in found:
            found.append(p)
    # Check YAML configs (Goose)
    for name in _YAML_CONFIG_FILES:
        p = project_root / name
        if p.is_file() and p not in found:
            found.append(p)
    # Recursively search for any *mcp*.json from project root
    for p in project_root.rglob("*mcp*.json"):
        if in_skip_dir(p, project_root):
            continue
        if p.is_file() and p not in found:
            found.append(p)
    # ZCode's workspace configs, `zcode.json` and `.zcode/config.json` at every
    # level, which ZCode connects on open (CVE-2026-88755); the glob misses both.
    for p in zcode_workspace_configs(project_root):
        if p.is_file() and p not in found:
            found.append(p)
    if include_user_config:
        user_claude = Path.home() / ".claude.json"
        if user_claude.is_file():
            found.append(user_claude)
    return found


_find_line_number = find_line_number
_make_finding = make_finding


def _check_server(
    server_name: str, server_cfg: dict[str, Any], file_path: str
) -> list[tuple[Finding, str]]:
    """One server's findings, each with the key its line is found by (see `placed`)."""
    findings: list[tuple[Finding, str]] = []

    # A field whose JSON type contradicts the MCP schema is reported by
    # AAK-MCP-CONFIG-MALFORMED-001 and is unevaluable here: there is no honest
    # answer to "does this command contain shell metacharacters" when the
    # command is a list. Treat it as absent for the rules below rather than
    # guessing at a coercion, and let the malformed rule be the one that speaks.
    url = _as_str(server_cfg.get("url", ""))
    command = _as_str(server_cfg.get("command", ""))
    # The program the command runs: its first word, or "" when it has none.
    # `command.strip().split()[0]` raised IndexError on a command of only
    # whitespace, and this is a core scanner, so one such server cost every
    # finding it makes in every file.
    cmd_bin = (command.split() or [""])[0]
    args = server_cfg.get("args", [])
    env = server_cfg.get("env", {})
    headers_helper = _as_str(server_cfg.get("headersHelper", ""))

    # AAK-MCP-001: Remote server without authentication. A server declaring a
    # recognized credential/access header — Authorization, Bearer, X-API-Key, or
    # the custom X-*-Key / *-API-Key family and the x402 X-PAYMENT gate — is
    # authenticated and must not fire (#475). A custom auth header whose value is
    # a hardcoded literal secret still fires: the credential is exposed in the
    # config, so the endpoint is effectively unprotected. A loopback server
    # (localhost, 127.0.0.0/8, ::1, 0.0.0.0) is the developer's own process, not
    # the remote server this rule is about; on 190 real `.vscode/mcp.json` files
    # its 24 loopback findings held no true positive.
    if url and not is_loopback_url(url):
        if not _server_declares_auth(server_cfg.get("headers", {})):
            findings.append((_make_finding(
                "AAK-MCP-001", file_path,
                f"Server '{server_name}' URL: {url} — no authentication headers",
            ), url))

    # AAK-MCP-002: Shell expansion in command. A VS Code variable is removed
    # first: VS Code substitutes `${workspaceFolder}` and its kind itself and
    # spawns without a shell, so its `$` is not one (both MCP-002 findings on
    # 190 real `.vscode/mcp.json` files were exactly that).
    if command:
        has_shell_meta = bool(SHELL_METACHARACTERS.search(strip_vscode_variables(command)))
        has_shell_wrapper = any(command.strip().startswith(sw) for sw in SHELL_WRAPPERS)
        if has_shell_meta or has_shell_wrapper:
            findings.append((_make_finding(
                "AAK-MCP-002", file_path,
                f"Server '{server_name}' command: {command}",
            ), command))

    # AAK-MCP-003: Hardcoded secrets in env
    if isinstance(env, dict):
        for key, value in env.items():
            if SECRET_KEY_PATTERNS.search(key) and isinstance(value, str):
                # Allow variable references like ${VAR}, and literals that cannot
                # be a credential (see _could_be_credential).
                if not re.match(r"^\$\{.+\}$", value) and value and _could_be_credential(key, value):
                    findings.append((_make_finding(
                        "AAK-MCP-003", file_path,
                        f"Server '{server_name}' env.{key} = (hardcoded value)",
                    ), key))

    # AAK-MCP-005: npx/uvx package fetcher
    if cmd_bin in PACKAGE_FETCHERS:
        findings.append((_make_finding(
            "AAK-MCP-005", file_path,
            f"Server '{server_name}' command: {command}",
        ), command))

    # AAK-MCP-006: Relative path command
    if command:
        is_absolute = cmd_bin.startswith("/")
        is_known = cmd_bin in KNOWN_BINARIES
        if not is_absolute and not is_known and cmd_bin:
            findings.append((_make_finding(
                "AAK-MCP-006", file_path,
                f"Server '{server_name}' command: {cmd_bin}",
            ), cmd_bin))

    # AAK-MCP-007: Unpinned package version in args. `engine.run_scan` drops a
    # finding here when AAK-SUPPLY-001 reports the same launch, which it
    # recognises by the evidence `launch_evidence` builds.
    if cmd_bin in PACKAGE_FETCHERS and isinstance(args, list):
        for index, arg in enumerate(args):
            if isinstance(arg, str) and not arg.startswith("-"):
                # Skip path-like arguments
                if arg.startswith("/") or arg.startswith("./") or arg.startswith("../"):
                    continue
                # Check if it looks like a package name without @version
                if arg and "@" not in arg:
                    findings.append((_make_finding(
                        "AAK-MCP-007", file_path,
                        launch_evidence(server_name, str(shown_arg(args, index)), "no version pin"),
                    ), arg))
                elif arg and "@" in arg:
                    # Has @ but check if it's scoped package without version
                    # e.g. @org/pkg has @ but no version; @org/pkg@1.0.0 is fine
                    parts = arg.split("@")
                    # Scoped: ['', 'org/pkg'] or ['', 'org/pkg', '1.0.0']
                    # Unscoped with version: ['pkg', '1.0.0']
                    if arg.startswith("@"):
                        # Scoped package
                        if len(parts) < 3 or not parts[2]:
                            findings.append((_make_finding(
                                "AAK-MCP-007", file_path,
                                launch_evidence(server_name, str(shown_arg(args, index)), "no version pin"),
                            ), arg))

    # AAK-MCP-008: headersHelper
    if headers_helper:
        findings.append((_make_finding(
            "AAK-MCP-008", file_path,
            f"Server '{server_name}' headersHelper: {headers_helper}",
        ), "headersHelper"))

    # AAK-MCP-009: Internal-network URL. A loopback server is left out, as in
    # AAK-MCP-001: a client config pointing at the local machine is not the
    # server-side reach into an internal network the rule describes, and 27 of its
    # 28 findings on real `.vscode/mcp.json` files were loopback, none a true
    # positive. RFC 1918 and `.local` hosts still fire.
    if url and not is_loopback_url(url) and _is_internal_url(url):
        findings.append((_make_finding(
            "AAK-MCP-009", file_path,
            f"Server '{server_name}' URL: {url}",
        ), url))

    # AAK-MCP-010: Filesystem root access
    if isinstance(args, list):
        for arg in args:
            if isinstance(arg, str) and arg in ("/", "~", "/home", "/Users", "/etc", "/var"):
                findings.append((_make_finding(
                    "AAK-MCP-010", file_path,
                    f"Server '{server_name}' grants access to '{arg}'",
                ), arg))

    return findings


# Fields whose MCP-schema type every client agrees on. `args` as a scalar is the
# shape reported in issue #743; it crashed the composition pass rather than
# being reported, so the run exited 0 on a config no client would agree about.
_EXPECTED_FIELD_TYPES: dict[str, tuple[type, ...]] = {
    "args": (list,),
    "command": (str,),
    "env": (dict,),
    "url": (str,),
}


def _as_str(value: object) -> str:
    """Return `value` if it is a string, else "" so callers skip it.

    Deliberately not `str(value)`: coercing `["node"]` to its repr would let a
    shell-metacharacter check run against `['node']` and report brackets that
    the operator never wrote.
    """
    return value if isinstance(value, str) else ""


def _check_malformed_fields(
    server_name: str, server_cfg: dict, rel_path: str
) -> list[tuple[Finding, str]]:
    """AAK-MCP-CONFIG-MALFORMED-001: a server field with the wrong JSON type, each
    finding with the key its line is found by (see `placed`)."""
    findings: list[tuple[Finding, str]] = []
    for field, expected in sorted(_EXPECTED_FIELD_TYPES.items()):
        if field not in server_cfg:
            continue
        value = server_cfg[field]
        if value is None or isinstance(value, expected):
            continue
        findings.append((_make_finding(
            "AAK-MCP-CONFIG-MALFORMED-001", rel_path,
            f"server {server_name!r} declares {field!r} as "
            f"{type(value).__name__}, expected "
            f"{' or '.join(t.__name__ for t in expected)}",
        ), f'"{field}"'))
    return findings


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()
    configs = _find_mcp_configs(project_root, include_user_config)

    for config_path in configs:
        zcode = is_zcode_workspace_config(config_path)
        try:
            # Decoded as Node decodes it (a bad byte becomes U+FFFD): a client
            # still loads the file, so a stray byte must not hide it.
            raw_text = read_text_capped(config_path, CONFIG_MAX_BYTES, errors="replace")
            if len(raw_text) > 1_000_000:
                continue
            # ZCode parses its config with JSON.parse and skips a file with a
            # comment in it, servers and all, so such a file is not read here.
            data = loads_json(raw_text, config_path) if zcode else loads_jsonc(raw_text, config_path)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = str(config_path.relative_to(project_root)) if config_path.is_relative_to(project_root) else str(config_path)
        scanned_files.add(rel_path)
        if not isinstance(data, dict):
            continue

        # Every server map in the file: `mcpServers`, and VS Code's `servers`,
        # which went unread until mcp_server_maps (see its docstring).
        for container, servers in mcp_server_maps(data, config_path):
            # AAK-MCP-004: Excessive server count, per map, since a client loads
            # one map of a file and not both.
            if len(servers) > 10:
                key = "servers" if container == ZCODE_SERVER_KEY else container
                findings.append(_make_finding(
                    "AAK-MCP-004", rel_path,
                    f"{len(servers)} MCP servers declared (threshold: 10)",
                    _find_line_number(raw_text, f'"{key}"'),
                ))

            unplaced: list[tuple[Finding, str]] = []
            for server_name, server_cfg in servers.items():
                if isinstance(server_cfg, dict):
                    unplaced.extend(_check_malformed_fields(server_name, server_cfg, rel_path))
                    unplaced.extend(_check_server(server_name, server_cfg, rel_path))

            # AAK-MCP-ATTEST-001: Servers admitted without attestation
            # (no signed clearance / well-known URI / pinned trust root).
            # Reference: Metere 2026, arXiv:2605.24248 — Attested Tool-Server Admission.
            unplaced.extend(_check_attestation(data, servers, rel_path))
            # Every finding's line in one pass over the file, not one search of it per finding.
            findings.extend(placed(raw_text, unplaced))

        # AAK-MCP-ZCODE-CVE-2026-88755-001: ZCode connects every server its
        # workspace config declares when the folder is opened, asking no one.
        if zcode:
            zcode_finding = _check_zcode_autoconnect(data, rel_path, raw_text)
            if zcode_finding is not None:
                findings.append(zcode_finding)

    return findings, scanned_files


# The `"servers"` key inside the `"mcp"` object, where a ZCode finding points.
_ZCODE_MCP_KEY_RE = re.compile(r'"mcp"\s*:\s*\{')
_ZCODE_SERVERS_KEY_RE = re.compile(r'"servers"\s*:')


def _zcode_started(name: str, cfg: object) -> str | None:
    """What ZCode does with one server when the workspace opens, or None.

    Mirrors ZCode 3.15.1's own reading (`schema.ts`, `adapters/src/mcp`):
    `enabled: false`, or the legacy `enable: false`, skips the connection; a
    missing or non-string `type` is inferred from `command`, then `url`; an
    entry with neither is dropped by the schema, so it starts nothing.
    """
    if not isinstance(cfg, dict) or cfg.get("enabled") is False or cfg.get("enable") is False:
        return None
    kind = cfg.get("type") if isinstance(cfg.get("type"), str) else None
    command, url = cfg.get("command"), cfg.get("url")
    if kind in (None, "stdio") and isinstance(command, str) and command.strip():
        raw_args = cfg.get("args")
        args: list[Any] = raw_args if isinstance(raw_args, list) else []
        shown = (str(shown_arg(args, i)) for i in range(len(args)))
        argv = " ".join([command, *(a if a else '""' for a in shown)])
        return f"'{name}' runs `{argv}`"
    if kind in (None, "http", "sse", "remote") and isinstance(url, str) and url.strip():
        return f"'{name}' connects to {url}"
    return None


def _check_zcode_autoconnect(data: dict, rel_path: str, raw_text: str) -> Finding | None:
    """AAK-MCP-ZCODE-CVE-2026-88755-001, once per ZCode workspace config file.

    ZCode merges `zcode.json` and `.zcode/config.json` into its MCP server table
    and connects every server at session start without a prompt: `runtime-config.ts`
    keeps its set of untrusted project servers empty, under the comment that
    workspace MCP is trusted by default and connects automatically. A stdio
    server's command therefore runs the moment the repository is opened, and the
    other servers' tool descriptions enter the agent's context. The file is what
    a hostile repository or pull request plants, so the file is what is reported,
    once, naming each server it starts. Whether a server is benign is not judged
    here; the class rules above judge its command and URL.
    """
    mcp = data.get("mcp")
    servers = mcp.get("servers") if isinstance(mcp, dict) else None
    if not isinstance(servers, dict):
        return None
    started = [s for name, cfg in servers.items() if (s := _zcode_started(str(name), cfg))]
    if not started:
        return None
    anchor = _ZCODE_MCP_KEY_RE.search(raw_text)
    key = _ZCODE_SERVERS_KEY_RE.search(raw_text, anchor.end()) if anchor else None
    line = raw_text.count("\n", 0, key.start()) + 1 if key else None
    return _make_finding(
        "AAK-MCP-ZCODE-CVE-2026-88755-001", rel_path,
        f"ZCode starts {len(started)} workspace MCP server(s) when this folder is "
        f"opened, without asking: {'; '.join(started)}",
        line,
    )


# ---------------------------------------------------------------------------
# AAK-MCP-ATTEST-001 — Attested Tool-Server Admission (arXiv:2605.24248)
# ---------------------------------------------------------------------------
# Metere 2026 proposes a small, offline-signed *clearance* assertion that an
# MCP server publishes at a well-known URI and a host verifies against a
# *pinned trust root* before any tool dispatch. An unextended host ignores
# the well-known document and behaves exactly as today — so the static
# evidence we look for is the host's own opt-in: per-server attestation
# fields, header carriers, a well-known clearance URI, or a host-level
# trust root.
#
# Server entries that do not dispatch (no `url` and no `command`) are
# skipped to avoid noise on stub / disabled entries that other rules
# already catch.

_SERVER_ATTEST_KEYS: frozenset[str] = frozenset({
    "attestation",
    "clearance",
    "clearance_url",
    "clearance_uri",
    "clearance_document",
    "clearancedocument",
    "mcp_clearance",
    "wellknown_clearance",
    "well_known_clearance",
    # A pinned trust root may also be carried per-server.
    "trust_root",
    "trustroot",
    "trust_anchor",
    "pinned_trust_root",
})

_HOST_ATTEST_KEYS: frozenset[str] = frozenset({
    "trust_root",
    "trustroot",
    "trust_anchor",
    "trustanchor",
    "pinned_trust_root",
    "trusted_roots",
    "trustedroots",
    "mcp_clearance_trust_root",
    "attestation_trust_root",
})

_HEADER_ATTEST_TOKENS: tuple[str, ...] = (
    "mcp-clearance",
    "mcp-attestation",
    "x-mcp-clearance",
)

_WELL_KNOWN_TOKEN: str = ".well-known/mcp-clearance"


def _normalize_key(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_")


def _host_has_attestation(data: Any) -> bool:
    """True iff the host config declares a pinned trust root or well-known URI."""
    if not isinstance(data, dict):
        return False
    for key in data.keys():
        if _normalize_key(key) in _HOST_ATTEST_KEYS:
            return True
    # Some hosts carry the well-known URI as a top-level setting.
    try:
        host_blob = json.dumps(data, default=str).lower()
    except (TypeError, ValueError, RecursionError):
        return False
    return _WELL_KNOWN_TOKEN in host_blob


def _server_has_attestation(server_cfg: Any) -> bool:
    """True iff the server entry references a clearance assertion or trust root."""
    if not isinstance(server_cfg, dict):
        return False
    for key in server_cfg.keys():
        if _normalize_key(key) in _SERVER_ATTEST_KEYS:
            return True
    # Header carriers (transport-level attestation).
    headers = server_cfg.get("headers", {})
    if isinstance(headers, dict):
        for hk in headers.keys():
            hkl = str(hk).lower()
            if any(tok in hkl for tok in _HEADER_ATTEST_TOKENS):
                return True
    # Well-known URI named anywhere in the server entry.
    try:
        server_blob = json.dumps(server_cfg, default=str).lower()
    except (TypeError, ValueError, RecursionError):
        return False
    return _WELL_KNOWN_TOKEN in server_blob


def _server_dispatches(server_cfg: Any) -> bool:
    """True iff the entry actually drives a remote URL or local command."""
    if not isinstance(server_cfg, dict):
        return False
    return bool(server_cfg.get("url") or server_cfg.get("command"))


def _check_attestation(
    data: Any,
    servers: Any,
    rel_path: str,
) -> list[tuple[Finding, str]]:
    """Flag dispatched servers admitted without any attestation evidence.

    A server is considered attested when ANY of the following is present:

    - The server entry carries an `attestation`/`clearance`/`clearance_url`
      field, an `MCP-Clearance` (or `MCP-Attestation`) header, or names the
      `/.well-known/mcp-clearance` URI anywhere in its entry.
    - The host config carries a pinned `trust_root` (or alias) the host
      verifies before tool dispatch.

    Args:
        data: Parsed host config (the top-level dict of the MCP config file).
        servers: The `mcpServers` map within `data`.
        rel_path: Config path relative to the project root (for the finding).

    Returns:
        One `Finding` per dispatched-but-unattested server entry, with the key
        its line is found by (see `placed`). An empty list if the host pins a
        trust root (which covers all servers) or if no servers dispatch.
    """
    if not isinstance(servers, dict) or not servers:
        return []
    if _host_has_attestation(data):
        return []
    out: list[tuple[Finding, str]] = []
    for server_name, server_cfg in servers.items():
        if not _server_dispatches(server_cfg):
            continue
        if _server_has_attestation(server_cfg):
            continue
        out.append((_make_finding(
            "AAK-MCP-ATTEST-001", rel_path,
            f"Server '{server_name}' admitted without attestation "
            f"(no signed clearance / pinned trust root) "
            f"— deny-by-default server admission unenforced",
        ), f'"{server_name}"'))
    return out
