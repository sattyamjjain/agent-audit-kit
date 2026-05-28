"""MCP Tunnels gateway-config + credential-exposure scanner.

Reference: Anthropic MCP Tunnels (research preview, launched 2026-05-19).

  - Overview: https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview
  - Reference: https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference
  - Security:  https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/security

Architecture (from the official reference, used to drive every detection
pattern here):

  cloudflared (outbound-only) ──► tunnel edge (Cloudflare) ──► Anthropic Proxy
                                                                     │
                                                            inner TLS, then
                                                            routes/upstream
                                                                     ▼
                                                              private MCP servers

The proxy reads `/etc/mcp-gateway/config.yaml` (Compose) or the rendered
ConfigMap (Helm). The fields below are taken verbatim from the reference:

  listen_addr / tunnel_domain / shutdown_timeout / log_level
  tls.cert_file / tls.key_file
  routes:                     # map[str, str]  subdomain → "scheme://host:port"
  upstream.allowed_ips        # IPv4 CIDR list — "the proxy's primary SSRF defense"
  upstream.disable_ip_validation
  upstream.tls.ca_file
  upstream.tls.include_system_cas

The security page additionally lists these as customer-managed
high-value secrets that must be protected at rest:

  tunnel token (from the Console / WIF setup)
  server TLS private key (under `tls.key_file`)

Three rule-specific detections, grounded in the docs:

  AAK-MCP-TUNNEL-001  (CRITICAL, CWE-918, MCP_CONFIG)
      The proxy's `upstream.allowed_ips` SSRF defense is disabled or
      effectively bypassed: `disable_ip_validation: true`, or an
      `allowed_ips:` entry covers a public-internet-sized CIDR
      (prefix length ≤ 7 for IPv4, or 0.0.0.0/0 / ::/0).

  AAK-MCP-TUNNEL-002  (HIGH, CWE-295, MCP_CONFIG)
      An `https://` upstream is configured in `routes:` but neither
      `upstream.tls.ca_file` nor `upstream.tls.include_system_cas` is
      set. Quoting the reference verbatim: "otherwise the proxy has
      no trust anchor for the upstream certificate."

  AAK-MCP-TUNNEL-003  (CRITICAL, CWE-798, MCP_CONFIG)
      Tunnel credentials or TLS private keys are hardcoded in the
      repository or a CI workflow. The overview page warns: "If an
      attacker obtains your tunnel token AND one of your TLS private
      keys, they could impersonate your proxy and read MCP request
      payloads. Treat both as high-value secrets."
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    SKIP_DIRS,
    find_line_number,
    make_finding,
)


# ---------------------------------------------------------------------------
# Proxy-config discovery
# ---------------------------------------------------------------------------
# The reference page documents the canonical Compose path
# (`/etc/mcp-gateway/config.yaml`) and the Helm `gateway.config.*` keys.
# In practice teams check one of these patterns into a repo:
#
#   mcp-gateway/config.yaml
#   mcp-tunnel/config.yaml
#   mcp-tunnel/proxy.yaml
#   gateway/config.yaml
#   deploy/mcp-gateway/values.yaml          (Helm values)
#
# To stay precise we ALSO accept any YAML that contains both a
# top-level `tunnel_domain:` and `routes:`, which is the unambiguous
# fingerprint of an MCP Tunnels proxy config per the reference table.

_TUNNEL_PROXY_FILENAMES: tuple[str, ...] = (
    "config.yaml",
    "config.yml",
    "proxy.yaml",
    "proxy.yml",
    "values.yaml",
    "values.yml",
)

_TUNNEL_PARENT_DIR_HINTS: tuple[str, ...] = (
    "mcp-gateway",
    "mcp-tunnel",
    "mcp_tunnel",
    "mcp_gateway",
    "mcp-tunnels",
    "tunnel",
    "gateway",
)

# CI files that may carry tunnel secrets (rule -003).
_CI_FILE_GLOBS: tuple[str, ...] = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    ".circleci/config.yml",
    ".circleci/config.yaml",
)


def _looks_like_tunnel_proxy_config(data: Any) -> bool:
    """True iff a parsed YAML doc has the unambiguous MCP Tunnels proxy shape.

    Per the reference table at
    https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference,
    the proxy config always carries `tunnel_domain` and `routes`. We also
    accept the Helm wrapper, which nests the same shape under `gateway.config`.
    """
    if not isinstance(data, dict):
        return False
    if "tunnel_domain" in data and "routes" in data:
        return True
    gw = data.get("gateway")
    if isinstance(gw, dict):
        inner = gw.get("config")
        if isinstance(inner, dict) and "tunnel_domain" in inner and "routes" in inner:
            return True
    return False


def _unwrap_proxy_config(data: Any) -> dict[str, Any] | None:
    """Return the proxy-config sub-dict, walking past the Helm `gateway.config` wrapper."""
    if not isinstance(data, dict):
        return None
    if "tunnel_domain" in data and "routes" in data:
        return data
    gw = data.get("gateway")
    if isinstance(gw, dict):
        inner = gw.get("config")
        if isinstance(inner, dict) and "tunnel_domain" in inner and "routes" in inner:
            return inner
    return None


def _path_hints_tunnel(p: Path, project_root: Path) -> bool:
    """True iff the path lives under an obvious MCP-Tunnels directory."""
    try:
        rel = p.relative_to(project_root)
    except ValueError:
        rel = p
    parts = {part.lower() for part in rel.parts}
    return bool(parts & set(_TUNNEL_PARENT_DIR_HINTS))


def _find_tunnel_proxy_configs(project_root: Path) -> list[Path]:
    """Return YAML files that are MCP-Tunnels proxy configs."""
    found: list[Path] = []
    for p in project_root.rglob("*.y*ml"):
        if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        if p.name.lower() not in _TUNNEL_PROXY_FILENAMES and not _path_hints_tunnel(p, project_root):
            continue
        try:
            raw = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if len(raw) > 1_000_000:
            continue
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            continue
        if _looks_like_tunnel_proxy_config(data):
            found.append(p)
    return found


# ---------------------------------------------------------------------------
# AAK-MCP-TUNNEL-001 — SSRF defense disabled / bypassed
# ---------------------------------------------------------------------------

# Per the reference: `upstream.allowed_ips` is documented as IPv4 CIDR
# ranges. We also tolerate IPv6 since field-survey configs sometimes
# add ::/0 by mistake — and that misconfiguration is exactly what we
# want to surface.
_PUBLIC_INTERNET_CIDRS_V4: tuple[str, ...] = ("0.0.0.0/0",)
_PUBLIC_INTERNET_CIDRS_V6: tuple[str, ...] = ("::/0",)


def _is_overly_broad_cidr(value: str) -> tuple[bool, str]:
    """Return (is_broad, reason) for a CIDR string.

    A CIDR is "overly broad" for an internal-network proxy when its prefix
    length covers more than a single org's address space. We use prefix ≤ 7
    for IPv4 (≥ 33 million addresses) and prefix ≤ 31 for IPv6 (which is
    similarly absurd at this layer).
    """
    s = value.strip()
    if not s:
        return False, ""
    if s in _PUBLIC_INTERNET_CIDRS_V4 or s in _PUBLIC_INTERNET_CIDRS_V6:
        return True, f"matches the entire public internet ({s})"
    try:
        net = ipaddress.ip_network(s, strict=False)
    except (ValueError, TypeError):
        return False, ""
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 7:
        return True, f"IPv4 /{net.prefixlen} covers {net.num_addresses:,} addresses"
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen <= 31:
        return True, f"IPv6 /{net.prefixlen} covers far more than a private network"
    return False, ""


def _check_ssrf_defense(
    cfg: dict[str, Any],
    file_path: str,
    raw_text: str,
) -> list[Finding]:
    out: list[Finding] = []
    upstream = cfg.get("upstream")
    if not isinstance(upstream, dict):
        return out
    if upstream.get("disable_ip_validation") is True:
        out.append(make_finding(
            "AAK-MCP-TUNNEL-001", file_path,
            "MCP Tunnels proxy: `upstream.disable_ip_validation: true` "
            "— the proxy's primary SSRF defense is turned off",
            find_line_number(raw_text, "disable_ip_validation"),
        ))
    allowed = upstream.get("allowed_ips")
    if isinstance(allowed, list):
        for item in allowed:
            if not isinstance(item, str):
                continue
            broad, reason = _is_overly_broad_cidr(item)
            if broad:
                out.append(make_finding(
                    "AAK-MCP-TUNNEL-001", file_path,
                    f"MCP Tunnels proxy: `upstream.allowed_ips` entry "
                    f"{item!r} is overly broad — {reason}",
                    find_line_number(raw_text, item),
                ))
    return out


# ---------------------------------------------------------------------------
# AAK-MCP-TUNNEL-002 — HTTPS upstream without trust anchor
# ---------------------------------------------------------------------------


def _check_upstream_trust_anchor(
    cfg: dict[str, Any],
    file_path: str,
    raw_text: str,
) -> list[Finding]:
    out: list[Finding] = []
    routes = cfg.get("routes")
    if not isinstance(routes, dict):
        return out
    upstream = cfg.get("upstream") or {}
    upstream_tls = upstream.get("tls") if isinstance(upstream, dict) else None
    has_ca_file = bool(
        isinstance(upstream_tls, dict)
        and isinstance(upstream_tls.get("ca_file"), str)
        and upstream_tls.get("ca_file", "").strip()
    )
    has_system_cas = (
        isinstance(upstream_tls, dict)
        and upstream_tls.get("include_system_cas") is True
    )
    if has_ca_file or has_system_cas:
        return out
    # No trust anchor configured — flag every https:// route.
    for subdomain, upstream_url in routes.items():
        if not isinstance(upstream_url, str):
            continue
        if upstream_url.strip().lower().startswith("https://"):
            out.append(make_finding(
                "AAK-MCP-TUNNEL-002", file_path,
                f"MCP Tunnels proxy: route {subdomain!r} forwards to "
                f"{upstream_url} but neither `upstream.tls.ca_file` nor "
                f"`upstream.tls.include_system_cas` is set — the proxy "
                f"has no trust anchor for the upstream certificate",
                find_line_number(raw_text, str(subdomain)),
            ))
    return out


# ---------------------------------------------------------------------------
# AAK-MCP-TUNNEL-003 — Tunnel credentials hardcoded in repo / CI
# ---------------------------------------------------------------------------

_TUNNEL_TOKEN_KEY_RE = re.compile(
    r"^(?:MCP[_-]?TUNNEL[_-]?TOKEN|"
    r"TUNNEL[_-]?TOKEN|"
    r"ANTHROPIC[_-]?TUNNEL[_-]?TOKEN|"
    r"TUNNELS?[_-]?API[_-]?TOKEN|"
    r"ANTHROPIC[_-]?IDENTITY[_-]?TOKEN)$",
    re.IGNORECASE,
)
# Literal-value detector: matches a key: "value" pair on one line where the
# value isn't a `${...}` reference, an `env.NAME` reference, or empty.
_TOKEN_LITERAL_LINE_RE = re.compile(
    r"""^\s*
        (?P<key>[A-Z][A-Z0-9_-]+)        # ENV-style key
        \s*[:=]\s*
        (?P<q>['\"]?)                     # optional quote
        (?P<val>[^\s'\"\$\{][^\s'\"]*)    # value that doesn't start with $/{
        (?P=q)\s*$
    """,
    re.VERBOSE,
)
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----"
)
# K8s Secret data block hint — the docs name these explicitly.
_K8S_TUNNEL_SECRET_NAMES: tuple[str, ...] = (
    "mcp-tunnel",
    "mcp-tunnel-token",
    "mcp-tunnel-cert",
)


def _check_ci_for_tunnel_tokens(
    project_root: Path,
) -> list[Finding]:
    out: list[Finding] = []
    for glob in _CI_FILE_GLOBS:
        for p in project_root.glob(glob):
            if not p.is_file():
                continue
            try:
                raw = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if len(raw) > 1_000_000:
                continue
            rel = str(p.relative_to(project_root))
            for line_no, line in enumerate(raw.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = _TOKEN_LITERAL_LINE_RE.match(line)
                if not m:
                    continue
                key = m.group("key")
                if not _TUNNEL_TOKEN_KEY_RE.match(key):
                    continue
                val = m.group("val")
                # Allow common indirection patterns even without quoting.
                if val.startswith(("${{", "$(", "$")) or val in (
                    "true", "false", "null", "~",
                ):
                    continue
                # Allow GitHub secrets / env references that survive the
                # regex (e.g. `secrets.MCP_TUNNEL_TOKEN`).
                if "secrets." in val or "env." in val:
                    continue
                out.append(make_finding(
                    "AAK-MCP-TUNNEL-003", rel,
                    f"Tunnel credential env var `{key}` has a literal "
                    f"value in CI config — must be sourced from a "
                    f"secrets store (vault, GitHub Actions secret, "
                    f"WIF identity token)",
                    line_no,
                ))
    return out


def _check_committed_tunnel_pem_keys(project_root: Path) -> list[Finding]:
    out: list[Finding] = []
    for p in project_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        if not _path_hints_tunnel(p, project_root):
            continue
        # Cheap rejection on size before reading.
        try:
            if p.stat().st_size > 100_000:
                continue
        except OSError:
            continue
        try:
            raw = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not _PEM_PRIVATE_KEY_RE.search(raw):
            continue
        rel = str(p.relative_to(project_root))
        line_no = find_line_number(raw, "BEGIN")
        out.append(make_finding(
            "AAK-MCP-TUNNEL-003", rel,
            f"TLS private key committed under MCP-Tunnels path {rel!r} "
            f"— per the MCP Tunnels security docs, the server TLS key "
            f"is a high-value secret that must be protected at rest",
            line_no,
        ))
    return out


def _check_committed_k8s_tunnel_secrets(project_root: Path) -> list[Finding]:
    """Detect a Kubernetes Secret manifest checked into the repo whose
    name matches the documented mcp-tunnel / mcp-tunnel-token / mcp-tunnel-cert
    naming AND whose `data:` block carries a non-empty literal value."""
    out: list[Finding] = []
    for p in project_root.rglob("*.y*ml"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        try:
            raw = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if len(raw) > 1_000_000:
            continue
        if "kind: Secret" not in raw and "kind: \"Secret\"" not in raw:
            continue
        try:
            docs = list(yaml.safe_load_all(raw))
        except yaml.YAMLError:
            continue
        rel = str(p.relative_to(project_root))
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get("kind") != "Secret":
                continue
            meta = doc.get("metadata") or {}
            if not isinstance(meta, dict):
                continue
            name = str(meta.get("name", "")).lower()
            if name not in _K8S_TUNNEL_SECRET_NAMES:
                continue
            data = doc.get("data") or doc.get("stringData") or {}
            if not isinstance(data, dict) or not data:
                continue
            # Flag only if the data block has a non-empty value (so an
            # empty placeholder Secret used as a target for `kubectl
            # create secret` is not a false positive).
            if not any(isinstance(v, str) and v.strip() for v in data.values()):
                continue
            out.append(make_finding(
                "AAK-MCP-TUNNEL-003", rel,
                f"Kubernetes Secret {name!r} for MCP Tunnels is "
                f"checked in with literal `data:` values — credentials "
                f"must be created out-of-band (sealed-secrets, "
                f"External Secrets Operator, vault-secrets-operator)",
                find_line_number(raw, name),
            ))
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP Tunnels gateway misconfigurations and credential exposure.

    Args:
        project_root: Repository root to scan.

    Returns:
        Tuple of (findings, evaluated_rule_ids). The evaluated set always
        contains all three MCP-TUNNEL rule IDs so the engine reports
        coverage even when no finding fires.
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    # Proxy-config detections (rules -001 and -002).
    for cfg_path in _find_tunnel_proxy_configs(project_root):
        try:
            raw = cfg_path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        cfg = _unwrap_proxy_config(data)
        if cfg is None:
            continue
        rel = str(cfg_path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_ssrf_defense(cfg, rel, raw))
        findings.extend(_check_upstream_trust_anchor(cfg, rel, raw))

    # Credential-exposure detections (rule -003).
    findings.extend(_check_ci_for_tunnel_tokens(project_root))
    findings.extend(_check_committed_tunnel_pem_keys(project_root))
    findings.extend(_check_committed_k8s_tunnel_secrets(project_root))

    evaluated = {"AAK-MCP-TUNNEL-001", "AAK-MCP-TUNNEL-002", "AAK-MCP-TUNNEL-003"}
    return findings, evaluated
