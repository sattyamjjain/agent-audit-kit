"""Third-party OAuth-app + agent-platform risk-surface scanner.

Fires:
- **AAK-OAUTH-SCOPE-001** — a config file grants broad Google Workspace
  scopes (admin.*, cloud-platform, drive) to a non-first-party client
  ID that isn't in the repo's `.aak-oauth-trust.yml` allowlist.
- **AAK-OAUTH-3P-001** — the repo imports a third-party agent-platform
  integration (context-ai / langsmith / helicone / langfuse / humanloop
  / any MCP client SDK). MEDIUM informational finding pointing at
  Vercel's "sensitive env var" guidance.

Both rules tag `incident_references=["VERCEL-2026-04-19"]` — the April
19 2026 Vercel × Context.ai OAuth breach is the template, not a CVE.

References:
- Vercel KB bulletin:
  https://vercel.com/kb/bulletin/vercel-april-2026-security-incident
- The Information briefing (ShinyHunters resale):
  https://www.theinformation.com/briefings/vercel-confirms-breach-hackers-list-stolen-data-2m
- Cryptopolitan writeup:
  https://www.cryptopolitan.com/vercel-breach-tied-to-compromised-ai-tool/
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

try:
    import tomllib
except ImportError:  # Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding


_BROAD_SCOPE_RE = re.compile(
    r"https://www\.googleapis\.com/auth/(?:"
    r"admin\.[a-z]+|"
    r"cloud-platform(?:\.[a-z]+)?|"
    r"drive(?:\.[a-z]+)?|"
    r"gmail\.(?:modify|send)|"
    r"directory\.[a-z]+"
    r")",
    re.IGNORECASE,
)

_CLIENT_ID_RE = re.compile(
    r"\b(?P<id>\d{10,14}-[a-z0-9]{20,40}\.apps\.googleusercontent\.com)\b",
    re.IGNORECASE,
)

# First-party Google client-ID prefixes we recognise as trusted by default.
# (An org can override by listing client IDs in .aak-oauth-trust.yml.)
_TRUSTED_CLIENT_ID_PREFIXES: tuple[str, ...] = ()

_CONFIG_GLOBS = (
    "app.yaml",
    "vercel.json",
    "netlify.toml",
    ".well-known/oauth-client-credentials.json",
    "oauth_client.json",
    "oauth.json",
    "client_secret*.json",
    ".google-cloud-sdk/**/*.json",
)

_AGENT_PLATFORM_PACKAGES: dict[str, str] = {
    # npm / Node
    "context-ai": "Context.ai (linked to the Vercel Apr 19 2026 breach)",
    "@langchain/langsmith": "LangSmith",
    "langsmith": "LangSmith",
    "helicone": "Helicone",
    "langfuse": "Langfuse",
    "humanloop": "Humanloop",
    "@modelcontextprotocol/sdk": "MCP SDK (any variant)",
    # PyPI
    "langsmith-py": "LangSmith (Python)",
    "helicone-py": "Helicone (Python)",
    "mcp": "Model Context Protocol Python SDK",
}


# ---------------------------------------------------------------------------
# Trust allowlist (.aak-oauth-trust.yml)
# ---------------------------------------------------------------------------


def _load_trust_allowlist(project_root: Path) -> set[str]:
    path = project_root / ".aak-oauth-trust.yml"
    if not path.is_file() or yaml is None:
        return set()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return set()
    trusted = data.get("trusted_client_ids") if isinstance(data, dict) else None
    if not isinstance(trusted, list):
        return set()
    return {str(x) for x in trusted}


# ---------------------------------------------------------------------------
# AAK-OAUTH-SCOPE-001 — broad scopes in config
# ---------------------------------------------------------------------------


def _iter_config_files(project_root: Path) -> Iterable[Path]:
    for pattern in _CONFIG_GLOBS:
        for candidate in project_root.glob(pattern):
            if candidate.is_file():
                yield candidate


def _check_config_file(
    path: Path,
    project_root: Path,
    trusted: set[str],
) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    scopes = list(_BROAD_SCOPE_RE.finditer(text))
    client_ids = {m.group("id") for m in _CLIENT_ID_RE.finditer(text)}
    if not scopes:
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))
    untrusted_ids = {cid for cid in client_ids if cid not in trusted and not any(cid.startswith(p) for p in _TRUSTED_CLIENT_ID_PREFIXES)}
    scope_list = sorted({m.group(0) for m in scopes})
    if untrusted_ids:
        for cid in sorted(untrusted_ids):
            findings.append(make_finding(
                "AAK-OAUTH-SCOPE-001",
                rel,
                f"Broad Google Workspace scopes ({', '.join(scope_list[:3])}"
                f"{'…' if len(scope_list) > 3 else ''}) granted to non-allowlisted client "
                f"{cid!r}. Add to .aak-oauth-trust.yml if intentional.",
                line_number=find_line_number(text, cid),
            ))
    elif not client_ids:
        # Broad scopes with no identifiable client ID at all — still suspicious.
        findings.append(make_finding(
            "AAK-OAUTH-SCOPE-001",
            rel,
            f"Broad Google Workspace scopes ({', '.join(scope_list[:3])}) granted; "
            "no client_id identified in the config — add an explicit client_id "
            "and allowlist it in .aak-oauth-trust.yml.",
            line_number=find_line_number(text, scope_list[0]),
        ))
    return findings


# ---------------------------------------------------------------------------
# AAK-OAUTH-3P-001 — agent-platform dependency detection
# ---------------------------------------------------------------------------


def _detect_package(manifest: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel = str(manifest.relative_to(project_root))
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    deps: dict[str, str] = {}
    if manifest.name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return findings
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            got = data.get(section) or {}
            if isinstance(got, dict):
                deps.update({str(k): str(v) for k, v in got.items()})
    elif manifest.name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return findings
        project = data.get("project", {}) or {}
        for name_spec in project.get("dependencies", []) or []:
            name = re.split(r"[<>=!~\s]", str(name_spec), maxsplit=1)[0].strip()
            if name:
                deps[name] = str(name_spec)
    elif manifest.name.startswith("requirements"):
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            name = re.split(r"[<>=!~\s]", line, maxsplit=1)[0].strip()
            if name:
                deps[name] = line

    for dep_name, spec in deps.items():
        if dep_name in _AGENT_PLATFORM_PACKAGES:
            desc = _AGENT_PLATFORM_PACKAGES[dep_name]
            findings.append(make_finding(
                "AAK-OAUTH-3P-001",
                rel,
                f"Depends on {dep_name!r} ({desc}). Pin version, audit OAuth "
                "scopes it requests, and keep any workspace-grant tokens in a "
                "secrets vault — not in a committed env file.",
                line_number=find_line_number(text, dep_name),
            ))
    return findings


def _iter_manifests(project_root: Path) -> Iterable[Path]:
    for name in ("package.json", "pyproject.toml"):
        p = project_root / name
        if p.is_file():
            yield p
    for pattern in ("requirements.txt", "requirements-*.txt", "dev-requirements.txt"):
        for p in project_root.glob(pattern):
            if p.is_file():
                yield p


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    trusted = _load_trust_allowlist(project_root)
    findings: list[Finding] = []
    scanned: set[str] = set()

    for cfg in _iter_config_files(project_root):
        rel = str(cfg.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_config_file(cfg, project_root, trusted))

    for manifest in _iter_manifests(project_root):
        rel = str(manifest.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_detect_package(manifest, project_root))

    return findings, scanned
