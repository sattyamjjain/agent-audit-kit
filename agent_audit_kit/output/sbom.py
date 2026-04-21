"""SBOM emission for scanned MCP/agent projects (CycloneDX 1.5 + SPDX 2.3).

Walks MCP config files and Python/Node manifests to enumerate the MCP
server packages the project depends on, then emits a minimal but
spec-compliant SBOM. Intended for EU AI Act Article 15 evidence bundles.

Refs:
- CycloneDX 1.5: https://cyclonedx.org/docs/1.5
- SPDX 2.3: https://spdx.github.io/spdx-spec/v2.3
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent_audit_kit import __version__


_MCP_CONFIG_NAMES = (
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp.json",
)
_PKG_NPM_RE = re.compile(r"@[\w\-./]+@[\d][\w\-.+]*")
_PKG_AT_RE = re.compile(r"[\w\-./]+@[\d][\w\-.+]*")


def _discover_mcp_packages(project_root: Path) -> list[dict]:
    pkgs: dict[str, dict] = {}
    for name in _MCP_CONFIG_NAMES:
        path = project_root / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        for server_name, server_cfg in (data.get("mcpServers") or {}).items():
            if not isinstance(server_cfg, dict):
                continue
            args = server_cfg.get("args") or []
            if not isinstance(args, list):
                continue
            for arg in args:
                if not isinstance(arg, str):
                    continue
                m = _PKG_NPM_RE.search(arg) or _PKG_AT_RE.fullmatch(arg.strip())
                if not m:
                    continue
                spec = m.group(0)
                name_part, version = spec.rsplit("@", 1)
                pkgs[spec] = {
                    "name": name_part,
                    "version": version,
                    "purl": f"pkg:npm/{name_part}@{version}",
                    "mcp_server": server_name,
                }
    return list(pkgs.values())


_AGENT_PLATFORM_SDKS: tuple[tuple[str, str], ...] = (
    ("langchain", "langchain"),
    ("langsmith", "langsmith"),
    ("langgraph", "langgraph"),
    ("langfuse", "langfuse"),
    ("helicone", "helicone"),
    ("humanloop", "humanloop"),
    ("anthropic", "anthropic"),
    ("openai", "openai"),
    ("@modelcontextprotocol/sdk", "@modelcontextprotocol/sdk"),
    ("modelcontextprotocol", "modelcontextprotocol"),
    ("mcp", "mcp"),
)

_ML_MODEL_HINTS: tuple[tuple[str, str, str], ...] = (
    ("anthropic", "Claude", "Anthropic"),
    ("openai", "GPT", "OpenAI"),
    ("cohere", "Command", "Cohere"),
)


def _discover_agent_platform_components(project_root: Path) -> list[dict]:
    """Enumerate detected agent-platform SDKs from package.json + Python deps.

    Returns CycloneDX 1.5 component dicts with type ``library``.
    """

    hits: list[dict] = []

    pkg = project_root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            all_deps: dict[str, str] = {}
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                d = data.get(section) or {}
                if isinstance(d, dict):
                    all_deps.update({k: str(v) for k, v in d.items()})
            for sdk_key, sdk_name in _AGENT_PLATFORM_SDKS:
                if sdk_key in all_deps:
                    hits.append({
                        "type": "library",
                        "name": sdk_name,
                        "version": all_deps[sdk_key],
                        "purl": f"pkg:npm/{sdk_name}@{all_deps[sdk_key]}",
                        "scope": "required",
                    })

    for req in project_root.glob("requirements*.txt"):
        try:
            text = req.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            name = line.split("#", 1)[0].strip().split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip()
            if not name:
                continue
            for sdk_key, sdk_name in _AGENT_PLATFORM_SDKS:
                if name.lower() == sdk_key.lower() and sdk_key.startswith("@") is False:
                    # Extract the literal pin if present (best-effort).
                    version = ""
                    if "==" in line:
                        version = line.split("==", 1)[1].strip().split()[0]
                    hits.append({
                        "type": "library",
                        "name": sdk_name,
                        "version": version,
                        "purl": f"pkg:pypi/{sdk_name}" + (f"@{version}" if version else ""),
                        "scope": "required",
                    })
                    break
    return hits


def _discover_ml_model_components(project_root: Path) -> list[dict]:
    """Return CycloneDX 1.5 ML/AI-BOM machine-learning-model components.

    Heuristic: presence of an API-client package hints at that vendor's
    model family. Deliberately coarse — v0.3.3 ships the emitter, the
    fine-grained detection can be layered on in later releases.
    """

    hits: list[dict] = []
    blob = ""
    for name in ("requirements.txt", "pyproject.toml", "package.json", "Pipfile"):
        p = project_root / name
        if p.is_file():
            try:
                blob += p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

    for needle, family, vendor in _ML_MODEL_HINTS:
        if needle in blob.lower():
            hits.append({
                "type": "machine-learning-model",
                "name": f"{vendor} {family}",
                "description": f"{vendor} {family} family inferred from declared SDK dependency",
                "supplier": {"name": vendor},
            })
    return hits


def emit_cyclonedx(
    project_root: Path,
    *,
    aibom: bool = False,
    rule_bundle_sha256: str | None = None,
    fired_incidents: list[str] | None = None,
) -> str:
    """Emit a CycloneDX 1.5 SBOM (or AI-BOM extension when ``aibom=True``).

    When ``aibom`` is True the emitter adds:
    - ``machine-learning-model`` components per detected vendor SDK.
    - A ``formulation`` block enumerating detected agent-platform SDKs.
    - Metadata properties for the rule-bundle sha256 and fired incident
      references — surface that aligns with the procurement-artifact
      shape the April 2026 AI-BOM briefs are coalescing around.
    """

    pkgs = _discover_mcp_packages(project_root)

    metadata: dict = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": [
            {
                "vendor": "agent-audit-kit",
                "name": "agent-audit-kit",
                "version": __version__,
            }
        ],
    }

    components: list[dict] = [
        {
            "type": "application",
            "name": p["name"],
            "version": p["version"],
            "purl": p["purl"],
            "properties": [
                {"name": "aak:mcp_server", "value": p["mcp_server"]},
            ],
        }
        for p in pkgs
    ]

    doc: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }

    if aibom:
        ml_models = _discover_ml_model_components(project_root)
        platform_sdks = _discover_agent_platform_components(project_root)
        components.extend(ml_models)

        properties = metadata.setdefault("properties", [])
        if rule_bundle_sha256:
            properties.append({
                "name": "aak:rule-bundle-sha256",
                "value": rule_bundle_sha256,
            })
        for inc in fired_incidents or []:
            properties.append({
                "name": "aak:incident-fired",
                "value": inc,
            })
        if platform_sdks:
            doc["formulation"] = [{
                "bom-ref": f"formulation-{uuid.uuid4().hex[:8]}",
                "components": platform_sdks,
            }]
        # Top-level marker so downstream tools can branch on "this BOM
        # is an AI-BOM" without sniffing for ml-model components.
        metadata.setdefault("properties", properties).append({
            "name": "aak:aibom",
            "value": "1",
        })

    return json.dumps(doc, indent=2)


def emit_spdx(project_root: Path) -> str:
    pkgs = _discover_mcp_packages(project_root)
    doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}"
    packages = []
    for i, p in enumerate(pkgs, start=1):
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{i}",
                "name": p["name"],
                "versionInfo": p["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": p["purl"],
                    }
                ],
            }
        )
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": project_root.name,
        "documentNamespace": f"https://agent-audit-kit.dev/sbom/{doc_id}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": [f"Tool: agent-audit-kit-{__version__}"],
        },
        "packages": packages,
    }
    return json.dumps(doc, indent=2)
