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


def emit_cyclonedx(project_root: Path) -> str:
    pkgs = _discover_mcp_packages(project_root)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "agent-audit-kit",
                    "name": "agent-audit-kit",
                    "version": __version__,
                }
            ],
        },
        "components": [
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
        ],
    }
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
