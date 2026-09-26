#!/usr/bin/env python3
"""Emit the SBOMs a release attaches: CycloneDX 1.5 and SPDX 2.3.

Run it with the interpreter of an environment that holds the package and
nothing else, as release.yml does::

    python -m venv --without-pip sbom-env
    python -m pip --python sbom-env/bin/python install .
    sbom-env/bin/python scripts/release_sbom.py --cyclonedx sbom.cdx.json --spdx sbom.spdx.json

Why this exists: from v0.3.0 to v0.6.9 the release job ran
`agent-audit-kit sbom .` on this repository. That command inventories the MCP
servers a *scanned project* declares, which is what it is for, and this
repository declares none, so every SBOM the release signed and attached listed
zero components. This one describes the thing being released: the package and
the runtime dependencies that came with it.

The dependency closure follows `Requires-Dist` from the package, skipping
requirements that belong to an extra and keeping those that are installed. In
the clean environment above, installed is exactly what the package pulled in on
that interpreter, so an environment marker (`tomli` below Python 3.11) resolves
the way it did for the install. Markers are not evaluated, so in a shared
environment a requirement whose marker is false but which is installed for some
other reason (click's Windows-only `colorama`) is listed too: run it clean.
Stdlib only: the environment holds nothing else.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import sys
import uuid
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

ROOT = "agent-audit-kit"
_REQ_NAME = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

Closure = tuple[metadata.Distribution, list[metadata.Distribution], dict[str, list[str]]]


def normalize(name: str) -> str:
    """PEP 503 name, which is also the purl name for PyPI."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(dist: metadata.Distribution) -> list[tuple[str, str]]:
    """``(name, marker)`` for each requirement that is not part of an extra."""
    out = []
    for req in dist.requires or []:
        spec, _, marker = req.partition(";")
        m = _REQ_NAME.match(spec)
        if m and "extra" not in marker:
            out.append((normalize(m.group(1)), marker.strip()))
    return out


def closure(root: str = ROOT) -> Closure:
    """The root distribution, its runtime dependencies, and the edges between them."""
    installed: dict[str, metadata.Distribution] = {}
    for dist in metadata.distributions():
        # First on sys.path wins, as it does for `import` and for
        # `metadata.distribution()`: a stale dist-info further down must not
        # replace the one that actually loads.
        installed.setdefault(normalize(dist.metadata["Name"]), dist)
    key = normalize(root)
    if key not in installed:
        raise SystemExit(f"release_sbom: {root} is not installed in {sys.executable}")
    missing = [n for n, marker in _requirements(installed[key]) if not marker and n not in installed]
    if missing:
        raise SystemExit(f"release_sbom: {root} requires {missing}, not installed: not its environment")
    graph: dict[str, list[str]] = {}
    queue = [key]
    while queue:
        current = queue.pop(0)
        graph[current] = [n for n, _ in _requirements(installed[current]) if n in installed]
        queue.extend(n for n in graph[current] if n not in graph and n not in queue)
    deps = sorted((installed[n] for n in graph if n != key), key=lambda d: normalize(d.metadata["Name"]))
    return installed[key], deps, graph


def purl(dist: metadata.Distribution) -> str:
    return f"pkg:pypi/{normalize(dist.metadata['Name'])}@{dist.version}"


def _license(dist: metadata.Distribution) -> str | None:
    """The SPDX expression the package declares (PEP 639), if it declares one."""
    expr = dist.metadata.get("License-Expression")
    return expr.strip() if expr else None


def _python() -> str:
    return f"{platform.python_implementation()} {platform.python_version()}"


def cyclonedx(root: metadata.Distribution, deps: list[metadata.Distribution],
              graph: dict[str, list[str]]) -> dict:
    by_name = {normalize(d.metadata["Name"]): d for d in [root, *deps]}

    def component(dist: metadata.Distribution, kind: str) -> dict:
        c: dict[str, object] = {"type": kind, "bom-ref": purl(dist), "name": dist.metadata["Name"],
                                "version": dist.version, "purl": purl(dist)}
        expression = _license(dist)
        if expression:
            c["licenses"] = [{"expression": expression}]
        return c

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "scripts/release_sbom.py"}]},
            "component": component(root, "application"),
            "properties": [{"name": "agent-audit-kit:sbom:environment", "value": _python()}],
        },
        "components": [component(d, "library") for d in deps],
        "dependencies": [
            {"ref": purl(by_name[n]), "dependsOn": [purl(by_name[m]) for m in graph[n]]}
            for n in graph
        ],
    }


def spdx(root: metadata.Distribution, deps: list[metadata.Distribution],
         graph: dict[str, list[str]]) -> dict:
    def spdx_id(name: str) -> str:
        return f"SPDXRef-Package-{name}"

    def package(dist: metadata.Distribution) -> dict:
        return {
            "SPDXID": spdx_id(normalize(dist.metadata["Name"])),
            "name": dist.metadata["Name"],
            "versionInfo": dist.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": _license(dist) or "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                              "referenceType": "purl", "referenceLocator": purl(dist)}],
        }

    root_id = spdx_id(normalize(root.metadata["Name"]))
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{root.metadata['Name']}-{root.version}",
        "documentNamespace": f"https://github.com/sattyamjjain/agent-audit-kit/sbom/{root.version}/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: agent-audit-kit-release-sbom"],
            "comment": f"Runtime dependency closure installed on {_python()}.",
        },
        "packages": [package(d) for d in [root, *deps]],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id},
            *({"spdxElementId": spdx_id(n), "relationshipType": "DEPENDS_ON", "relatedSpdxElement": spdx_id(m)}
              for n in graph for m in graph[n]),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--cyclonedx", type=Path, required=True, help="CycloneDX 1.5 JSON output")
    parser.add_argument("--spdx", type=Path, required=True, help="SPDX 2.3 JSON output")
    parser.add_argument("--root", default=ROOT, help=f"distribution to describe (default: {ROOT})")
    args = parser.parse_args(argv)
    found = closure(args.root)
    args.cyclonedx.write_text(json.dumps(cyclonedx(*found), indent=2) + "\n", encoding="utf-8")
    args.spdx.write_text(json.dumps(spdx(*found), indent=2) + "\n", encoding="utf-8")
    root, deps, _ = found
    listed = ", ".join(f"{d.metadata['Name']} {d.version}" for d in deps)
    sys.stderr.write(f"release_sbom: {root.metadata['Name']} {root.version} + {len(deps)} ({listed}) on {_python()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
