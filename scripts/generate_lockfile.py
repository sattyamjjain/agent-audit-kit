#!/usr/bin/env python3
"""Generate requirements-lock.txt with verified SHA256 hashes from PyPI.

This script fetches the real hashes from PyPI's JSON API and writes a
pip-installable lockfile with --hash constraints for click and pyyaml.

Usage:
    python scripts/generate_lockfile.py
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

PACKAGES: list[tuple[str, str]] = [
    ("click", "8.1.7"),
    ("PyYAML", "6.0.2"),
]

HEADER = """\
# Locked dependencies with hashes for supply chain security.
# Generated for AgentAuditKit v0.2.0.
# Install with: pip install --require-hashes -r requirements-lock.txt
#
# To regenerate: python scripts/generate_lockfile.py
"""


def fetch_hashes(package: str, version: str) -> list[str]:
    """Fetch SHA256 hashes for all distributions of a package version from PyPI.

    Args:
        package: The PyPI package name.
        version: The exact version string.

    Returns:
        Sorted list of sha256 hex digest strings.
    """
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    hashes: list[str] = []
    for url_info in data.get("urls", []):
        sha = url_info.get("digests", {}).get("sha256")
        if sha:
            hashes.append(sha)
    return sorted(set(hashes))


def main() -> None:
    """Generate the lockfile."""
    project_root = Path(__file__).resolve().parent.parent
    output = project_root / "requirements-lock.txt"

    lines: list[str] = [HEADER]

    for package, version in PACKAGES:
        # Use lowercase normalized name for pip compatibility
        pip_name = package.lower().replace("-", "_")
        if pip_name == "pyyaml":
            pip_name = "pyyaml"

        print(f"Fetching hashes for {package}=={version}...")
        hashes = fetch_hashes(package, version)
        print(f"  Found {len(hashes)} distribution hashes.")

        entry = f"{pip_name}=={version}"
        hash_lines = [f"    --hash=sha256:{h}" for h in hashes]
        lines.append(entry + " \\\n" + " \\\n".join(hash_lines))

    content = "\n".join(lines) + "\n"
    output.write_text(content, encoding="utf-8")
    print(f"\nWrote {output}")


if __name__ == "__main__":
    main()
