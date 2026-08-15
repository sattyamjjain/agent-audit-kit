"""The scanner count must be derivable, not asserted.

`rules.json` can be counted by anyone in one command; before this the scanner
count could not. These tests tie four surfaces to one machine-readable manifest
(`scanners.json`, generated from the engine registry) so the scanner count is a
number a stranger can reproduce with `agent-audit-kit scanners --json`, not a
claim — the count itself is never spelled out here, so this docstring cannot go
stale when a scanner is added. They also guard against the exact bug the manifest
surfaced: the old directory-listing count included two back-compat shims
(`typescript_scan`, `rust_scan`) that only re-export a registered pattern scanner,
inflating the true module count by two.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit import SCANNER_COUNT
from agent_audit_kit.cli import cli
from agent_audit_kit.engine import scanner_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNERS_JSON = REPO_ROOT / "scanners.json"


def _manifest_count() -> int:
    return len(scanner_manifest())


def test_scanner_count_matches_registry() -> None:
    assert SCANNER_COUNT == _manifest_count(), (
        "SCANNER_COUNT drifted from the engine registry — run "
        "`python scripts/sync_scanner_count.py`."
    )


def test_scanners_json_is_committed_and_current() -> None:
    assert SCANNERS_JSON.exists(), "scanners.json is missing — run sync_scanner_count.py"
    data = json.loads(SCANNERS_JSON.read_text(encoding="utf-8"))
    assert data["count"] == len(data["scanners"]) == SCANNER_COUNT
    # The committed file must equal a fresh render (byte-deterministic).
    expected = json.dumps(
        {"count": _manifest_count(), "scanners": scanner_manifest()},
        indent=2,
        sort_keys=True,
    ) + "\n"
    assert SCANNERS_JSON.read_text(encoding="utf-8") == expected, (
        "scanners.json is stale — run `python scripts/sync_scanner_count.py`"
    )


def test_readme_scanner_marker_matches_count() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    markers = re.findall(
        r"<!--\s*scanner-count:total\s*-->(\d+)<!--\s*/scanner-count\s*-->", readme
    )
    assert markers, "README lost its scanner-count marker"
    assert all(int(m) == SCANNER_COUNT for m in markers), "README scanner marker drift"


def test_back_compat_shims_are_not_counted() -> None:
    modules = {s["module"] for s in scanner_manifest()}
    assert "typescript_scan" not in modules, "back-compat shim miscounted as a scanner"
    assert "rust_scan" not in modules, "back-compat shim miscounted as a scanner"
    # The real pattern scanners they re-export ARE counted.
    assert "typescript_pattern_scan" in modules
    assert "rust_pattern_scan" in modules


def test_scanners_cli_reproduces_the_count() -> None:
    res = CliRunner().invoke(cli, ["scanners", "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["count"] == SCANNER_COUNT
    assert len(data["scanners"]) == SCANNER_COUNT
