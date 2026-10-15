"""AAK-MCP-APPS-001/002 — SEP-1865 MCP Apps UI iframe sandbox + sanitization."""

from __future__ import annotations

import json
import time
from pathlib import Path

from agent_audit_kit.models import ScanResult
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_apps_ui import scan


def _ids(tmp: Path, name: str, src: str) -> set[str]:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return {f.rule_id for f in scan(tmp)[0]}


def test_rules_registered() -> None:
    for rid in ("AAK-MCP-APPS-001", "AAK-MCP-APPS-002"):
        assert rid in RULES
        assert RULES[rid].severity.value == "high"
        assert RULES[rid].category.value == "tool-poisoning"


def test_unsandboxed_iframe_fires_001(tmp_path: Path) -> None:
    src = "// @mcp-ui/client renders ui:// resource\nexport const App = () => <iframe src={resource.uri}></iframe>;\n"
    assert "AAK-MCP-APPS-001" in _ids(tmp_path, "App.tsx", src)


def test_sandbox_with_scripts_and_same_origin_fires_001(tmp_path: Path) -> None:
    src = '<!-- ui:// mcp-ui -->\n<iframe sandbox="allow-scripts allow-same-origin" src="ui://widget"></iframe>\n'
    assert "AAK-MCP-APPS-001" in _ids(tmp_path, "widget.html", src)


def test_hardened_sandbox_clears_001(tmp_path: Path) -> None:
    src = '<!-- @mcp-ui/client ui:// -->\n<iframe sandbox="allow-forms allow-popups" src="ui://widget"></iframe>\n'
    assert "AAK-MCP-APPS-001" not in _ids(tmp_path, "widget.html", src)


def test_innerhtml_without_sanitizer_fires_002(tmp_path: Path) -> None:
    src = "// createUIResource ui://\nel.innerHTML = resource.text;\n"
    assert "AAK-MCP-APPS-002" in _ids(tmp_path, "render.ts", src)


def test_dompurify_clears_002(tmp_path: Path) -> None:
    src = (
        "// @mcp-ui/client ui://\n"
        "import DOMPurify from 'dompurify';\n"
        "el.innerHTML = DOMPurify.sanitize(resource.text);\n"
    )
    assert "AAK-MCP-APPS-002" not in _ids(tmp_path, "render.ts", src)


def test_non_mcp_app_ignored(tmp_path: Path) -> None:
    """A plain React app iframe with no MCP-Apps context must not fire."""
    src = "export const Ad = () => <iframe src='https://ads.example'></iframe>;\nel.innerHTML = x;\n"
    assert not _ids(tmp_path, "Ad.tsx", src)


def test_sarif_shape_unchanged(tmp_path: Path) -> None:
    """New rules serialize like existing ones: fingerprint + security-severity +
    properties.remediation, and NO invalid SARIF `fixes`."""
    _ids(tmp_path, "a.tsx", "// @mcp-ui/client ui://\n<iframe src={u}></iframe>\nel.innerHTML = x;")
    findings, _ = scan(tmp_path)
    res = ScanResult()
    res.findings.extend(findings)
    sarif = json.loads(format_results(res))
    run = sarif["runs"][0]
    result = next(r for r in run["results"] if r["ruleId"] == "AAK-MCP-APPS-001")
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "AAK-MCP-APPS-001")
    assert "partialFingerprints" in result
    assert "fixes" not in result
    assert result["properties"]["remediation"]
    assert float(rule["properties"]["security-severity"]) >= 7.0


def test_unclosed_iframe_tags_scan_in_linear_time(tmp_path: Path) -> None:
    """About 1 MB of `<iframe` and no `>`, under the scanner's cap. Each tag
    read the rest of the file: 1 MB took 45 seconds. The bound is loose for
    slow CI runners."""
    src = "// @mcp-ui/client ui://\n" + "<iframe" * 140_000
    started = time.perf_counter()
    ids = _ids(tmp_path, "App.tsx", src)
    assert time.perf_counter() - started < 5.0
    assert "AAK-MCP-APPS-001" not in ids
