"""Every finding a scanner emits carries its registered rule's metadata.

`scanners/_helpers.make_finding(rule_id, ...)` builds a `Finding` from the rule
registry, so a scanner only says where a rule fired and why (`evidence`). Eight
scanners used to build `Finding(...)` by hand with their own titles,
descriptions and remediation, and every one of those copies had drifted from
`rules/builtin.py`:

- SARIF printed the registry title in the rule descriptor and the scanner's own
  title on each result, and the result fingerprint hashes that title.
- `docsgpt_transport_flip` and `gpt_researcher_transport_flip` still told users
  to set `deny_stdio_transport: true` after #597 rewrote the registry
  remediation to say that key is an AAK convention the MCP client ignores.
  `tests/test_transport_flip_remediation.py` checked the registry text and
  passed throughout, because nothing checked what the scanners emitted.

Two guards, because each alone leaves a gap: the static one cannot see a field
rewritten at runtime, and the runtime one only sees scanners whose fixtures
fire.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Finding, Severity
from agent_audit_kit.rules.builtin import RULES

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNERS = REPO_ROOT / "agent_audit_kit" / "scanners"
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# Fields a scanner takes from the registry and never sets itself.
REGISTRY_FIELDS = (
    "title",
    "description",
    "severity",
    "category",
    "remediation",
    "cve_references",
    "owasp_mcp_references",
    "owasp_agentic_references",
    "adversa_references",
    "incident_references",
    "aicm_references",
    "owasp_ast_references",
)

# A field that must differ from the registry goes through `dataclasses.replace`
# on a `make_finding` result, and only severity has a reason to so far.
SEVERITY_OVERRIDE_MODULES = {
    "ide_task_rce.py": (
        "AAK-IDE-TASK-001 escalates HIGH -> CRITICAL when the auto-run command "
        "is a shell, interpreter or network fetch"
    ),
}
SEVERITY_OVERRIDE_RULES = {"AAK-IDE-TASK-001": {Severity.CRITICAL}}

# The fixtures root fires most scanners. These three only read configs at the
# project root, so they get their own fixture directories as roots.
SCAN_ROOTS = (
    FIXTURES,
    FIXTURES / "cves" / "cve-2026-26015-docsgpt" / "config-unsafe",
    FIXTURES / "cves" / "cve-2025-65720-gpt-researcher" / "config-unsafe",
    FIXTURES / "openapi_smells",
)

# The rules whose scanners built findings by hand until this guard existed.
# Each must fire under SCAN_ROOTS, or the runtime check passes vacuously.
FORMERLY_HAND_BUILT = {
    "AAK-AGENT-HARNESS-SHARED-STATE-001",
    "AAK-DOCSGPT-MCP-STDIO-MITM-001",
    "AAK-GPTRESEARCHER-MCP-STDIO-MITM-001",
    "AAK-IDE-TASK-001",
    "AAK-MCP-LINEAGE-STAINLESS-001",
    "AAK-MCP-OPENAPI-BLOATED-PARAMS-001",
    "AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001",
    "AAK-MCP-OPENAPI-TANGLED-METHODS-001",
    "AAK-MCP-TOOL-UNSAFE-EVAL-001",
    "AAK-METIS-REFUSAL-REFEED-001",
    "AAK-METIS-SCORING-SINK-001",
    "AAK-SKILL-LIFECYCLE-ATTRIBUTION-001",
}


def _scanner_modules() -> list[Path]:
    return sorted(p for p in SCANNERS.glob("*.py") if p.name != "_helpers.py")


def _is_finding_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "Finding"
    return isinstance(func, ast.Attribute) and func.attr == "Finding"


def _is_dataclasses_replace(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "replace"
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "replace"
        and isinstance(func.value, ast.Name)
        and func.value.id == "dataclasses"
    )


def test_no_scanner_builds_a_finding_by_hand() -> None:
    offenders = [
        f"{path.name}:{node.lineno}"
        for path in _scanner_modules()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call) and _is_finding_call(node)
    ]
    assert not offenders, (
        "build findings with `_helpers.make_finding(rule_id, file_path, evidence, "
        "line_number)`; a hand-built Finding copies registry metadata and drifts "
        f"from it: {offenders}"
    )


def test_registry_fields_are_overridden_only_where_listed() -> None:
    problems: list[str] = []
    for path in _scanner_modules():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and _is_dataclasses_replace(node):
                fields = {k.arg for k in node.keywords if k.arg} & set(REGISTRY_FIELDS)
                if fields and (fields != {"severity"} or path.name not in SEVERITY_OVERRIDE_MODULES):
                    problems.append(f"{path.name}:{node.lineno} replaces {sorted(fields)}")
            elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and target.attr in REGISTRY_FIELDS:
                        problems.append(f"{path.name}:{node.lineno} assigns .{target.attr}")
    assert not problems, (
        "a scanner may override only severity, via dataclasses.replace, and only "
        f"with a reason in SEVERITY_OVERRIDE_MODULES: {problems}"
    )


@pytest.fixture(scope="module")
def emitted() -> list[Finding]:
    findings: list[Finding] = []
    for root in SCAN_ROOTS:
        findings.extend(run_scan(project_root=root).findings)
    return findings


def _comparable(value: object) -> object:
    return list(value) if isinstance(value, (list, tuple)) else value


def test_no_scanner_crashed_under_the_scan_roots(emitted: list[Finding]) -> None:
    crashed = [f.evidence for f in emitted if f.rule_id == "AAK-INTERNAL-SCANNER-FAIL"]
    assert not crashed, f"a scanner crashed, so the metadata check below is incomplete: {crashed}"


def test_every_emitted_finding_carries_its_registry_metadata(emitted: list[Finding]) -> None:
    drift: set[str] = set()
    for finding in emitted:
        rule = RULES[finding.rule_id]
        for field in REGISTRY_FIELDS:
            got = getattr(finding, field)
            if field == "severity" and got in SEVERITY_OVERRIDE_RULES.get(finding.rule_id, set()):
                continue
            if _comparable(got) != _comparable(getattr(rule, field)):
                drift.add(f"{finding.rule_id}.{field}")
    assert not drift, f"emitted findings disagree with rules/builtin.py: {sorted(drift)}"


def test_the_formerly_hand_built_rules_all_fire_under_the_scan_roots(emitted: list[Finding]) -> None:
    """Guard the guard: a rule that never fires here is never checked above."""
    missing = FORMERLY_HAND_BUILT - {f.rule_id for f in emitted}
    assert not missing, f"no fixture under SCAN_ROOTS fires {sorted(missing)}"
