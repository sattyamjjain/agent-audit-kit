"""NVD-classification + evasion-gap coverage for the CrewAI chain rules.

Two follow-ups to the v0.3.10 CrewAI chain (CVE-2026-2275/2285/2286/2287,
CERT/CC VU#221883):

1. NVD severity reconciliation — CVE-2026-2286 (SSRF, CWE-918) and
   CVE-2026-2287 (Docker-liveness, CWE-94) are both rated CVSS 9.8 CRITICAL
   by NVD; the rules now carry Severity.CRITICAL (previously HIGH).
2. Evasion-gap closures in `crewai_rce_chain.py` — positional tool args and
   aliased tool imports are now detected, with the clean fixture still passing
   (no new false positives).
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.crewai_rce_chain import scan


def _write(tmp_path: Path, src: str, name: str = "agent.py") -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _rids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# 1. NVD severity reconciliation
# ---------------------------------------------------------------------------


def test_ssrf_and_docker_liveness_are_critical_per_nvd() -> None:
    """NVD rates CVE-2026-2286 and CVE-2026-2287 at CVSS 9.8 (CRITICAL)."""
    assert RULES["AAK-CREWAI-CVE-2026-2286-001"].severity is Severity.CRITICAL
    assert RULES["AAK-CREWAI-CVE-2026-2287-001"].severity is Severity.CRITICAL
    # Unchanged anchors: 2275 already CRITICAL (9.6), 2285 HIGH (7.5).
    assert RULES["AAK-CREWAI-CVE-2026-2275-001"].severity is Severity.CRITICAL
    assert RULES["AAK-CREWAI-CVE-2026-2285-001"].severity is Severity.HIGH


# ---------------------------------------------------------------------------
# 2a. Evasion gap — positional tool arguments
# ---------------------------------------------------------------------------


def test_positional_rag_url_is_flagged(tmp_path: Path) -> None:
    """`RagTool(user_url)` (positional, not url=) must fire CVE-2026-2286."""
    _write(tmp_path, (
        "from crewai_tools import RagTool\n"
        "def handler(user_input):\n"
        "    return RagTool(user_input['docs_url'])\n"
    ))
    findings, _ = scan(tmp_path)
    assert "AAK-CREWAI-CVE-2026-2286-001" in _rids(findings)


def test_positional_json_path_is_flagged(tmp_path: Path) -> None:
    """`JSONSearchTool(user_path)` positional must fire CVE-2026-2285."""
    _write(tmp_path, (
        "from crewai_tools import JSONSearchTool\n"
        "def handler(user_input):\n"
        "    return JSONSearchTool(user_input['template_path'])\n"
    ))
    findings, _ = scan(tmp_path)
    assert "AAK-CREWAI-CVE-2026-2285-001" in _rids(findings)


# ---------------------------------------------------------------------------
# 2b. Evasion gap — aliased tool imports
# ---------------------------------------------------------------------------


def test_aliased_code_interpreter_is_flagged(tmp_path: Path) -> None:
    """`from crewai_tools import CodeInterpreterTool as CIT; CIT(unsafe_mode=True)`
    must still fire CVE-2026-2275 via alias resolution."""
    _write(tmp_path, (
        "from crewai_tools import CodeInterpreterTool as CIT\n"
        "def build():\n"
        "    return CIT(unsafe_mode=True)\n"
    ))
    findings, _ = scan(tmp_path)
    assert "AAK-CREWAI-CVE-2026-2275-001" in _rids(findings)


def test_plain_import_crewai_tools_gate(tmp_path: Path) -> None:
    """`import crewai_tools` (plain form) must pass the import gate so the
    scanner runs at all."""
    _write(tmp_path, (
        "import crewai_tools\n"
        "def build():\n"
        "    return crewai_tools.CodeInterpreterTool(unsafe_mode=True)\n"
    ))
    findings, _ = scan(tmp_path)
    assert "AAK-CREWAI-CVE-2026-2275-001" in _rids(findings)


# ---------------------------------------------------------------------------
# False-positive guards — the new positional/alias paths must not over-fire
# ---------------------------------------------------------------------------


def test_positional_static_literal_url_passes(tmp_path: Path) -> None:
    """A positional but *constant* URL is not attacker-controlled — no SSRF."""
    _write(tmp_path, (
        "from crewai_tools import RagTool\n"
        "def build():\n"
        "    return RagTool('https://docs.example.com')\n"
    ))
    findings, _ = scan(tmp_path)
    assert "AAK-CREWAI-CVE-2026-2286-001" not in _rids(findings)


def test_no_crewai_import_still_passes(tmp_path: Path) -> None:
    """A file using the same names but with no crewai import is out of scope."""
    _write(tmp_path, (
        "def build(user_url):\n"
        "    return RagTool(user_url)\n"
    ))
    findings, _ = scan(tmp_path)
    assert "AAK-CREWAI-CVE-2026-2286-001" not in _rids(findings)
