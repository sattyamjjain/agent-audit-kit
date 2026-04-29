"""v0.3.10 SAST tests — CrewAI 4-CVE chain, LangChain prompt-loader,
OpenClaw privesc."""
from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.crewai_rce_chain import scan as crewai_scan
from agent_audit_kit.scanners.langchain_prompt_loader import scan as langchain_scan
from agent_audit_kit.scanners.openclaw_privesc import scan as openclaw_scan

FIXTURES = Path(__file__).parent / "fixtures"


# -------------------- AAK-CREWAI-CHAIN-2026-04-001 (meta + 4 children) --------------------

def test_crewai_full_chain_fires_meta_plus_4(tmp_path: Path) -> None:
    src = (FIXTURES / "crewai" / "vulnerable" / "full_chain.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = crewai_scan(tmp_path)
    rids = sorted({f.rule_id for f in findings})
    assert "AAK-CREWAI-CHAIN-2026-04-001" in rids
    assert "AAK-CREWAI-CVE-2026-2275-001" in rids
    assert "AAK-CREWAI-CVE-2026-2285-001" in rids
    assert "AAK-CREWAI-CVE-2026-2286-001" in rids
    assert "AAK-CREWAI-CVE-2026-2287-001" in rids


def test_crewai_safe_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "crewai" / "safe" / "full_chain.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = crewai_scan(tmp_path)
    assert findings == []


def test_crewai_no_import_passes(tmp_path: Path) -> None:
    """File must import crewai for the scope gate to engage."""
    (tmp_path / "x.py").write_text(
        "def f(): return CodeInterpreterTool(unsafe_mode=True)\n",
        encoding="utf-8",
    )
    findings, _ = crewai_scan(tmp_path)
    assert findings == []


def test_crewai_meta_only_fires_when_all_4_present(tmp_path: Path) -> None:
    """Only one CVE shape → meta-rule does not fire."""
    (tmp_path / "agent.py").write_text(
        "from crewai_tools import CodeInterpreterTool\n"
        "def f():\n"
        "    return CodeInterpreterTool(unsafe_mode=True, docker_required=True)\n",
        encoding="utf-8",
    )
    findings, _ = crewai_scan(tmp_path)
    rids = {f.rule_id for f in findings}
    assert "AAK-CREWAI-CVE-2026-2275-001" in rids
    assert "AAK-CREWAI-CHAIN-2026-04-001" not in rids


# -------------------- AAK-LANGCHAIN-PROMPT-LOADER-PATH-001 --------------------

def test_langchain_prompt_loader_user_path_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "langchain_prompt_loader" / "user_path_unsafe.py").read_text()
    (tmp_path / "x.py").write_text(src, encoding="utf-8")
    findings, _ = langchain_scan(tmp_path)
    assert any(
        f.rule_id == "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001" for f in findings
    )


def test_langchain_prompt_loader_constant_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "langchain_prompt_loader" / "constant_safe.py").read_text()
    (tmp_path / "x.py").write_text(src, encoding="utf-8")
    findings, _ = langchain_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001" for f in findings
    )


def test_langchain_prompt_loader_validated_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "langchain_prompt_loader" / "validated_safe.py").read_text()
    (tmp_path / "x.py").write_text(src, encoding="utf-8")
    findings, _ = langchain_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001" for f in findings
    )


# -------------------- AAK-OPENCLAW-PRIVESC-001 --------------------

def test_openclaw_unsafe_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "openclaw" / "role_default_admin_unsafe.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = openclaw_scan(tmp_path)
    fired = [f for f in findings if f.rule_id == "AAK-OPENCLAW-PRIVESC-001"]
    # Three unsafe constructions in the fixture (missing role, role=None, role=user_role)
    assert len(fired) == 3


def test_openclaw_safe_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "openclaw" / "role_explicit_safe.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = openclaw_scan(tmp_path)
    assert not any(f.rule_id == "AAK-OPENCLAW-PRIVESC-001" for f in findings)


def test_openclaw_no_import_passes(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text(
        "class OpenClawAgent: pass\n"
        "OpenClawAgent()\n",
        encoding="utf-8",
    )
    findings, _ = openclaw_scan(tmp_path)
    assert findings == []
