"""Smoke tests for the v0.3.9 rules (4 SAST scanners + autofix codemod)."""
from __future__ import annotations

from pathlib import Path

from agent_audit_kit.autofix.langgraph_toolnode import fix as autofix_toolnode
from agent_audit_kit.scanners.deepseek_v4_tool_injection import scan as deepseek_scan
from agent_audit_kit.scanners.langgraph_toolnode import scan as langgraph_scan
from agent_audit_kit.scanners.project_deal_drift import scan as deal_scan
from agent_audit_kit.scanners.social_agent_hijack import scan as social_scan

FIXTURES = Path(__file__).parent / "fixtures"


# -------------------- AAK-PROJECT-DEAL-DRIFT-001 --------------------

def test_project_deal_drift_vulnerable_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "project_deal" / "vulnerable" / "pricer.py").read_text()
    (tmp_path / "pricing").mkdir()
    (tmp_path / "pricing" / "pricer.py").write_text(src, encoding="utf-8")
    findings, _ = deal_scan(tmp_path)
    assert any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


def test_project_deal_drift_safe_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "project_deal" / "safe" / "pricer.py").read_text()
    (tmp_path / "pricing").mkdir()
    (tmp_path / "pricing" / "pricer.py").write_text(src, encoding="utf-8")
    findings, _ = deal_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


def test_project_deal_drift_non_commerce_passes(tmp_path: Path) -> None:
    """No commerce hint + non-commerce path → must not fire."""
    (tmp_path / "set_price.py").write_text(
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def set_price(item, model):\n"
        "    return client.messages.create(model=model, messages=[])\n",
        encoding="utf-8",
    )
    findings, _ = deal_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


def test_project_deal_drift_constant_model_passes(tmp_path: Path) -> None:
    """Hard-coded model literal is single-tier; no parity drift class."""
    (tmp_path / "pricing").mkdir()
    (tmp_path / "pricing" / "p.py").write_text(
        "import stripe\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def set_price(item):\n"
        "    return client.messages.create(model='claude-opus-4-7', messages=[])\n",
        encoding="utf-8",
    )
    findings, _ = deal_scan(tmp_path)
    assert not any(f.rule_id == "AAK-PROJECT-DEAL-DRIFT-001" for f in findings)


# -------------------- AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001 --------------------

def test_langgraph_toolnode_positional_list_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "langgraph" / "vulnerable" / "graph.py").read_text()
    (tmp_path / "graph.py").write_text(src, encoding="utf-8")
    findings, _ = langgraph_scan(tmp_path)
    assert sum(
        1 for f in findings
        if f.rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
    ) == 2


def test_langgraph_toolnode_kwargs_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "langgraph" / "safe" / "graph.py").read_text()
    (tmp_path / "graph.py").write_text(src, encoding="utf-8")
    findings, _ = langgraph_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
        for f in findings
    )


def test_langgraph_toolnode_unrelated_class_passes(tmp_path: Path) -> None:
    """ToolNode call without the langgraph.prebuilt import gate must not fire."""
    (tmp_path / "other.py").write_text(
        "class ToolNode:\n    pass\n"
        "node = ToolNode([1, 2, 3])\n",
        encoding="utf-8",
    )
    findings, _ = langgraph_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
        for f in findings
    )


def test_langgraph_toolnode_autofix_idempotent() -> None:
    src = "node = ToolNode([a, b])\n"
    once = autofix_toolnode(src)
    twice = autofix_toolnode(once)
    assert once == "node = ToolNode(tools=[a, b])\n"
    assert once == twice


# -------------------- AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001 --------------------

def test_deepseek_v4_tool_injection_vulnerable_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "deepseek" / "vulnerable" / "agent.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = deepseek_scan(tmp_path)
    assert any(f.rule_id == "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001" for f in findings)


def test_deepseek_v4_sanitizer_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "deepseek" / "safe" / "agent.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = deepseek_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001" for f in findings
    )


def test_deepseek_v4_no_deepseek_hint_passes(tmp_path: Path) -> None:
    """No deepseek base_url / import → scope gate excludes."""
    (tmp_path / "x.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI(base_url='https://api.openai.com/v1')\n"
        "def handle(request):\n"
        "    body = request.json()\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4', messages=[],\n"
        "        tools=[{'description': body['x']}])\n",
        encoding="utf-8",
    )
    findings, _ = deepseek_scan(tmp_path)
    assert not any(
        f.rule_id == "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001" for f in findings
    )


# -------------------- AAK-TIKTOK-AGENT-HIJACK-001 --------------------

def test_tiktok_agent_hijack_unsafe_fires(tmp_path: Path) -> None:
    src = (FIXTURES / "social_agents" / "tiktok_unsafe.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = social_scan(tmp_path)
    assert any(f.rule_id == "AAK-TIKTOK-AGENT-HIJACK-001" for f in findings)


def test_tiktok_agent_hijack_human_in_loop_passes(tmp_path: Path) -> None:
    src = (FIXTURES / "social_agents" / "tiktok_human_in_loop.py").read_text()
    (tmp_path / "agent.py").write_text(src, encoding="utf-8")
    findings, _ = social_scan(tmp_path)
    assert not any(f.rule_id == "AAK-TIKTOK-AGENT-HIJACK-001" for f in findings)


def test_tiktok_agent_hijack_no_user_input_passes(tmp_path: Path) -> None:
    """Reply call with hardcoded text (no taint source) → no finding."""
    (tmp_path / "agent.py").write_text(
        "import tiktok_api\n"
        "tiktok_api.reply('123', 'static reply')\n",
        encoding="utf-8",
    )
    findings, _ = social_scan(tmp_path)
    assert not any(f.rule_id == "AAK-TIKTOK-AGENT-HIJACK-001" for f in findings)
