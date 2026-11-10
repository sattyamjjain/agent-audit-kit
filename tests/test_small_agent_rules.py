"""AAK-PROMPT-DELIMITER-001, AAK-LLM-NO-MAX-TOKENS-001 and AAK-TOOL-NEAR-DUPLICATE-001."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import llm_call_shapes, mcp_tool_names

DELIMITER = llm_call_shapes.RULE_DELIMITER
MAX_TOKENS = llm_call_shapes.RULE_MAX_TOKENS
NEAR = mcp_tool_names.RULE


@pytest.mark.parametrize("rule, severity, category", [
    (DELIMITER, Severity.LOW, Category.TAINT_ANALYSIS),
    (MAX_TOKENS, Severity.LOW, Category.TRUST_BOUNDARY),
    (NEAR, Severity.MEDIUM, Category.TOOL_POISONING),
])
def test_rules_are_registered(rule: str, severity: Severity, category: Category) -> None:
    assert RULES[rule].severity is severity
    assert RULES[rule].category is category
    assert RULES[rule].limitations


@pytest.mark.parametrize("rule, rel, text", [
    (DELIMITER, "p.py", 'import openai\n\n\ndef f(m):\n    return f"<q>{m}</q>", openai\n'),
    (NEAR, ".mcp.json", json.dumps({"mcpServers": {
        "a": {"command": "a", "tools": [{"name": "flight_search"}]},
        "b": {"command": "b", "tools": [{"name": "flight_search_pro"}]},
    }})),
])
def test_the_engine_runs_them(tmp_path: Path, rule: str, rel: str, text: str) -> None:
    (tmp_path / rel).write_text(text)
    result = run_scan(project_root=tmp_path, rules=[rule], strict_loading=True)
    assert [f.rule_id for f in result.findings] == [rule]


# -- AAK-PROMPT-DELIMITER-001 ------------------------------------------------------------------


def _prompt(tmp_path: Path, body: str, name: str = "prompts.py") -> list[Any]:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"import openai\n\n_ = openai\n\n\n{body}\n")
    return [f for f in llm_call_shapes.scan(tmp_path)[0] if f.rule_id == DELIMITER]


@pytest.mark.parametrize("template", [
    "<user_input>{m}</user_input>",
    "<user_input>\\n{m}\\n</user_input>",
    "<document name='x'>{m}</document>",
    "```{m}```",
    "---\\n{m}\\n---",
    "###{m}###",
    "<<<{m}>>>",
    '"""{m}"""',
])
def test_a_parameter_between_delimiters_fires(tmp_path: Path, template: str) -> None:
    quote = "'''" if '"""' in template else '"""'
    found = _prompt(tmp_path, f"def f(m):\n    return f{quote}{template}{quote}")
    assert len(found) == 1 and "`m`" in found[0].evidence and found[0].line_number == 7


@pytest.mark.parametrize("value", ["m.body", 'm["body"]'])
def test_a_field_of_a_parameter_fires(tmp_path: Path, value: str) -> None:
    quote = "'" if '"' in value else '"'
    assert len(_prompt(tmp_path, f"def f(m):\n    return f{quote}<q>{{{value}}}</q>{quote}")) == 1


@pytest.mark.parametrize("body", [
    'def f(m):\n    return f"<q>{m.replace(chr(60), str())}</q>"',
    'def f(m):\n    return f"<q>{escape(m)}</q>"',
    'def f(m):\n    m = m.replace("</q>", "")\n    return f"<q>{m}</q>"',
    'def f(m):\n    return f"<div>{m}</div>"',
    'def f(m):\n    return f"<q>{m}</other>"',
    'def f(m):\n    return f"<q>{m} and more</q>"',
    'def f(m):\n    return f"plain {m} text"',
    'def f():\n    m = "x"\n    return f"<q>{m}</q>"',
    'def f(m):\n    return f"--- {m} ###"',
])
def test_other_shapes_stay_quiet(tmp_path: Path, body: str) -> None:
    assert _prompt(tmp_path, body) == []


def test_a_file_with_no_model_api_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text('def f(m):\n    return f"<q>{m}</q>"\n')
    assert llm_call_shapes.scan(tmp_path)[0] == []


@pytest.mark.parametrize("name", ["tests/p.py", "examples/p.py", "test_p.py", "conftest.py"])
def test_test_paths_are_skipped(tmp_path: Path, name: str) -> None:
    assert _prompt(tmp_path, 'def f(m):\n    return f"<q>{m}</q>"', name) == []


# -- AAK-LLM-NO-MAX-TOKENS-001 -----------------------------------------------------------------


def _handler(tmp_path: Path, decorator: str, call: str) -> list[Any]:
    (tmp_path / "app.py").write_text(f"import openai\n\n_ = openai\n\n\n{decorator}\ndef f(m):\n    return {call}\n")
    return [f for f in llm_call_shapes.scan(tmp_path)[0] if f.rule_id == MAX_TOKENS]


@pytest.mark.parametrize("decorator", ['@app.post("/x")', '@router.get("/x")', '@app.route("/x")', "@tool", "@mcp.tool()", "@function_tool"])
def test_a_handler_with_no_cap_fires(tmp_path: Path, decorator: str) -> None:
    found = _handler(tmp_path, decorator, "client.chat.completions.create(model='m', messages=[])")
    assert len(found) == 1 and found[0].line_number == 8


@pytest.mark.parametrize("call", ["litellm.completion(model='m')", "openai.ChatCompletion.create(model='m')", "self.client.chat.completions.create(model='m')"])
def test_the_calls_it_reads(tmp_path: Path, call: str) -> None:
    assert len(_handler(tmp_path, '@app.post("/x")', call)) == 1


@pytest.mark.parametrize("call", [
    "client.chat.completions.create(model='m', max_tokens=5)",
    "client.chat.completions.create(model='m', max_completion_tokens=5)",
    "client.chat.completions.create(**options)",
    "client.embeddings.create(model='m')",
])
def test_a_cap_or_another_call_stays_quiet(tmp_path: Path, call: str) -> None:
    assert _handler(tmp_path, '@app.post("/x")', call) == []


@pytest.mark.parametrize("decorator", ["@staticmethod", "@cached", "@pytest.fixture"])
def test_a_function_that_answers_no_request_stays_quiet(tmp_path: Path, decorator: str) -> None:
    assert _handler(tmp_path, decorator, "client.chat.completions.create(model='m')") == []


# -- AAK-TOOL-NEAR-DUPLICATE-001 ---------------------------------------------------------------


def _names(tmp_path: Path, **servers: list[str]) -> list[Any]:
    config = {"mcpServers": {s: {"command": s, "tools": [{"name": n} for n in names]} for s, names in servers.items()}}
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    return [f for f in mcp_tool_names.scan(tmp_path)[0] if f.rule_id == NEAR]


@pytest.mark.parametrize("first, second", [
    ("flight_search", "flight_search_pro"),
    ("flight_search", "official_flight_search"),
    ("flight_search", "flight-search-v2"),
    ("read_file", "readFile"),
    ("read_file", "ReadFile"),
    ("get_customer", "get_custmer"),
    ("get_customer", "get_customers2x"),
])
def test_near_names_on_two_servers_fire(tmp_path: Path, first: str, second: str) -> None:
    found = _names(tmp_path, a=[first], b=[second])
    if second == "get_customers2x":
        assert found == []  # three characters apart
        return
    assert len(found) == 1 and first in found[0].evidence and second in found[0].evidence


@pytest.mark.parametrize("servers", [
    {"a": ["flight_search"], "b": ["flight_search"]},
    {"a": ["flight_search", "flight_search_pro"]},
    {"a": ["get_customer"], "b": ["get_customers"]},
    {"a": ["get_weather"], "b": ["get_forecast"]},
    {"a": ["pro"], "b": ["plus"]},
    {"a": ["ls"], "b": ["ls2"]},
])
def test_other_pairs_stay_quiet(tmp_path: Path, servers: dict[str, list[str]]) -> None:
    assert _names(tmp_path, **servers) == []


def test_the_pin_file_is_read(tmp_path: Path) -> None:
    pins = tmp_path / ".agent-audit-kit" / "tool-pins.json"
    pins.parent.mkdir()
    pins.write_text(json.dumps({"a/flight_search": {"hash": "x"}, "b/flight_search_pro": {"hash": "y"}}))
    found = [f for f in mcp_tool_names.scan(tmp_path)[0] if f.rule_id == NEAR]
    assert [f.file_path for f in found] == [".agent-audit-kit/tool-pins.json"]


def test_a_name_over_the_edit_bound_is_not_compared(tmp_path: Path) -> None:
    long_name = "a" * 65
    assert _names(tmp_path, a=[long_name], b=[long_name + "b"]) == []
    at_bound = "a" * 63
    assert len(_names(tmp_path, a=[at_bound + "b"], b=[at_bound + "c"])) == 1


def test_a_project_reports_at_most_two_hundred_pairs(tmp_path: Path) -> None:
    first = [f"flight_{i}_search" for i in range(300)]
    second = [f"flight_{i}_search_pro" for i in range(300)]
    assert len(_names(tmp_path, a=first, b=second)) == 200


def test_malformed_configs_do_not_crash_it(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"a": {"tools": "x"}, "b": {"tools": [1, {"name": 2}, {}]}, "c": 3}}))
    assert mcp_tool_names.scan(tmp_path)[0] == []
