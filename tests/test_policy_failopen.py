"""AAK-POLICY-VERDICT-FAILOPEN-001 and AAK-POLICY-IMPORT-FAILOPEN-001.

The verdict rule is a regression pattern from the Nobulex failopen corpus
(github.com/arian-gogani/failopen, MIT, Arian Gogani), case
`historical/autogen-verdict`, with credit agreed by its author. The fixtures are written
here, in the shapes of commits 0cd67042 (fires) and ec6cf48c (must not), and the first
tests run them, so the rule's verdict and the code's behaviour are checked side by side.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.policy_failopen import RULE_IMPORT, RULE_VERDICT, scan

FIXTURES = Path(__file__).parent / "fixtures" / "policy_failopen"
UNKNOWN = ["denied", "DENY", "block", "error", "", None]


def _load(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"failopen_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ids(root: Path) -> list[tuple[str, int | None]]:
    return [(f.rule_id, f.line_number) for f in scan(root)[0]]


def _file(tmp_path: Path, source: str, name: str = "gate.py") -> list[tuple[str, int | None]]:
    (tmp_path / name).write_text(source)
    return _ids(tmp_path)


def test_the_positive_fixture_executes_six_unknown_verdicts_and_blocks_deny() -> None:
    export = _load(FIXTURES / "verdict" / "positive.py").governed_export
    assert [export({"verdict": v}) for v in UNKNOWN] == ["EXECUTED"] * 6
    assert export({"verdict": "deny"}) == "blocked"


@pytest.mark.parametrize("name", ["negative_allowed_set.py", "negative_enum.py"])
def test_the_negative_fixtures_block_all_seven(name: str) -> None:
    export = _load(FIXTURES / "verdict" / name).governed_export
    assert [export({"verdict": v}) for v in [*UNKNOWN, "deny"]] == ["blocked"] * 7
    assert export({"verdict": "allow"}) == "EXECUTED"


def test_the_scanner_fires_on_the_positive_fixture_only(tmp_path: Path) -> None:
    rules = {path.name: [rule for rule, _ in _ids_of(path, tmp_path)] for path in (FIXTURES / "verdict").glob("*.py")}
    assert rules == {"positive.py": [RULE_VERDICT], "negative_allowed_set.py": [], "negative_enum.py": []}


def _ids_of(path: Path, tmp_path: Path) -> list[tuple[str, int | None]]:
    root = tmp_path / path.stem
    root.mkdir()
    (root / path.name).write_text(path.read_text())
    return _ids(root)


@pytest.mark.parametrize("check", [
    'verdict == "deny"', '"deny" == verdict', 'verdict in ("deny", "reject")', 'verdict.lower() == "deny"',
    'str(verdict).strip().lower() == "denied"', 'not verdict or verdict == "deny"',
])
def test_each_exact_form_fires(tmp_path: Path, check: str) -> None:
    source = f"def run(verdict, tool):\n    if {check}:\n        return False\n    return tool()\n"
    assert _file(tmp_path, source) == [(RULE_VERDICT, 2)]


@pytest.mark.parametrize("source", [
    'def run(resp, tool):\n    if resp["decision"] == "deny":\n        raise PermissionError("no")\n    tool()\n',
    'def run(resp, tool):\n    if resp.decision == "deny":\n        return\n    tool()\n',
    'def run(resp, tool):\n    if resp.get("approval") == "rejected":\n        return\n    tool()\n',
    'import json\ndef run(raw, tool):\n    v = json.loads(raw)["verdict"]\n    v = v.lower()\n    if v == "deny":\n'
    '        return\n    tool()\n',
    'async def run(verdict, tool):\n    if verdict == "deny":\n        return\n    await tool()\n',
    'def run(verdict, tool):\n    if verdict != "deny":\n        tool()\n',
    'def run(verdict, tool):\n    if verdict == "deny":\n        block()\n    else:\n        tool()\n',
    'def is_allowed(verdict):\n    if verdict == "deny":\n        return False\n    return True\n',
    'def run(items, tool):\n    for verdict in items:\n        if verdict == "deny":\n            continue\n'
    '        tool()\n',
], ids=["subscript", "attribute", "get", "alias", "async", "not-equal", "else-branch", "predicate", "loop"])
def test_each_way_of_reaching_the_action_fires(tmp_path: Path, source: str) -> None:
    assert [rule for rule, _ in _file(tmp_path, source)] == [RULE_VERDICT]


@pytest.mark.parametrize("source", [
    'def run(verdict, tool):\n    if verdict != "allow":\n        return\n    tool()\n',
    'def run(verdict, tool):\n    if verdict == "allow":\n        tool()\n',
    'ALLOWED = {"allow"}\ndef run(verdict, tool):\n    if verdict not in ALLOWED:\n        return\n    tool()\n',
    'def run(verdict, tool):\n    if verdict == "deny":\n        return\n    if verdict != "allow":\n        return\n'
    '    tool()\n',
    'TABLE = {"allow": "allow"}\ndef run(raw, tool):\n    verdict = TABLE.get(raw, "deny")\n    if verdict == "deny":\n'
    '        return\n    tool()\n',
    'def run(verdict, tool):\n    if verdict == "deny":\n        return\n',
    'def run(verdict):\n    if verdict == "deny":\n        return "deny"\n    return verdict\n',
    'def run(verdict):\n    if verdict == "deny":\n        return "blocked"\n    return "pending"\n',
    'def run(verdict, log):\n    if verdict == "deny":\n        return\n    print(verdict)\n',
    'def run(verdict, tool):\n    if verdict == "deny":\n        return\n    raise ValueError(verdict)\n',
    'def test_run(verdict, tool):\n    if verdict == "deny":\n        return\n    tool()\n',
    'def run(self, exc):\n    if self.verdict == "block":\n        logger.warning("x", **{k: v for k, v in exc.d.items()})\n'
    '        raise exc\n    logger.warning("y", **{k: v for k, v in exc.d.items()})\n',
    'def run(self, values):\n    for value in values:\n        if self.decision == "block":\n            break\n'
    '        self.inspect(value)\n',
    'def run(self, call):\n    result = self.evaluate(call)\n    if result.verdict == "block":\n        raise E\n'
    '    return result\n',
], ids=["permit-ne", "permit-eq", "allowed-set", "second-check", "table-default", "nothing-after", "hands-back",
        "another-state", "only-logs", "raises-after", "a-test", "log-arguments", "search-loop", "hands-back-a-result"])
def test_default_deny_forms_and_non_actions_stay_quiet(tmp_path: Path, source: str) -> None:
    assert _file(tmp_path, source) == []


def test_a_common_word_counts_only_where_the_name_is_about_a_gate(tmp_path: Path) -> None:
    body = '(action, tool):\n    if action == "block":\n        return\n    tool()\n'
    assert _file(tmp_path, "def apply" + body, "web.py") == []
    (tmp_path / "web.py").unlink()
    assert [rule for rule, _ in _file(tmp_path, "def guard_call" + body, "web.py")] == [RULE_VERDICT]
    (tmp_path / "web.py").unlink()
    assert [rule for rule, _ in _file(tmp_path, "def apply" + body, "pre_tool_hook.py")] == [RULE_VERDICT]


def test_a_function_is_reported_once_however_many_checks_it_holds(tmp_path: Path) -> None:
    checks = '    if verdict == "deny":\n        return\n' * 5
    assert len(_file(tmp_path, f"def run(verdict, tool):\n{checks}    tool()\n")) == 1


# ---- the import rule ----------------------------------------------------------------


def test_the_import_fixtures(tmp_path: Path) -> None:
    rules = {path.name: [rule for rule, _ in _ids_of(path, tmp_path)] for path in (FIXTURES / "imports").glob("*.py")}
    assert rules == {"positive.py": [RULE_IMPORT], "negative_denies.py": [], "negative_exits.py": [],
                     "negative_optional.py": []}


def test_the_positive_import_fixture_allows_and_the_denying_one_does_not() -> None:
    assert _load(FIXTURES / "imports" / "positive.py").decide("mcp__x__y", {}) == {"decision": "allow"}
    assert _load(FIXTURES / "imports" / "negative_denies.py").decide("mcp__x__y", {}) == {"decision": "deny"}


TRY = "try:\n    from policy_engine import check\nexcept ImportError:\n"


@pytest.mark.parametrize("handler", [
    "    def check(*a):\n        return True\n",
    "    check = lambda *a: True\n",
    "    ENFORCE = False\n",
    "    POLICY_ENABLED = False\n",
    '    def wrapper():\n        return "allow"\n',
], ids=["stub-def", "stub-lambda", "enforce-flag", "enabled-flag", "stub-string"])
def test_a_handler_that_opens_at_import_fires(tmp_path: Path, handler: str) -> None:
    assert [rule for rule, _ in _file(tmp_path, TRY + handler)] == [RULE_IMPORT]


@pytest.mark.parametrize("source", [
    'def f():\n    try:\n        from policy_engine import check\n    except ImportError:\n        return True\n'
    "    return check()\n",
    'def f():\n    try:\n        from policy_engine import check\n    except ModuleNotFoundError:\n'
    '        return {"decision": "allow"}\n    return check()\n',
    'import sys\ndef f():\n    try:\n        from policy_engine import check\n    except ImportError:\n'
    "        sys.exit(0)\n    return check()\n",
    'def f(tool):\n    try:\n        from policy_engine import check\n        check(tool)\n    except ImportError:\n'
    "        pass\n    tool()\n",
    'try:\n    import auth_policy as check\nexcept (ImportError, ValueError):\n    check = None\ndef f(tool):\n'
    "    if not check:\n        return True\n    return check.run(tool)\n",
    TRY + "    check = None\ndef f(tool):\n    if check is not None:\n        check(tool)\n    tool()\n",
    TRY + "    check = None\ndef f(tool):\n    if check:\n        check(tool)\n    return True\n",
    TRY + '    check = None\ndef f(tool):\n    if check is None:\n        print("no policy")\n    return tool()\n',
], ids=["returns-true", "returns-allow", "exit-zero", "skips-the-check", "not-name", "not-none-then-acts",
        "truthy-then-true", "body-only-logs"])
def test_each_open_path_fires(tmp_path: Path, source: str) -> None:
    assert [rule for rule, _ in _file(tmp_path, source)] == [RULE_IMPORT]


@pytest.mark.parametrize("source", [
    TRY + "    raise\n",
    TRY + '    raise RuntimeError("no policy")\n',
    "import sys\n" + TRY + "    sys.exit(1)\n",
    TRY + "    check = None\ndef f(tool):\n    if check is None:\n        raise PermissionError\n    return check(tool)\n",
    TRY + '    check = None\ndef f(tool):\n    if check is None:\n        return {"decision": "deny"}\n',
    TRY + "    check = None\ndef f(tool):\n    if check is None:\n        return False\n    return check(tool)\n",
    TRY + "    check = None\ndef f(tool):\n    if check is not None:\n        return check(tool)\n    raise PermissionError\n",
    TRY + "    check = None\ndef f(tool):\n    if check:\n        return check(tool)\n    else:\n        return False\n",
    TRY + "    check = None\n",
    TRY + "    check = None\nif check:\n    register(check)\n",
    TRY + "    check = deny_all\n",
    'try:\n    import rich\nexcept ImportError:\n    rich = None\ndef f():\n    if rich is None:\n        return True\n',
    'try:\n    from aggregate_author import navigate_stats\nexcept ImportError:\n    def navigate_stats():\n'
    "        return True\n",
    "def f(tool):\n    try:\n        from policy_engine import check\n    except ImportError:\n        pass\n    tool()\n",
    'try:\n    from policy_engine import check\nexcept Exception:\n    check = lambda *a: True\n',
], ids=["reraise", "raises", "exit-one", "test-raises", "test-denies", "test-false", "falls-to-raise", "else-false",
        "no-later-test", "module-level-feature", "stub-denies", "not-policy", "name-holds-the-word-inside",
        "pass-without-a-check", "broad-except"])
def test_each_closed_path_stays_quiet(tmp_path: Path, source: str) -> None:
    assert _file(tmp_path, source) == []


# ---- the registry and the engine ------------------------------------------------------


@pytest.mark.parametrize("rule_id", [RULE_VERDICT, RULE_IMPORT])
def test_the_rules_are_registered_as_stated(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert rule.severity is Severity.HIGH and rule.category is Category.TRUST_BOUNDARY
    assert rule.owasp_agentic_references == ["ASI02"] and not rule.owasp_mcp_references
    assert rule.limitations.strip()


def test_the_verdict_rule_credits_the_corpus_and_says_what_the_case_is_not() -> None:
    text = RULES[RULE_VERDICT].limitations
    for part in ("Nobulex failopen corpus", "github.com/arian-gogani/failopen", "MIT", "historical/autogen-verdict",
                 "0cd67042", "ec6cf48c", "not an unresolved AutoGen vulnerability"):
        assert part in text, part
    assert "15 of 36" not in text and "15-of-36" not in text


def test_the_module_docstring_credits_the_corpus() -> None:
    from agent_audit_kit.scanners import policy_failopen

    doc = policy_failopen.__doc__ or ""
    assert "github.com/arian-gogani/failopen" in doc and "MIT" in doc and "Arian Gogani" in doc


def test_a_full_scan_reports_both(tmp_path: Path) -> None:
    (tmp_path / "gate.py").write_text('def run(verdict, tool):\n    if verdict == "deny":\n        return\n    tool()\n')
    (tmp_path / "hook.py").write_text((FIXTURES / "imports" / "positive.py").read_text())
    found: dict[str, Any] = {f.rule_id: f for f in run_scan(tmp_path).findings}
    assert found[RULE_VERDICT].file_path == "gate.py" and found[RULE_VERDICT].line_number == 2
    assert found[RULE_IMPORT].file_path == "hook.py"
    assert "mcp_security_validator" in found[RULE_IMPORT].evidence
    assert json.dumps(found[RULE_IMPORT].evidence)
