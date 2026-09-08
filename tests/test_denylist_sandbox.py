"""AAK-SANDBOX-DENYLIST-001 — the detector #656 was deferred for (#704).

#656 sat open at CVSS 10 for twelve days because its disposition bundled a CVE
response (which had a vendor fix all along, shipped as a pin in v0.3.96) with a
new rule class. This is the rule class. The stated blocker was precision: telling
a deny-list sandbox from a real one *without firing on every codebase that
mentions `eval`*. So the negatives below are the point of this file, not padding
— three of them are the acceptance list from #704, and the fourth is the one that
matters most in practice: a module that merely mentions the vocabulary.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import denylist_sandbox as ds

RULE = "AAK-SANDBOX-DENYLIST-001"


def _ids(tmp_path: Path, src: str, name: str = "executor.py") -> set[str]:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return {f.rule_id for f in ds.scan(tmp_path)[0]}


def _findings(tmp_path: Path, src: str) -> list:
    (tmp_path / "executor.py").write_text(src, encoding="utf-8")
    return ds.scan(tmp_path)[0]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_rule_is_registered_and_critical() -> None:
    assert RULE in RULES
    assert RULES[RULE].severity.value == "critical"


def test_rule_cites_both_products_that_make_it_a_class() -> None:
    assert set(RULES[RULE].cve_references) == {"CVE-2026-81096", "CVE-2026-53710"}


def test_rule_states_that_subprocess_isolation_never_matches() -> None:
    assert "subprocess never matches" in RULES[RULE].limitations


# ---------------------------------------------------------------------------
# Positive: the ToolUniverse shape (CVE-2026-81096)
# ---------------------------------------------------------------------------

TOOLUNIVERSE = '''
DENIED_ATTRS = ["__class__", "__subclasses__", "__globals__", "eval", "exec", "os", "subprocess"]

def python_code_executor(source, extra_imports=None):
    """The MCP tool behind python_code_executor."""
    for bad in DENIED_ATTRS:
        if bad in source:
            raise ValueError("denied token: %s" % bad)
    ns = {"__builtins__": {"getattr": getattr, "len": len, "range": range}}
    exec(source, ns)
    return ns.get("result")
'''


def test_fires_on_the_tooluniverse_shape(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, TOOLUNIVERSE)


def test_evidence_names_the_reachable_primitive(tmp_path: Path) -> None:
    """The finding has to say *which* lookup survived, or the reader cannot act."""
    f = [x for x in _findings(tmp_path, TOOLUNIVERSE) if x.rule_id == RULE][0]
    assert "`getattr`" in f.evidence
    assert "CVE-2026-81096" in f.evidence
    assert "DENIED_ATTRS" in f.evidence


# ---------------------------------------------------------------------------
# Positive: the RestrictedPython getattr shape (CVE-2026-53710)
# ---------------------------------------------------------------------------

RESTRICTED = '''
import re
BLOCKED = {"__class__", "__bases__", "__mro__", "importlib", "ctypes"}

def run_snippet(src):
    """mcp tool: evaluate a jq-like expression"""
    if any(re.search(tok, src) for tok in BLOCKED):
        raise ValueError("blocked")
    env = {"getattr": getattr, "vars": vars}
    code = compile_restricted(src, "<inline>", "exec")
    exec(code, env)
'''


def test_fires_on_the_restrictedpython_shape(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, RESTRICTED)


# ---------------------------------------------------------------------------
# Negatives — #704's acceptance list
# ---------------------------------------------------------------------------

def test_allowlist_sandbox_is_silent(tmp_path: Path) -> None:
    """A deny-list on top of a real allow-list is defence in depth, not the
    boundary. Firing here would punish the correct design."""
    src = '''
ALLOWED_BUILTINS = {"len": len, "range": range, "min": min}
DENIED = ["__class__", "__subclasses__", "eval", "exec", "os"]

def run(src):
    """mcp code tool"""
    for bad in DENIED:
        if bad in src:
            raise ValueError("denied")
    exec(src, {"__builtins__": ALLOWED_BUILTINS})
'''
    assert RULE not in _ids(tmp_path, src)


def test_subprocess_isolated_executor_is_silent(tmp_path: Path) -> None:
    """The submitted source is never run in this process, so signal (3) is absent
    by design rather than by luck."""
    src = '''
import subprocess
DENIED = ["__class__", "__subclasses__", "eval", "exec", "os"]

def run(src):
    """mcp code tool"""
    for bad in DENIED:
        if bad in src:
            raise ValueError("denied")
    return subprocess.run(["python", "-c", src], capture_output=True, timeout=5)
'''
    assert RULE not in _ids(tmp_path, src)


def test_ordinary_eval_on_trusted_input_is_silent(tmp_path: Path) -> None:
    """No deny-list of names, so nothing here claims to be a sandbox. This is the
    "fires on every codebase that mentions eval" failure the deferral named."""
    src = '''
def parse_config_expr(expr):
    return eval(expr, {"__builtins__": {}})
'''
    assert RULE not in _ids(tmp_path, src)


def test_a_denylist_that_also_denies_the_lookups_is_silent(tmp_path: Path) -> None:
    """Fragile, but not bypassable by construction — which is the line this rule
    draws. Reporting it would make the rule an opinion about style."""
    src = '''
DENIED = ["__class__", "__subclasses__", "__globals__", "eval", "exec",
          "getattr", "__getattribute__", "vars", "globals", "dir"]

def run(src):
    """mcp code tool"""
    for bad in DENIED:
        if bad in src:
            raise ValueError("denied")
    exec(src, {"__builtins__": {}})
'''
    assert RULE not in _ids(tmp_path, src)


# ---------------------------------------------------------------------------
# Negatives — the ones that decide whether this is shippable at all
# ---------------------------------------------------------------------------

def test_a_module_that_only_mentions_the_vocabulary_is_silent(tmp_path: Path) -> None:
    """A security scanner's own rule text is full of these strings. If naming them
    were enough, this rule would fire on the tool that ships it."""
    src = '''
DANGEROUS = ["__class__", "__subclasses__", "eval", "exec", "os", "subprocess"]

def describe():
    """Documentation for an mcp rule about sandbox escapes."""
    return "Rules flag " + ", ".join(DANGEROUS)
'''
    assert RULE not in _ids(tmp_path, src)


def test_a_denylist_defined_but_never_checked_is_silent(tmp_path: Path) -> None:
    src = '''
DENIED = ["__class__", "__subclasses__", "eval", "exec", "os"]

def run(src):
    """mcp code tool"""
    exec(src, {"getattr": getattr})
'''
    assert RULE not in _ids(tmp_path, src)


def test_exec_on_a_literal_is_not_a_sandbox(tmp_path: Path) -> None:
    src = '''
DENIED = ["__class__", "__subclasses__", "eval", "exec", "os"]

def bootstrap():
    for bad in DENIED:
        pass
    exec("x = 1")
'''
    assert RULE not in _ids(tmp_path, src)


def test_two_dangerous_names_is_below_the_floor(tmp_path: Path) -> None:
    """Three is the floor. Two is a config list that happens to overlap."""
    src = '''
SKIP = ["os", "sys"]

def run(src):
    """mcp code tool"""
    for bad in SKIP:
        if bad in src:
            raise ValueError("no")
    exec(src, {"getattr": getattr})
'''
    assert RULE not in _ids(tmp_path, src)


def test_syntax_error_does_not_crash_the_scan(tmp_path: Path) -> None:
    assert _ids(tmp_path, "def broken(:\n    pass\n") == set()


def test_scanner_is_silent_on_this_repository() -> None:
    """The strongest negative available: run it over the tool that ships it.
    agent_audit_kit's own rule text names every token in the vocabulary."""
    repo = Path(__file__).resolve().parents[1]
    findings, _ = ds.scan(repo / "agent_audit_kit")
    assert findings == [], [f"{f.file_path}:{f.line_number}" for f in findings]
