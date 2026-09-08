"""The `scan` command lives in its own module now (issue #701).

`cli.py` was 1,618 lines for 23 top-level commands, and 440 of them — a quarter
of the file — were the `scan` command plus its private `_run_scan` helper. They
moved to `agent_audit_kit/commands/scan.py` unchanged.

"Unchanged" is the whole claim, so it is what these tests hold:

* the command's public surface — every option, its flags, type, default and help
  string — is asserted structurally rather than against a golden `--help` capture,
  because the rendered text also depends on the terminal width and the installed
  click version, and a test that fails when click changes its wrapping is a test
  people learn to ignore;
* the import direction is one-way. `cli` imports `commands`, and a command module
  reaching back for `EXIT_ERROR` would make the group unimportable. That is why
  the shared constants moved to `commands/_common.py`, and why this is asserted
  from the AST rather than trusted to code review;
* the names `cli` used to define are still importable from `cli`, so nothing
  outside this package had to change.
"""

from __future__ import annotations

import ast
import pathlib

import click

from agent_audit_kit.cli import cli
from agent_audit_kit.commands.scan import scan_cmd

REPO = pathlib.Path(__file__).resolve().parents[1]
PKG = REPO / "agent_audit_kit"


# ---------------------------------------------------------------------------
# The command is still registered, and still the same object
# ---------------------------------------------------------------------------

def test_scan_is_registered_on_the_group() -> None:
    assert "scan" in cli.commands


def test_registered_command_is_the_extracted_one() -> None:
    """`cli.add_command` replaced `@cli.command`; it must register the same
    object, not a wrapper that could drift."""
    assert cli.commands["scan"] is scan_cmd


def test_bare_invocation_still_falls_through_to_scan() -> None:
    """The group is `invoke_without_command=True` and calls `ctx.invoke(scan_cmd)`.
    That reference now resolves through an import, so it is worth asserting the
    name is bound at module scope rather than shadowed."""
    import agent_audit_kit.cli as cli_mod

    assert cli_mod.scan_cmd is scan_cmd


# ---------------------------------------------------------------------------
# The public surface, structurally
# ---------------------------------------------------------------------------

EXPECTED_PARAMS = {
    "path", "output_format", "min_severity", "output_file", "include_user_config",
    "ignore_paths", "rules", "exclude_rules", "preset", "profile", "fail_on",
    "config_path", "ci", "verbose", "show_score", "owasp_report", "compliance",
    "verify_secrets", "diff_base", "llm_scan", "sessions", "llm_model",
    "strict_loading", "advisories_repo", "advisories_dry_run", "step_summary",
    "pr_summary_out", "fingerprint_strategy", "quiet", "version",
}


def test_option_set_is_unchanged() -> None:
    assert {p.name for p in scan_cmd.params} == EXPECTED_PARAMS


def test_every_option_still_carries_its_help_text() -> None:
    """`--help` is rendered from these strings. If one went missing in the move,
    the rendered output changes even though the option still exists."""
    missing = [
        p.name for p in scan_cmd.params
        if isinstance(p, click.Option) and not p.help and p.name != "version"
    ]
    assert missing == [], f"options lost their help text: {missing}"


def test_docstring_is_the_short_help() -> None:
    assert scan_cmd.help is not None
    assert scan_cmd.help.strip().startswith(
        "Scan a project for MCP agent security vulnerabilities."
    )


def test_defaults_are_unchanged() -> None:
    defaults = {p.name: p.default for p in scan_cmd.params}
    assert defaults["path"] == "."
    assert defaults["output_format"] == "console"
    assert defaults["min_severity"] == "low"
    assert defaults["fail_on"] is None
    assert defaults["llm_model"] == "ollama/gemma2:2b"
    assert defaults["fingerprint_strategy"] == "auto"
    assert defaults["step_summary"] is True
    assert defaults["ci"] is False


# ---------------------------------------------------------------------------
# Import direction — the reason `_common` exists
# ---------------------------------------------------------------------------

def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
        elif isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
    return out


def test_no_command_module_imports_cli() -> None:
    """One-way: `cli` imports `commands`. The reverse is a cycle that makes the
    group unimportable, and it is an easy one to reintroduce by reaching for
    `EXIT_ERROR` from the file it used to live in."""
    offenders = [
        p.name for p in sorted((PKG / "commands").glob("*.py"))
        if "agent_audit_kit.cli" in _imported_modules(p)
    ]
    assert offenders == [], f"commands modules importing cli: {offenders}"


def test_cli_no_longer_defines_the_scan_body() -> None:
    tree = ast.parse((PKG / "cli.py").read_text(encoding="utf-8"))
    defined = {
        n.name for n in tree.body
        if isinstance(n, ast.FunctionDef)
    }
    assert "scan_cmd" not in defined
    assert "_run_scan" not in defined


def test_scan_module_owns_the_body() -> None:
    tree = ast.parse((PKG / "commands" / "scan.py").read_text(encoding="utf-8"))
    defined = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert {"scan_cmd", "_run_scan"} <= defined


def test_cli_lost_roughly_the_extracted_lines() -> None:
    """A soft guard on the thing the issue actually asked for. If cli.py creeps
    back over 1,300 lines, something is being added to the wrong file."""
    n = len((PKG / "cli.py").read_text(encoding="utf-8").splitlines())
    assert n < 1300, f"cli.py is {n} lines; the #701 split put it near 1,100"


# ---------------------------------------------------------------------------
# Nothing outside the package had to change
# ---------------------------------------------------------------------------

def test_moved_names_are_still_importable_from_cli() -> None:
    from agent_audit_kit.cli import (  # noqa: F401
        EXIT_ERROR,
        EXIT_FINDINGS,
        EXIT_PASS,
        FAIL_ON_CHOICES,
        SEVERITY_MAP,
        _apply_config_defaults,
        _load_config,
        _to_list,
    )

    assert EXIT_PASS == 0 and EXIT_FINDINGS == 1 and EXIT_ERROR == 2
    assert "critical" in SEVERITY_MAP
    assert FAIL_ON_CHOICES[0] == "critical"


def test_the_two_modules_agree_on_the_constants() -> None:
    """Re-export, not a second copy."""
    from agent_audit_kit import cli as cli_mod
    from agent_audit_kit.commands import _common

    for name in ("SEVERITY_MAP", "FAIL_ON_CHOICES", "EXIT_ERROR", "_to_list"):
        assert getattr(cli_mod, name) is getattr(_common, name)
