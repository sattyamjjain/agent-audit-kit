"""Every CLI invocation a rule's text names runs as written.

A rule's title, description, remediation and limitations reach the user through
the console, SARIF and the rule pages, so a command named there is advice someone
types. AAK-TOXICFLOW-001 sent people to `agent-audit-kit toxic-flow --explain`,
which never existed, AAK-MCP-LINEAGE-STAINLESS-001 to an `aak ignore` config, and
AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001 to an `aak suggest --rule` option
`suggest` does not have. Nothing checked any of them.

An invocation is a code span, or single- or double-quoted text, that starts with
`aak ` or `agent-audit-kit `. Commands are written as code, so prose such as "a
bug in agent-audit-kit itself" and paths such as `.agent-audit-kit.yml` are not
read. Each invocation must name a command, a subcommand when the command is a
group (`aak rule lint`, `aak corpus update`), only options that command declares,
a value its Choice accepts, and every required argument.
"""

from __future__ import annotations

import re

import click
import pytest

from agent_audit_kit.cli import cli
from agent_audit_kit.rules.builtin import RULES

FIELDS = ("title", "description", "remediation", "limitations")

_INVOCATION_RE = re.compile(
    r"`((?:aak|agent-audit-kit) [^`\n]*)`"
    r"|'((?:aak|agent-audit-kit) [^'\n]*)'"
    r'|"((?:aak|agent-audit-kit) [^"\n]*)"'
)


def _invocations(text: str) -> list[str]:
    return [next(g for g in m.groups() if g) for m in _INVOCATION_RE.finditer(text)]


def _problems(invocation: str) -> list[str]:
    """What stops `invocation` from running as written, or [] when nothing does."""
    tokens = invocation.split()
    if len(tokens) < 2:
        return ["no command named"]
    cmd = cli.commands.get(tokens[1])
    if cmd is None:
        return [f"no command {tokens[1]!r}"]
    rest = tokens[2:]
    if isinstance(cmd, click.Group):
        if not rest or rest[0] not in cmd.commands:
            sub = rest[0] if rest else "(none)"
            return [f"{tokens[1]!r} has no subcommand {sub!r}"]
        cmd, rest = cmd.commands[rest[0]], rest[1:]
    options = {
        name: param
        for param in cmd.params
        if isinstance(param, click.Option)
        for name in (*param.opts, *param.secondary_opts)
    }
    problems: list[str] = []
    positional: list[str] = []
    i = 0
    while i < len(rest):
        token = rest[i]
        if token.startswith("-") and len(token) > 1:
            name, _, value = token.partition("=")
            option = options.get(name)
            if option is None:
                problems.append(f"no option {name!r}")
            elif not (option.is_flag or option.count):
                if not value and i + 1 < len(rest):
                    value = rest[i + 1]
                    i += 1
                if isinstance(option.type, click.Choice) and value and value not in option.type.choices:
                    problems.append(f"{name} {value!r} is not one of {list(option.type.choices)}")
        else:
            positional.append(token)
        i += 1
    arguments = [param for param in cmd.params if isinstance(param, click.Argument)]
    for argument, token in zip(arguments, positional):
        if isinstance(argument.type, click.Choice) and token not in argument.type.choices:
            problems.append(f"{(argument.name or '').upper()} {token!r} is not one of {list(argument.type.choices)}")
    problems += [f"missing {(a.name or '').upper()}" for a in arguments[len(positional):] if a.required]
    if len(positional) > len(arguments) and not any(a.nargs == -1 for a in arguments):
        problems.append(f"unexpected arguments {positional[len(arguments):]}")
    return problems


CASES = [
    (rule_id, field, invocation)
    for rule_id, rule in sorted(RULES.items())
    for field in FIELDS
    for invocation in _invocations(getattr(rule, field) or "")
]


@pytest.mark.parametrize(("rule_id", "field", "invocation"), CASES, ids=lambda v: str(v)[:60])
def test_every_command_a_rule_names_runs_as_written(rule_id: str, field: str, invocation: str) -> None:
    assert _problems(invocation) == [], f"{rule_id} {field}: `{invocation}`"


def test_the_registry_is_read_for_invocations() -> None:
    """Guard the guard: a pattern that read nothing would pass every rule."""
    found = {invocation for _, _, invocation in CASES}
    assert "aak corpus update --ipi" in found  # a group's subcommand and an option
    assert "agent-audit-kit pin" in found  # single-quoted, in AAK-RUGPULL-001
    assert "aak parity report" in found  # a Choice argument
    assert len(CASES) >= 10


@pytest.mark.parametrize(("invocation", "problem"), [
    ("aak toxic-flow --explain", "no command 'toxic-flow'"),
    ("aak ignore", "no command 'ignore'"),
    ("aak corpus refresh", "'corpus' has no subcommand 'refresh'"),
    ("aak rule", "'rule' has no subcommand '(none)'"),
    ("aak suggest --apply-trivial --rule AAK-X-001", "no option '--rule'"),
    ("aak suggest --apply-trivial", "missing SARIF_PATH"),
    ("aak scan --severity bogus", "--severity 'bogus' is not one of"),
    ("aak parity summary", "SUBCOMMAND 'summary' is not one of"),
    ("aak pin . extra", "unexpected arguments ['extra']"),
])
def test_the_checker_reports_what_would_not_run(invocation: str, problem: str) -> None:
    assert any(p.startswith(problem) for p in _problems(invocation)), _problems(invocation)


@pytest.mark.parametrize("invocation", [
    "aak rule lint --ci",
    "aak corpus update --fhi",
    "aak scan --severity info",
    "aak scan . --exclude-rules=AAK-MCP-001",
    "agent-audit-kit fix --dry-run",
    "aak suggest results.sarif --apply-trivial",
])
def test_the_checker_passes_what_would_run(invocation: str) -> None:
    assert _problems(invocation) == []


@pytest.mark.parametrize("text", [
    "which is a bug in agent-audit-kit itself; please file an issue",
    "list it under `exclude-rules` in `.agent-audit-kit.yml`",
    "gate it with `@aak.parity.check(dimensions=['model'])`",
    "add it to `.aak-toxic-flow-trust.yml`",
])
def test_prose_and_paths_are_not_invocations(text: str) -> None:
    assert _invocations(text) == []
