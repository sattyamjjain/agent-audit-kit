"""Draft-PR delivery for mechanically-safe fixes — issue #68, narrow scope.

`aak fix` and `suggest --apply-trivial` already apply the mechanical fixes; the
only missing step was handing them to the user as a reviewable PR instead of a
dirty working tree. That is what this module does.

Three deliberate constraints, because this is the one part of AAK that writes
outward:

**No credentials.** Delivery goes through the ``gh`` CLI, which is already
authenticated on the operator's machine under their own scopes. AAK never asks
for, stores, or reads a token, so there is no new secret to leak and no way for
AAK to exceed the access the operator already granted ``gh``.

**Draft only, never merged.** ``gh pr create --draft``. A mechanical edit that
nobody reviewed is a diff, not a decision.

**Allow-list, not a severity filter.** ``--auto-pr`` refuses outright if any
pending fix is for a rule not in ``AUTO_PR_ALLOWLIST``. Being marked
``auto_fixable`` is necessary but not sufficient: the allow-list is the second
signature, so widening auto-fix coverage cannot silently widen what gets pushed.

On the two fix shapes that are *not* on the list, and why they never will be as
stated — see ``NON_MECHANICAL`` below. Issue #68 named three shapes as
"purely mechanical". One of them is.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from agent_audit_kit.fix import FixAction, run_fixes
from agent_audit_kit.rules.builtin import RULES

# Rules whose fix is a value substitution with no behavioural ambiguity: the
# edit has exactly one correct form, and a reviewer can confirm it by reading
# the diff without reading the surrounding program.
#
# Kept as an explicit literal rather than derived from `auto_fixable`, so that
# marking a new rule auto-fixable does not, on its own, make AAK push it.
AUTO_PR_ALLOWLIST: frozenset[str] = frozenset({
    # Dependency floor bumps — one version string, vendor-published fix version.
    "AAK-FLOWISE-001",
    "AAK-LANGCHAIN-001",
    "AAK-LANGCHAIN-003",
    "AAK-LITELLM-CVE-2026-30623-PIN-001",
    "AAK-NEO4J-001",
    # Config flips — a boolean or enum with a known-safe value.
    "AAK-TRUST-001",
    "AAK-TRUST-004",
    "AAK-TRUST-007",
    "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001",
})

# Fix shapes that cannot be made mechanical, recorded here because issue #68
# lists two of them as if they could. Each entry is (shape, why not).
NON_MECHANICAL: tuple[tuple[str, str], ...] = (
    (
        "add an auth dependency to a route",
        "There is no single correct edit. The right dependency is whichever "
        "scheme the project already uses, declared wherever that project keeps "
        "it, and a wrong guess produces a route that looks protected and is "
        "not. A fix that can fail closed-looking-open is worse than no fix.",
    ),
    (
        "rewrite a quoted shell string as a parameterised call",
        "Splitting a command string into argv requires knowing which spaces are "
        "separators and which are data — that is the shell's own parse, and it "
        "depends on values only known at run time. It also silently changes "
        "behaviour for any command relying on globbing or redirection.",
    ),
    (
        "declare RFC 9728 Protected Resource Metadata discovery (AAK-OAUTH-008)",
        "The only edit that silences the rule is one that fixes nothing. The "
        "detector clears when the file mentions `authorization_servers` / "
        "`oauth-protected-resource`, so writing that key into an MCP client "
        "config makes the finding disappear while the hardcoded bearer token "
        "sits untouched beside it -- the v0.3.78 failure exactly. A real fix "
        "means serving metadata at `/.well-known/oauth-protected-resource` on "
        "the resource server, naming an authorization server AAK has no way to "
        "know, and moving the client onto a 401 `WWW-Authenticate` challenge. "
        "None of that lives in the file the finding points at: the artifact that "
        "must change is the server, and the artifact AAK would edit is the "
        "client. Reported as #607's largest single remaining rule, and "
        "deliberately left advisory.",
    ),
    (
        "swap a bind address from 0.0.0.0 to 127.0.0.1",
        "Mechanical to write, but it takes a reachable service off the network. "
        "Whether that is a fix or an outage is a deployment fact AAK cannot see, "
        "so it stays a suggestion.",
    ),
)

_BRANCH_SAFE_RE = re.compile(r"[^a-zA-Z0-9._-]+")
_FIX_LOG = ".agent-audit-kit/fix-log.json"


@dataclass
class AutoPrPlan:
    """What ``--auto-pr`` would do, resolved before anything is written.

    ``fixes`` are the allow-listed fixes that write their file, ``unchanged`` the
    allow-listed actions that write nothing (a refused file, nothing to change), and
    ``blocked`` every action for a rule off the allow-list, written or not.
    """

    fixes: list[FixAction] = field(default_factory=list)
    blocked: list[FixAction] = field(default_factory=list)
    unchanged: list[FixAction] = field(default_factory=list)
    branch: str = ""
    title: str = ""
    body: str = ""

    @property
    def is_runnable(self) -> bool:
        return self.refusal is None

    @property
    def refusal(self) -> str | None:
        """Why `open_auto_pr` refuses this plan, or None when it goes ahead."""
        if self.blocked:
            return (
                "refusing: "
                + ", ".join(sorted({f.rule_id for f in self.blocked}))
                + " is not on the auto-PR allow-list. Apply it with `aak fix` and "
                "review the diff yourself."
            )
        if self.fixes:
            return None
        if self.unchanged:
            return "nothing to do: no allow-listed fix would change a file here."
        return "nothing to do: no allow-listed fix applies here."


class AutoPrError(RuntimeError):
    """Delivery failed. The message is shown to the operator verbatim."""


def _run(args: list[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            args, cwd=cwd, capture_output=True, text=True, check=False, timeout=120
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment-specific
        raise AutoPrError(f"{args[0]} not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - environment-specific
        raise AutoPrError(f"{' '.join(args[:2])} timed out") from exc
    if proc.returncode != 0:
        raise AutoPrError(
            f"`{' '.join(args)}` failed ({proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip()[:400]}"
        )
    return proc.stdout.strip()


def _branch_name(fixes: list[FixAction]) -> str:
    rules = sorted({f.rule_id for f in fixes})
    stem = rules[0].lower() if len(rules) == 1 else f"{len(rules)}-rules"
    return "aak/autofix/" + _BRANCH_SAFE_RE.sub("-", stem).strip("-")


def _render_body(fixes: list[FixAction]) -> str:
    lines = [
        "Mechanical remediation drafted by "
        "[agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit).",
        "",
        "Every change below is a value substitution for a rule on the auto-PR "
        "allow-list. Nothing here has been reviewed by a human, which is why "
        "this PR opens as a draft.",
        "",
        "| Rule | File | Change | CVE |",
        "| --- | --- | --- | --- |",
    ]
    for fix in sorted(fixes, key=lambda f: (f.rule_id, f.file_path)):
        rule = RULES.get(fix.rule_id)
        cves = ", ".join(rule.cve_references) if rule and rule.cve_references else "—"
        title = rule.title if rule else fix.rule_id
        lines.append(
            f"| `{fix.rule_id}` — {title} | `{fix.file_path}` | {fix.description} | {cves} |"
        )
    lines += [
        "",
        "### What this PR does not cover",
        "",
        "Findings whose fix depends on how the project is deployed or wired are "
        "reported but never auto-edited:",
        "",
    ]
    lines += [f"- **{shape}** — {why}" for shape, why in NON_MECHANICAL]
    lines += [
        "",
        "Run `agent-audit-kit scan .` on this branch to see what remains.",
    ]
    return "\n".join(lines)


def plan_auto_pr(project_root: Path) -> AutoPrPlan:
    """Resolve what would be pushed, without writing anything.

    The plan comes from a dry run, whose actions all read ``applied=False``: a fix the
    recipe would write, and a file it refused or had nothing to change in, alike. Every
    allow-listed action counted as a fix, so a plan made only of refusals opened a draft
    PR whose commit held just the fix log, and a mixed plan named the refused file in
    the PR's branch, title and body as changed. Only an action that ``writes`` its file
    is a fix now; the others go in ``unchanged``, out of the branch, title and body, and
    a plan with no fix left is refused. A rule off the allow-list still blocks the PR
    whether or not its fix writes, since the live run applies every auto-fixable fix.
    """
    pending = run_fixes(project_root, dry_run=True)
    allowed = [f for f in pending if f.rule_id in AUTO_PR_ALLOWLIST]
    writing = [f for f in allowed if f.writes]
    plan = AutoPrPlan(
        fixes=writing,
        blocked=[f for f in pending if f.rule_id not in AUTO_PR_ALLOWLIST],
        unchanged=[f for f in allowed if not f.writes],
    )
    if writing:
        plan.branch = _branch_name(writing)
        rules = sorted({f.rule_id for f in writing})
        plan.title = (
            f"fix({rules[0]}): mechanical remediation"
            if len(rules) == 1
            else f"fix: mechanical remediation for {len(rules)} rules"
        )
        plan.body = _render_body(writing)
    return plan


def open_auto_pr(project_root: Path, plan: AutoPrPlan, base: str | None = None) -> str:
    """Apply the planned fixes on a new branch and open a draft PR.

    Returns the PR URL. Raises AutoPrError with an operator-readable message on
    any precondition failure — this deliberately does not fall back to a partial
    outcome, because half of a push is worse than none.
    """
    refusal = plan.refusal
    if refusal is not None:
        raise AutoPrError(refusal)

    if _run(["git", "status", "--porcelain"], project_root):
        raise AutoPrError(
            "working tree is dirty. Commit or stash first — auto-PR will not "
            "bundle your uncommitted changes into its branch."
        )

    base_ref = base or _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], project_root)
    _run(["git", "checkout", "-b", plan.branch], project_root)

    applied = run_fixes(project_root, dry_run=False)
    # What the live run changed, from git rather than from the recipes' word: a recipe
    # that reports a write it did not make would otherwise push a branch whose commit
    # holds only the fix log. The tree was clean before the run, so putting it back
    # discards nothing but what the run wrote.
    changed = [
        name
        for args in (["git", "diff", "--name-only", "HEAD"], ["git", "ls-files", "--others", "--exclude-standard"])
        for name in _run(args, project_root).splitlines()
    ]
    if not any(f.writes for f in applied) or all(name == _FIX_LOG for name in changed):
        _run(["git", "checkout", "-f", base_ref], project_root)
        _run(["git", "clean", "-f", "--", _FIX_LOG], project_root)
        _run(["git", "branch", "-D", plan.branch], project_root)
        raise AutoPrError(
            "the fixes changed no file besides the fix log; nothing was committed or pushed, "
            "and the working tree is as it was."
        )

    _run(["git", "add", "-A"], project_root)
    _run(["git", "commit", "-m", plan.title, "-m", plan.body], project_root)
    _run(["git", "push", "-u", "origin", plan.branch], project_root)

    return _run(
        [
            "gh", "pr", "create", "--draft",
            "--base", base_ref,
            "--head", plan.branch,
            "--title", plan.title,
            "--body", plan.body,
        ],
        project_root,
    )
