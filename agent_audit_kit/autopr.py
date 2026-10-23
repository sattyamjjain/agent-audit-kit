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

import contextlib
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from agent_audit_kit.fix import FixAction, _read_bytes, run_fixes
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
    ``blocked`` every action that refuses the PR: one for a rule off the allow-list,
    written or not, and an allow-listed fix whose file git ignores, which no commit can
    carry. ``ignored`` maps each such fix's ``file_path`` to the name git ignores.
    """

    fixes: list[FixAction] = field(default_factory=list)
    blocked: list[FixAction] = field(default_factory=list)
    unchanged: list[FixAction] = field(default_factory=list)
    ignored: dict[str, str] = field(default_factory=dict)
    branch: str = ""
    title: str = ""
    body: str = ""

    @property
    def is_runnable(self) -> bool:
        return self.refusal is None

    def _held_back(self, fix: FixAction) -> bool:
        return fix.rule_id in AUTO_PR_ALLOWLIST and fix.file_path in self.ignored

    def blocked_reason(self, fix: FixAction) -> str:
        """Why ``fix``, one of ``blocked``, refuses the PR, as the plan's listing says it."""
        return "git ignores it" if self._held_back(fix) else "not allow-listed"

    @property
    def refusal(self) -> str | None:
        """Why `open_auto_pr` refuses this plan, or None when it goes ahead."""
        if self.blocked:
            reasons = []
            off_list = sorted({f.rule_id for f in self.blocked if not self._held_back(f)})
            if off_list:
                reasons.append(
                    ", ".join(off_list) + " is not on the auto-PR allow-list. Apply it with "
                    "`aak fix` and review the diff yourself."
                )
            names = sorted({self.ignored[f.file_path] for f in self.blocked if self._held_back(f)})
            if names:
                reasons.append(
                    f"git ignores {', '.join(names)}, so a PR cannot carry the change. "
                    "`aak fix` applies it in place."
                )
            return "refusing: " + " ".join(reasons)
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


def _git_name(project_root: Path, file_path: str) -> str | None:
    """``file_path`` as git names it from the project root: the file a write reaches, a
    link to a directory inside the project followed as `aak fix` follows it, since git
    reads no path past a link. None for a path outside the project, which no fix writes."""
    path = Path(file_path)
    try:
        rel = os.path.relpath(os.path.realpath(project_root / path), os.path.realpath(project_root))
    except ValueError:  # pragma: no cover - another drive, on Windows
        return None
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return None
    return Path(rel).as_posix()


def _ignored_by_git(project_root: Path, names: list[str]) -> set[str]:
    """Those of ``names``, relative to ``project_root``, that git ignores.

    A tracked file is never ignored, whatever a pattern says. Outside a work tree, or
    without git, nothing is, and `open_auto_pr` stops at its first git command. Inside
    one, git failing to answer (a path in a submodule) raises: a plan that cannot tell
    whether a commit would carry its fixes is not one to push.
    """
    if not names:
        return set()
    try:
        proc = subprocess.run(
            ["git", "check-ignore", "-z", "--stdin"], cwd=project_root, input="\0".join(names) + "\0",
            capture_output=True, text=True, check=False, timeout=120,
        )
    except FileNotFoundError:  # pragma: no cover - environment-specific
        return set()
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - environment-specific
        raise AutoPrError("`git check-ignore` timed out") from exc
    if proc.returncode in (0, 1):
        return {name for name in proc.stdout.split("\0") if name}
    inside = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"], cwd=project_root,
        capture_output=True, text=True, check=False, timeout=120,
    )
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return set()
    raise AutoPrError(
        "git could not say whether it ignores the files these fixes write: `git check-ignore` "
        f"failed ({proc.returncode}): {(proc.stderr or proc.stdout).strip()[:400]}"
    )


def _ignored_entries(project_root: Path) -> set[str]:
    """What `git status --porcelain --ignored` lists as ignored, a directory as one entry."""
    listing = _run(["git", "status", "--porcelain", "-z", "--ignored"], project_root)
    return {entry[3:] for entry in listing.split("\0") if entry.startswith("!! ")}


def _digests(project_root: Path, names: list[str]) -> dict[str, str | None]:
    """Each named file's SHA-256, read as `aak fix` reads (a regular file only, through no
    link, never waiting), or None where there is no such file."""
    digests: dict[str, str | None] = {}
    for name in names:
        try:
            digests[name] = hashlib.sha256(_read_bytes(project_root / name)).hexdigest()
        except OSError:
            digests[name] = None
    return digests


@dataclass(frozen=True)
class _Before:
    """The tree before a live run, as the guard compares it after one."""

    had_log: bool
    had_log_dir: bool
    ignored: set[str]
    digests: dict[str, str | None]


def _before_run(project_root: Path, plan: AutoPrPlan) -> _Before:
    """Whether the fix log and its directory exist, what git lists as ignored, and the
    hash of the fix log and of every file the plan's actions name, resolved as
    `_git_name` resolves them."""
    log = project_root / _FIX_LOG
    names = {_git_name(project_root, f.file_path) for f in (*plan.fixes, *plan.unchanged)}
    names.add(_git_name(project_root, str(log)))
    return _Before(
        had_log=os.path.lexists(log),
        had_log_dir=os.path.lexists(log.parent),
        ignored=_ignored_entries(project_root),
        digests=_digests(project_root, sorted(name for name in names if name)),
    )


def _put_back(project_root: Path, base_ref: str, branch: str, before: _Before) -> str:
    """Undo a live run that changed nothing besides the fix log, and say what is left.

    The checkout restores every tracked file, and a fix log the run created goes even
    where git ignores it, with the directory if the run made that too. What stays
    changed is named: anything new `git status --porcelain --ignored` lists, and the fix
    log or a file the plan's actions name whose bytes differ from before the run. A
    recipe that rewrites an ignored file no action names leaves both blind, so with
    nothing to name the message says git shows no change, not that the tree is as it was.
    """
    _run(["git", "checkout", "-f", base_ref], project_root)
    if not before.had_log:
        _run(["git", "clean", "-f", "-x", "--", _FIX_LOG], project_root)
        if not before.had_log_dir:
            with contextlib.suppress(OSError):
                (project_root / _FIX_LOG).parent.rmdir()
    _run(["git", "branch", "-D", branch], project_root)
    after = _digests(project_root, list(before.digests))
    rewritten = {name for name, digest in after.items() if digest != before.digests[name]}
    left = sorted((_ignored_entries(project_root) - before.ignored) | rewritten)
    said = "the fixes changed no file besides the fix log; nothing was committed or pushed"
    if left:
        return f"{said}, but these files git ignores are not as they were: {', '.join(left)}."
    return f"{said}, and git shows no change."


def _branch_name(fixes: list[FixAction]) -> str:
    rules = sorted({f.rule_id for f in fixes})
    stem = rules[0].lower() if len(rules) == 1 else f"{len(rules)}-rules"
    return "aak/autofix/" + _BRANCH_SAFE_RE.sub("-", stem).strip("-")


def _shown_path(project_root: Path, file_path: str) -> str:
    """``file_path`` for the PR body: relative to the project root, never the operator's
    absolute local path. `FixAction.file_path` is the path the recipe wrote, as the
    scan built it, so until #1060 a public draft PR carried the operator's home
    directory in its File column. A path outside the project, which no fix writes,
    shows its name alone."""
    return _git_name(project_root, file_path) or Path(file_path).name


def _render_body(fixes: list[FixAction], project_root: Path) -> str:
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
            f"| `{fix.rule_id}` — {title} | `{_shown_path(project_root, fix.file_path)}` "
            f"| {fix.description} | {cves} |"
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

    So does a fix whose file git ignores, such as the usual `.claude/settings.local.json`.
    No commit carries it: the live run rewrote it on the operator's disk alone and pushed
    a commit holding only the fix log, and the guard in `open_auto_pr`, which asks git
    what changed, saw nothing and called the tree as it was.
    """
    pending = run_fixes(project_root, dry_run=True)
    allowed = [f for f in pending if f.rule_id in AUTO_PR_ALLOWLIST]
    names = {f.file_path: _git_name(project_root, f.file_path) for f in allowed if f.writes}
    git_ignores = _ignored_by_git(project_root, sorted({name for name in names.values() if name}))
    ignored = {path: name for path, name in names.items() if name is not None and name in git_ignores}
    writing = [f for f in allowed if f.writes and f.file_path not in ignored]
    plan = AutoPrPlan(
        fixes=writing,
        blocked=[f for f in pending if f.rule_id not in AUTO_PR_ALLOWLIST]
        + [f for f in allowed if f.writes and f.file_path in ignored],
        unchanged=[f for f in allowed if not f.writes],
        ignored=ignored,
    )
    if writing:
        plan.branch = _branch_name(writing)
        rules = sorted({f.rule_id for f in writing})
        plan.title = (
            f"fix({rules[0]}): mechanical remediation"
            if len(rules) == 1
            else f"fix: mechanical remediation for {len(rules)} rules"
        )
        plan.body = _render_body(writing, project_root)
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
    before = _before_run(project_root, plan)
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
        raise AutoPrError(_put_back(project_root, base_ref, plan.branch, before))

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
