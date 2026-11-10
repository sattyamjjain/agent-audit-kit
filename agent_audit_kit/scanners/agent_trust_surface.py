"""Agent config / skill auto-trust across a headless ``-p`` run in CI.

AAK-AGENT-TRUST-001..004.

Coding agents auto-load repo-resident config and skill files on open and trust
them on first use. A risk assessment of malicious skill files (Yang, Fu,
Tantithamthavorn, Arora, Chua; arXiv:2608.05223, submitted 2026-08-05) measured
Gemini CLI executing the shell commands hidden in benign-appearing skill files in
95.5-96.1% of runs and Qwen Code in 71.6-74.0%, with explicit safety recognition
in only 1.99% of 5,629 runs (a three-judge panel validated against a blind human
gold standard at Cohen's kappa 0.85). The interactive workspace-trust prompt is
the one guardrail in that path, and a non-interactive ``-p`` / headless run is
exactly what removes it.

This scanner covers the CI amplifier and the persisted-trust surface that the
per-file scanners (`AAK-IDE-TASK-*`, `AAK-SKILL-*`, `AAK-AGENT-*`, `mcp_config`)
do not. It extends, rather than duplicates, those families: it does not re-detect
injection content or `folderOpen` auto-run; it flags the trust model around them.

- AAK-AGENT-TRUST-001: a CI workflow runs a coding-agent CLI non-interactively
  (`-p` / `--print` / `--yolo` / `--dangerously-skip-permissions` / `--full-auto`
  / `--yes`), so every repo-resident skill / config / tasks file is trusted
  without a prompt.
- AAK-AGENT-TRUST-002: 001 on an attacker-controllable ref (`pull_request_target`,
  `issue_comment`, `workflow_run`, or an explicit checkout of the PR head), so a
  fork PR's skill / config files execute with the base repo's secrets (CRITICAL).
- AAK-AGENT-TRUST-003: a checked-in agent settings file bakes in trust /
  auto-approve (`bypassPermissions`, `autoApprove`, `yolo`, `trust: true`),
  persisting the first-use trust across every invocation and traveling with a
  fork.
- AAK-AGENT-TRUST-004: a Gemini context / instruction file (`GEMINI.md`,
  `.gemini/`) carries an embedded shell payload; the `AAK-AGENT-*` instruction
  family did not cover the Gemini surface, the agent the study exploited most.

Accuracy note: nothing here claims validation against the paper's announced
2,826-skill benchmark. That corpus is not published, so the citation is to the
measured result only, never to a dataset AAK ran against.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, NamedTuple

import yaml

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    in_skip_dir,
    find_line_number,
    load_yaml,
    make_finding,
)

_WORKFLOWS_DIR = ".github/workflows"
_MAX_FILE_BYTES = 1_000_000

# A coding-agent CLI invoked with a flag that removes the interactive
# workspace-trust / permission prompt, or a first-party agent GitHub Action
# (which runs the agent non-interactively by construction).
_HEADLESS_AGENT_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bclaude\b[^\n|&;]*?(?:\s-p\b|--print\b|--dangerously-skip-permissions\b|--permission-mode[= ]+bypassPermissions)", re.I),
    re.compile(r"\banthropics/claude-code(?:-base)?-action\b", re.I),
    re.compile(r"\bgemini\b[^\n|&;]*?(?:\s-p\b|--yolo\b|--approval-mode[= ]+yolo|-y\b)", re.I),
    re.compile(r"\b(?:google-github-actions/run-gemini-cli|google-gemini/[\w.-]*gemini[\w.-]*action)\b", re.I),
    re.compile(r"\bqwen\b[^\n|&;]*?\s-p\b", re.I),
    re.compile(r"\bcursor-agent\b", re.I),
    re.compile(r"\baider\b[^\n|&;]*?(?:--yes\b|--yolo\b)", re.I),
    re.compile(r"\bcodex\b[^\n|&;]*?(?:\bexec\b|--full-auto\b|--dangerously-bypass-approvals(?:-and-sandbox)?\b)", re.I),
    re.compile(r"\bopenai/codex-action\b", re.I),
    re.compile(r"\bopencode\b[^\n|&;]*?\brun\b", re.I),
    # Bare dangerous flags in a run step, whatever the wrapper.
    re.compile(r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals(?:-and-sandbox)?\b", re.I),
)

# Workflow triggers where the checked-out / referenced content can be
# attacker-controlled while the job holds the base repo's write-scoped token.
# Indentation is `[^\S\n]*`: from every line start in a run of blank lines `^\s*`
# read to the end of the run, so a crafted workflow grew with the square of the
# run. The match now opens on the trigger's own line; its stripped text, which
# the evidence quotes, is the same.
_UNTRUSTED_TRIGGER_RE = re.compile(
    r"^[^\S\n]*(?:-\s*)?(pull_request_target|issue_comment|workflow_run|pull_request_review_comment|pull_request_review)\b",
    re.M,
)
# An explicit checkout of the PR head ref (the classic pwn-request escalation).
_PR_HEAD_CHECKOUT_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref|repo)|github\.event\.pull_request\.head\b",
    re.I,
)

# The other way an attacker reaches a headless agent's prompt: the trigger is trusted
# (a schedule, a dispatch, a caller's `workflow_call`) and the data is not. The job fetches
# another project's commits or diff, then hands them to an agent holding write access.
_THIRD_PARTY_HINT_RE = re.compile(r"\bgit\s+(?:fetch|remote\s+add)\b|\bgh\s+api\b|api\.github\.com")
_GIT_FETCH_RE = re.compile(r"\bgit\s+fetch\b([^\n|&;]*)")
_REMOTE_ADD_RE = re.compile(r"\bgit\s+remote\s+add\b[^\n|&;]*")
_GH_API_RE = re.compile(r"\bgh\s+api\b|api\.github\.com")
_API_REPO_RE = re.compile(r"repos/(\$\{\{[^}\n]*\}\}|[^/\s\"']+(?:/[^/\s\"']+)?)/(?:compare|commits)\b")
_OWN_REPO_RE = re.compile(r"github\.repository\b|GITHUB_REPOSITORY\b|github\.event\.repository\b|\{owner\}|\{repo\}|:owner|:repo")
_SHELL_VAR_RE = re.compile(r"\$\{?(\w+)\}?")
# The Copilot agent, on top of the agents `_HEADLESS_AGENT_RES` names.
_COPILOT_AGENT_RE = re.compile(r"\bgh\s+agent-task\b|\bcopilot-swe-agent\b", re.I)
_COPILOT_CLI_RE = re.compile(r"\bcopilot\b[^\n|&;]*?\s(?:-p|--prompt|--allow-all-tools|--yolo)\b", re.I)
_COPILOT_CLI_LEAD_RE = re.compile(r"\bcopilot\b", re.I)
_SECRET_NAME_RE = re.compile(r"\bsecrets\.(\w+)")
_PAT_NAME_RE = re.compile(r"PAT|TOKEN", re.I)
_NOT_PERSONAL_RE = re.compile(r"GITHUB_TOKEN|ANTHROPIC|CLAUDE|OPENAI|GEMINI", re.I)
_WRITE_SCOPES = ("contents", "pull-requests")

# Repo-resident agent settings that persist trust / auto-approval so first-use
# trust survives every subsequent (including headless) invocation.
_SETTINGS_FILES: tuple[str, ...] = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    ".cursor/settings.json",
    ".cursor/environment.json",
    ".codex/config.toml",
    ".opencode/config.json",
)
_TRUST_FLAG_RE = re.compile(
    r'"?(?:bypassPermissions|dangerouslySkipPermissions)"?'
    r'|"permissionMode"\s*:\s*"bypassPermissions"'
    r'|"defaultMode"\s*:\s*"bypassPermissions"'
    r'|"?(?:autoApprove|auto_approve|autoExecute|auto_execute)"?\s*:\s*(?:true|\[)'
    r'|"?(?:yolo|full_auto|fullAuto)"?\s*:\s*true'
    r'|"?trust"?\s*:\s*true'
    r'|approval[_-]?mode\s*[:=]\s*"?(?:yolo|never|full-auto)"?',
    re.I,
)

# Gemini context / instruction files, auto-loaded on session start.
_GEMINI_INSTRUCTION_NAMES: tuple[str, ...] = ("GEMINI.md",)
_GEMINI_INSTRUCTION_DIRS: tuple[str, ...] = (".gemini",)
# An embedded shell payload inside an instruction file: a fenced shell block or a
# pipe-to-shell one-liner. Kept narrow so a benign GEMINI.md does not fire.
_SHELL_PAYLOAD_RE = re.compile(
    r"```(?:ba|z)?sh(?:ell)?\b|`{3}console\b|\bcurl\b[^\n]*\|\s*(?:ba|z)?sh\b"
    r"|\bwget\b[^\n]*\|\s*(?:ba|z)?sh\b|\beval\s*\(",
    re.I,
)

# Repo-resident surfaces a headless agent auto-trusts on load; named in the CI
# findings so the amplifier is tied to the surfaces the per-file scanners flag.
_AUTOTRUST_SURFACES: tuple[str, ...] = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".vscode/tasks.json",
    ".claude",
    ".cursor",
    ".gemini",
    "AGENTS.md",
    "GEMINI.md",
    "CLAUDE.md",
)


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _iter_workflows(project_root: Path) -> list[Path]:
    wf_dir = project_root / _WORKFLOWS_DIR
    if not wf_dir.is_dir():
        return []
    return sorted(
        p for p in wf_dir.iterdir()
        if p.is_file() and p.suffix in (".yml", ".yaml")
    )


def _present_surfaces(project_root: Path) -> list[str]:
    return [s for s in _AUTOTRUST_SURFACES if (project_root / s).exists()]


# The patterns that open with a CLI name and read on with `[^\n|&;]*?` to a flag.
# Every such opening in one stretch of a line (up to a newline, `|`, `&` or `;`)
# reads to the same end, so a later opening can match only if the stretch's
# first one does, and that one would match first. Trying only the first opening
# per stretch keeps the search linear (a line of `claude claude claude ...` used
# to read to its end from every word) and finds the same match.
_STRETCH_READ = r"[^\n|&;]*?"
# Each such pattern's opening, the part before its `[^\n|&;]*?` (`\bclaude\b`).
_CLI_LEADS = {
    rx: re.compile(rx.pattern[: rx.pattern.index(_STRETCH_READ)], rx.flags)
    for rx in _HEADLESS_AGENT_RES
    if _STRETCH_READ in rx.pattern
}
_STRETCH_END_RE = re.compile(r"[\n|&;]")


def _first_per_stretch(rx: re.Pattern[str], lead: re.Pattern[str], text: str) -> re.Match[str] | None:
    pos = 0
    while True:
        opening = lead.search(text, pos)
        if opening is None:
            return None
        m = rx.match(text, opening.start())
        if m:
            return m
        stop = _STRETCH_END_RE.search(text, opening.end())
        if stop is None:
            return None
        pos = stop.end()


def _headless_hit(text: str) -> re.Match[str] | None:
    for rx in _HEADLESS_AGENT_RES:
        lead = _CLI_LEADS.get(rx)
        m = _first_per_stretch(rx, lead, text) if lead else rx.search(text)
        if m:
            return m
    return None


class _ThirdPartyAgent(NamedTuple):
    job: str
    agent: str
    fetch: str
    credential: str


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps")
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _env_block(block: dict[str, Any]) -> dict[str, Any]:
    env = block.get("env")
    return env if isinstance(env, dict) else {}


def _elsewhere(subject: str, envs: tuple[dict[str, Any], ...]) -> bool:
    """Does a `repos/<subject>/...` path name a repository other than this one?"""
    if _OWN_REPO_RE.search(subject):
        return False
    for name in _SHELL_VAR_RE.findall(subject):
        for env in envs:
            value = env.get(name)
            if isinstance(value, str) and _OWN_REPO_RE.search(value):
                return False
    return True


def _fetch_in_step(run: str, envs: tuple[dict[str, Any], ...]) -> str | None:
    for match in _GIT_FETCH_RE.finditer(run):
        words = [w.strip("\"'") for w in match.group(1).split() if not w.startswith("-") and not w.isdigit()]
        if words and "origin" not in words:
            return match.group(0).strip()
    remote = _REMOTE_ADD_RE.search(run)
    if remote:
        return remote.group(0).strip()
    for line in run.splitlines():
        if _GH_API_RE.search(line):
            for match in _API_REPO_RE.finditer(line):
                if _elsewhere(match.group(1), envs):
                    return match.group(0)
    return None


def _third_party_fetch(doc: dict[str, Any], jobs: dict[str, Any]) -> str | None:
    doc_env = _env_block(doc)
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_env = _env_block(job)
        for step in _steps(job):
            run = step.get("run")
            found = _fetch_in_step(run, (_env_block(step), job_env, doc_env)) if isinstance(run, str) else None
            if found:
                return found
    return None


def _agent_in_job(job: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    for step in _steps(job):
        text = " ".join(v for v in (step.get("uses"), step.get("run")) if isinstance(v, str))
        hit = (
            _headless_hit(text)
            or _COPILOT_AGENT_RE.search(text)
            or _first_per_stretch(_COPILOT_CLI_RE, _COPILOT_CLI_LEAD_RE, text)
        )
        if hit:
            return hit.group(0).strip(), step
    return None


def _personal_token(values: Any) -> str | None:
    """The first personal token named among these values."""
    for value in values:
        if isinstance(value, str):
            for name in _SECRET_NAME_RE.findall(value):
                if _PAT_NAME_RE.search(name) and not _NOT_PERSONAL_RE.search(name):
                    return name
    return None


def _write_credential(
    doc: dict[str, Any], job: dict[str, Any], step: dict[str, Any], workflow_token: str | None,
) -> str | None:
    """The write scope the agent's job holds, or a personal token handed to the agent."""
    permissions = job["permissions"] if "permissions" in job else doc.get("permissions")
    if permissions == "write-all":
        return "`permissions: write-all`"
    if isinstance(permissions, dict):
        for scope in _WRITE_SCOPES:
            if permissions.get(scope) == "write":
                return f"`{scope}: write`"
    with_block = step.get("with")
    with_values = with_block.values() if isinstance(with_block, dict) else ()
    token = (
        _personal_token(_env_block(step).values())
        or _personal_token(with_values)
        or _personal_token(_env_block(job).values())
        or workflow_token
    )
    return f"the personal token `secrets.{token}`" if token else None


def _egress_blocked(job: dict[str, Any]) -> bool:
    for step in _steps(job):
        uses = step.get("uses")
        with_block = step.get("with")
        if isinstance(uses, str) and "step-security/harden-runner" in uses and isinstance(with_block, dict) \
                and with_block.get("egress-policy") == "block":
            return True
    return False


def _third_party_agent(text: str, path: Path) -> _ThirdPartyAgent | None:
    """A job that gives an agent write access in a workflow that fetches another project's commits."""
    if not _THIRD_PARTY_HINT_RE.search(text):
        return None
    try:
        doc = load_yaml(text, path)
    except yaml.YAMLError:
        return None
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        return None
    fetch = _third_party_fetch(doc, jobs)
    if fetch is None:
        return None
    workflow_token = _personal_token(_env_block(doc).values())
    for name, job in jobs.items():
        agent = _agent_in_job(job) if isinstance(job, dict) else None
        if agent is None or _egress_blocked(job):
            continue
        credential = _write_credential(doc, job, agent[1], workflow_token)
        if credential:
            return _ThirdPartyAgent(str(name), agent[0], fetch, credential)
    return None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for the agent config/skill auto-trust surface (AAK-AGENT-TRUST-*).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (findings, set of scanned file paths relative to
        ``project_root``). This used to return the rule ids the scanner
        evaluates, which the engine unions into ``files_scanned`` -- so an
        empty directory reported four files that do not exist (issue #743).
        Rule coverage is computed separately, from the active rule set.
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    surfaces = _present_surfaces(project_root)
    surface_note = (
        " Repo-resident surfaces a headless run would trust: "
        + ", ".join(surfaces)
        if surfaces
        else ""
    )

    # --- AAK-AGENT-TRUST-001 / 002: coding agent run headless in CI -----------
    for wf in _iter_workflows(project_root):
        text = _read(wf)
        if not text:
            continue
        scanned.add(wf.relative_to(project_root).as_posix())
        rel = wf.relative_to(project_root).as_posix()
        hit = _headless_hit(text)
        untrusted = hit and (_UNTRUSTED_TRIGGER_RE.search(text) or _PR_HEAD_CHECKOUT_RE.search(text))
        third_party = None if untrusted else _third_party_agent(text, wf)
        if third_party:
            findings.append(
                make_finding(
                    "AAK-AGENT-TRUST-002",
                    rel,
                    f"job {third_party.job!r} runs an agent ({third_party.agent[:80]!r}) holding "
                    f"{third_party.credential}, in a workflow that fetches another project's commits "
                    f"({third_party.fetch[:80]!r}), with no egress block. Whoever can land a commit "
                    f"upstream writes part of this agent's prompt." + surface_note,
                    find_line_number(text, third_party.agent.split()[0]),
                )
            )
            continue
        if not hit:
            continue
        line = find_line_number(text, hit.group(0).strip().split()[0])
        if untrusted:
            findings.append(
                make_finding(
                    "AAK-AGENT-TRUST-002",
                    rel,
                    f"headless agent invocation ({hit.group(0).strip()[:80]!r}) in a "
                    f"workflow that runs on an attacker-controllable ref "
                    f"({untrusted.group(0).strip()!r}). A fork PR's skill / config "
                    f"files execute with this repo's secrets, no trust prompt."
                    + surface_note,
                    line,
                )
            )
        else:
            findings.append(
                make_finding(
                    "AAK-AGENT-TRUST-001",
                    rel,
                    f"coding-agent CLI run non-interactively in CI "
                    f"({hit.group(0).strip()[:80]!r}); the workspace-trust prompt is "
                    f"absent, so repo-resident skill / config / tasks files are "
                    f"trusted on load." + surface_note,
                    line,
                )
            )

    # --- AAK-AGENT-TRUST-003: settings bake in trust / auto-approve -----------
    for rel_name in _SETTINGS_FILES:
        p = project_root / rel_name
        if not p.is_file():
            continue
        text = _read(p)
        if not text:
            continue
        scanned.add(rel_name)
        m = _TRUST_FLAG_RE.search(text)
        if m:
            findings.append(
                make_finding(
                    "AAK-AGENT-TRUST-003",
                    rel_name,
                    f"checked-in agent settings persist trust / auto-approval "
                    f"({m.group(0).strip()[:60]!r}); first-use trust survives every "
                    f"invocation, including a headless CI run, and travels with a fork.",
                    find_line_number(text, m.group(0).strip()),
                )
            )

    # --- AAK-AGENT-TRUST-004: Gemini instruction file with a shell payload -----
    gemini_files: list[Path] = []
    for name in _GEMINI_INSTRUCTION_NAMES:
        p = project_root / name
        if p.is_file():
            gemini_files.append(p)
    for d in _GEMINI_INSTRUCTION_DIRS:
        gdir = project_root / d
        if gdir.is_dir():
            for p in gdir.rglob("*.md"):
                if p.is_file() and not in_skip_dir(p, project_root):
                    gemini_files.append(p)
    for p in gemini_files:
        text = _read(p)
        if not text:
            continue
        scanned.add(p.relative_to(project_root).as_posix())
        m = _SHELL_PAYLOAD_RE.search(text)
        if m:
            findings.append(
                make_finding(
                    "AAK-AGENT-TRUST-004",
                    p.relative_to(project_root).as_posix(),
                    f"Gemini context/instruction file carries an embedded shell "
                    f"payload ({m.group(0).strip()[:40]!r}); Gemini auto-loads it as "
                    f"context and the study measured this surface exploited in "
                    f"95.5-96.1% of runs.",
                    find_line_number(text, m.group(0).strip()),
                )
            )

    return findings, scanned
