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

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    SKIP_DIRS,
    find_line_number,
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
_UNTRUSTED_TRIGGER_RE = re.compile(
    r"^\s*(?:-\s*)?(pull_request_target|issue_comment|workflow_run|pull_request_review_comment|pull_request_review)\b",
    re.M,
)
# An explicit checkout of the PR head ref (the classic pwn-request escalation).
_PR_HEAD_CHECKOUT_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref|repo)|github\.event\.pull_request\.head\b",
    re.I,
)

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


def _headless_hit(text: str) -> re.Match[str] | None:
    for rx in _HEADLESS_AGENT_RES:
        m = rx.search(text)
        if m:
            return m
    return None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for the agent config/skill auto-trust surface (AAK-AGENT-TRUST-*).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (findings, set of rule ids this scanner evaluates).
    """
    findings: list[Finding] = []
    evaluated = {
        "AAK-AGENT-TRUST-001",
        "AAK-AGENT-TRUST-002",
        "AAK-AGENT-TRUST-003",
        "AAK-AGENT-TRUST-004",
    }

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
        hit = _headless_hit(text)
        if not hit:
            continue
        rel = wf.relative_to(project_root).as_posix()
        line = find_line_number(text, hit.group(0).strip().split()[0])
        untrusted = _UNTRUSTED_TRIGGER_RE.search(text) or _PR_HEAD_CHECKOUT_RE.search(text)
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
                if p.is_file() and not any(part in SKIP_DIRS for part in p.parts):
                    gemini_files.append(p)
    for p in gemini_files:
        text = _read(p)
        if not text:
            continue
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

    return findings, evaluated
