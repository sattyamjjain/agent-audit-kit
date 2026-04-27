"""AAK-PRTITLE-IPI-001 — PR-title / issue-title indirect prompt injection.

Aonan Guan's 2026-04-25 Comment-and-Control disclosure (CVSS 9.4)
spread credential-theft payloads across Claude Code Security Review,
Gemini CLI Action, and GitHub Copilot Agent. The exploit shape: an
attacker opens a PR whose title contains an injected instruction; the
review agent reads the title, builds an LLM prompt by string-concat,
and the LLM follows the injected instruction with the agent's
credentials.

This rule fires when a function pulls a title-like field from a
GitHub-event source and feeds it into a known LLM client call without
HTML-escape, code-fencing, or a sanitiser pass.

Sources:

- https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
- https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


# Title-shape sources from GitHub event payloads, env vars, gh CLI.
_TITLE_SOURCE_RE = re.compile(
    r"""
    (?:
        pull_request\s*\.\s*title
      | pull_request\s*\.\s*head\s*\.\s*ref
      | issue\s*\.\s*title
      | event\s*\.\s*pull_request\s*\.\s*title
      | event\s*\.\s*issue\s*\.\s*title
      | github\.event\.pull_request\.title
      | github\.event\.issue\.title
      | os\.environ\[\s*['"]PR_TITLE['"]\s*\]
      | os\.environ\[\s*['"]GITHUB_HEAD_REF['"]\s*\]
      | os\.getenv\(\s*['"]PR_TITLE['"]
      | os\.getenv\(\s*['"]GITHUB_HEAD_REF['"]
      | gh\s+pr\s+view.*?title
    )
    """,
    re.VERBOSE | re.DOTALL,
)

# LLM client call shapes that turn a string into model output.
_LLM_SINK_RE = re.compile(
    r"""
    (?:
        anthropic\s*\.\s*\w*\s*\.?\s*(?:messages\.create|completions\.create|create)
      | client\s*\.\s*messages\s*\.\s*create
      | openai\s*\.\s*chat\s*\.\s*completions\s*\.\s*create
      | openai\s*\.\s*ChatCompletion\.create
      | openai\s*\.\s*Completion\.create
      | genai\s*\.\s*GenerativeModel
      | model\s*\.\s*generate_content
      | langchain\s*\.\s*\w+\s*\.\s*(?:invoke|run|call)
      | LLMChain\s*\(
      | ChatAnthropic\s*\(
      | ChatOpenAI\s*\(
      | LLM\s*\(\s*\)\s*\.\s*invoke
      | claude_agent_sdk\.\s*\w+
    )
    """,
    re.VERBOSE,
)

# Sanitiser markers — if any of these appear between source and sink in
# the same function, we suppress.
_SANITIZE_RE = re.compile(
    r"""
    (?:
        html\.escape\s*\(
      | bleach\.clean\s*\(
      | markupsafe\.escape\s*\(
      | re\.sub\s*\([^)]*['"][^'"]*\\\\\\\\[a-z][^'"]*['"]
      | json\.dumps\s*\(
      | shlex\.quote\s*\(
      | hashlib\.\w+\s*\(
      | re\.escape\s*\(
      | \.replace\s*\(\s*['"]<['"]
      | sanitize|sanitise|escape_html|escape_md
      | ALLOWED_TITLE|TITLE_ALLOWLIST|TITLE_REGEX
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Per-function: title source seen + LLM sink seen + no sanitiser → fire."""
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def _scan(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            lines = text.splitlines()
            start = max(0, func.lineno - 1)
            end = min(len(lines), (func.end_lineno or func.lineno))
            body = "\n".join(lines[start:end])
            if not _TITLE_SOURCE_RE.search(body):
                return
            if not _LLM_SINK_RE.search(body):
                return
            if _SANITIZE_RE.search(body):
                return
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            # Locate the title source line.
            m = _TITLE_SOURCE_RE.search(body)
            line_no = func.lineno + (body.count("\n", 0, m.start()) if m else 0)
            findings.append(make_finding(
                "AAK-PRTITLE-IPI-001",
                rel,
                "PR/issue title flows into an LLM client call without "
                "HTML-escape, code-fencing, or allowlist validation. "
                "Comment-and-Control class (CVSS 9.4 — Aonan Guan "
                "2026-04-25): an attacker-controlled title injects "
                "instructions the agent executes with its own creds.",
                line_number=line_no,
            ))

    V().visit(tree)
    return findings


def _walk_ts(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Regex pass for TS/JS — title source + LLM sink within 4KB window."""
    findings: list[Finding] = []
    title_match = _TITLE_SOURCE_RE.search(text)
    if title_match is None:
        return findings
    sink_match = _LLM_SINK_RE.search(text)
    if sink_match is None:
        return findings
    if _SANITIZE_RE.search(text):
        return findings
    rel = str(path.relative_to(project_root))
    scanned.add(rel)
    line = text.count("\n", 0, title_match.start()) + 1
    findings.append(make_finding(
        "AAK-PRTITLE-IPI-001",
        rel,
        "PR/issue title source reaches an LLM client call without a "
        "sanitiser in this file (TS/JS). Comment-and-Control class.",
        line_number=line,
    ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            findings.extend(_walk_python(text, path, project_root, scanned))
        elif suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            findings.extend(_walk_ts(text, path, project_root, scanned))
    return findings, scanned
