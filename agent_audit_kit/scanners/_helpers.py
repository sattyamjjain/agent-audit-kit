from __future__ import annotations

import re
from pathlib import Path
from typing import AbstractSet

from agent_audit_kit.models import Finding
from agent_audit_kit.rules.builtin import get_rule

# Interpolation of a caller-controlled variable into a command / shell string.
# Shared by hook_rce and ide_task_rce so there is exactly ONE definition of the
# "user input reaches a command string" signature (promoted here from
# hook_rce.py, which now imports it).
INTERPOLATION_RE = re.compile(
    r"""(?:["']\s*\+\s*|\$\{|%\{|{{\s*|\$\(|`)\s*(?:input|args|event|payload|user|argv|request)""",
    re.IGNORECASE,
)

SKIP_DIRS = frozenset({
    "node_modules", ".git", "dist", "build", "__pycache__",
    ".next", ".nuxt", "vendor", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "target", "out", ".terraform",
})


def in_skip_dir(
    path: Path,
    root: Path,
    skip_dirs: AbstractSet[str] = SKIP_DIRS,
) -> bool:
    """True when a component of `path` *below* `root` is in `skip_dirs`.

    A skip list exists to keep vendored and generated trees inside the project
    (`node_modules/`, `build/`, `.venv/`) out of the scan. Every scanner used to
    test all of `path.parts`, and on an absolute path that includes the
    directories the project itself lives in. A checkout under a directory with
    one of those names therefore lost every finding from every scanner that
    walked the tree that way. That is not a corner case: Bitbucket Pipelines
    clones into `/opt/atlassian/pipelines/agent/build`, Travis into
    `/home/travis/build/<owner>/<repo>`, and `aak scan .` resolves the path
    before any scanner sees it. The scan then reported a clean project and
    said nothing about what it had skipped: a false all-clear, the worst
    answer a security scanner can give.

    The root is the directory the user chose to scan, so it can never itself
    be "vendored"; only the parts below it are tested. A `node_modules/` or
    `build/` inside the project is skipped exactly as before.

    A path that is not under `root` (a resolved symlink target, an explicit
    user-config path such as `~/.cursor/mcp.json`) has no parts below the root
    and is never skipped: it was named on purpose, and skipping it on the
    strength of its own ancestors would be this bug again. Neither case raises.
    A relative `path` that is not under `root` is taken as already relative to
    it, which is what a caller holding a `relative_to(project_root)` result
    has. When the lexical comparison fails for an absolute path, both sides
    are resolved before giving up, so a `/var` vs `/private/var` spelling of
    one directory still counts as under the root.

    This is for skip lists only. A check that classifies a file by an enclosing
    directory (`hook_rce`'s `.claude/hooks`, `mcp_config`'s `.windsurf`) may
    look above the root on purpose: `aak scan ~/.claude` depends on the root's
    own name. `tests/test_skip_dirs.py` fails on a scanner that tests a skip set
    against `.parts` by hand instead of calling this.
    """
    return any(part in skip_dirs for part in _parts_below(path, root))


def _parts_below(path: Path, root: Path) -> tuple[str, ...]:
    """The components of `path` below `root`; `()` when it is not under it."""
    try:
        return path.relative_to(root).parts
    except ValueError:
        pass
    if not path.is_absolute():
        return path.parts
    try:
        return path.resolve().relative_to(root.resolve()).parts
    except (OSError, RuntimeError, ValueError):
        # RuntimeError: a symlink loop on Python < 3.13 (3.13 raises OSError).
        return ()


def find_line_number(raw: str, key: object) -> int | None:
    """Locate `key` in `raw`, tolerating a non-string key.

    Callers pass a value straight out of parsed JSON, and a malformed config can
    put an int or a list where the MCP schema says string. Substring search then
    raised TypeError and took the whole scanner down (issue #743). The value is
    only ever used to point a finding at a line, so coercing is the right
    trade: a wrong-typed key simply fails to match and the finding carries no
    line number, which is what a missing match already did.
    """
    if not isinstance(key, str):
        key = str(key)
    if not key:
        return None
    for i, line in enumerate(raw.splitlines(), 1):
        if key in line:
            return i
    return None


def make_finding(
    rule_id: str,
    file_path: str,
    evidence: str,
    line_number: int | None = None,
    related_locations: list[dict] | None = None,
) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        category=rule.category,
        file_path=file_path,
        line_number=line_number,
        evidence=evidence,
        remediation=rule.remediation,
        cve_references=rule.cve_references,
        owasp_mcp_references=rule.owasp_mcp_references,
        owasp_agentic_references=rule.owasp_agentic_references,
        adversa_references=rule.adversa_references,
        incident_references=rule.incident_references,
        aicm_references=rule.aicm_references,
        owasp_ast_references=rule.owasp_ast_references,
        related_locations=related_locations or [],
    )
