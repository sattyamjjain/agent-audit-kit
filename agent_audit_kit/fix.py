from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES


@dataclass
class FixAction:
    """Represents an auto-fix action applied (or proposed) for a finding.

    Attributes:
        rule_id: The rule ID that triggered the fix.
        file_path: Path to the file that was fixed.
        description: Human-readable description of the fix.
        applied: Whether the fix was actually applied (False in dry-run).
    """

    rule_id: str
    file_path: str
    description: str
    applied: bool = False


def run_fixes(project_root: Path, dry_run: bool = False) -> list[FixAction]:
    """Run auto-fixes for all fixable findings in a project.

    Performs a scan, identifies findings for rules marked as
    ``auto_fixable``, and applies the corresponding fix logic.
    When fixes are actually applied (not dry-run), a log file is
    written to ``.agent-audit-kit/fix-log.json``.

    Args:
        project_root: The project root directory to scan and fix.
        dry_run: If True, report what would be fixed without modifying
            any files.

    Returns:
        A list of FixAction objects describing what was (or would be)
        fixed.
    """
    result = run_scan(project_root=project_root)
    fixable_rules = {rid for rid, rule in RULES.items() if rule.auto_fixable}
    fixes: list[FixAction] = []

    for finding in result.findings:
        if finding.rule_id not in fixable_rules:
            continue
        fix = _apply_fix(project_root, finding.rule_id, finding.file_path, dry_run)
        if fix:
            fixes.append(fix)

    if not dry_run and fixes:
        _write_fix_log(project_root, fixes)

    return fixes


def _write_fix_log(project_root: Path, fixes: list[FixAction]) -> None:
    """Write a JSON log of applied fixes to .agent-audit-kit/fix-log.json.

    Args:
        project_root: The project root directory.
        fixes: List of FixAction objects that were applied.
    """
    log_dir = project_root / ".agent-audit-kit"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "fix-log.json"

    log_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "fixes_applied": [
            {
                "rule_id": fix.rule_id,
                "file": fix.file_path,
                "description": fix.description,
            }
            for fix in fixes
            if fix.applied
        ],
    }
    log_file.write_text(json.dumps(log_data, indent=2) + "\n")


def _apply_fix(
    project_root: Path,
    rule_id: str,
    file_path: str,
    dry_run: bool,
) -> FixAction | None:
    """Dispatch to the appropriate fix function for a given rule.

    Args:
        project_root: The project root directory.
        rule_id: The rule ID to fix.
        file_path: Relative path to the file containing the finding.
        dry_run: If True, do not modify files.

    Returns:
        A FixAction if a fix was attempted, or None if not applicable.
    """
    full_path = project_root / file_path
    if not full_path.is_file():
        return None

    if rule_id == "AAK-TRUST-001":
        return _fix_enable_all_mcp(full_path, dry_run)
    elif rule_id == "AAK-TRUST-004":
        return _fix_missing_deny(full_path, dry_run)
    elif rule_id == "AAK-TRUST-007":
        return _fix_missing_allowlist(full_path, dry_run)
    elif rule_id == "AAK-SECRET-006":
        return _fix_env_gitignore(project_root, dry_run)
    elif rule_id == "AAK-SECRET-007":
        return _fix_secret_env_ref(full_path, dry_run)
    elif rule_id in ("AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003"):
        return _fix_langchain_version(full_path, rule_id, dry_run)
    elif rule_id == "AAK-LITELLM-CVE-2026-30623-PIN-001":
        return _fix_litellm_version(full_path, dry_run)
    elif rule_id in _DEPENDENCY_FLOORS:
        return _fix_dependency_floor(full_path, rule_id, dry_run)
    elif rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001":
        return _fix_langgraph_toolnode(full_path, dry_run)
    return None


# ---------------------------------------------------------------------------
# CVE auto-remediations (--cve flag)
# ---------------------------------------------------------------------------

_CVE_FIXABLE_RULES: frozenset[str] = frozenset({
    "AAK-LANGCHAIN-001",  # CVE-2026-34070 — bump langchain-core >=1.2.22
    "AAK-LANGCHAIN-003",  # CVE-2025-68664 — bump langchain-core >=0.3.14
    "AAK-LITELLM-CVE-2026-30623-PIN-001",  # CVE-2026-30623 — bump litellm >=1.83.7
})

# Both floors are langchain-core's, so both bumps rewrite that one distribution,
# in any PEP 503 spelling, the same name `langchain_vuln` reports.
_LANGCHAIN_MIN_VERSIONS = {
    "AAK-LANGCHAIN-001": ("1.2.22", r"langchain[-_.]+core"),
    "AAK-LANGCHAIN-003": ("0.3.14", r"langchain[-_.]+core"),
}


def run_cve_fixes(project_root: Path, dry_run: bool = True) -> list[FixAction]:
    """Apply the `--cve` subset of auto-fixes.

    Scope is deliberately narrow: only rules where the remediation is
    mechanical (version bump in a lockfile or manifest). Any rule that
    needs a code change — auth-bypass handlers, SSRF hardening, OAuth
    scope reshuffles — is refused here, because false confidence kills
    scanners (ROADMAP §5).

    Args:
        project_root: project to fix.
        dry_run: if True, report proposed fixes without modifying files.
    """
    result = run_scan(project_root=project_root)
    fixes: list[FixAction] = []
    for finding in result.findings:
        if finding.rule_id not in _CVE_FIXABLE_RULES:
            continue
        fix = _apply_fix(project_root, finding.rule_id, finding.file_path, dry_run)
        if fix:
            fixes.append(fix)
    if not dry_run and fixes:
        _write_fix_log(project_root, fixes)
    return fixes


def _fix_langchain_version(path: Path, rule_id: str, dry_run: bool) -> FixAction:
    """Bump a vulnerable langchain-core pin to the patched version.

    Rewrites requirements.txt / requirements-*.txt line by line. The rules
    read only Python manifests, so there is no package.json case. poetry's
    pyproject.toml and uv.lock are intentionally out of scope because their
    locking semantics make a naive text bump unsafe.
    """
    import re as _re

    min_version, name_pattern = _LANGCHAIN_MIN_VERSIONS[rule_id]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return FixAction(rule_id, str(path), "Unable to read file", False)

    if path.name.endswith(".txt"):
        pin_re = _re.compile(
            rf"^(\s*)({name_pattern})\s*(?:==|>=|<=|<|>|~=|!=)?\s*([0-9][0-9a-zA-Z.\-_]*)",
            _re.MULTILINE | _re.IGNORECASE,
        )
        floor = tuple(int(n) for n in min_version.split("."))
        count = 0

        def _bump(m: _re.Match[str]) -> str:
            # Never lower a pin. AAK-LANGCHAIN-001 and -003 both rewrite
            # langchain-core, and whichever runs second must leave the higher
            # floor the first one wrote.
            nonlocal count
            current = tuple(int(n) for n in _re.findall(r"\d+", m.group(3))[:3])
            if current >= floor:
                return m.group(0)
            count += 1
            return f"{m.group(1)}{m.group(2)}>={min_version}"

        new_text = pin_re.sub(_bump, text)
        if count == 0:
            return FixAction(rule_id, str(path), "No langchain-core pin below the fix", False)
        if not dry_run:
            path.write_text(new_text, encoding="utf-8")
        return FixAction(
            rule_id,
            str(path),
            f"Bumped {count} langchain-core pin(s) to >={min_version}",
            not dry_run,
        )

    return FixAction(
        rule_id,
        str(path),
        f"{path.name} is not a supported manifest for auto-bump",
        False,
    )


def _fix_litellm_version(path: Path, dry_run: bool) -> FixAction:
    """Bump a vulnerable litellm pin to 1.83.7 (CVE-2026-30623).

    Same posture as `_fix_langchain_version`: rewrite line-based
    requirements*.txt manifests in place; refuse to touch lockfiles
    or pyproject.toml because their locking semantics make a naive
    text bump unsafe.
    """
    import re as _re

    rule_id = "AAK-LITELLM-CVE-2026-30623-PIN-001"
    min_version = "1.83.7"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return FixAction(rule_id, str(path), "Unable to read file", False)

    if path.name.endswith(".txt"):
        pin_re = _re.compile(
            r"^(\s*)(litellm)\s*(?:==|>=|<=|<|>|~=|!=)?\s*[0-9][0-9a-zA-Z.\-_]*",
            _re.MULTILINE | _re.IGNORECASE,
        )
        new_text, count = pin_re.subn(rf"\1\2>={min_version}", text)
        if count == 0:
            return FixAction(rule_id, str(path), "No matching litellm pin", False)
        if not dry_run:
            path.write_text(new_text, encoding="utf-8")
        return FixAction(
            rule_id,
            str(path),
            f"Bumped {count} litellm pin(s) to >={min_version}",
            not dry_run,
        )

    return FixAction(
        rule_id,
        str(path),
        f"{path.name} is not a supported manifest for auto-bump "
        "(only requirements*.txt is line-safe to rewrite)",
        False,
    )


# Dependency floor bumps that had an AUTO_PR_ALLOWLIST entry but no recipe, so
# `aak fix` silently did nothing and `suggest --auto-pr` could never reach them
# (run_fixes -> _apply_fix returned None, so they never entered `pending`).
# rule_id -> (package-name regex, minimum version, label used in the FixAction)
_DEPENDENCY_FLOORS: dict[str, tuple[str, str, str]] = {
    # Pin floor is the highest fixed version, matching _FLOWISE_PATCHED_VERSION in
    # scanners/stdio_injection.py, so 3.1.0/3.1.1/3.1.2 stay flagged for the CVEs
    # they remain exposed to.
    "AAK-FLOWISE-001": (r"flowise(?:-components)?", "3.1.3", "flowise"),
    # CVE-2026-35402, patched in 0.6.0 — see scanners/neo4j_cve.py.
    "AAK-NEO4J-001": (r"mcp-neo4j-cypher", "0.6.0", "mcp-neo4j-cypher"),
}


def _fix_dependency_floor(path: Path, rule_id: str, dry_run: bool) -> FixAction:
    """Raise a vulnerable dependency to its vendor-published fixed version.

    Same posture as ``_fix_langchain_version``: rewrite line-based
    ``requirements*.txt`` and the ``package.json`` dependency maps, and refuse
    lockfiles or poetry's ``pyproject.toml``, whose locking semantics make a naive
    text bump unsafe.
    """
    name_pattern, min_version, label = _DEPENDENCY_FLOORS[rule_id]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return FixAction(rule_id, str(path), "Unable to read file", False)

    if path.name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return FixAction(rule_id, str(path), "package.json is not valid JSON", False)
        bumped = 0
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name in list(deps):
                if re.fullmatch(name_pattern, dep_name):
                    deps[dep_name] = f">={min_version}"
                    bumped += 1
        if bumped == 0:
            return FixAction(rule_id, str(path), f"No matching {label} dep found", False)
        if not dry_run:
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return FixAction(
            rule_id,
            str(path),
            f"Bumped {bumped} {label} dep(s) to >={min_version} (package.json)",
            not dry_run,
        )

    if path.name.endswith(".txt"):
        pin_re = re.compile(
            rf"^(\s*)({name_pattern})\s*(?:==|>=|<=|<|>|~=|!=)?\s*[0-9][0-9a-zA-Z.\-_]*",
            re.MULTILINE | re.IGNORECASE,
        )
        new_text, count = pin_re.subn(rf"\1\2>={min_version}", text)
        if count == 0:
            return FixAction(rule_id, str(path), f"No matching {label} pin", False)
        if not dry_run:
            path.write_text(new_text, encoding="utf-8")
        return FixAction(
            rule_id,
            str(path),
            f"Bumped {count} {label} pin(s) to >={min_version}",
            not dry_run,
        )

    return FixAction(
        rule_id,
        str(path),
        f"{path.name} is not a supported manifest for auto-bump "
        "(only requirements*.txt and package.json are safe to rewrite)",
        False,
    )


def _fix_langgraph_toolnode(path: Path, dry_run: bool) -> FixAction | None:
    """Apply the ``ToolNode([...]) -> ToolNode(tools=[...])`` codemod.

    The codemod itself already lived in ``autofix/langgraph_toolnode.py`` but was
    only reachable from ``suggest --apply-trivial``, so the rule's
    ``AUTO_PR_ALLOWLIST`` entry was dead: ``run_fixes`` never produced an action for
    it. Wiring it here makes the existing claim true.

    Returns None when the codemod is a no-op, so an unchanged file never reports as
    a fix (the rewrite is idempotent, so re-running is safe).
    """
    from agent_audit_kit.autofix.langgraph_toolnode import fix as _toolnode_fix

    rule_id = "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return FixAction(rule_id, str(path), "Unable to read file", False)

    new_text = _toolnode_fix(text)
    if new_text == text:
        return None
    if not dry_run:
        try:
            path.write_text(new_text, encoding="utf-8")
        except OSError:
            return FixAction(rule_id, str(path), "Failed to fix", False)
    return FixAction(
        rule_id,
        str(path),
        "Rewrote ToolNode(positional list) to ToolNode(tools=[...])",
        not dry_run,
    )


def _fix_enable_all_mcp(path: Path, dry_run: bool) -> FixAction:
    """Set enableAllProjectMcpServers to false."""
    try:
        data = json.loads(path.read_text())
        data["enableAllProjectMcpServers"] = False
        if not dry_run:
            path.write_text(json.dumps(data, indent=2) + "\n")
        return FixAction(
            "AAK-TRUST-001",
            str(path),
            "Set enableAllProjectMcpServers to false",
            not dry_run,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-001", str(path), "Failed to fix", False)


def _fix_missing_deny(path: Path, dry_run: bool) -> FixAction:
    """Add default deny rules to the permissions block."""
    try:
        data = json.loads(path.read_text())
        perms = data.setdefault("permissions", {})
        if not perms.get("deny"):
            perms["deny"] = [
                "Bash(rm -rf *)",
                "Bash(curl *)",
                "Bash(wget *)",
            ]
            if not dry_run:
                path.write_text(json.dumps(data, indent=2) + "\n")
        return FixAction(
            "AAK-TRUST-004",
            str(path),
            "Added default deny rules",
            not dry_run,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-004", str(path), "Failed to fix", False)


def _fix_missing_allowlist(path: Path, dry_run: bool) -> FixAction:
    """Add an empty enabledMcpjsonServers allowlist."""
    try:
        data = json.loads(path.read_text())
        if "enabledMcpjsonServers" not in data:
            data["enabledMcpjsonServers"] = []
            if not dry_run:
                path.write_text(json.dumps(data, indent=2) + "\n")
        return FixAction(
            "AAK-TRUST-007",
            str(path),
            "Added empty enabledMcpjsonServers allowlist",
            not dry_run,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-007", str(path), "Failed to fix", False)


def _fix_secret_env_ref(path: Path, dry_run: bool) -> FixAction | None:
    """Replace a literal secret in an MCP server ``env`` block with ``${KEY}``.

    Mechanical by this project's own bar (see ``autopr.AUTO_PR_ALLOWLIST``): the edit
    has exactly one correct form, because the variable name is already present as the
    JSON key, and a reviewer confirms it from the diff without reading the program.

    The substitution is the exact inverse of the detection predicate in
    ``scanners/secret_exposure.py`` — same ``MCP_ENV_SECRET_KEYS`` pattern, imported
    rather than restated so the fix cannot drift from what fires. That matters: the
    rule stops firing because the literal is genuinely gone, not because a key the
    client ignores was added. Adding an ignored key is the v0.3.78 defect
    (``deny_stdio_transport``), and this is deliberately the opposite shape.

    The ``${VAR}`` form is attested, not invented: 158 env values across the 748
    public configs in ``benchmarks/data`` already use it, overwhelmingly as
    ``KEY = ${KEY}``.

    Deliberately NOT in ``AUTO_PR_ALLOWLIST``: the server stops working until the
    operator exports the variable, and whether that is a fix or an outage is a
    deployment fact AAK cannot see — the same reason the bind-address swap is listed
    in ``autopr.NON_MECHANICAL``. It is a recipe ``aak fix`` will apply on request,
    not something AAK pushes.

    Returns None when nothing matched, so a no-op never reports as a fix.
    """
    # Imported here rather than at module scope to keep fix.py free of a hard
    # dependency on any individual scanner module.
    from agent_audit_kit.scanners.secret_exposure import MCP_ENV_SECRET_KEYS

    try:
        original = path.read_text()
        data = json.loads(original)
    except (json.JSONDecodeError, OSError):
        return None

    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return None

    rewritten: list[str] = []
    for server_cfg in servers.values():
        if not isinstance(server_cfg, dict):
            continue
        env = server_cfg.get("env")
        if not isinstance(env, dict):
            continue
        for key, value in list(env.items()):
            if not isinstance(value, str) or not value:
                continue
            if not MCP_ENV_SECRET_KEYS.search(key):
                continue
            if re.match(r"^\$\{.+\}$", value):
                continue  # already a reference
            env[key] = "${" + key + "}"
            rewritten.append(key)

    if not rewritten:
        return None

    if not dry_run:
        try:
            path.write_text(json.dumps(data, indent=2) + "\n")
        except OSError:
            return FixAction("AAK-SECRET-007", str(path), "Failed to fix", False)

    names = ", ".join(sorted(set(rewritten)))
    return FixAction(
        "AAK-SECRET-007",
        str(path),
        f"Replaced literal secret with an environment reference for: {names} "
        "(export the variable before starting the server, and rotate the exposed value)",
        not dry_run,
    )


def _fix_env_gitignore(project_root: Path, dry_run: bool) -> FixAction:
    """Add .env patterns to .gitignore."""
    gitignore = project_root / ".gitignore"
    try:
        content = gitignore.read_text() if gitignore.is_file() else ""
        if ".env" not in content:
            new_content = content.rstrip() + "\n\n# Environment files\n.env\n.env.*\n"
            if not dry_run:
                gitignore.write_text(new_content)
        return FixAction(
            "AAK-SECRET-006",
            ".gitignore",
            "Added .env patterns to .gitignore",
            not dry_run,
        )
    except OSError:
        return FixAction("AAK-SECRET-006", ".gitignore", "Failed to fix", False)
