"""`AAK-APPROVAL-PARSER-DESYNC-001` — CVE-2026-19591 (Codex CLI).

The command is neither truncated nor rebuilt. The checker and the shell read the
same bytes and disagree about them, which is a third route to an approval bypass
and is why the two near neighbours stay silent —
`test_neither_neighbour_covers_this` asserts that rather than asserting it in
prose.

The benign fixture rejects `--%` before classifying. Knowing the token exists is
the entire mitigation, so that one line is the difference between the two
fixtures.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.approval_parser_desync import scan

RULE = "AAK-APPROVAL-PARSER-DESYNC-001"
CVE = "CVE-2026-19591"

POSITIVE = """\
import { spawn } from "node:child_process";

const SAFE_GIT = new Set(["status", "diff", "log"]);

export function isSafeCommand(argv: string[]): boolean {
  const [bin, sub] = argv;
  if (bin === "git" && SAFE_GIT.has(sub)) return true;
  if (bin === "pwsh" || bin === "powershell") {
    return argv.slice(1).every((a) => !a.startsWith("-") || a === "-Command");
  }
  return false;
}

export async function run(argv: string[]) {
  if (!isSafeCommand(argv)) return requestApproval(argv);
  return spawn(argv[0], argv.slice(1));
}
"""

# Refuse to classify anything carrying the token that suspends pwsh's parsing.
BENIGN = POSITIVE.replace(
    "  const [bin, sub] = argv;\n",
    '  const [bin, sub] = argv;\n'
    '  if (argv.some((a) => a === "--%")) return false;\n',
)


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


def test_positive_fires(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, "src/safety.ts", POSITIVE)


def test_benign_is_silent(tmp_path: Path) -> None:
    """Rejecting the token is the mitigation, so recognising it must clear the
    finding."""
    assert RULE not in _ids(tmp_path, "src/safety.ts", BENIGN)


def test_the_two_fixtures_differ_only_in_the_token_check() -> None:
    assert BENIGN != POSITIVE
    assert BENIGN.replace(
        '  if (argv.some((a) => a === "--%")) return false;\n', ""
    ) == POSITIVE


def test_a_gate_with_no_powershell_is_not_flagged(tmp_path: Path) -> None:
    """The rule claims to know one interpreter's stop-parsing token, not every
    shell's grammar. A bash-only gate is outside what it can honestly say."""
    bash_only = POSITIVE.replace('bin === "pwsh" || bin === "powershell"', 'bin === "bash"')
    assert RULE not in _ids(tmp_path, "src/safety.ts", bash_only)


def test_spawning_pwsh_without_an_approval_gate_is_not_flagged(tmp_path: Path) -> None:
    """No approval decision, no divergence to find."""
    plain = """\
import { spawn } from "node:child_process";
export const run = (argv: string[]) => spawn("pwsh", argv);
"""
    assert RULE not in _ids(tmp_path, "src/run.ts", plain)


def test_neither_neighbour_covers_this(tmp_path: Path) -> None:
    """`AAK-POLICY-TRUNCATION-001` needs the value cut to a fixed length;
    `AAK-MCP-ARGV-TOCTOU-001` needs the argv rebuilt after approval. Here it is
    neither. If either starts firing on this shape, the overlap needs deciding."""
    from agent_audit_kit.engine import run_scan

    target = tmp_path / "src" / "safety.ts"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(POSITIVE, encoding="utf-8")
    ids = {f.rule_id for f in run_scan(tmp_path).findings}
    assert RULE in ids
    assert "AAK-POLICY-TRUNCATION-001" not in ids
    assert "AAK-MCP-ARGV-TOCTOU-001" not in ids


def test_rule_metadata() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.HIGH
    assert rule.category is Category.TRUST_BOUNDARY
    assert rule.cve_references == [CVE]
    assert rule.limitations


def test_rule_is_a_class_not_a_package_signature() -> None:
    rule = RULES[RULE]
    text = f"{rule.title} {rule.description} {rule.remediation}".lower()
    assert "codex" not in text
