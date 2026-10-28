"""AAK-GHA-SECRET-DUMP-001: a run step that prints secrets through an encoder.

The Gheist campaign (Wiz, 2026-10-25) pushed `sync-check.yml` workflows that ran
`env | base32 -w 120` and `echo -n '${{ toJSON(secrets) }}' | base32 -w 120`, so the
secrets printed in full past GitHub's log masking. These tests pin the routes the
rule reads (a pipe, a here-string, a heredoc, a process substitution, an env var set
from a secret, a whole-environment dump), the steps it leaves alone (a secret handed
to a CLI, a decode into a file, a non-secret decode, a consumer at the end of the
pipe) and the CRITICAL raise on the campaign's published markers. The fixtures live
under tests/fixtures/gha_secret_dump/, where GitHub never runs them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.gha_hardening import scan

FIXTURES = Path(__file__).parent / "fixtures" / "gha_secret_dump"
RULE = "AAK-GHA-SECRET-DUMP-001"


def _dumps(root: Path) -> list[tuple[Severity, str, int | None]]:
    findings, _ = scan(root)
    return [(f.severity, f.file_path, f.line_number) for f in findings if f.rule_id == RULE]


def _workflow(root: Path, run: str, env: str = "", name: str = "ci.yml") -> Path:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    indented = "\n".join("          " + line for line in run.splitlines())
    env_block = "".join(f"        env:\n          {line}\n" for line in env.splitlines()) if env else ""
    (wf / name).write_text(
        "name: ci\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - name: step\n{env_block}        run: |\n{indented}\n"
    )
    return root


# ---- the fixtures ----------------------------------------------------------------


def test_the_campaign_workflow_is_critical_on_both_dump_lines() -> None:
    root = FIXTURES / "campaign"
    path = ".github/workflows/sync-check.yml"
    assert _dumps(root) == [(Severity.CRITICAL, path, 13), (Severity.CRITICAL, path, 14)]
    findings, _ = scan(root)
    assert all("Gheist" in f.evidence and "ci-sync-*" in f.evidence for f in findings if f.rule_id == RULE)


def test_an_encoded_secret_is_high() -> None:
    assert _dumps(FIXTURES / "encoded-secret") == [(Severity.HIGH, ".github/workflows/debug.yml", 8)]


def test_a_secret_handed_to_a_cli_and_a_non_secret_decode_are_quiet() -> None:
    assert _dumps(FIXTURES / "env-cli") == []
    assert _dumps(FIXTURES / "decode-file") == []


def test_the_rule_is_high_in_the_registry() -> None:
    assert RULES[RULE].severity is Severity.HIGH


def test_sarif_round_trip_places_the_rule_on_a_line() -> None:
    findings, _ = scan(FIXTURES / "encoded-secret")
    sarif = json.loads(format_results(ScanResult(findings=[f for f in findings if f.rule_id == RULE])))
    (result,) = sarif["runs"][0]["results"]
    assert result["ruleId"] == RULE
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 8


# ---- what is read ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "run",
    [
        "printenv | gzip | base64",
        "set | xxd",
        "export -p | base64 -w0",
        "declare -x | rev",
        'echo "${{ secrets.NPM_TOKEN }}" | openssl enc -base64',
        "echo '${{ toJson(secrets) }}' | base64 | tr -d '='",
        "base32 <<< '${{ toJSON(secrets) }}'",
        "base64 < <(env)",
        "base64 <<EOF\n${{ secrets.DEPLOY_KEY }}\nEOF",
        'echo "${{ secrets.TOKEN }}" | base64 -d',  # the decoded value is not masked either
        'echo "${{ secrets.TOKEN }}" | base64 >> "$GITHUB_STEP_SUMMARY"',
        'set -euo pipefail\necho "${{ secrets[\'TOKEN\'] }}" | xxd -p',
        "make build && env | base64",
        "sudo env | LC_ALL=C base64 -w0",  # the program after `sudo` and assignments
        "echo start; \\\n  env | \\\n  base64",
        # The step is skipped unless it names an encoder; one ending a continued line still counts.
        "echo '${{ secrets.TOKEN }}' | base64\\\n| cat",
        'echo "\\"" ; env | base64',  # an escaped quote does not end the string
        "base64 <<A\nhello\nA\nbase64 <<B\n${{ secrets.DEPLOY_KEY }}\nB",  # each heredoc read for itself
    ],
)
def test_a_dump_reaching_the_log_is_reported(tmp_path: Path, run: str) -> None:
    assert [s for s, _, _ in _dumps(_workflow(tmp_path, run))] == [Severity.HIGH]


def test_a_step_naming_no_encoder_is_not_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The rule needs an encoder, so a step without one is skipped before it is
    parsed: a workflow of ordinary steps costs only its YAML parse."""
    from agent_audit_kit.scanners import gha_hardening

    parsed: list[str] = []
    real = gha_hardening._commands
    monkeypatch.setattr(gha_hardening, "_commands", lambda script: parsed.append(script) or real(script))
    _workflow(tmp_path, 'echo "${{ secrets.TOKEN }}" | node build.js\ngit rev-parse HEAD > rev.txt')
    assert _dumps(tmp_path) == [] and parsed == []
    _workflow(tmp_path, "env | base64")
    assert len(_dumps(tmp_path)) == 1 and parsed == ["env | base64\n"]


def test_an_env_var_set_from_a_secret_counts_as_the_secret(tmp_path: Path) -> None:
    _workflow(tmp_path, 'echo "$API_TOKEN" | base64', env="API_TOKEN: ${{ secrets.API_TOKEN }}")
    findings, _ = scan(tmp_path)
    (finding,) = [f for f in findings if f.rule_id == RULE]
    assert "`$API_TOKEN`, set from a secret" in finding.evidence


@pytest.mark.parametrize(
    "run",
    [
        'echo "${{ secrets.CERT }}" | base64 -d > cert.p12',
        'echo "${{ secrets.KUBECONFIG }}" | base64 --decode > "$HOME/.kube/config"',
        'echo "${{ secrets.GPG_KEY }}" | base64 --decode | gpg --import',
        'echo "${{ secrets.REGISTRY_TOKEN }}" | base64 -d | docker login -u bot --password-stdin',
        'echo "${{ secrets.TOKEN }}" | base64 >> "$GITHUB_OUTPUT"',
        "set -euo pipefail",
        "env FOO=1 make | base64",
        "base64 -d assets/logo.b64 > logo.png",
        'gh release create v1 --notes "x"',
        "# env | base64",
    ],
)
def test_steps_that_do_not_print_an_encoded_secret_are_quiet(tmp_path: Path, run: str) -> None:
    assert _dumps(_workflow(tmp_path, run)) == []


def test_the_gdmp_pivot_string_marks_any_workflow(tmp_path: Path) -> None:
    _workflow(tmp_path, 'echo "===== gdmp-pivot: host ====="\nenv | base64', name="deploy.yml")
    assert [s for s, _, _ in _dumps(tmp_path)] == [Severity.CRITICAL]


def test_the_campaign_step_outside_sync_check_yml_is_high(tmp_path: Path) -> None:
    _workflow(tmp_path, "echo -n '${{ toJSON(secrets) }}' | base32 -w 120", name="other.yml")
    assert [s for s, _, _ in _dumps(tmp_path)] == [Severity.HIGH]


def test_only_the_workflows_directory_is_read(tmp_path: Path) -> None:
    action = tmp_path / ".github" / "actions" / "x"
    action.mkdir(parents=True)
    (action / "action.yml").write_text("runs:\n  using: composite\n  steps:\n    - run: env | base64\n")
    assert _dumps(tmp_path) == []
