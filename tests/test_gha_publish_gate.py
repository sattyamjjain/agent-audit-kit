"""AAK-GHA-PUBLISH-GATE-001: a workflow job that publishes a package with no environment.

@ethersphere/bee-js 13.3.0 (GHSA-hh7j-5m3j-23pf, 2026-11-09) shipped malware through the
project's own release workflow: stolen CI credentials created a GitHub release, the
release started the npm publish job, and the job published with no approval and with
valid provenance. These tests pin what the rule reads (the publishing commands and
actions of `_PUBLISHERS`, the launchers in front of them, the job's `environment:`),
what it leaves alone (a dry run, a pack, TestPyPI, a registry on the runner, a reusable
workflow), where it places the finding, and what the evidence says about the trigger and
`id-token`. The fixtures live under tests/fixtures/gha_publish_gate/, where GitHub never
runs them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.models import Category, ScanResult, Severity
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import gha_hardening
from agent_audit_kit.scanners.gha_hardening import scan

FIXTURES = Path(__file__).parent / "fixtures" / "gha_publish_gate"
RULE = "AAK-GHA-PUBLISH-GATE-001"
WORKFLOW = ".github/workflows/publish.yml"


def _gates(root: Path) -> list[tuple[Severity, str, int | None]]:
    findings, _ = scan(root)
    return [(f.severity, f.file_path, f.line_number) for f in findings if f.rule_id == RULE]


def _evidence(root: Path) -> list[str]:
    findings, _ = scan(root)
    return [f.evidence for f in findings if f.rule_id == RULE]


def _workflow(root: Path, body: str, name: str = "publish.yml") -> Path:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(body)
    return root


def _job(run: str = "", uses: str = "", on: str = "on: release", job: str = "", step: str = "") -> str:
    """A workflow of one job with one step that runs `run` (a block scalar) or uses `uses`."""
    if uses:
        action = f"      - uses: {uses}\n"
    else:
        action = "      - run: |\n" + "".join(f"          {line}\n" for line in run.splitlines())
    return f"{on}\njobs:\n  release:\n    runs-on: ubuntu-latest\n{job}    steps:\n{action}{step}"


def _line_of(path: Path, text: str, occurrence: int = 1) -> int:
    hits = [n for n, line in enumerate(path.read_text().splitlines(), 1) if text in line]
    return hits[occurrence - 1]


# ---- the fixtures ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "needle", "occurrence"),
    [
        ("release-npm-no-env", "npm publish --provenance", 1),
        ("tag-pypi-action-no-env", "uses: pypa/gh-action-pypi-publish@", 1),
        ("dispatch-cargo-no-env", "cargo publish --locked", 1),
        # The gated job runs the same command first: the finding is on the second.
        ("two-jobs", "npm publish --access public", 2),
    ],
)
def test_an_ungated_publishing_job_is_high_on_its_publish_step(case: str, needle: str, occurrence: int) -> None:
    root = FIXTURES / case
    line = _line_of(root / WORKFLOW, needle, occurrence)
    assert _gates(root) == [(Severity.HIGH, WORKFLOW, line)]


@pytest.mark.parametrize("case", ["release-npm-env", "env-mapping", "dry-run", "build-only"])
def test_a_gated_dry_or_build_only_workflow_is_quiet(case: str) -> None:
    assert _gates(FIXTURES / case) == []


def test_the_two_jobs_finding_names_the_ungated_job() -> None:
    (evidence,) = _evidence(FIXTURES / "two-jobs")
    assert "Job `npm-canary`" in evidence and "npm-gated" not in evidence


def test_the_release_evidence_names_the_incident_and_provenance() -> None:
    (evidence,) = _evidence(FIXTURES / "release-npm-no-env")
    assert "runs `npm publish --provenance --access public`" in evidence
    assert "(on: release)" in evidence
    assert "`id-token` permission set to `write`" in evidence
    assert "Anyone who can create a release publishes with no human in the loop" in evidence
    assert "GHSA-hh7j-5m3j-23pf" in evidence


def test_the_tag_evidence_names_the_action_and_the_tag_push() -> None:
    (evidence,) = _evidence(FIXTURES / "tag-pypi-action-no-env")
    assert "uses `pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc`" in evidence
    assert "(on: push (tags))" in evidence and "Anyone who can push a tag" in evidence


def test_a_dispatch_has_no_release_sentence() -> None:
    (evidence,) = _evidence(FIXTURES / "dispatch-cargo-no-env")
    assert "(on: workflow_dispatch)" in evidence
    assert "no `id-token` write permission" in evidence
    assert "Anyone who can" not in evidence


def test_the_rule_in_the_registry() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.HIGH
    assert rule.category is Category.SUPPLY_CHAIN is RULES["AAK-SUPPLY-001"].category
    assert rule.incident_references == ["GHSA-hh7j-5m3j-23pf"]
    assert "required reviewers" in rule.remediation


def test_sarif_round_trip_places_the_rule_on_a_line() -> None:
    root = FIXTURES / "release-npm-no-env"
    findings, _ = scan(root)
    sarif = json.loads(format_results(ScanResult(findings=[f for f in findings if f.rule_id == RULE])))
    (result,) = sarif["runs"][0]["results"]
    assert result["ruleId"] == RULE
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == _line_of(
        root / WORKFLOW, "npm publish --provenance"
    )


# ---- triggers --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("on", "named", "human"),
    [
        ("on: release", "on: release", "create a release"),
        ('"on": release', "on: release", "create a release"),  # the quoted key, read as a string
        ("on: [push, release]", "on: push (branches and tags), release", "create a release or push a tag"),
        ("on:\n  release:\n    types: [published]", "on: release", "create a release"),
        ("on:\n  push:\n    tags: ['v*']", "on: push (tags)", "push a tag"),
        ("on:\n  push:\n    paths: ['src/**']", "on: push (branches and tags)", "push a tag"),
        ("on:\n  push:\n    branches: [main]", "on: push (branches)", None),
        ("on:\n  push:\n    branches: [main]\n    tags: ['v*']", "on: push (branches and tags)", "push a tag"),
        ("on:\n  workflow_run:\n    workflows: [CI]", "on: workflow_run", None),
        ("on:\n  schedule:\n    - cron: '0 3 * * 1'", "on: schedule", None),
    ],
)
def test_every_form_of_on_is_read(tmp_path: Path, on: str, named: str, human: str | None) -> None:
    """`on` as a string, a list and a mapping; unquoted, PyYAML reads the key as True."""
    (evidence,) = _evidence(_workflow(tmp_path, _job("npm publish", on=on)))
    assert f"({named})" in evidence
    if human is None:
        assert "Anyone who can" not in evidence
    else:
        assert f"Anyone who can {human} publishes" in evidence


def test_a_workflow_with_no_trigger_still_reports(tmp_path: Path) -> None:
    (evidence,) = _evidence(_workflow(tmp_path, _job("npm publish", on="name: x")))
    assert "(no trigger the rule reads)" in evidence


# ---- id-token ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("workflow_perms", "job_perms", "mints"),
    [
        ("", "    permissions:\n      id-token: write\n", True),
        ("permissions:\n  id-token: write\n", "", True),
        ("permissions: write-all\n", "", True),
        # The job's own block replaces the workflow's.
        ("permissions:\n  id-token: write\n", "    permissions:\n      contents: read\n", False),
        ("", "    permissions:\n      id-token: read\n", False),
        ("", "", False),
    ],
)
def test_id_token_is_read_from_the_job_else_the_workflow(
    tmp_path: Path, workflow_perms: str, job_perms: str, mints: bool
) -> None:
    (evidence,) = _evidence(_workflow(tmp_path, workflow_perms + _job("npm publish", job=job_perms)))
    assert ("`id-token` permission set to `write`" in evidence) is mints
    assert ("no `id-token` write permission" in evidence) is not mints


# ---- the gate ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("environment", "gated"),
    [
        ("    environment: npm\n", True),
        ("    environment:\n      name: npm\n", True),
        ("    environment: ${{ inputs.target }}\n", True),
        ('    environment: ""\n', False),
        ("    environment:\n      url: https://npmjs.com/package/x\n", False),
        ("", False),
    ],
)
def test_a_named_environment_is_the_gate(tmp_path: Path, environment: str, gated: bool) -> None:
    assert (_gates(_workflow(tmp_path, _job("npm publish", job=environment))) == []) is gated


def test_a_reusable_workflow_job_is_not_read_and_does_not_crash(tmp_path: Path) -> None:
    _workflow(tmp_path, "on: release\njobs:\n  publish:\n    uses: ./.github/workflows/npm.yml\n    secrets: inherit\n")
    assert _gates(tmp_path) == []


def test_one_finding_per_job_at_its_first_publishing_step(tmp_path: Path) -> None:
    _workflow(tmp_path, _job("npm publish", step="      - run: cargo publish\n"))
    ((_, _, line),) = _gates(tmp_path)
    assert line == _line_of(tmp_path / ".github/workflows/publish.yml", "npm publish")


def test_each_ungated_job_reports_on_its_own_line(tmp_path: Path) -> None:
    jobs = "".join(
        f"  j{i}:\n    runs-on: x\n    steps:\n      - run: npm publish\n" for i in range(3)
    )
    _workflow(tmp_path, "on: release\njobs:\n" + jobs)
    assert [line for _, _, line in _gates(tmp_path)] == [6, 10, 14]


# ---- what publishes ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "publisher", [p for p in gha_hardening._PUBLISHERS if not p.startswith("uses: ")]
)
def test_every_publishing_command_in_the_vocabulary_is_read(tmp_path: Path, publisher: str) -> None:
    assert len(_gates(_workflow(tmp_path, _job(publisher)))) == 1


@pytest.mark.parametrize("publisher", [p for p in gha_hardening._PUBLISHERS if p.startswith("uses: ")])
@pytest.mark.parametrize("ref", ["@v1", "@release/v1", "@" + "a" * 40])
def test_every_publishing_action_is_read_at_any_ref(tmp_path: Path, publisher: str, ref: str) -> None:
    action = publisher[len("uses: "):]
    assert len(_gates(_workflow(tmp_path, _job(uses=action + ref)))) == 1
    assert len(_gates(_workflow(tmp_path, _job(uses=action.lower() + ref)))) == 1


@pytest.mark.parametrize(
    "run",
    [
        "npx vsce publish -p $VSCE_PAT",
        "npx --yes @vscode/vsce@2.24.0 publish",
        "npx ovsx publish extension.vsix",
        "python -m twine upload dist/*",
        "python3.12 -m twine upload --skip-existing dist/*",
        "pipx run twine upload dist/*",
        "uvx twine upload dist/*",
        "pnpm -r publish --access public --no-git-checks",
        "yarn npm publish --tolerate-republish",
        "NODE_AUTH_TOKEN=$TOKEN npm publish",
        "env NODE_AUTH_TOKEN=$TOKEN npm publish",
        "sudo -E npm publish",
        "cd packages/core && npm publish",
        "(cd packages/core && npm publish)",
        "npm ci; npm publish",
        "npm publish 2>&1 | tee publish.log",
        "dotnet nuget push out/*.nupkg --api-key $KEY --source https://api.nuget.org/v3/index.json",
        "gem push pkg/*.gem",
        "uv build && uv publish",
        "poetry publish --build",
        "cargo publish \\\n  --token $TOKEN",
        "npm publish --dry-run && npm publish",
        "for p in a b; do npm publish; done",
    ],
)
def test_publishing_commands_are_read_through_launchers_and_lists(tmp_path: Path, run: str) -> None:
    assert len(_gates(_workflow(tmp_path, _job(run)))) == 1


@pytest.mark.parametrize(
    "run",
    [
        "npm publish --dry-run",
        "cargo publish --dry-run --locked",
        "npm pack",
        "npm run publish",
        'echo "npm publish"',
        "# npm publish",
        "npm ci  # then npm publish",
        "git push --tags",
        "docker push ghcr.io/x/y:1",
        "twine upload --repository testpypi dist/*",
        "twine upload --repository-url https://test.pypi.org/legacy/ dist/*",
        "npm publish --registry http://localhost:4873",
        "npm_config_registry=http://127.0.0.1:4873 npm publish",
        "./scripts/release.sh",
        # Option words alone may sit between a program and its subcommand: a value is not read.
        "pnpm --filter ./packages/core publish",
    ],
)
def test_steps_that_do_not_publish_a_release_are_quiet(tmp_path: Path, run: str) -> None:
    assert _gates(_workflow(tmp_path, _job(run))) == []


def test_a_registry_named_in_env_or_with_is_read(tmp_path: Path) -> None:
    step_env = "        env:\n          NPM_CONFIG_REGISTRY: http://localhost:4873\n"
    assert _gates(_workflow(tmp_path, _job("npm publish") + step_env)) == []
    testpypi = "        with:\n          repository-url: https://test.pypi.org/legacy/\n"
    assert _gates(_workflow(tmp_path, _job(uses="pypa/gh-action-pypi-publish@v1") + testpypi)) == []
    # An env value that names localhost for anything but the registry does not count.
    unrelated = "        env:\n          DATABASE_URL: postgres://localhost/db\n"
    assert len(_gates(_workflow(tmp_path, _job("npm publish") + unrelated))) == 1


def test_only_the_workflows_directory_is_read(tmp_path: Path) -> None:
    action = tmp_path / ".github" / "actions" / "release"
    action.mkdir(parents=True)
    (action / "action.yml").write_text("runs:\n  using: composite\n  steps:\n    - run: npm publish\n      shell: bash\n")
    assert _gates(tmp_path) == []


# ---- cost ------------------------------------------------------------------------------


def test_a_step_naming_no_publish_word_is_not_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parsed: list[str] = []
    real = gha_hardening._commands
    monkeypatch.setattr(gha_hardening, "_commands", lambda script: parsed.append(script) or real(script))
    _workflow(tmp_path, _job("npm ci\nnpm test"))
    assert _gates(tmp_path) == [] and parsed == []


def test_the_document_is_composed_only_for_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Placing a finding composes the YAML a second time, so a workflow without one is
    parsed once."""
    composed: list[str] = []
    real = gha_hardening.compose_yaml_all
    monkeypatch.setattr(gha_hardening, "compose_yaml_all", lambda text, path: composed.append(text) or real(text, path))
    scan(FIXTURES / "release-npm-env")
    assert composed == []
    scan(FIXTURES / "release-npm-no-env")
    assert len(composed) == 1


def test_each_job_is_placed_by_reading_only_its_own_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every reported job is placed by searching the lines of its own step, never the file
    from the top: 200 jobs cost at most one line search each. A search from the top costs
    about 400 per job here, a quadratic the timing rows cannot see under the YAML parse."""
    searched: list[str] = []
    real = gha_hardening.linear_find
    monkeypatch.setattr(gha_hardening, "linear_find", lambda text, key: searched.append(key) or real(text, key))
    jobs = "".join(f"  j{i}:\n    runs-on: x\n    steps:\n      - run: npm publish p{i}\n" for i in range(200))
    _workflow(tmp_path, "on: release\njobs:\n" + jobs)
    assert [line for _, _, line in _gates(tmp_path)] == [6 + 4 * i for i in range(200)]
    assert len(searched) <= 200


def test_an_uncomposable_document_falls_back_to_the_first_matching_line(monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    def refuse(text: str, path: object) -> list[object]:
        raise yaml.YAMLError("refused")

    monkeypatch.setattr(gha_hardening, "compose_yaml_all", refuse)
    root = FIXTURES / "release-npm-no-env"
    assert _gates(root) == [(Severity.HIGH, WORKFLOW, _line_of(root / WORKFLOW, "npm publish --provenance"))]
