"""AAK-GHA-IMMUTABLE-001 — SHA pinning for third-party GitHub Actions."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.gha_hardening import scan


def _write_workflow(root: Path, filename: str, body: str) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / filename).write_text(body, encoding="utf-8")


def test_tag_pin_fires(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v7
""",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-GHA-IMMUTABLE-001" for f in findings)


def test_sha_pin_passes(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@4a13e500e55cf31b7a5d59a38ab2040ab0f42f56
""",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-GHA-IMMUTABLE-001" for f in findings)


def test_first_party_tag_exempt(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
""",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-GHA-IMMUTABLE-001" for f in findings)


def test_branch_pin_fires(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: random-owner/random-action@main
""",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-GHA-IMMUTABLE-001" for f in findings)


def test_local_composite_action_exempt(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/setup
""",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-GHA-IMMUTABLE-001" for f in findings)


def test_no_workflows_dir_passes(tmp_path: Path) -> None:
    findings, scanned = scan(tmp_path)
    assert findings == []
    assert scanned == set()


def test_mixed_workflow_reports_only_non_sha(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "ci.yml",
        """
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: random/third-party@v1
      - uses: another/ok@1234567890abcdef1234567890abcdef12345678
""",
    )
    findings, _ = scan(tmp_path)
    rule_ids = [f.rule_id for f in findings]
    evidence = [f.evidence for f in findings]
    assert rule_ids.count("AAK-GHA-IMMUTABLE-001") == 1
    assert any("random/third-party@v1" in ev for ev in evidence)
