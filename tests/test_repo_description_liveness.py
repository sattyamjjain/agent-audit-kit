"""``make count-check`` compares github.com's repo description, not only the files.

On 2026-09-27 two reads of the description disagreed, "332 rules" from the API and
"362 rules" from a rendered page, and nothing local could say which one matched the
code: every step of ``make count-check`` read tracked files, and the live description
is not one. The comparison already existed, once, in ``render_repo_metadata.py
--check-live``, which release.yml and the daily description-liveness workflow run, so
count-check calls it instead of growing a second copy.

It reads with ``gh repo view --json description``, the command a person runs to check
by hand, and fails on a mismatch. When gh is missing or holds no credentials (a fresh
machine, or any CI job without a token, CI's ``counts`` job included) it skips and
prints that it skipped. This file already follows one rule: a surface nobody read must
never look like a matching one.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from agent_audit_kit import RULE_COUNT

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "render_repo_metadata.py"
_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("render_repo_metadata", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeGh:
    """Stands in for ``subprocess.run`` and records every argv it was handed."""

    def __init__(
        self,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        raises: BaseException | None = None,
    ) -> None:
        self.returncode, self.stdout, self.stderr, self.raises = returncode, stdout, stderr, raises
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(argv, self.returncode, self.stdout, self.stderr)


@pytest.fixture()
def mod() -> ModuleType:
    return _load()


def _gh(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> _FakeGh:
    fake = _FakeGh(**kwargs)  # type: ignore[arg-type]
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def test_it_reads_the_description_the_way_a_person_checks_it(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _gh(monkeypatch, stdout=mod.render() + "\n")
    assert mod.main(["--check-live", "owner/repo"]) == 0
    assert fake.calls == [
        ["gh", "repo", "view", "owner/repo", "--json", "description", "--jq", '.description // ""'],
    ]


def test_a_match_prints_the_description_it_compared(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The count in the output is the one that was compared, so nobody has to assume it."""
    _gh(monkeypatch, stdout=mod.render() + "\n")
    assert mod.main(["--check-live", "owner/repo"]) == 0
    assert f"{RULE_COUNT} rules across" in capsys.readouterr().out


def test_a_stale_description_fails_and_prints_the_command_that_fixes_it(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stale = mod.render().replace(f"{RULE_COUNT} rules", "332 rules")
    assert stale != mod.render()
    _gh(monkeypatch, stdout=stale + "\n")
    assert mod.main(["--check-live", "owner/repo"]) == 1
    err = capsys.readouterr().err
    assert "332 rules" in err
    assert "gh repo edit owner/repo --description" in err


def test_unauthenticated_gh_skips_and_says_so(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``gh help exit-codes``: 4 means the command needs authentication it does not have."""
    _gh(monkeypatch, returncode=4, stderr="To get started with GitHub CLI, please run:  gh auth login\n")
    assert mod.main(["--check-live", "owner/repo"]) == 0
    captured = capsys.readouterr()
    assert "gh is not authenticated" in captured.err
    assert "not a pass" in captured.err
    assert "live == rendered" not in captured.out


def test_a_missing_gh_skips_and_says_so(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _gh(monkeypatch, raises=FileNotFoundError(2, "No such file or directory", "gh"))
    assert mod.main(["--check-live", "owner/repo"]) == 0
    err = capsys.readouterr().err
    assert "gh is not installed" in err
    assert "not a pass" in err


def test_any_other_read_failure_is_reported_not_passed(
    mod: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rejected token is not "unauthenticated" to gh (exit 1, not 4), and not a match."""
    _gh(monkeypatch, returncode=1, stderr="HTTP 401: Bad credentials (https://api.github.com/graphql)\n")
    assert mod.main(["--check-live", "owner/repo"]) == 0
    captured = capsys.readouterr()
    assert "NOT COMPARED" in captured.err
    assert "Bad credentials" in captured.err
    assert "live == rendered" not in captured.out


@pytest.mark.skipif(shutil.which("gh") is None, reason="gh is not installed")
def test_real_gh_without_credentials_is_a_skip(tmp_path: Path) -> None:
    """The skip rests on gh's documented exit code 4, so pin it against the real binary.

    No token in the environment and an empty config dir: gh refuses before it sends
    a request, so this needs no network and cannot read the live description.
    """
    env = {k: v for k, v in os.environ.items() if k not in _TOKEN_VARS}
    env["GH_CONFIG_DIR"] = str(tmp_path)
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--check-live", "sattyamjjain/agent-audit-kit"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "gh is not authenticated" in out.stderr
    assert "live == rendered" not in out.stdout
