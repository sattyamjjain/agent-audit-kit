"""`aak scan --verify-secrets` probes with the real key, found the real way.

Through 0.6.20 these tests hand-built findings whose evidence held a whole
key, so they passed while the feature never worked: secret_exposure writes
only a prefix into the evidence, and verification read the key back out of
it, so every Anthropic probe sent `sk-ant-api03...` and reported a live key as
INACTIVE/ROTATED. Every test here starts from a file on disk, runs the real
scanner, then verifies with urlopen replaced by a recorder, so what is
asserted is the request a provider would have received.

The keys are assembled at runtime so no literal secret sits in the source.
No test touches the network.
"""
from __future__ import annotations

import dataclasses
import email.message
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit import verification
from agent_audit_kit.cli import cli
from agent_audit_kit.models import Finding, ScanResult, Severity
from agent_audit_kit.output import console, json_report, sarif
from agent_audit_kit.scanners import secret_exposure
from agent_audit_kit.scanners._helpers import make_finding
from agent_audit_kit.verification import _mask_key, _probe, verify_findings


def _anthropic(tag: str = "A") -> str:
    return "sk-ant-" + "api03-" + (tag * 8 + "0123456789") * 3


def _openai(tag: str = "Q") -> str:
    return "sk-" + "TESTONLY" + tag * 12 + "123456"


def _github(tag: str = "T") -> str:
    return "ghp_" + (tag + "3st") * 9


def _gitlab(tag: str = "T") -> str:
    return "glpat-" + (tag + "estOnly") * 3


def _aws() -> str:
    return "AKIA" + "TESTONLY" * 2


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Provider:
    """Stands in for urllib.request.urlopen and records every request."""

    def __init__(
        self,
        status: int = 200,
        error: int | None = None,
        headers: dict[str, str] | None = None,
        raises: Exception | None = None,
    ) -> None:
        self.status = status
        self.error = error
        self.headers = headers or {}
        self.raises = raises
        self.requests: list[urllib.request.Request] = []

    def __call__(self, req: urllib.request.Request, timeout: float | None = None) -> _Response:
        self.requests.append(req)
        if self.raises is not None:
            raise self.raises
        if self.error is not None:
            hdrs = email.message.Message()
            for name, value in self.headers.items():
                hdrs[name] = value
            raise urllib.error.HTTPError(req.full_url, self.error, "error", hdrs, None)
        return _Response(self.status)


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> _Provider:
    fake = _Provider()
    monkeypatch.setattr(verification.urllib.request, "urlopen", fake)
    return fake


def _scan(root: Path, text: str, name: str = ".env") -> ScanResult:
    (root / name).write_text(text, encoding="utf-8")
    findings, _files = secret_exposure.scan(root)
    return ScanResult(findings=findings)


def _only(result: ScanResult, rule_id: str) -> list[Finding]:
    return [f for f in result.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# The key the provider receives is the whole key from the file
# ---------------------------------------------------------------------------


def test_anthropic_probe_sends_the_full_key(tmp_path: Path, provider: _Provider) -> None:
    key = _anthropic()
    result = _scan(tmp_path, f"ANTHROPIC_API_KEY={key}\n")
    (finding,) = _only(result, "AAK-SECRET-001")
    assert key not in finding.evidence  # the scanner shows a prefix only

    verify_findings(result, tmp_path)

    (req,) = provider.requests
    assert req.full_url == "https://api.anthropic.com/v1/models"
    assert req.get_header("X-api-key") == key
    assert "[verification: CONFIRMED ACTIVE (key: sk-ant-a***)]" in finding.evidence


def test_openai_probe_sends_the_full_key(tmp_path: Path, provider: _Provider) -> None:
    key = _openai()
    result = _scan(tmp_path, f"OPENAI_API_KEY={key}\n")
    (finding,) = _only(result, "AAK-SECRET-002")

    verify_findings(result, tmp_path)

    (req,) = provider.requests
    assert req.full_url == "https://api.openai.com/v1/models"
    assert req.get_header("Authorization") == f"Bearer {key}"
    assert "CONFIRMED ACTIVE" in finding.evidence


def test_github_probe_sends_the_full_token(tmp_path: Path, provider: _Provider) -> None:
    token = _github()
    result = _scan(tmp_path, f"GITHUB_TOKEN={token}\n")
    (finding,) = _only(result, "AAK-SECRET-008")

    verify_findings(result, tmp_path)

    (req,) = provider.requests
    assert req.full_url == "https://api.github.com/user"
    assert req.get_header("Authorization") == f"token {token}"
    assert "CONFIRMED ACTIVE" in finding.evidence


def test_gitlab_probe_sends_the_full_token(tmp_path: Path, provider: _Provider) -> None:
    token = _gitlab()
    result = _scan(tmp_path, f"GITLAB_TOKEN={token}\n")
    (finding,) = _only(result, "AAK-SECRET-008")

    verify_findings(result, tmp_path)

    (req,) = provider.requests
    assert req.full_url == "https://gitlab.com/api/v4/user"
    assert req.get_header("Private-token") == token
    assert "CONFIRMED ACTIVE" in finding.evidence


def test_two_keys_sharing_a_prefix_are_each_probed_as_themselves(tmp_path: Path, provider: _Provider) -> None:
    # Every Anthropic key starts "sk-ant-api03", so both findings carry the
    # same evidence and the same reported line; order is what tells them apart.
    first, second = _anthropic("A"), _anthropic("B")
    result = _scan(tmp_path, f"PRIMARY={first}\nFALLBACK={second}\n")
    assert len(_only(result, "AAK-SECRET-001")) == 2

    verify_findings(result, tmp_path)

    assert [r.get_header("X-api-key") for r in provider.requests] == [first, second]


def test_the_same_key_twice_is_probed_once(tmp_path: Path, provider: _Provider) -> None:
    key = _anthropic()
    result = _scan(tmp_path, f"A={key}\nB={key}\n")
    findings = _only(result, "AAK-SECRET-001")
    assert len(findings) == 2

    verify_findings(result, tmp_path)

    assert len(provider.requests) == 1
    assert all("CONFIRMED ACTIVE" in f.evidence for f in findings)


# ---------------------------------------------------------------------------
# What each answer means
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("make_key", "env", "rule_id"),
    [(_anthropic, "ANTHROPIC_API_KEY", "AAK-SECRET-001"), (_openai, "OPENAI_API_KEY", "AAK-SECRET-002")],
)
@pytest.mark.parametrize(
    ("fake", "status"),
    [
        (_Provider(error=401), "INACTIVE/ROTATED"),
        (_Provider(error=403), "INACTIVE/ROTATED"),
        (_Provider(status=204), "INACTIVE/ROTATED"),
        (_Provider(error=500), "VERIFICATION FAILED (HTTP 500)"),
        (_Provider(raises=urllib.error.URLError("refused")), "VERIFICATION FAILED"),
        (_Provider(raises=OSError("network down")), "VERIFICATION FAILED"),
    ],
)
def test_provider_answers_map_to_statuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    make_key: Callable[[], str],
    env: str,
    rule_id: str,
    fake: _Provider,
    status: str,
) -> None:
    monkeypatch.setattr(verification.urllib.request, "urlopen", fake)
    result = _scan(tmp_path, f"{env}={make_key()}\n")
    (finding,) = _only(result, rule_id)

    verify_findings(result, tmp_path)

    assert f"[verification: {status} (key: " in finding.evidence
    assert finding.severity == Severity.CRITICAL  # unchanged; the rules ship at CRITICAL


@pytest.mark.parametrize(
    ("make_token", "status"),
    [(_github, "NOT VALID ON GITHUB.COM"), (_gitlab, "NOT VALID ON GITLAB.COM")],
)
def test_a_token_rejected_by_the_public_service_is_not_called_rotated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_token: Callable[[], str], status: str
) -> None:
    # Enterprise Server and self-managed GitLab issue the same formats, so a
    # 401 from the public service is not evidence the token is dead.
    monkeypatch.setattr(verification.urllib.request, "urlopen", _Provider(error=401))
    result = _scan(tmp_path, f"TOKEN={make_token()}\n")
    (finding,) = _only(result, "AAK-SECRET-008")

    verify_findings(result, tmp_path)

    assert f"[verification: {status} (key: " in finding.evidence
    assert "ROTATED" not in finding.evidence


def test_a_rate_limited_github_answer_says_nothing_about_the_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _Provider(error=403, headers={"x-ratelimit-remaining": "0"})
    monkeypatch.setattr(verification.urllib.request, "urlopen", fake)
    result = _scan(tmp_path, f"GITHUB_TOKEN={_github()}\n")
    (finding,) = _only(result, "AAK-SECRET-008")

    verify_findings(result, tmp_path)

    assert "VERIFICATION FAILED (rate limited)" in finding.evidence


def test_an_unexpected_error_in_a_probe_is_contained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verification.urllib.request, "urlopen", _Provider(raises=ValueError("bad URL")))
    result = _scan(tmp_path, f"ANTHROPIC_API_KEY={_anthropic()}\n")
    (finding,) = _only(result, "AAK-SECRET-001")

    verify_findings(result, tmp_path)

    assert "[verification: VERIFICATION FAILED (key: " in finding.evidence


def test_a_confirmed_live_key_raises_a_lowered_severity_to_critical(tmp_path: Path, provider: _Provider) -> None:
    result = _scan(tmp_path, f"ANTHROPIC_API_KEY={_anthropic()}\n")
    (finding,) = _only(result, "AAK-SECRET-001")
    finding.severity = Severity.HIGH  # as a severity override in config would

    verify_findings(result, tmp_path)

    assert finding.severity == Severity.CRITICAL


def test_a_rejected_key_keeps_its_severity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verification.urllib.request, "urlopen", _Provider(error=401))
    result = _scan(tmp_path, f"ANTHROPIC_API_KEY={_anthropic()}\n")
    (finding,) = _only(result, "AAK-SECRET-001")
    finding.severity = Severity.HIGH

    verify_findings(result, tmp_path)

    assert finding.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# What is not probed, and what cannot be
# ---------------------------------------------------------------------------


def test_aws_keys_are_annotated_not_probed(tmp_path: Path, provider: _Provider) -> None:
    secret = "aws_secret_access_key = " + "TESTONLY" * 5
    result = _scan(tmp_path, f"AWS_ACCESS_KEY_ID={_aws()}\n{secret}\n", name="credentials.ini")
    aws = _only(result, "AAK-SECRET-003")
    assert len(aws) == 2  # the access key id and the secret assignment

    verify_findings(result, tmp_path)

    assert provider.requests == []
    for finding in aws:
        assert "active check skipped" in finding.evidence
        assert "STS" in finding.evidence


def test_gcp_service_account_keys_are_annotated_not_probed(tmp_path: Path, provider: _Provider) -> None:
    body = json.dumps({"type": "service_account", "project_id": "test-only"})
    result = _scan(tmp_path, body, name="service-account.json")
    (finding,) = _only(result, "AAK-SECRET-009")

    verify_findings(result, tmp_path)

    assert provider.requests == []
    assert "active check skipped" in finding.evidence
    assert "JWT" in finding.evidence
    assert "ROTATED" not in finding.evidence


def test_a_key_removed_after_the_scan_is_reported_as_gone(tmp_path: Path, provider: _Provider) -> None:
    result = _scan(tmp_path, f"ANTHROPIC_API_KEY={_anthropic()}\n")
    (finding,) = _only(result, "AAK-SECRET-001")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=${FROM_VAULT}\n", encoding="utf-8")

    verify_findings(result, tmp_path)

    assert provider.requests == []
    assert finding.evidence.endswith("[verification: key no longer in file]")


def test_a_file_deleted_after_the_scan_is_reported_as_gone(tmp_path: Path, provider: _Provider) -> None:
    result = _scan(tmp_path, f"ANTHROPIC_API_KEY={_anthropic()}\n")
    (finding,) = _only(result, "AAK-SECRET-001")
    (tmp_path / ".env").unlink()

    verify_findings(result, tmp_path)

    assert provider.requests == []
    assert finding.evidence.endswith("[verification: key no longer in file]")


def test_an_unrecognised_prefix_has_no_verifier(tmp_path: Path, provider: _Provider) -> None:
    finding = make_finding("AAK-SECRET-008", ".env", "Found GitHub token: zzzz1234...", 1)
    result = ScanResult(findings=[finding])

    verify_findings(result, tmp_path)

    assert provider.requests == []
    assert finding.evidence.endswith("[verification: no verifier available]")


def test_non_secret_findings_are_left_alone(tmp_path: Path, provider: _Provider) -> None:
    finding = make_finding("AAK-MCP-001", ".mcp.json", "original evidence only", 1)
    result = ScanResult(findings=[finding])

    assert verify_findings(result, tmp_path) is result
    assert finding.evidence == "original evidence only"
    assert provider.requests == []


# ---------------------------------------------------------------------------
# The full key never leaves the process
# ---------------------------------------------------------------------------


def test_the_full_key_is_in_no_finding_field_and_no_output(tmp_path: Path, provider: _Provider) -> None:
    keys = [_anthropic(), _openai(), _github(), _gitlab()]
    result = _scan(tmp_path, "".join(f"K{i}={k}\n" for i, k in enumerate(keys)))
    verify_findings(result, tmp_path)
    assert len(provider.requests) == 4

    rendered = [
        json_report.format_results(result),
        sarif.format_results(result, project_root=tmp_path),
        console.format_results(result),
        json.dumps([dataclasses.asdict(f) for f in result.findings], default=str),
    ]
    for key in keys:
        for text in rendered:
            assert key not in text


def test_the_cli_passes_the_project_root_and_prints_no_key(tmp_path: Path, provider: _Provider) -> None:
    project = tmp_path / "project"
    project.mkdir()
    key = _anthropic()
    (project / ".env").write_text(f"ANTHROPIC_API_KEY={key}\n", encoding="utf-8")
    out = tmp_path / "report.json"

    run = CliRunner().invoke(
        cli, ["scan", str(project), "--verify-secrets", "--format", "json", "--output", str(out)]
    )

    assert run.exit_code == 0, run.output
    report = out.read_text(encoding="utf-8")
    assert "CONFIRMED ACTIVE" in report
    assert key not in report
    assert key not in run.output
    assert [r.get_header("X-api-key") for r in provider.requests] == [key]


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


class TestMaskKey:
    def test_returns_first_8_chars_plus_stars(self) -> None:
        assert _mask_key("sk-ant-api03-abc123def456") == "sk-ant-a***"

    def test_short_key(self) -> None:
        assert _mask_key("abcdefgh") == "abcdefgh***"

    def test_very_short_key(self) -> None:
        assert _mask_key("ab") == "ab***"


def test_probe_reads_a_403_without_a_rate_limit_as_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verification.urllib.request, "urlopen", _Provider(error=403))
    assert _probe("https://example.invalid/", {}, rejected="NOPE") == "NOPE"
