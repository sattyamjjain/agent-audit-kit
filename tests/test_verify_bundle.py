"""`verify-bundle --signature` verifies a release's Sigstore bundle and signer.

Through 0.6.9 it could not. `verify_bundle()` imported `VerificationMaterials`,
which sigstore-python removed in 3.0, so with sigstore installed it still said
"sigstore package not installed"; past that it called `Verifier.verify(blob,
sig)`, which no longer exists either, with no identity policy, which would have
accepted a valid signature from anyone. And the documented command named
`rules.json.sigstore` where the release attaches `rules.json.sigstore.json`.

The fixture is the smallest file v0.6.9 signed, its SBOM (``rules.json`` is
531 KB), with the Sigstore bundle release.yml attached beside it. Both are
byte-identical to the published assets.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from agent_audit_kit import bundle as bundle_mod
from agent_audit_kit.bundle import verify_bundle
from agent_audit_kit.cli import cli

REPO = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures" / "sigstore" / "v0.6.9"
ARTIFACT = FIX / "sbom.cdx.json"
SIGNATURE = FIX / "sbom.cdx.json.sigstore.json"
SIGNER = "https://github.com/sattyamjjain/agent-audit-kit/.github/workflows/release.yml@refs/tags/v0.6.9"

needs_sigstore = pytest.mark.skipif(
    importlib.util.find_spec("sigstore") is None,
    reason='needs sigstore: pip install "agent-audit-kit[verify]" ([dev] pulls it in)',
)


@needs_sigstore
def test_a_release_signature_verifies_and_names_its_signer() -> None:
    ok, message = verify_bundle(ARTIFACT, SIGNATURE, offline=True)
    assert ok, message
    assert SIGNER in message


@needs_sigstore
def test_the_tag_pins_the_release() -> None:
    assert verify_bundle(ARTIFACT, SIGNATURE, tag="v0.6.9", offline=True)[0]
    ok, message = verify_bundle(ARTIFACT, SIGNATURE, tag="v0.6.8", offline=True)
    assert not ok
    assert "v0.6.8" in message


@needs_sigstore
def test_a_changed_file_fails(tmp_path: Path) -> None:
    changed = tmp_path / ARTIFACT.name
    changed.write_bytes(ARTIFACT.read_bytes().replace(b"CycloneDX", b"CycloneDx", 1))
    ok, message = verify_bundle(changed, SIGNATURE, offline=True)
    assert not ok
    assert "digest" in message.lower()


@needs_sigstore
def test_a_signature_from_another_workflow_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid Sigstore signature is not enough: it must be release.yml's, on a tag."""
    other = "https://github.com/someone-else/agent-audit-kit/.github/workflows/release.yml"
    monkeypatch.setattr(bundle_mod, "_RELEASE_WORKFLOW", other)
    ok, message = verify_bundle(ARTIFACT, SIGNATURE, offline=True)
    assert not ok
    assert other in message


def test_without_sigstore_the_message_says_how_to_install_it(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("sigstore", "sigstore.models", "sigstore.verify", "sigstore.errors"):
        monkeypatch.setitem(sys.modules, name, None)
    ok, message = verify_bundle(ARTIFACT, SIGNATURE)
    assert not ok
    assert 'pip install "agent-audit-kit[verify]"' in message


@needs_sigstore
def test_the_cli_takes_the_tag_and_works_offline() -> None:
    result = CliRunner().invoke(cli, [
        "verify-bundle", str(ARTIFACT), "--signature", str(SIGNATURE), "--tag", "v0.6.9", "--offline",
    ])
    assert result.exit_code == 0, result.output
    assert "sigstore verified" in result.output


def test_the_documented_command_names_the_published_signature_file() -> None:
    why = (REPO / "docs" / "why.md").read_text(encoding="utf-8")
    assert "verify-bundle rules.json --signature rules.json.sigstore.json" in why
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    body = next(s["with"]["body"] for s in doc["jobs"]["github-release"]["steps"]
                if s.get("name") == "Create release")
    assert "verify-bundle rules.json --signature rules.json.sigstore.json --tag ${{ github.ref_name }}" in body
