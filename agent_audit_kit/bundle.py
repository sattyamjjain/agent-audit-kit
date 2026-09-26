"""Rule-bundle packaging and verification.

Sigstore signs release artifacts in CI (see .github/workflows/release.yml).
This module:
- builds a reproducible JSON bundle of the rule catalog
  (`agent-audit-kit export-rules --out rules.json`)
- computes a SHA-256 digest the user can independently verify
- verifies a file a release signed against the Sigstore bundle published
  beside it, and that the signer is this repository's release workflow, when
  sigstore is installed (`pip install "agent-audit-kit[verify]"`;
  `agent-audit-kit verify-bundle`)

The scanner still runs without these deps; signing is opt-in for
compliance workflows.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from agent_audit_kit.rules.builtin import RULES

# Who signs a release: release.yml, keyless, on a `v*` tag push. The Fulcio
# certificate's SAN is that workflow at the tag, `<this>@refs/tags/v0.6.9`.
_RELEASE_WORKFLOW = "https://github.com/sattyamjjain/agent-audit-kit/.github/workflows/release.yml"
_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def build_bundle() -> dict:
    """Assemble a deterministic dict of every rule (for signing)."""
    from agent_audit_kit.models import SCHEMA_VERSION

    entries = sorted(RULES.items())
    return {
        # schema-version string is bumped whenever RuleDefinition grows
        # new reference fields. v2 adds incident_references + aicm_references.
        "schema": f"agent-audit-kit/rule-bundle/{SCHEMA_VERSION}",
        "rules": [
            {
                "rule_id": rid,
                **{
                    k: (v.value if hasattr(v, "value") else v)
                    for k, v in asdict(rule).items()
                    if k != "rule_id"
                },
            }
            for rid, rule in entries
        ],
    }


def write_bundle(path: Path) -> str:
    """Write bundle to `path`. Returns the SHA-256 digest."""
    bundle = build_bundle()
    blob = json.dumps(bundle, indent=2, sort_keys=True).encode("utf-8")
    path.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


def _signers(cert: Any) -> list[str]:
    """The URI identities in a signing certificate's SAN."""
    from cryptography.x509 import SubjectAlternativeName, UniformResourceIdentifier

    try:
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
    except Exception:  # noqa: BLE001 -- no SAN extension: no identity to report
        return []
    return list(san.get_values_for_type(UniformResourceIdentifier))


def _release_policy(tag: str | None) -> Any:
    """The identity a release signature has to carry.

    With ``tag``, exactly release.yml at that tag. Without it, release.yml at any
    ``v*`` tag: a rule bundle does not record its own version, so that is as far
    as the file alone can pin it. A valid Sigstore signature from anyone else --
    another repository, another workflow, a branch -- fails either way.
    """
    from sigstore.errors import VerificationError
    from sigstore.verify import policy

    if tag:
        return policy.Identity(identity=f"{_RELEASE_WORKFLOW}@refs/tags/{tag}", issuer=_GITHUB_OIDC_ISSUER)

    class _ReleaseTag(policy.VerificationPolicy):
        def verify(self, cert: Any) -> None:
            signers = _signers(cert)
            if not any(s.startswith(f"{_RELEASE_WORKFLOW}@refs/tags/v") for s in signers):
                raise VerificationError(f"signed by {signers}, not by {_RELEASE_WORKFLOW} on a version tag")

    return policy.AllOf([policy.OIDCIssuer(_GITHUB_OIDC_ISSUER), _ReleaseTag()])


def verify_bundle(
    bundle_path: Path,
    signature_path: Path | None = None,
    *,
    tag: str | None = None,
    offline: bool = False,
) -> tuple[bool, str]:
    """Verify a rule bundle, or any other file a release signed.

    Without ``signature_path`` only the SHA-256 is returned, to compare with the
    published ``rules.json.sha256``. With it, the Sigstore bundle
    (``rules.json.sigstore.json``) must verify for this file and carry the
    release workflow's identity (`_release_policy`). ``offline`` uses the trust
    root that ships with sigstore instead of refreshing it over TUF.

    Through 0.6.9 this imported ``VerificationMaterials`` and called
    ``Verifier.verify``, both gone since sigstore 3.0, with no identity policy:
    it could not verify a release, and said sigstore was missing when it was not.

    Returns (ok, message).
    """
    if not bundle_path.is_file():
        return False, f"bundle not found: {bundle_path}"
    blob = bundle_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()

    if signature_path is None:
        return True, f"sha256={digest} (signature not supplied; compare against trusted digest)"

    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
    except ImportError:
        return False, (
            'sigstore is not installed: pip install "agent-audit-kit[verify]" '
            f"and re-run. Bundle SHA-256: {digest}"
        )

    try:
        signed = Bundle.from_json(signature_path.read_bytes())
        Verifier.production(offline=offline).verify_artifact(blob, signed, _release_policy(tag))
    except Exception as exc:  # noqa: BLE001 -- any failure is a failed verification, and says why
        return False, f"sigstore verification failed: {exc}. Bundle SHA-256: {digest}"
    signers = ", ".join(_signers(signed.signing_certificate))
    return True, f"sigstore verified · signed by {signers} · sha256={digest}"
