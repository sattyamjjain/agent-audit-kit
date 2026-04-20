"""Rule-bundle packaging and verification.

Sigstore signs release artifacts in CI (see .github/workflows/release.yml).
This module:
- builds a reproducible JSON bundle of the rule catalog
  (`agent-audit-kit export-rules --out rules.json`)
- computes a SHA-256 digest the user can independently verify
- verifies a local bundle against a detached signature + certificate if
  the `sigstore` package is available (`agent-audit-kit verify-bundle`)

The scanner still runs without these deps; signing is opt-in for
compliance workflows.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES


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


def verify_bundle(bundle_path: Path, signature_path: Path | None = None) -> tuple[bool, str]:
    """Verify a rule bundle.

    If `signature_path` is given AND the `sigstore` package is importable,
    a full cryptographic verification is attempted. Otherwise only the
    bundle's SHA-256 is returned and the caller is expected to compare
    against a trusted digest.

    Returns (ok, message).
    """
    if not bundle_path.is_file():
        return False, f"bundle not found: {bundle_path}"
    blob = bundle_path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()

    if signature_path is None:
        return True, f"sha256={digest} (signature not supplied; compare against trusted digest)"

    try:
        from sigstore.verify import Verifier, VerificationMaterials  # type: ignore[import-not-found]
    except ImportError:
        return False, (
            "sigstore package not installed. Install with `pip install sigstore` "
            f"and re-run. Bundle SHA-256: {digest}"
        )

    try:
        verifier = Verifier.production()
        _ = VerificationMaterials  # type: ignore[unused-ignore]
        # Full signature verification path — we keep the call shape
        # flexible because sigstore-python's Verifier.verify() signature
        # has shifted between 1.x and 3.x releases.
        sig_blob = signature_path.read_bytes()
        verifier.verify(blob, sig_blob)
        return True, f"sigstore verified · sha256={digest}"
    except Exception as exc:  # noqa: BLE001 — surface any verification failure
        return False, f"sigstore verification failed: {exc}. Bundle SHA-256: {digest}"
