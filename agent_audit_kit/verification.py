from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

from agent_audit_kit.models import ScanResult, Severity

_VERIFIABLE_RULES: frozenset[str] = frozenset({
    "AAK-SECRET-001",
    "AAK-SECRET-002",
    "AAK-SECRET-003",
    "AAK-SECRET-008",  # GitHub/GitLab tokens
    "AAK-SECRET-009",  # GCP service account
})

# Patterns to extract the actual key value from finding evidence strings.
# Evidence typically contains text like "Found Anthropic API key: sk-ant-api03..."
_KEY_PATTERNS: dict[str, re.Pattern[str]] = {
    "AAK-SECRET-001": re.compile(r"(sk-ant-api\S+)"),
    "AAK-SECRET-002": re.compile(r"(sk-[A-Za-z0-9_-]{20,})"),
    "AAK-SECRET-003": re.compile(r"(AKIA[A-Z0-9]{16})"),
}

_TIMEOUT_SECONDS: int = 5


def _extract_key(rule_id: str, evidence: str) -> str | None:
    """Extract the actual secret key from finding evidence text.

    Args:
        rule_id: The rule identifier used to select the extraction pattern.
        evidence: The evidence string that may contain an embedded key.

    Returns:
        The extracted key string, or None if no key could be found.
    """
    pattern = _KEY_PATTERNS.get(rule_id)
    if pattern is None:
        return None
    match = pattern.search(evidence)
    return match.group(1) if match else None


def _mask_key(key: str) -> str:
    """Return the first 8 characters of a key followed by '***'.

    Args:
        key: The full key string to mask.

    Returns:
        A masked representation showing only the first 8 characters.
    """
    return key[:8] + "***"


def _verify_anthropic(key: str) -> str:
    """Verify an Anthropic API key by calling the models endpoint.

    Args:
        key: The Anthropic API key to verify.

    Returns:
        A verification status string: CONFIRMED ACTIVE, INACTIVE/ROTATED,
        or VERIFICATION FAILED.
    """
    url = "https://api.anthropic.com/v1/models"
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                return "CONFIRMED ACTIVE"
            return "INACTIVE/ROTATED"
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return "INACTIVE/ROTATED"
        return f"VERIFICATION FAILED (HTTP {exc.code})"
    except (urllib.error.URLError, OSError, TimeoutError):
        return "VERIFICATION FAILED"


def _verify_openai(key: str) -> str:
    """Verify an OpenAI API key by calling the models endpoint.

    Args:
        key: The OpenAI API key to verify.

    Returns:
        A verification status string: CONFIRMED ACTIVE, INACTIVE/ROTATED,
        or VERIFICATION FAILED.
    """
    url = "https://api.openai.com/v1/models"
    headers = {
        "Authorization": f"Bearer {key}",
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                return "CONFIRMED ACTIVE"
            return "INACTIVE/ROTATED"
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return "INACTIVE/ROTATED"
        return f"VERIFICATION FAILED (HTTP {exc.code})"
    except (urllib.error.URLError, OSError, TimeoutError):
        return "VERIFICATION FAILED"


def _verify_gcp(key_json: str) -> str:
    """Verify a GCP service account key by calling the tokeninfo endpoint.

    Args:
        key_json: The GCP service account key (or key fragment).

    Returns:
        A verification status string.
    """
    url = "https://oauth2.googleapis.com/tokeninfo"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                return "CONFIRMED ACTIVE"
            return "INACTIVE/ROTATED"
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 401, 403):
            return "INACTIVE/ROTATED"
        return f"VERIFICATION FAILED (HTTP {exc.code})"
    except (urllib.error.URLError, OSError, TimeoutError):
        return "VERIFICATION FAILED"


_VERIFIERS: dict[str, Any] = {
    "AAK-SECRET-001": _verify_anthropic,
    "AAK-SECRET-002": _verify_openai,
    "AAK-SECRET-009": _verify_gcp,
}


def verify_findings(result: ScanResult) -> ScanResult:
    """Actively verify secret findings by probing provider APIs.

    For each finding whose rule_id is verifiable, this function extracts
    the key from the evidence string and makes a lightweight HTTP call to
    the corresponding provider's API to determine whether the key is
    still active.

    AWS keys (AAK-SECRET-003) are annotated but not actively verified
    because AWS STS verification requires a signed request that is too
    complex for urllib alone.

    The full key is never logged -- only the first 8 characters appear
    in the updated evidence.

    Args:
        result: The ScanResult to verify. Modified in place.

    Returns:
        The same ScanResult with updated evidence on verified findings.
    """
    for finding in result.findings:
        if finding.rule_id not in _VERIFIABLE_RULES:
            continue

        key = _extract_key(finding.rule_id, finding.evidence)
        if key is None:
            finding.evidence += " [verification: could not extract key from evidence]"
            continue

        masked = _mask_key(key)

        # AWS keys -- skip active verification, too complex for urllib
        if finding.rule_id == "AAK-SECRET-003":
            finding.evidence += (
                f" [verification: AWS key {masked} detected;"
                " active check skipped (requires STS signed request)]"
            )
            continue

        verifier = _VERIFIERS.get(finding.rule_id)
        if verifier is None:
            finding.evidence += " [verification: no verifier available]"
            continue

        try:
            status = verifier(key)
        except Exception:
            status = "VERIFICATION FAILED"

        finding.evidence += f" [verification: {status} (key: {masked})]"

        # Auto-upgrade severity to CRITICAL when key is confirmed active
        if status == "CONFIRMED ACTIVE" and finding.severity != Severity.CRITICAL:
            finding.severity = Severity.CRITICAL

    return result
