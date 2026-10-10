"""Active verification of leaked secrets: ``aak scan --verify-secrets``.

The scanner never writes a whole secret into a finding. secret_exposure's
evidence carries only a prefix (``Found Anthropic API key: sk-ant-api03...``),
deliberately, because evidence goes into every output format. Through 0.6.20
this module read the key back out of that evidence, so it probed the provider
with the 12-character prefix, got a 401, and reported a live key as
INACTIVE/ROTATED: a false all-clear, the worst answer this feature can give.
Its tests passed only because they hand-built evidence containing a full key.

Verification now re-reads the file the finding names and re-finds the full
secret with secret_exposure's own patterns, imported rather than copied so the
two cannot drift. The full key exists only in local variables for the length
of one run; it is never stored on a finding, in its evidence, or in any output.

What is probed:

- AAK-SECRET-001 (Anthropic) and AAK-SECRET-002 (OpenAI), against each
  provider's models endpoint. Each key belongs to that one provider, so a
  401/403 means the key is dead.
- AAK-SECRET-008: GitHub ``ghp_`` tokens against api.github.com, GitLab
  ``glpat-`` tokens against gitlab.com. Self-hosted instances (GitHub
  Enterprise Server, self-managed GitLab) issue the same formats, so a 401
  there says only that the token is not valid on the public service, and the
  status says exactly that instead of INACTIVE/ROTATED, which would be another
  false all-clear.

What is not: an AWS key (AAK-SECRET-003) needs an STS request signed with its
secret key, and a GCP service-account key (AAK-SECRET-009) needs a JWT signed
with its private key. Neither is possible with the standard library, so both
are annotated as detected but not checked. (A ``_verify_gcp`` that called
tokeninfo without any token used to stand in for the second; every call it
made failed, so every GCP key it saw was reported INACTIVE/ROTATED.)
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.scanners.secret_exposure import (
    ANTHROPIC_KEY,
    GITHUB_TOKEN,
    GITLAB_TOKEN,
    OPENAI_KEY,
)

_VERIFIABLE_RULES: frozenset[str] = frozenset({
    "AAK-SECRET-001",
    "AAK-SECRET-002",
    "AAK-SECRET-003",
    "AAK-SECRET-008",  # GitHub/GitLab tokens
    "AAK-SECRET-009",  # GCP service account
})

# Rules that are annotated as found but deliberately not probed, with why.
_NOT_PROBED: dict[str, str] = {
    "AAK-SECRET-003": (
        "AWS key detected; active check skipped"
        " (requires an STS request signed with the secret key)"
    ),
    "AAK-SECRET-009": (
        "GCP service account key detected; active check skipped"
        " (requires a JWT signed with the private key)"
    ),
}

# secret_exposure's evidence shape: "Found <what>: <prefix>...".
_EVIDENCE_PREFIX_RE = re.compile(r": (\S+?)\.\.\.")

_TIMEOUT_SECONDS: int = 5


def _mask_key(key: str) -> str:
    """Return the first 8 characters of a key followed by '***'.

    Args:
        key: The full key string to mask.

    Returns:
        A masked representation showing only the first 8 characters.
    """
    return key[:8] + "***"


def _probe(url: str, headers: dict[str, str], rejected: str = "INACTIVE/ROTATED") -> str:
    """GET ``url`` with ``headers`` and turn the answer into a status.

    200 is CONFIRMED ACTIVE. Any other success, a 401 and a 403 are
    ``rejected``, except a 403 that reports an exhausted rate limit (GitHub
    answers a throttled request that way), which says nothing about the key.

    Args:
        url: The provider endpoint to call.
        headers: Request headers, the credential among them.
        rejected: The status for a key the provider turned down.

    Returns:
        A verification status string.
    """
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            if resp.status == 200:
                return "CONFIRMED ACTIVE"
            return rejected
    except urllib.error.HTTPError as exc:
        if exc.code == 403 and exc.headers is not None and exc.headers.get("x-ratelimit-remaining") == "0":
            return "VERIFICATION FAILED (rate limited)"
        if exc.code in (401, 403):
            return rejected
        return f"VERIFICATION FAILED (HTTP {exc.code})"
    except (urllib.error.URLError, OSError, TimeoutError):
        return "VERIFICATION FAILED"


def _verify_anthropic(key: str) -> str:
    """Verify an Anthropic API key by calling the models endpoint.

    Args:
        key: The Anthropic API key to verify.

    Returns:
        A verification status string: CONFIRMED ACTIVE, INACTIVE/ROTATED,
        or VERIFICATION FAILED.
    """
    return _probe(
        "https://api.anthropic.com/v1/models",
        {"x-api-key": key, "anthropic-version": "2023-06-01"},
    )


def _verify_openai(key: str) -> str:
    """Verify an OpenAI API key by calling the models endpoint.

    Args:
        key: The OpenAI API key to verify.

    Returns:
        A verification status string: CONFIRMED ACTIVE, INACTIVE/ROTATED,
        or VERIFICATION FAILED.
    """
    return _probe("https://api.openai.com/v1/models", {"Authorization": f"Bearer {key}"})


def _verify_github(token: str) -> str:
    """Verify a GitHub personal access token against api.github.com.

    Args:
        token: The ``ghp_`` token to verify.

    Returns:
        A verification status string: CONFIRMED ACTIVE, NOT VALID ON
        GITHUB.COM (it may still be an Enterprise Server token), or
        VERIFICATION FAILED.
    """
    return _probe(
        "https://api.github.com/user",
        {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "agent-audit-kit",
        },
        rejected="NOT VALID ON GITHUB.COM",
    )


def _verify_gitlab(token: str) -> str:
    """Verify a GitLab personal access token against gitlab.com.

    Args:
        token: The ``glpat-`` token to verify.

    Returns:
        A verification status string: CONFIRMED ACTIVE, NOT VALID ON
        GITLAB.COM (it may still belong to a self-managed instance), or
        VERIFICATION FAILED.
    """
    return _probe(
        "https://gitlab.com/api/v4/user",
        {"PRIVATE-TOKEN": token},
        rejected="NOT VALID ON GITLAB.COM",
    )


def _probe_for(rule_id: str, prefix: str) -> tuple[re.Pattern[str], Callable[[str], str]] | None:
    """The scanner pattern that finds the full secret, and the provider check.

    AAK-SECRET-008 covers two providers; the token prefix the evidence shows
    tells them apart.
    """
    if rule_id == "AAK-SECRET-001":
        return ANTHROPIC_KEY, _verify_anthropic
    if rule_id == "AAK-SECRET-002":
        return OPENAI_KEY, _verify_openai
    if rule_id == "AAK-SECRET-008":
        if prefix.startswith("ghp_"):
            return GITHUB_TOKEN, _verify_github
        if prefix.startswith("glpat-"):
            return GITLAB_TOKEN, _verify_gitlab
    return None


def _read(file_path: Path) -> str | None:
    """The file's text, decoded the way secret_exposure decodes it, or None."""
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _candidates(text: str | None, pattern: re.Pattern[str], prefix: str) -> list[tuple[int, str]]:
    """``(line, full secret)`` for each match in ``text`` starting with ``prefix``.

    Lines are counted incrementally between matches, so a file with many
    matches costs one pass, not one pass per match.
    """
    if text is None:
        return []
    found: list[tuple[int, str]] = []
    line, pos = 1, 0
    for match in pattern.finditer(text):
        line += text.count("\n", pos, match.start())
        pos = match.start()
        if match.group().startswith(prefix):
            found.append((line, match.group()))
    return found


def _take(candidates: list[tuple[int, str]], line_number: int | None) -> str | None:
    """Remove and return one finding's key: the one on its reported line if
    there is one, else the next in file order.

    Findings that share a prefix share a reported line as well: every
    Anthropic key starts ``sk-ant-api03``, and secret_exposure reports the
    first line containing the prefix. Taking in file order then gives the
    n-th such finding the n-th key, which is the order the scanner emitted
    them in, so two keys in one file are each probed as themselves.
    """
    if not candidates:
        return None
    for index, (line, _key) in enumerate(candidates):
        if line == line_number:
            return candidates.pop(index)[1]
    return candidates.pop(0)[1]


def verify_findings(result: ScanResult, project_root: Path) -> ScanResult:
    """Actively verify secret findings by probing provider APIs.

    Re-reads each verifiable finding's file under ``project_root`` to recover
    the full secret (the module docstring says why the evidence cannot be
    used), asks the provider whether it is live, and appends the answer to
    the evidence with the key masked to its first 8 characters. A key
    confirmed live raises the finding to CRITICAL. Each distinct key is
    probed once per run.

    Args:
        result: The ScanResult to verify. Modified in place.
        project_root: The directory the scan ran over; finding paths are
            relative to it.

    Returns:
        The same ScanResult with updated evidence on verifiable findings.
    """
    texts: dict[str, str | None] = {}
    unused: dict[tuple[str, str, str], list[tuple[int, str]]] = {}
    statuses: dict[str, str] = {}

    for finding in result.findings:
        if finding.rule_id not in _VERIFIABLE_RULES:
            continue
        if finding.rule_id in _NOT_PROBED:
            finding.evidence += f" [verification: {_NOT_PROBED[finding.rule_id]}]"
            continue

        shown = _EVIDENCE_PREFIX_RE.search(finding.evidence)
        prefix = shown.group(1) if shown else ""
        probe = _probe_for(finding.rule_id, prefix) if prefix else None
        if probe is None:
            finding.evidence += " [verification: no verifier available]"
            continue
        pattern, verifier = probe

        group = (finding.file_path, finding.rule_id, prefix)
        if group not in unused:
            if finding.file_path not in texts:
                texts[finding.file_path] = _read(project_root / finding.file_path)
            unused[group] = _candidates(texts[finding.file_path], pattern, prefix)
        key = _take(unused[group], finding.line_number)
        if key is None:
            finding.evidence += " [verification: key no longer in file]"
            continue

        if key not in statuses:
            try:
                statuses[key] = verifier(key)
            except Exception:
                statuses[key] = "VERIFICATION FAILED"
        status = statuses[key]
        finding.evidence += f" [verification: {status} (key: {_mask_key(key)})]"

        # Auto-upgrade severity to CRITICAL when the key is confirmed active
        if status == "CONFIRMED ACTIVE" and finding.severity != Severity.CRITICAL:
            finding.severity = Severity.CRITICAL

    return result
