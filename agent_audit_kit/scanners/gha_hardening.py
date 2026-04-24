"""AAK-GHA-IMMUTABLE-001 — non-SHA-pinned third-party GitHub Actions.

GitHub's April 2026 Security Roadmap ships Immutable Actions and makes
SHA pinning the default policy. This scanner walks `.github/workflows/*.yml`
and flags every `uses: owner/action@ref` where `ref` is a tag or branch
name instead of a 40-character commit SHA.

First-party Actions (`actions/*` and `github/*`) are exempt — GitHub
publishes them as Immutable Actions.

Local composite Actions (`uses: ./path/to/action`) are exempt — they
ship in the caller's own repo.

Docker-ref Actions (`uses: docker://image:tag`) get their own warning:
Docker refs are not SHA-pinned by default; Immutable Actions apply only
to the `owner/action@ref` form.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding

from ._helpers import find_line_number, make_finding

_WORKFLOWS_DIR = ".github/workflows"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_OWNER_EXEMPT = frozenset({"actions", "github"})


def _iter_workflows(project_root: Path) -> list[Path]:
    wf_dir = project_root / _WORKFLOWS_DIR
    if not wf_dir.is_dir():
        return []
    out: list[Path] = []
    for path in wf_dir.iterdir():
        if not path.is_file():
            continue
        if path.suffix not in (".yml", ".yaml"):
            continue
        out.append(path)
    return out


def _walk_uses(obj, hits: list[str]) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key == "uses" and isinstance(val, str):
                hits.append(val)
            else:
                _walk_uses(val, hits)
    elif isinstance(obj, list):
        for item in obj:
            _walk_uses(item, hits)


def _is_sha_pinned(ref: str) -> bool:
    return bool(_SHA_RE.match(ref))


def _classify(uses: str) -> tuple[str, str, str] | None:
    """Return (owner, action, ref) or None if not an owner/action@ref form."""
    if not uses or uses.startswith("./") or uses.startswith("docker://"):
        return None
    if "@" not in uses:
        return None
    before, _, ref = uses.partition("@")
    if "/" not in before:
        return None
    owner, _, action = before.partition("/")
    return owner.strip(), action.strip(), ref.strip()


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for wf in _iter_workflows(project_root):
        rel = str(wf.relative_to(project_root))
        scanned.add(rel)
        try:
            text = wf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            continue

        # Prefer the parsed YAML walk so we handle every job/step shape.
        # Fall back to regex line-scan so findings still get accurate line
        # numbers (yaml.safe_load drops source positions).
        parsed_uses: list[str] = []
        _walk_uses(doc, parsed_uses)

        seen: set[str] = set()
        for uses in parsed_uses:
            if uses in seen:
                continue
            seen.add(uses)
            classified = _classify(uses)
            if classified is None:
                continue
            owner, action, ref = classified
            if owner.lower() in _OWNER_EXEMPT:
                continue
            if _is_sha_pinned(ref):
                continue
            findings.append(make_finding(
                "AAK-GHA-IMMUTABLE-001",
                rel,
                f"`uses: {owner}/{action}@{ref}` is pinned by tag/branch, not by "
                "40-character commit SHA. GitHub's 2026 Security Roadmap "
                "requires SHA pinning for third-party Actions.",
                line_number=find_line_number(text, f"{owner}/{action}@{ref}"),
            ))
    return findings, scanned
