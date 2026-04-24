#!/usr/bin/env python3
"""Sync repo-level metadata with the shipped release.

Two jobs:

1. Rewrite every `sattyamjjain/agent-audit-kit@vX.Y.Z` reference in
   README.md + docs/**/*.md to the version recorded in pyproject.toml.
2. Generate the target GitHub repo-description string so CI can
   `gh repo edit --description "$(python scripts/sync_repo_metadata.py --description)"`.

Pre-commit use: `python scripts/sync_repo_metadata.py --check` exits
non-zero if README / docs disagree with the live pyproject version.
`--write` rewrites on disk. `--description` prints the canonical
repo-description and exits.

Hard constraints:
- Never auto-edit docs/launch/release-notes-v*.md — those are historical
  artifacts and should pin the version they documented.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:  # Python 3.11+ stdlib
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"
DOCS_DIR = REPO_ROOT / "docs"
AAK_PKG = REPO_ROOT / "agent_audit_kit" / "__init__.py"

_REPO_REF_RE = re.compile(r"sattyamjjain/agent-audit-kit@v\d+\.\d+\.\d+")
_HISTORY_STEM_RE = re.compile(r"release-notes-v\d+\.\d+\.\d+")


def _read_version() -> str:
    with PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    return str(data["project"]["version"])


def _read_rule_count() -> int:
    text = AAK_PKG.read_text(encoding="utf-8")
    m = re.search(r"RULE_COUNT\s*=\s*(\d+)", text)
    if not m:
        raise RuntimeError("RULE_COUNT not found in agent_audit_kit/__init__.py")
    return int(m.group(1))


def _iter_docs() -> list[Path]:
    out: list[Path] = [README] if README.is_file() else []
    if DOCS_DIR.is_dir():
        for path in DOCS_DIR.rglob("*.md"):
            if _HISTORY_STEM_RE.search(path.stem):
                continue
            out.append(path)
    return out


def _rewrite(doc: Path, target_ref: str) -> tuple[bool, int]:
    text = doc.read_text(encoding="utf-8")
    new_text, n = _REPO_REF_RE.subn(target_ref, text)
    if n and new_text != text:
        doc.write_text(new_text, encoding="utf-8")
        return True, n
    return False, 0


def _check(target_ref: str) -> list[Path]:
    drift: list[Path] = []
    for doc in _iter_docs():
        text = doc.read_text(encoding="utf-8")
        for m in _REPO_REF_RE.finditer(text):
            if m.group(0) != target_ref:
                drift.append(doc)
                break
    return drift


def _description_string() -> str:
    version = _read_version()
    rule_count = _read_rule_count()
    return (
        f"AgentAuditKit v{version} — security scanner for MCP-connected "
        f"AI agent pipelines ({rule_count} rules across "
        "OWASP Agentic Top 10 + MCP Top 10, CSA AICM, EU AI Act)."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 if pins drift")
    mode.add_argument("--write", action="store_true", help="rewrite README+docs")
    mode.add_argument(
        "--description",
        action="store_true",
        help="print the canonical GitHub repo description and exit",
    )
    args = parser.parse_args(argv)

    version = _read_version()
    target_ref = f"sattyamjjain/agent-audit-kit@v{version}"

    if args.description:
        sys.stdout.write(_description_string() + "\n")
        return 0

    if args.check:
        drift = _check(target_ref)
        if not drift:
            return 0
        sys.stderr.write(
            "pin drift: docs reference a version other than "
            f"{target_ref!r}:\n"
        )
        for doc in drift:
            sys.stderr.write(f"  - {doc.relative_to(REPO_ROOT)}\n")
        sys.stderr.write(
            "Run `python scripts/sync_repo_metadata.py --write` to fix.\n"
        )
        return 1

    # --write
    total = 0
    for doc in _iter_docs():
        wrote, n = _rewrite(doc, target_ref)
        if wrote:
            sys.stdout.write(
                f"{doc.relative_to(REPO_ROOT)}: {n} rewrite(s) → {target_ref}\n"
            )
            total += n
    if total == 0:
        sys.stdout.write("no changes needed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
