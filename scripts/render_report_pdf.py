"""Render the State-of-MCP report PDF from `results.json`, and stamp its source.

The PDF is the citable human artifact: the Black Hat abstracts point conference
reviewers at it, and the docs site now serves it at a stable URL. It is generated
from `results.json` by `output.pdf_report.emit_report_pdf` — but nothing
regenerated it and nothing checked it. The committed PDF was written 2026-07-26
while `results.json` moved on 2026-08-17, 2026-09-14 and 2026-09-19 without it.
Giving a stale artifact a permanent address is worse than leaving it hard to
find, which is why this script exists rather than a one-off regeneration.

**Why a stamp and not a diff.** `make report-check` compares a fresh `results.json`
byte-for-byte against the committed one. That cannot work here: reportlab writes a
`/CreationDate` into every PDF, so two renders of identical input differ. Instead
this records the SHA-256 of the `results.json` the PDF was rendered from, beside
the PDF. `--check` re-hashes the live `results.json` and compares — which answers
the question that actually matters ("was this PDF built from the current numbers?")
rather than the one a byte-diff would answer.

Usage:
    python scripts/render_report_pdf.py            # render + stamp
    python scripts/render_report_pdf.py --check    # exit 1 if the stamp is stale
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "research/state-of-mcp-2026/results.json"
PDF = REPO_ROOT / "research/state-of-mcp-2026/state-of-mcp-security-2026.pdf"
STAMP = PDF.with_suffix(".pdf.source.sha256")


def results_digest() -> str:
    """SHA-256 of the results.json the PDF is supposed to describe."""
    return hashlib.sha256(RESULTS.read_bytes()).hexdigest()


def stamped_digest() -> str | None:
    """The digest recorded beside the PDF, or None when unstamped."""
    if not STAMP.is_file():
        return None
    first = STAMP.read_text(encoding="utf-8").split()
    return first[0] if first else None


def render() -> tuple[bool, str]:
    """Render the PDF, and stamp it only if the render happened.

    Returns `emit_report_pdf`'s result. Without reportlab that call writes a text
    fallback and reports failure. The stamp used to be written regardless, which
    certified the PDF already on disk -- built from an older results.json -- as
    current, so `--check` passed on exactly the stale artifact it exists to catch.
    """
    from agent_audit_kit.output.pdf_report import emit_report_pdf

    ok, message = emit_report_pdf(json.loads(RESULTS.read_text(encoding="utf-8")), PDF)
    if ok:
        STAMP.write_text(f"{results_digest()}  results.json\n", encoding="utf-8")
    return ok, message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the PDF was built from a different results.json",
    )
    args = parser.parse_args(argv)

    if not RESULTS.is_file():
        print(f"render_report_pdf: {RESULTS} is missing", file=sys.stderr)
        return 2

    live = results_digest()
    if args.check:
        stamped = stamped_digest()
        if stamped is None:
            print(
                "render_report_pdf: the report PDF carries no source stamp, so "
                "nothing can say which numbers it shows. Run "
                "`python scripts/render_report_pdf.py` and commit both files.",
                file=sys.stderr,
            )
            return 1
        if stamped != live:
            print(
                "render_report_pdf: the report PDF was built from a different "
                f"results.json (stamped {stamped[:12]}…, live {live[:12]}…). "
                "The site serves this PDF at a stable URL, so a stale one is a "
                "published wrong number. Run `make report-pdf` and commit.",
                file=sys.stderr,
            )
            return 1
        print(f"report PDF is current (results.json {live[:12]}…).")
        return 0

    ok, message = render()
    print(message)
    if not ok:
        print(
            "render_report_pdf: reportlab is not installed, so a text fallback "
            "was written instead of the PDF the site links to. The stamp was "
            "left untouched, so `--check` still describes the PDF on disk. "
            "`pip install reportlab`, then `make report-pdf`.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
