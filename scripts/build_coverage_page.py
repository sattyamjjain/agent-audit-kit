#!/usr/bin/env python3
"""F3 — Build the public coverage page (`aak.dev/coverage`).

Reads every coverage source AAK ships with — currently OX-disclosed
CVEs and the Prisma AIRS catalog — and emits a static HTML matrix at
`site/coverage/index.html` (gh-pages target).

Each row links back to the rule documentation and the upstream
disclosure. Re-runnable; the GitHub workflow at
`.github/workflows/coverage-page.yml` invokes this nightly.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from agent_audit_kit import __version__
from agent_audit_kit.coverage import load_manifest, summarize as ox_summarize
from agent_audit_kit.translators.prisma_airs import summarize as airs_summarize


REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "site" / "coverage"

# The latency figure is computed by the same code that writes docs/cve-latency.md,
# so the page and the doc can never quote different numbers for the same window.
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from cve_latency import WindowStats, window_stats  # noqa: E402


_HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>AAK Coverage Matrix — v{version}</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
  body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem auto; max-width: 1080px; color: #111; }}
  h1, h2 {{ font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
  th, td {{ border: 1px solid #d0d7de; padding: 6px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f6f8fa; }}
  .ok {{ color: #1a7f37; }}
  .miss {{ color: #cf222e; }}
  .runtime {{ color: #57606a; font-style: italic; }}
  code {{ font-size: 0.9em; }}
  .meta {{ color: #57606a; font-size: 0.9em; }}
</style>
</head>
<body>
<h1>AAK coverage — v{version}</h1>
<p class="meta">Static matrix. Generated nightly. Source manifests under
<code>agent_audit_kit/data/</code>.</p>
"""


def _render_ox(summary: dict) -> str:
    rows = []
    for entry in summary["entries"]:
        mark = "<span class='ok'>covered</span>" if entry["covered"] else "<span class='miss'>missing</span>"
        rules = ", ".join(f"<code>{r}</code>" for r in entry["rules"]) or "—"
        rows.append(
            f"<tr><td>{entry['cve']}</td><td>{entry['title']}</td>"
            f"<td>{mark}</td><td>{rules}</td></tr>"
        )
    return (
        f"<h2>OX-disclosed CVEs ({summary['covered']}/{summary['total']} "
        f"= {summary['coverage_pct']}%)</h2>"
        "<table><tr><th>CVE / disclosure</th><th>Title</th><th>Status</th><th>Covering rule(s)</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def _render_airs(summary: dict) -> str:
    rows = []
    for entry in summary["entries"]:
        if entry["status"] == "covered" and entry["aak_rule_ids"]:
            mark = "<span class='ok'>covered</span>"
        elif entry["status"] in {"runtime-only", "catalog-private"}:
            mark = f"<span class='runtime'>{entry['status']}</span>"
        else:
            mark = "<span class='miss'>uncovered</span>"
        rules = ", ".join(f"<code>{r}</code>" for r in entry["aak_rule_ids"]) or "—"
        rows.append(
            f"<tr><td>{entry['airs_attack_id']}</td><td>{entry['title']}</td>"
            f"<td>{mark}</td><td>{rules}</td></tr>"
        )
    return (
        f"<h2>Prisma AIRS attack catalog "
        f"({summary['covered']}/{summary['total_static']} static-relevant "
        f"= {summary['coverage_pct']}%)</h2>"
        "<table><tr><th>Attack ID</th><th>Title</th><th>Status</th><th>Covering rule(s)</th></tr>"
        + "".join(rows)
        + "</table>"
    )


# --- CVE response latency -----------------------------------------------------
#
# A coverage matrix says which CVEs have a rule. It says nothing about how long
# the rule took to arrive, and this project retired its public 48-hour SLA
# because a promise is the wrong instrument. A published, recomputed number is
# the right one.
#
# The figure carries its own denominator and its own computed-on date. The date
# is not decoration: `--check` fails the build once it is more than
# MAX_FIGURE_AGE_DAYS old, so a page that quietly stops being rebuilt says so
# instead of going on displaying a number from an unknown past. Same instrument
# the README's MCP Security Index line uses, deliberately, so the two surfaces
# cannot disagree about what "current" means.

LATENCY_WINDOW_DAYS = 90
MAX_FIGURE_AGE_DAYS = 7

_COMPUTED_ON_RE = re.compile(
    r"<!--\s*cve-latency-computed-on:\s*(\d{4}-\d{2}-\d{2})\s*-->"
)


def _latency_stats() -> "Optional[WindowStats]":
    return window_stats(LATENCY_WINDOW_DAYS)


def _render_latency(stats: "Optional[WindowStats]") -> str:
    head = "<h2>CVE response latency</h2>"
    if stats is None:
        return (
            f"{head}\n<p class=\"runtime\">No CVE published in the trailing "
            f"{LATENCY_WINDOW_DAYS} days has a recorded rule-ship date, so there "
            "is nothing to report. A figure would be a statistic over an empty "
            "sample.</p>\n"
        )
    backlog = (
        ""
        if not stats.backlog_n
        else (
            f" {stats.backlog_n} of them shipped more than 30 days after "
            "publication and are backlog rather than fresh response."
        )
    )
    return (
        f"{head}\n"
        f"<!-- cve-latency-computed-on: {stats.computed_on.isoformat()} -->\n"
        "<p>Days from NVD publication to the commit that shipped the rule, for "
        f"CVEs published in the trailing {stats.window_days} days. Computed from "
        "<code>CHANGELOG.cves.md</code>; every underlying row is listed in "
        "<code>docs/cve-latency.md</code>.</p>\n"
        "<table>\n"
        "<tr><th>Median</th><th>p90 (nearest-rank)</th><th>Sample (n)</th>"
        "<th>Computed on</th></tr>\n"
        f"<tr><td>{stats.median_days:.1f} days</td>"
        f"<td>{stats.p90_days} days</td>"
        f"<td>{stats.n}</td>"
        f"<td>{stats.computed_on.isoformat()}</td></tr>\n"
        "</table>\n"
        f"<p class=\"runtime\">n is printed because a median over a handful of "
        f"CVEs is not a median.{backlog} This is a measurement, not a service "
        "level: AgentAuditKit publishes no CVE-response SLA.</p>\n"
    )


def check_figure_freshness() -> int:
    """Fail when the committed page's computed-on date has gone stale.

    Rebuilding always stamps today, so checking the freshly built page would
    prove nothing. This reads what is committed.
    """
    out = OUT_DIR / "index.html"
    if not out.is_file():
        print(f"{out} has not been built", file=sys.stderr)
        return 1
    found = _COMPUTED_ON_RE.search(out.read_text(encoding="utf-8"))
    if not found:
        print(
            "the coverage page carries no cve-latency-computed-on marker; the "
            "latency figure must state when it was computed",
            file=sys.stderr,
        )
        return 1
    computed = datetime.strptime(found.group(1), "%Y-%m-%d").date()
    age = (date.today() - computed).days
    if age > MAX_FIGURE_AGE_DAYS:
        print(
            f"coverage page CVE-latency figure was computed {computed.isoformat()} "
            f"({age} days ago, limit {MAX_FIGURE_AGE_DAYS}). The nightly "
            "coverage-page workflow has not published in over a week — check it "
            "before trusting the number on the page.",
            file=sys.stderr,
        )
        return 1
    print(f"coverage page latency figure is current (computed {computed}, {age}d ago)")
    return 0


def main(argv: "Optional[list[str]]" = None) -> int:
    """Build the page, or with ``--check`` verify the committed one is fresh.

    ``argv`` defaults to EMPTY, not to ``sys.argv[1:]``: this is called directly
    from tests, and a default of ``sys.argv`` would parse pytest's own flags and
    exit. The entry point below passes the real argv. Same bug that made
    ``gen_owasp_coverage.py`` silently ignore every flag it was given.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed page's latency figure is fresh; do not rebuild.",
    )
    args = parser.parse_args(argv or [])

    if args.check:
        return check_figure_freshness()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ox = ox_summarize(load_manifest("ox"))
    airs = airs_summarize()
    stats = _latency_stats()
    html = (
        _HTML_HEAD.format(version=__version__)
        + _render_ox(ox)
        + _render_airs(airs)
        + _render_latency(stats)
        + "</body></html>\n"
    )
    out = OUT_DIR / "index.html"
    out.write_text(html, encoding="utf-8")
    (OUT_DIR / "ox.json").write_text(json.dumps(ox, indent=2), encoding="utf-8")
    (OUT_DIR / "prisma-airs.json").write_text(json.dumps(airs, indent=2), encoding="utf-8")
    latency = (
        "no CVE in window"
        if stats is None
        else f"latency median {stats.median_days}d p90 {stats.p90_days}d n={stats.n}"
    )
    print(
        f"wrote {out} (ox={ox['coverage_pct']}%, airs={airs['coverage_pct']}%, "
        f"{latency})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
