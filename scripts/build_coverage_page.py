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

import json
from pathlib import Path

from agent_audit_kit import __version__
from agent_audit_kit.coverage import load_manifest, summarize as ox_summarize
from agent_audit_kit.translators.prisma_airs import summarize as airs_summarize


REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "site" / "coverage"


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


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ox = ox_summarize(load_manifest("ox"))
    airs = airs_summarize()
    html = (
        _HTML_HEAD.format(version=__version__)
        + _render_ox(ox)
        + _render_airs(airs)
        + "</body></html>\n"
    )
    out = OUT_DIR / "index.html"
    out.write_text(html, encoding="utf-8")
    (OUT_DIR / "ox.json").write_text(json.dumps(ox, indent=2), encoding="utf-8")
    (OUT_DIR / "prisma-airs.json").write_text(json.dumps(airs, indent=2), encoding="utf-8")
    print(f"wrote {out} (ox={ox['coverage_pct']}%, airs={airs['coverage_pct']}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
