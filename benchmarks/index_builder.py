"""MCP Security Index builder.

Consumes the output of `benchmarks/crawler.py` (which discovers public
`.mcp.json` files from GitHub code search), runs `agent-audit-kit scan`
on each downloaded repo slice, scores it, and emits a JSON dataset +
a static HTML site ready for Cloudflare Pages deployment.

Outputs:
    benchmarks/site/data/index.json   — per-server grades (A–F)
    benchmarks/site/data/history.json — weekly snapshots
    benchmarks/site/index.html        — leaderboard
    benchmarks/site/server/<slug>.html — per-server card

Usage:
    python benchmarks/index_builder.py \\
        --input benchmarks/results.json \\
        --site-dir benchmarks/site

Per-server disclosure follows docs/disclosure-policy.md: findings are
only surfaced in the public leaderboard 90 days after private notice.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class ServerCard:
    slug: str
    name: str
    repo_url: str
    grade: str
    score: int
    critical: int
    high: int
    medium: int
    low: int
    last_scanned: str
    disclosure_state: str  # "embargoed" | "public" | "no-findings"


_TEMPLATE_INDEX = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>MCP Security Index — agent-audit-kit</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: -apple-system, Segoe UI, Inter, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; color:#0c0c0d; }}
  h1 {{ font-size: 1.6rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th, td {{ padding: .55rem .7rem; border-bottom: 1px solid #e6e6e9; font-size: .95rem; text-align: left; }}
  th {{ background: #f6f6f8; font-weight: 600; }}
  .grade {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-weight: 600; }}
  .grade-A {{ background: #16a34a; }} .grade-B {{ background: #65a30d; }} .grade-C {{ background: #ca8a04; }}
  .grade-D {{ background: #ea580c; }} .grade-F {{ background: #dc2626; }}
  .muted {{ color: #6b7280; font-size: .85rem; }}
  .badge {{ font-size: .75rem; padding: 1px 6px; border-radius: 3px; background:#f3f4f6; color:#374151; margin-left:.4rem; }}
</style>
</head><body>
<h1>MCP Security Index</h1>
<p class="muted">Weekly grade across {total} public MCP servers. Scanner:
<a href="https://github.com/sattyamjjain/agent-audit-kit">agent-audit-kit</a>. Snapshot: {snapshot}.</p>
<p class="muted">New vulnerabilities are reported privately first and surfaced here only after our 90-day
<a href="https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/disclosure-policy.md">disclosure policy</a> window.</p>
<table>
<thead><tr><th>#</th><th>Server</th><th>Grade</th><th>Score</th><th>Criticals</th><th>Highs</th><th>Last scanned</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<p class="muted" style="margin-top:2rem">
Data: <a href="data/index.json">index.json</a> (weekly).
Prior snapshots: <a href="data/history.json">history.json</a>.
Index code: <a href="https://github.com/sattyamjjain/agent-audit-kit/tree/main/benchmarks">benchmarks/</a>.
</p>
</body></html>
"""


_TEMPLATE_ROW = """<tr>
<td>{idx}</td>
<td><a href="server/{slug}.html">{name}</a> {badge}</td>
<td><span class="grade grade-{grade_letter}">{grade}</span></td>
<td>{score}/100</td>
<td>{critical}</td>
<td>{high}</td>
<td class="muted">{last_scanned}</td>
</tr>"""


_TEMPLATE_CARD = """<!doctype html>
<html><head>
<meta charset="utf-8"><title>{name} — MCP Security Index</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Inter, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }}
  .grade {{ display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: 700; font-size:1.2rem; }}
  .grade-A {{ background: #16a34a; }} .grade-B {{ background: #65a30d; }} .grade-C {{ background: #ca8a04; }}
  .grade-D {{ background: #ea580c; }} .grade-F {{ background: #dc2626; }}
  .stat {{ display: inline-block; margin-right: 1rem; padding: 4px 10px; background: #f3f4f6; border-radius: 4px; }}
</style>
</head><body>
<p><a href="../index.html">← index</a></p>
<h1>{name}</h1>
<p><a href="{repo_url}">{repo_url}</a></p>
<p><span class="grade grade-{grade_letter}">{grade}</span>
<span class="stat">Score {score}/100</span>
<span class="stat">Critical {critical}</span>
<span class="stat">High {high}</span>
<span class="stat">Medium {medium}</span>
<span class="stat">Low {low}</span></p>
<p>Last scanned {last_scanned}. Disclosure state: <strong>{disclosure_state}</strong>.</p>
<p>Findings below the 90-day embargo window are omitted. See the
<a href="https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/disclosure-policy.md">disclosure policy</a>.</p>
</body></html>
"""


def score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


_SEVERITY_PENALTY = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}


def _score_from_severity_counts(counts: dict[str, int]) -> int:
    total = sum(counts.get(sev, 0) * pen for sev, pen in _SEVERITY_PENALTY.items())
    return max(0, 100 - total)


def cards_from_results(results_path: Path) -> list[ServerCard]:
    """Load crawler output and produce ServerCard entries.

    Accepts either:
    (a) the v0.2.x `benchmarks/crawler.py` schema (configs list with
        findings_by_severity per config), OR
    (b) a flat list of per-server dicts (tests, third-party tools).

    Disclosure state:
    - no-findings if the scan had zero findings,
    - embargoed if the entry has embargoed=true (still inside the
      90-day window from docs/disclosure-policy.md),
    - public otherwise.
    """
    raw = json.loads(results_path.read_text(encoding="utf-8"))
    cards: list[ServerCard] = []
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    if isinstance(raw, dict) and "configs" in raw:
        crawl_ts = raw.get("crawl_timestamp") or now
        entries = raw["configs"]
        for entry in entries:
            if entry.get("scan_error"):
                continue
            repo = entry.get("source_repo") or ""
            counts = entry.get("findings_by_severity") or {}
            cards.append(_card_from_crawler_entry(entry, repo, counts, crawl_ts))
    else:
        entries = raw if isinstance(raw, list) else raw.get("results") or []
        for entry in entries:
            repo = entry.get("repo") or entry.get("repository") or ""
            counts = {
                "critical": entry.get("critical") or 0,
                "high": entry.get("high") or 0,
                "medium": entry.get("medium") or 0,
                "low": entry.get("low") or 0,
            }
            score = int(entry.get("score")) if entry.get("score") is not None else _score_from_severity_counts(counts)
            last_scanned = entry.get("last_scanned") or now
            cards.append(_build_card(repo, entry.get("name") or repo, score, counts, last_scanned, bool(entry.get("embargoed"))))

    cards.sort(key=lambda c: (-c.score, c.name))
    return cards


def _card_from_crawler_entry(
    entry: dict,
    repo: str,
    counts: dict[str, int],
    last_scanned: str,
) -> ServerCard:
    # Default: embargo brand-new findings per the 90-day disclosure policy.
    has_findings = sum(counts.values()) > 0
    embargoed = entry.get("embargoed", has_findings)
    score = _score_from_severity_counts(counts)
    # Use source_path to disambiguate multiple configs from the same repo.
    path_hint = entry.get("source_path", "")
    name = f"{repo}/{path_hint}" if path_hint and path_hint != ".mcp.json" else repo
    return _build_card(repo, name, score, counts, last_scanned, embargoed)


def _build_card(
    repo: str,
    name: str,
    score: int,
    counts: dict[str, int],
    last_scanned: str,
    embargoed: bool,
) -> ServerCard:
    slug = (repo or name or "unknown").replace("/", "__").replace(".", "_").lower()
    has_findings = sum(counts.values()) > 0
    disclosure_state = (
        "no-findings"
        if not has_findings
        else ("embargoed" if embargoed else "public")
    )
    return ServerCard(
        slug=slug,
        name=name or slug,
        repo_url=f"https://github.com/{repo}" if repo else "",
        grade=score_to_grade(score),
        score=score,
        critical=int(counts.get("critical", 0)),
        high=int(counts.get("high", 0)),
        medium=int(counts.get("medium", 0)),
        low=int(counts.get("low", 0)),
        last_scanned=last_scanned,
        disclosure_state=disclosure_state,
    )


def write_site(cards: list[ServerCard], site_dir: Path) -> None:
    (site_dir / "data").mkdir(parents=True, exist_ok=True)
    (site_dir / "server").mkdir(parents=True, exist_ok=True)

    index_json = site_dir / "data" / "index.json"
    index_json.write_text(
        json.dumps([asdict(c) for c in cards], indent=2),
        encoding="utf-8",
    )

    history_path = site_dir / "data" / "history.json"
    history = []
    if history_path.is_file():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            history = []
    history.append(
        {
            "snapshot": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "total": len(cards),
            "distribution": {
                "A": sum(1 for c in cards if c.grade == "A"),
                "B": sum(1 for c in cards if c.grade == "B"),
                "C": sum(1 for c in cards if c.grade == "C"),
                "D": sum(1 for c in cards if c.grade == "D"),
                "F": sum(1 for c in cards if c.grade == "F"),
            },
        }
    )
    history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")

    rows = "\n".join(
        _TEMPLATE_ROW.format(
            idx=i + 1,
            slug=html.escape(c.slug),
            name=html.escape(c.name),
            badge=f'<span class="badge">{html.escape(c.disclosure_state)}</span>' if c.disclosure_state != "public" else "",
            grade=c.grade,
            grade_letter=c.grade,
            score=c.score,
            critical=c.critical,
            high=c.high,
            last_scanned=c.last_scanned.split("T")[0],
        )
        for i, c in enumerate(cards)
    )
    (site_dir / "index.html").write_text(
        _TEMPLATE_INDEX.format(
            total=len(cards),
            snapshot=dt.datetime.now(dt.timezone.utc).isoformat(timespec="minutes"),
            rows=rows,
        ),
        encoding="utf-8",
    )

    for c in cards:
        (site_dir / "server" / f"{c.slug}.html").write_text(
            _TEMPLATE_CARD.format(
                name=html.escape(c.name),
                repo_url=html.escape(c.repo_url),
                grade=c.grade,
                grade_letter=c.grade,
                score=c.score,
                critical=c.critical,
                high=c.high,
                medium=c.medium,
                low=c.low,
                last_scanned=c.last_scanned,
                disclosure_state=c.disclosure_state,
            ),
            encoding="utf-8",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the MCP Security Index site.")
    parser.add_argument(
        "--input",
        default="benchmarks/results.json",
        help="Crawler output JSON.",
    )
    parser.add_argument(
        "--site-dir",
        default="benchmarks/site",
        help="Destination directory for the static site.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove site_dir before building.",
    )
    args = parser.parse_args()
    input_path = Path(args.input)
    site_dir = Path(args.site_dir)

    if args.clean and site_dir.exists():
        shutil.rmtree(site_dir)

    if not input_path.is_file():
        raise SystemExit(f"input not found: {input_path}")

    cards = cards_from_results(input_path)
    write_site(cards, site_dir)
    print(f"wrote {len(cards)} cards to {site_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
