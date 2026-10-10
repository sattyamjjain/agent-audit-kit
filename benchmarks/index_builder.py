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
        --site-dir benchmarks/site \\
        --ledger benchmarks/disclosure_ledger.json

    # Re-render the published index without a new crawl or snapshot:
    python benchmarks/index_builder.py \\
        --from-index pages_staging/data/index.json \\
        --site-dir benchmarks/site \\
        --ledger benchmarks/disclosure_ledger.json

Per-server disclosure follows docs/disclosure-policy.md: rule-level detail
is published only 90 days after the maintainer was privately notified, and
the notice date comes from benchmarks/disclosure_ledger.json. A server with
findings and no notice in the ledger stays withheld.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import logging
import re
import shutil
from collections import Counter
from dataclasses import asdict, dataclass, field, fields
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
    # C11 — which rules fired for this server. Never published while withheld.
    rule_hits: dict[str, int] = field(default_factory=dict)
    # When findings were first seen. Informational only: the disclosure clock
    # is the ledger's notice date, not this.
    first_seen: str = ""
    # From benchmarks/disclosure_ledger.json. Both None while no notice has
    # been sent, which is how a consumer tells "notice pending" apart.
    notified_at: str | None = None
    embargo_ends: str | None = None


EMBARGO_DAYS = 90

LEDGER_CHANNELS: frozenset[str] = frozenset({"private-advisory", "security-md", "email"})
_LEDGER_TOP_KEYS: frozenset[str] = frozenset({"_about", "notices"})
_LEDGER_ENTRY_KEYS: frozenset[str] = frozenset({"notified_at", "channel", "reminders", "fixed_at"})
# The slug _build_card derives: lowercase, "/" -> "__", "." -> "_". A key in
# owner/repo form is the likeliest ledger typo, and it would silently match
# nothing, so it is rejected instead.
_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")
_DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class LedgerError(ValueError):
    """benchmarks/disclosure_ledger.json is malformed. Raised, never skipped."""


@dataclass(frozen=True)
class Notice:
    """One private disclosure notice, as recorded in the ledger."""

    notified_at: dt.date
    channel: str
    reminders: tuple[dt.date, ...] = ()
    fixed_at: dt.date | None = None


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
<p class="muted">Findings are reported privately to each maintainer first. Rule-level detail appears here only
90 days after that notice, under our
<a href="https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/disclosure-policy.md">disclosure policy</a>.</p>

<h2 style="margin-top:1.5rem;font-size:1.1rem">Week-over-week grade distribution</h2>
{trend_svg}

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


logger = logging.getLogger(__name__)


def _render_trend_svg(history: list[dict]) -> str:
    """C12 — week-over-week grade-distribution trend chart (pure SVG, no deps)."""
    if len(history) < 2:
        return '<p class="muted">Not enough snapshots yet for a trend chart (need ≥2).</p>'
    weeks = history[-12:]  # last 12 weeks
    width = 720
    height = 180
    pad_left = 50
    pad_right = 15
    pad_top = 20
    pad_bottom = 30
    grades = ["A", "B", "C", "D", "F"]
    colors = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#dc2626"}
    max_total = max((w.get("total") or 1) for w in weeks)
    n = len(weeks)
    x_step = (width - pad_left - pad_right) / max(n - 1, 1)
    y_scale = (height - pad_top - pad_bottom) / max_total

    parts: list[str] = [f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="grade distribution trend">']
    # axis
    parts.append(f'<line x1="{pad_left}" y1="{height - pad_bottom}" x2="{width - pad_right}" y2="{height - pad_bottom}" stroke="#9ca3af" />')
    parts.append(f'<line x1="{pad_left}" y1="{pad_top}" x2="{pad_left}" y2="{height - pad_bottom}" stroke="#9ca3af" />')
    parts.append(f'<text x="5" y="{pad_top + 10}" font-size="9" fill="#374151">{max_total}</text>')
    parts.append(f'<text x="5" y="{height - pad_bottom}" font-size="9" fill="#374151">0</text>')

    for g in grades:
        pts: list[str] = []
        for i, week in enumerate(weeks):
            count = (week.get("distribution") or {}).get(g, 0)
            x = pad_left + i * x_step
            y = (height - pad_bottom) - count * y_scale
            pts.append(f"{x:.1f},{y:.1f}")
        parts.append(f'<polyline fill="none" stroke="{colors[g]}" stroke-width="2" points="{" ".join(pts)}" />')
        # end-label
        last_week = weeks[-1]
        count = (last_week.get("distribution") or {}).get(g, 0)
        last_y = (height - pad_bottom) - count * y_scale
        parts.append(f'<text x="{width - pad_right + 3}" y="{last_y + 4}" font-size="10" fill="{colors[g]}">{g}</text>')

    # x-axis week ticks (first and last only, to avoid clutter)
    parts.append(f'<text x="{pad_left}" y="{height - 10}" font-size="9" fill="#374151">{html.escape(weeks[0]["snapshot"].split("T")[0])}</text>')
    parts.append(f'<text x="{width - pad_right - 55}" y="{height - 10}" font-size="9" fill="#374151">{html.escape(weeks[-1]["snapshot"].split("T")[0])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


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
  table.rules {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; font-size: .9rem; }}
  table.rules th, table.rules td {{ padding: .4rem .6rem; border-bottom: 1px solid #e6e6e9; text-align: left; }}
  table.rules th {{ background: #f6f6f8; }}
  .muted {{ color: #6b7280; font-size: .85rem; }}
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

{rule_hit_section}

<p class="muted">Findings are shown as aggregate counts only until 90 days after
the maintainer is privately notified; rule IDs and per-rule counts are
published after that.
<a href="https://github.com/sattyamjjain/agent-audit-kit/blob/main/docs/disclosure-policy.md">Disclosure policy</a>.</p>
</body></html>
"""


_TEMPLATE_RULE_HIT_SECTION_WITHHELD_NOTIFIED = """<p class="muted">Rule-level detail is withheld until
{embargo_ends}, 90 days after the maintainer was notified. Aggregate severity counts above.</p>"""


_TEMPLATE_RULE_HIT_SECTION_WITHHELD_PENDING = """<p class="muted">Rule-level detail is withheld until
90 days after the maintainer is notified. Aggregate severity counts above.</p>"""


_TEMPLATE_RULE_HIT_SECTION_PUBLIC = """<h3 style="margin-top:1.5rem">Rule hits</h3>
<table class="rules">
<thead><tr><th>Rule</th><th>Hits</th></tr></thead>
<tbody>{rule_rows}</tbody>
</table>"""


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

    That is only the input's view. write_site re-decides every card with
    findings from the disclosure ledger (`_apply_disclosure`), so no input
    can publish a card whose maintainer was not notified 90 days earlier.
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
    rule_hits = dict(Counter(entry.get("rule_violations") or []))
    first_seen = entry.get("first_seen", "")
    return _build_card(
        repo=repo,
        name=name,
        score=score,
        counts=counts,
        last_scanned=last_scanned,
        embargoed=embargoed,
        rule_hits=rule_hits,
        first_seen=first_seen,
    )


def _build_card(
    repo: str,
    name: str,
    score: int,
    counts: dict[str, int],
    last_scanned: str,
    embargoed: bool,
    rule_hits: dict[str, int] | None = None,
    first_seen: str = "",
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
        rule_hits=rule_hits or {},
        first_seen=first_seen,
    )


def _parse_day(value: object, where: str) -> dt.date:
    if not isinstance(value, str) or not _DAY_RE.fullmatch(value):
        raise LedgerError(f"{where}: expected a YYYY-MM-DD date, got {value!r}")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise LedgerError(f"{where}: {exc}") from None


def _parse_notice(slug: str, entry: object, today: dt.date) -> Notice:
    where = f"disclosure ledger notices[{slug!r}]"
    if not isinstance(entry, dict):
        raise LedgerError(f"{where}: expected an object, got {type(entry).__name__}")
    unknown = set(entry) - _LEDGER_ENTRY_KEYS
    if unknown:
        raise LedgerError(f"{where}: unknown key(s) {sorted(unknown)}")
    for required in ("notified_at", "channel"):
        if required not in entry:
            raise LedgerError(f"{where}: missing {required!r}")
    notified_at = _parse_day(entry["notified_at"], f"{where}.notified_at")
    if notified_at > today:
        raise LedgerError(f"{where}.notified_at: {notified_at} is in the future")
    channel = entry["channel"]
    if channel not in LEDGER_CHANNELS:
        raise LedgerError(
            f"{where}.channel: {channel!r} is not one of {sorted(LEDGER_CHANNELS)}"
        )
    raw_reminders = entry.get("reminders", [])
    if not isinstance(raw_reminders, list):
        raise LedgerError(f"{where}.reminders: expected a list of dates")
    reminders = tuple(
        _parse_day(day, f"{where}.reminders[{i}]") for i, day in enumerate(raw_reminders)
    )
    for day in reminders:
        if day < notified_at:
            raise LedgerError(f"{where}.reminders: {day} is before notified_at {notified_at}")
    fixed_at = None
    if entry.get("fixed_at") is not None:
        fixed_at = _parse_day(entry["fixed_at"], f"{where}.fixed_at")
        if fixed_at < notified_at:
            raise LedgerError(f"{where}.fixed_at: {fixed_at} is before notified_at {notified_at}")
    return Notice(notified_at=notified_at, channel=channel, reminders=reminders, fixed_at=fixed_at)


def load_ledger(ledger_path: Path | None, today: dt.date | None = None) -> dict[str, Notice]:
    """Load and validate benchmarks/disclosure_ledger.json.

    The ledger is the only disclosure clock, so a malformed one fails the
    build instead of being skipped: a skipped entry would silently re-withhold
    a server, and a mis-read date would publish one early. No ledger path
    means no notices, and with no notices nothing that has findings is ever
    published.

    Args:
        ledger_path: The ledger file, or None for "no notices sent".
        today: The build date, for rejecting a notice dated in the future.

    Returns:
        ``{slug: Notice}``.

    Raises:
        LedgerError: The file is missing, not JSON, or any entry is malformed.
    """
    if ledger_path is None:
        return {}
    today = today or dt.datetime.now(dt.timezone.utc).date()
    try:
        raw = json.loads(ledger_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LedgerError(f"cannot read disclosure ledger {ledger_path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise LedgerError(f"disclosure ledger {ledger_path} is not valid JSON: {exc}") from None
    if not isinstance(raw, dict):
        raise LedgerError("disclosure ledger: expected a JSON object at the top level")
    unknown = set(raw) - _LEDGER_TOP_KEYS
    if unknown:
        raise LedgerError(f"disclosure ledger: unknown top-level key(s) {sorted(unknown)}")
    notices = raw.get("notices", {})
    if not isinstance(notices, dict):
        raise LedgerError("disclosure ledger: 'notices' must be an object keyed by server slug")
    ledger: dict[str, Notice] = {}
    for slug, entry in notices.items():
        if not isinstance(slug, str) or not _SLUG_RE.fullmatch(slug):
            raise LedgerError(
                f"disclosure ledger: {slug!r} is not an index slug "
                "(lowercase, '/' written as '__', '.' as '_')"
            )
        ledger[slug] = _parse_notice(slug, entry, today)
    return ledger


def _carry_first_seen(
    cards: list[ServerCard],
    prior_index: dict[str, dict],
    now: dt.datetime,
) -> list[ServerCard]:
    """Keep each card's first_seen from the previously published index.

    first_seen is informational. It used to be the disclosure clock, and it
    was restamped on every run, because the prior index the workflow fetched
    was never passed in: every card was always "first seen" this week, so
    nothing ever reached day 90. The clock is now the ledger's notice date
    (`_apply_disclosure`), so a wrong first_seen can no longer publish or
    withhold anything.
    """
    today = now.isoformat(timespec="seconds")
    for card in cards:
        prior = prior_index.get(card.slug)
        if prior and prior.get("first_seen"):
            card.first_seen = prior["first_seen"]
        elif not card.first_seen:
            card.first_seen = today if card.disclosure_state != "no-findings" else ""
    return cards


def _apply_disclosure(
    cards: list[ServerCard],
    ledger: dict[str, Notice],
    now: dt.datetime,
    *,
    allow_publish: bool = True,
) -> list[ServerCard]:
    """Decide what each card may publish. The ledger is the only clock.

    docs/disclosure-policy.md starts the 90 days at the private notice to
    the maintainer, so a card with findings is withheld ("embargoed") until
    EMBARGO_DAYS after its ledger notice, or until the ledger records a fix
    landing earlier. A card with no ledger entry has had no notice, so it
    stays withheld however long it has been in the index: it never becomes
    public on time alone. Whatever the input said about disclosure is
    overridden here, so no input format can publish around the ledger.

    With ``allow_publish=False`` (re-rendering an already published index,
    with no fresh crawl), a card is public only if it was already public in
    that input. The published index carries no rule detail for withheld
    cards, so a card that came due in between would be published with an
    empty rule table; it waits for the next weekly snapshot instead.

    Args:
        cards: Cards to update in place.
        ledger: ``{slug: Notice}`` from `load_ledger`.
        now: The build time.
        allow_publish: False to never publish a card that was not public.

    Returns:
        The same list, updated.
    """
    today = now.date()
    for card in cards:
        card.notified_at = None
        card.embargo_ends = None
        if card.disclosure_state == "no-findings":
            continue
        was_public = card.disclosure_state == "public"
        card.disclosure_state = "embargoed"
        notice = ledger.get(card.slug)
        if notice is None:
            continue
        ends = notice.notified_at + dt.timedelta(days=EMBARGO_DAYS)
        card.notified_at = notice.notified_at.isoformat()
        card.embargo_ends = ends.isoformat()
        due = today >= ends or (notice.fixed_at is not None and notice.fixed_at <= today)
        if due and (allow_publish or was_public):
            card.disclosure_state = "public"
    return cards


def _public_row(card: ServerCard) -> dict:
    """The data/index.json row for a card, without rule ids while withheld.

    write_site used to dump ``asdict(card)`` for every card, so the published
    JSON carried the rule ids of every embargoed server while the HTML card
    hid them, against docs/disclosure-policy.md's "aggregate counts only".
    """
    row = asdict(card)
    if card.disclosure_state != "public":
        row["rule_hits"] = {}
    return row


def _load_index_rows(index_path: Path) -> list[dict]:
    """Rows of a published data/index.json, or [] if absent or unreadable."""
    if not index_path.is_file():
        return []
    try:
        rows = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict) and row.get("slug")]


def _rows_by_slug(rows: list[dict]) -> dict[str, dict]:
    return {row["slug"]: row for row in rows}


def _load_prior_index(site_dir: Path) -> dict[str, dict]:
    """Return {slug: dict} from site_dir's own previous index.json, if any."""
    return _rows_by_slug(_load_index_rows(site_dir / "data" / "index.json"))


def cards_from_index(index_path: Path) -> list[ServerCard]:
    """Rebuild cards from a published data/index.json, keeping its order.

    Used to re-render the site without a new crawl (the workflow's push
    path), so a fix to the builder or a new ledger notice reaches the
    published site without waiting for Monday's snapshot.
    """
    names = {f.name for f in fields(ServerCard)}
    cards: list[ServerCard] = []
    for row in _load_index_rows(index_path):
        known = {k: v for k, v in row.items() if k in names}
        try:
            cards.append(ServerCard(**known))
        except TypeError:
            logger.warning("Skipping malformed index row for %s", row.get("slug"))
    return cards


def _rule_hit_section(card: ServerCard) -> str:
    """C11 — render the rule-hit breakdown for a card (or the withheld notice)."""
    if card.disclosure_state == "embargoed":
        if card.embargo_ends:
            return _TEMPLATE_RULE_HIT_SECTION_WITHHELD_NOTIFIED.format(
                embargo_ends=html.escape(card.embargo_ends)
            )
        return _TEMPLATE_RULE_HIT_SECTION_WITHHELD_PENDING
    if not card.rule_hits:
        return ""
    rows = "".join(
        f"<tr><td>{html.escape(rid)}</td><td>{count}</td></tr>"
        for rid, count in sorted(card.rule_hits.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return _TEMPLATE_RULE_HIT_SECTION_PUBLIC.format(rule_rows=rows)


def _snapshot_label(history: list[dict], fallback: dt.datetime) -> str:
    """The last published snapshot's time, to the minute, else the fallback."""
    if history:
        raw = str(history[-1].get("snapshot") or "").replace("Z", "+00:00")
        try:
            return dt.datetime.fromisoformat(raw).isoformat(timespec="minutes")
        except ValueError:
            pass
    return fallback.isoformat(timespec="minutes")


def write_site(
    cards: list[ServerCard],
    site_dir: Path,
    history_seed: Path | None = None,
    *,
    ledger: dict[str, Notice] | None = None,
    prior_index: Path | None = None,
    republish: bool = False,
) -> None:
    """Write data/index.json, data/history.json, index.html and server pages.

    Args:
        cards: The cards to publish.
        site_dir: Output directory.
        history_seed: The previously published history.json.
        ledger: Disclosure notices from `load_ledger`; None means none sent.
        prior_index: The previously published index.json, for first_seen.
        republish: Re-render an already published index: no new history
            snapshot (README's index-cadence line counts snapshots) and no
            card published that was not public before.
    """
    (site_dir / "data").mkdir(parents=True, exist_ok=True)
    (site_dir / "server").mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)

    prior_rows = (
        _rows_by_slug(_load_index_rows(prior_index))
        if prior_index is not None
        else _load_prior_index(site_dir)
    )
    cards = _carry_first_seen(cards, prior_rows, now)
    cards = _apply_disclosure(cards, ledger or {}, now, allow_publish=not republish)

    index_json = site_dir / "data" / "index.json"
    index_json.write_text(
        json.dumps([_public_row(c) for c in cards], indent=2),
        encoding="utf-8",
    )

    history_path = site_dir / "data" / "history.json"
    history: list[dict] = []
    # `--clean` rmtree's site_dir before we get here, so the prior history never
    # survives into this read: every run started from empty, appended one entry,
    # and published a one-entry file. That is why the site said "not enough
    # snapshots yet for a trend chart (need >= 2)" even after a successful run --
    # the condition was unsatisfiable by construction, independently of the
    # scheduled failures. `--history` seeds from the previously published copy.
    if not history_path.is_file() and history_seed is not None and history_seed.is_file():
        try:
            seeded = json.loads(history_seed.read_text(encoding="utf-8"))
            if isinstance(seeded, list):
                history = seeded
                logger.info("Seeded %d prior snapshot(s) from %s", len(history), history_seed)
        except (OSError, json.JSONDecodeError):
            logger.warning("Could not read history seed %s; starting fresh", history_seed)
    if history_path.is_file():
        try:
            loaded = json.loads(history_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                history = loaded
        except json.JSONDecodeError:
            history = []
    if not republish:
        history.append(
            {
                "snapshot": now.isoformat(timespec="seconds"),
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
    # A re-render is not a new snapshot, so the page keeps the date of the
    # crawl its data came from.
    snapshot = _snapshot_label(history, now) if republish else now.isoformat(timespec="minutes")

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
            snapshot=snapshot,
            rows=rows,
            trend_svg=_render_trend_svg(history),
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
                rule_hit_section=_rule_hit_section(c),
            ),
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
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
    parser.add_argument(
        "--history",
        default=None,
        help=(
            "Previously published history.json to seed from. Required with --clean "
            "if the trend chart is ever to have more than one point: --clean removes "
            "site_dir, so without a seed each run starts from an empty history."
        ),
    )
    parser.add_argument(
        "--ledger",
        default=None,
        help=(
            "Disclosure notices (benchmarks/disclosure_ledger.json). The 90-day "
            "clock starts at each notice; without one, no server with findings "
            "is ever published."
        ),
    )
    parser.add_argument(
        "--prior-index",
        default=None,
        help="Previously published data/index.json, so first_seen persists across runs.",
    )
    parser.add_argument(
        "--from-index",
        default=None,
        help=(
            "Re-render this published data/index.json instead of reading --input: "
            "no new history snapshot, and no card published that was not already "
            "public. A missing file is a no-op."
        ),
    )
    args = parser.parse_args(argv)
    site_dir = Path(args.site_dir)
    ledger = load_ledger(Path(args.ledger) if args.ledger else None)

    if args.from_index:
        source = Path(args.from_index)
        if not source.is_file():
            print(f"no published index at {source}; nothing to re-render")
            return 0
        if args.clean and site_dir.exists():
            shutil.rmtree(site_dir)
        cards = cards_from_index(source)
        write_site(
            cards,
            site_dir,
            history_seed=Path(args.history) if args.history else None,
            ledger=ledger,
            prior_index=source,
            republish=True,
        )
        print(f"re-rendered {len(cards)} cards to {site_dir}/ (no new snapshot)")
        return 0

    input_path = Path(args.input)
    if args.clean and site_dir.exists():
        shutil.rmtree(site_dir)

    if not input_path.is_file():
        raise SystemExit(f"input not found: {input_path}")

    cards = cards_from_results(input_path)
    write_site(
        cards,
        site_dir,
        history_seed=Path(args.history) if args.history else None,
        ledger=ledger,
        prior_index=Path(args.prior_index) if args.prior_index else None,
    )
    print(f"wrote {len(cards)} cards to {site_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
