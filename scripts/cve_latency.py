#!/usr/bin/env python3
"""CVE-to-rule latency, computed from the ledger and published as a doc.

A rule count says how much we wrote. It says nothing about how fast coverage
lands after a CVE goes public, which is the property anyone relying on this tool
actually depends on — and the one the CRA reporting regime makes relevant from
2026-09-11.

This reads `CHANGELOG.cves.md` (which release shipped each CVE's rule) and
`docs/data/cve-published.json` (when NVD published it), and writes
`docs/cve-latency.md`: median and p90 days, plus every underlying row so the
number can be checked rather than believed.

Usage::

    python scripts/cve_latency.py                 # regenerate docs/cve-latency.md
    python scripts/cve_latency.py --check         # fail if the doc is stale
    python scripts/cve_latency.py --refresh       # top up published dates from NVD

Determinism: the default path is offline and reads only committed files, so the
release workflow can regenerate on every tag and get a byte-identical result for
unchanged inputs. `--refresh` is the one network step, kept separate on purpose —
the same split `make report` and `make corpus` already use.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from datetime import date, datetime
from pathlib import Path
from typing import NamedTuple, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"
PUBLISHED = REPO_ROOT / "docs" / "data" / "cve-published.json"
OUT = REPO_ROOT / "docs" / "cve-latency.md"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# NVD allows 5 requests per rolling 30s without an API key.
NVD_SLEEP_SECONDS = 6.5

_SECTION_RE = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})\s*\(([^)]*)\)")
_ROW_RE = re.compile(r"^\|\s*(CVE-\d{4}-\d{4,7})")
# The leading CVE id(s) of a row, before the description opens. Handles a row
# that covers several CVEs at once ("CVE-A / CVE-B (desc)").
_SUBJECT_RE = re.compile(r"^\|\s*((?:CVE-\d{4}-\d{4,7}[\s,/+&and]*)+)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+$")
# A row whose disposition says the CVE was ruled out never shipped a rule, so it
# has no latency. Counted and disclosed separately rather than dropped silently.
_OUT_OF_SCOPE_RE = re.compile(r"out of scope", re.I)
# Above this, a row is a deferred backlog item rather than a response to a fresh
# disclosure. Listed separately in the doc so the median/p90 are not read as if
# every row answered the same question.
_BACKLOG_DAYS = 30


class Row(NamedTuple):
    cve: str
    published: date
    shipped: date
    release: str
    days: int


def _parse_iso_date(raw: str) -> Optional[date]:
    text = raw.strip().replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def parse_ledger(text: str) -> tuple[dict[str, tuple[date, str]], set[str]]:
    """Map each in-scope CVE to the (date, release) that shipped its rule.

    The ledger runs newest-first. A section headed ``(unreleased)`` landed in the
    next tagged release, which is the nearest tagged section *above* it, so the
    walk carries the last version seen downward.

    Returns ``(shipped, out_of_scope)``. A CVE that appears both ruled-out and
    later in scope counts as in scope, from its earliest in-scope release.
    """
    shipped: dict[str, tuple[date, str]] = {}
    out_of_scope: set[str] = set()

    section_date: Optional[date] = None
    section_release = "unreleased"
    pending_release = "unreleased"

    for line in text.splitlines():
        section = _SECTION_RE.match(line)
        if section:
            section_date = _parse_iso_date(section.group(1))
            label = section.group(2).strip()
            version = label.split(",")[0].strip()
            if _VERSION_RE.match(version):
                section_release = version
                pending_release = version
            else:
                # Unreleased: shipped in the nearest tagged release above.
                section_release = pending_release
            continue

        row = _ROW_RE.match(line)
        if not row or section_date is None:
            continue

        # The row's subject is the leading run of CVE ids, before the
        # parenthesised description. Everything after it — the rest of the first
        # cell and every later cell — routinely names other CVEs for context
        # ("the CVE-... mitigation denied ...", "distinct from CVE-..."), and
        # counting those would backdate an unrelated CVE into this release.
        subject = _SUBJECT_RE.match(line)
        if not subject:
            continue
        cves = set(_CVE_RE.findall(subject.group(1)))
        if not cves:
            continue

        if _OUT_OF_SCOPE_RE.search(line):
            out_of_scope.update(cves - set(shipped))
            continue

        for cve in cves:
            out_of_scope.discard(cve)
            prior = shipped.get(cve)
            # Keep the earliest release that carried coverage.
            if prior is None or section_date < prior[0]:
                shipped[cve] = (section_date, section_release)

    return shipped, out_of_scope


def percentile_nearest_rank(values: list[int], pct: float) -> int:
    """Nearest-rank percentile: smallest value at or above ``pct`` of the data.

    Chosen over interpolation because the sample is small and a real observed
    latency is more defensible in a compliance context than a synthetic one.
    """
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))  # ceil
    return ordered[int(rank) - 1]


def build_rows(
    shipped: dict[str, tuple[date, str]], published: dict[str, str]
) -> tuple[list[Row], list[str]]:
    rows: list[Row] = []
    missing: list[str] = []
    for cve, (ship_date, release) in shipped.items():
        raw = published.get(cve)
        pub = _parse_iso_date(raw) if raw else None
        if pub is None:
            missing.append(cve)
            continue
        rows.append(Row(cve, pub, ship_date, release, (ship_date - pub).days))
    rows.sort(key=lambda r: (r.shipped, r.cve), reverse=True)
    return rows, sorted(missing)


class WindowStats(NamedTuple):
    """Response latency over a trailing window, carried with its sample size.

    ``n`` travels with the figure everywhere it is rendered. A median over three
    CVEs is not a median, and a reader who cannot see the denominator has no way
    to know which they are looking at.
    """

    window_days: int
    n: int
    median_days: float
    p90_days: int
    backlog_n: int
    computed_on: date


def window_stats(
    window_days: int = 90, today: Optional[date] = None
) -> Optional[WindowStats]:
    """Median and p90 response latency for CVEs *published* in the last N days.

    The window is keyed on publication rather than ship date on purpose: it
    answers "for the CVEs disclosed recently, how fast did coverage land",
    which is the question a reader has. Keying on ship date would let a burst of
    backlog work make a bad quarter look fast.

    Returns ``None`` when the window is empty, so a caller renders "no data"
    rather than a statistic over nothing.
    """
    when = today or date.today()
    try:
        shipped, _ = parse_ledger(LEDGER.read_text(encoding="utf-8"))
        published = json.loads(PUBLISHED.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    rows, _ = build_rows(shipped, published)
    in_window = [r for r in rows if 0 <= (when - r.published).days <= window_days]
    if not in_window:
        return None

    days = sorted(r.days for r in in_window)
    return WindowStats(
        window_days=window_days,
        n=len(days),
        median_days=round(statistics.median(days), 1),
        p90_days=percentile_nearest_rank(days, 90),
        backlog_n=sum(1 for d in days if d > _BACKLOG_DAYS),
        computed_on=when,
    )


def render(rows: list[Row], missing: list[str], out_of_scope: set[str]) -> str:
    measured = [r.days for r in rows]
    lines: list[str] = []
    add = lines.append

    add("# CVE-to-rule latency")
    add("")
    add(
        "How long it takes a rule to land after a CVE goes public. Generated by "
        "`scripts/cve_latency.py` from `CHANGELOG.cves.md` and "
        "`docs/data/cve-published.json`, and regenerated on every tag — do not "
        "edit by hand."
    )
    add("")
    add(
        "AgentAuditKit publishes no fixed CVE-response SLA; the 48-hour commitment "
        "was retired in PR #432. This is a measurement of what happened, not a "
        "promise about what will."
    )
    add("")

    if not measured:
        add("_No CVE has both a published date and a shipping release yet._")
        add("")
    else:
        # Two populations live here and they answer different questions. A CVE
        # triaged the day the watcher surfaced it measures response. A roadmap
        # row picked up months later measures backlog. Averaging them produces a
        # figure that describes neither: when four old Letta CVEs were pinned in
        # one sitting, a mixed p90 jumped from 2 days to 122 while the actual
        # response time to fresh disclosures had not changed at all.
        response = [r.days for r in rows if r.days <= _BACKLOG_DAYS]
        backlog = [r.days for r in rows if r.days > _BACKLOG_DAYS]

        add("## Summary")
        add("")
        add(
            f"Response to newly disclosed CVEs — the {len(response)} rows shipped "
            f"within {_BACKLOG_DAYS} days of publication:"
        )
        add("")
        add("| Metric | Days |")
        add("|---|---|")
        if response:
            add(f"| Median | {statistics.median(response):.1f} |")
            add(f"| p90 (nearest-rank) | {percentile_nearest_rank(response, 90)} |")
            add(f"| Fastest | {min(response)} |")
            add(f"| Slowest | {max(response)} |")
        else:
            add("| — | no rows in this population |")
        add("")

        if backlog:
            add(
                f"Separately, **{len(backlog)}** deferred roadmap rows were picked "
                f"up later, between {min(backlog)} and {max(backlog)} days after "
                f"publication (median {statistics.median(backlog):.0f}). They are "
                f"listed in full below. They are not response times and are "
                f"deliberately kept out of the figures above — mixing them would "
                f"describe neither population."
            )
            add("")

        add(
            f"Both populations together: {len(measured)} CVEs with a known "
            f"publication date and shipping release."
        )
        add("")

    add("## Coverage of this measurement")
    add("")
    add("| Population | Count |")
    add("|---|---|")
    add(f"| Measured (published date + shipping release known) | {len(rows)} |")
    add(f"| Shipped, but no published date on file | {len(missing)} |")
    add(f"| Adjudicated out of scope (no rule, so no latency) | {len(out_of_scope)} |")
    add("")

    if missing:
        add(
            "Excluded for want of a published date, so the figures above describe "
            "the measured set only: "
            + ", ".join(f"`{c}`" for c in missing)
            + ". Run `python scripts/cve_latency.py --refresh` to fetch them."
        )
        add("")

    add("## Method")
    add("")
    add(
        "- **Published** is NVD's `published` timestamp, cached in "
        "`docs/data/cve-published.json`."
    )
    add(
        "- **Shipped** is the date of the `CHANGELOG.cves.md` section carrying the "
        "CVE. A section marked `(unreleased)` is attributed to the next tagged "
        "release above it."
    )
    add(
        "- **Days** is calendar days, `shipped - published`. A negative value would "
        "mean coverage landed before NVD published, which happens when a rule is "
        "written from a vendor advisory ahead of NVD enrichment."
    )
    add(
        "- A CVE appearing in several sections is counted from the earliest one "
        "that carried coverage."
    )
    add(
        "- p90 uses the nearest-rank method, so every reported figure is a latency "
        "that actually occurred."
    )
    add("")

    # Two different things live in this population and a reader should not have to
    # infer which is which from the row list.
    outliers = [r for r in rows if r.days > _BACKLOG_DAYS]
    if outliers:
        add("## Backlog rows")
        add("")
        noun = "row" if len(outliers) == 1 else "rows"
        add(
            f"{len(outliers)} {noun} took more than {_BACKLOG_DAYS} days — deferred "
            "roadmap items picked up later, not slow responses to a fresh disclosure. "
            "The population mixes watcher-driven triage with backlog catch-up, and the "
            "two answer different questions. Read the median and p90 as the response "
            "figure; read these as the backlog:"
        )
        add("")
        add("| CVE | Published | Rule shipped | Days |")
        add("|---|---|---|---|")
        for r in sorted(outliers, key=lambda r: -r.days):
            add(f"| {r.cve} | {r.published.isoformat()} | {r.shipped.isoformat()} | {r.days} |")
        add("")

    add("## Rows")
    add("")
    add("| CVE | Published | Rule shipped | Release | Days |")
    add("|---|---|---|---|---|")
    for r in rows:
        add(f"| {r.cve} | {r.published.isoformat()} | {r.shipped.isoformat()} | {r.release} | {r.days} |")
    add("")

    return "\n".join(lines)


def refresh_published(cves: list[str], store: dict[str, str]) -> dict[str, str]:
    """Fetch missing published dates from NVD. The one network step."""
    import time
    import urllib.request

    todo = [c for c in cves if c not in store]
    print(f"cve-latency: {len(store)} cached, {len(todo)} to fetch", file=sys.stderr)
    for i, cve in enumerate(todo, 1):
        try:
            req = urllib.request.Request(
                NVD_API + cve, headers={"User-Agent": "agent-audit-kit/cve-latency"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
            vulns = payload.get("vulnerabilities") or []
            if vulns:
                store[cve] = vulns[0]["cve"]["published"]
                print(f"  [{i}/{len(todo)}] {cve} -> {store[cve]}", file=sys.stderr)
            else:
                print(f"  [{i}/{len(todo)}] {cve} -> not in NVD", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - a refresh must not abort the run
            print(f"  [{i}/{len(todo)}] {cve} failed: {exc}", file=sys.stderr)
        time.sleep(NVD_SLEEP_SECONDS)
    return store


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="Fail if docs/cve-latency.md differs from a fresh run (drift guard).",
    )
    parser.add_argument(
        "--refresh", action="store_true",
        help="Fetch missing published dates from NVD before rendering (network).",
    )
    parser.add_argument("--ledger", default=str(LEDGER))
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args()

    ledger_path = Path(args.ledger)
    if not ledger_path.is_file():
        print(f"cve-latency: no ledger at {ledger_path}", file=sys.stderr)
        return 2

    shipped, out_of_scope = parse_ledger(ledger_path.read_text(encoding="utf-8"))

    published: dict[str, str] = {}
    if PUBLISHED.is_file():
        try:
            published = json.loads(PUBLISHED.read_text(encoding="utf-8"))
        except ValueError:
            print(f"cve-latency: {PUBLISHED} is not valid JSON", file=sys.stderr)
            return 2

    if args.refresh:
        published = refresh_published(sorted(shipped), published)
        PUBLISHED.parent.mkdir(parents=True, exist_ok=True)
        PUBLISHED.write_text(
            json.dumps(dict(sorted(published.items())), indent=2) + "\n", encoding="utf-8"
        )

    rows, missing = build_rows(shipped, published)
    rendered = render(rows, missing, out_of_scope)

    out_path = Path(args.out)
    if args.check:
        current = out_path.read_text(encoding="utf-8") if out_path.is_file() else ""
        if current != rendered:
            print(
                "cve-latency: docs/cve-latency.md is stale — "
                "run 'python scripts/cve_latency.py' and commit",
                file=sys.stderr,
            )
            return 1
        print("cve-latency: up to date")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    # Mirror the doc: report the response population, disclose the backlog
    # separately. A mixed figure describes neither.
    response = [r.days for r in rows if r.days <= _BACKLOG_DAYS]
    backlog = [r.days for r in rows if r.days > _BACKLOG_DAYS]
    if response:
        summary = (
            f"response median {statistics.median(response):.1f}d, "
            f"p90 {percentile_nearest_rank(response, 90)}d over {len(response)} CVEs"
            + (f"; {len(backlog)} backlog row(s) excluded" if backlog else "")
        )
    else:
        summary = "no measurable CVEs yet"
    print(f"cve-latency: wrote {out_path.relative_to(REPO_ROOT)} ({summary})")
    if missing:
        print(f"cve-latency: {len(missing)} CVE(s) lack a published date", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
