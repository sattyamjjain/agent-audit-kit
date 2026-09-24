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

The open queue, and why omitting it flattered the number
--------------------------------------------------------
Until 2026-09-22 this page had three coverage rows — measured, undated, out of
scope — and every one of them describes a CVE that already reached a
disposition. "Shipped" is the date of the `CHANGELOG.cves.md` section carrying
the CVE, so a disclosure that is open and untriaged appears in *no* population.
Not measured, not undated, not out of scope. Absent.

That omission is not neutral, it is directional. A CVE only enters the
measurement on the day it is dispositioned, so every slow case is invisible
while it is slow and counted only once it resolves. A queue left to sit makes
the published median look better, never worse — the one bias a latency figure
must not have, because the reader is using it to judge exactly that.

It was not hypothetical. On 2026-09-22 the tracker held ten open `cve-response`
issues opened 2026-09-19, one of them CRITICAL, none deferred and none
commented, while this page published a median of 1.0 days. `check_cve_ageing.py`
already knew — it holds critical to three days and runs daily — but the ageing
signal had no path into the measurement. The fourth row is that path.

The Release column, and the label the ledger stopped writing
------------------------------------------------------------
On 2026-09-24, 66 of the 102 rows on this page said `unreleased` — every row
from 2026-08-16 onward, while PyPI had been serving 0.3.78 through 0.6.7 the
whole time. `parse_ledger` reads the version out of a section heading's
parenthesised label and, for a section without one, carries down the nearest
labelled section above it. The ledger simply stopped writing that label after
`## 2026-08-15 (v0.3.77)`, so twenty-two sections had nothing above them to
inherit and all of them fell back to the string the walk starts with.

The parser was doing exactly what it documents. What was missing is the only
thing that could have caught it: nothing compared the Release column against the
releases that actually exist. A reader asking whether their installed 0.6.7
carries a rule for CVE-2026-91932 read `unreleased` and concluded it did not —
false, and false in the direction that makes this project look slower to ship
than it is, on the page whose whole job is to measure that.

`--check` now reads the release headings from `CHANGELOG.md` and fails when a
row resolves to `unreleased` while a release exists *strictly after* its section
date. Strictly, because a section dated the day of a release may honestly be
unreleased — the ledger entry is written before the tag is cut, and that is the
normal state of the newest section, not a defect.

`--check-queue` is what keeps the row honest, and it is deliberately NOT part of
`--check`. `--check` is offline, byte-deterministic, and has two callers that
must stay that way: `tests/test_regulatory_dates.py` runs it inside pytest, and
`release.yml` runs it on every tag. A network read in there would make the test
suite depend on a token and the internet, and would let queue depth fail a
release — which is the precise mistake `check_cve_ageing.py`'s own docstring was
written to avoid ("a release blocked on queue depth is what produced the
deferral label in the first place"). So the live comparison runs on the daily
cron beside the ageing gate, red on its own schedule, holding no lever over
shipping.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, NamedTuple, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"
PUBLISHED = REPO_ROOT / "docs" / "data" / "cve-published.json"
OUT = REPO_ROOT / "docs" / "cve-latency.md"
RELEASES = REPO_ROOT / "CHANGELOG.md"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# NVD allows 5 requests per rolling 30s without an API key.
NVD_SLEEP_SECONDS = 6.5

# A ledger section heading. The parenthesised label is OPTIONAL, because the
# ledger uses both forms: "## 2026-08-21 (v0.3.83): ..." and plain
# "## 2026-08-22: ...". Requiring the parens meant a plain heading did not
# match at all, so the previous parenthesised section kept ownership of every
# row beneath it and those CVEs were dated to the wrong day. Found when a new
# "(later)" section at the top of the file silently backdated three sections
# of rows onto its own date and moved the published p90.
_SECTION_RE = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})\s*(?:\(([^)]*)\))?")
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
# Below zero, the rule was already shipped when NVD published the CVE, because
# coverage was written from a vendor advisory (or from the shape, generically)
# ahead of NVD enrichment. That is not a fast response, it is the absence of a
# response to time, and reporting it as "Fastest: -29 days" describes a
# turnaround that never happened. Third population, same reasoning as the
# backlog split: mixing them would describe neither.
_PRE_COVERED_DAYS = 0


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


#: A released heading in CHANGELOG.md: ``## [0.6.7] - 2026-09-19``. The
#: ``[Unreleased]`` heading deliberately does not match — it names no version
#: and carries no date, so it cannot date anything.
_RELEASE_HEADING_RE = re.compile(
    r"^##\s+\[(\d+\.\d+\.\d+)\]\s+-\s+(\d{4}-\d{2}-\d{2})\s*$", re.M
)


def release_dates(changelog_text: str) -> list[tuple[str, date]]:
    """``(version, date)`` for every released CHANGELOG.md heading, oldest first.

    Committed and offline, which is why this check belongs in `--check` rather
    than beside `--check-queue`: it needs no tracker and no token, so it can run
    inside pytest and on every tag like the rest of the drift guard.
    """
    out: list[tuple[str, date]] = []
    for version, raw in _RELEASE_HEADING_RE.findall(changelog_text):
        parsed = _parse_iso_date(raw)
        if parsed is not None:
            out.append((version, parsed))
    return sorted(out, key=lambda pair: pair[1])


def find_unlabelled_shipped(
    shipped: dict[str, tuple[date, str]], releases: list[tuple[str, date]]
) -> list[str]:
    """Rows claiming `unreleased` that a release has already overtaken.

    A row is a fault when some release was cut **strictly after** its section
    date: the rule was in the tree when that release was built, so the section
    should carry a version label and the page should name it.

    Strictly after, and not on-or-after, because same-day is the honest case.
    A ledger section is written when the disposition is done, and the tag is cut
    afterwards on the same day; at the moment the section lands there is no
    release above it to inherit, and saying `unreleased` is then simply true.
    Treating that as a fault would make the newest section permanently red and
    the guard permanently ignored.
    """
    if not releases:
        return []
    newest_version, newest_date = releases[-1]
    faults: list[tuple[date, str]] = []
    for cve, (section_date, release) in shipped.items():
        if release != "unreleased":
            continue
        later = [v for v, d in releases if d > section_date]
        if not later:
            continue
        faults.append((
            section_date,
            f"{cve}  section {section_date}  resolves to 'unreleased', but "
            f"{later[0]} shipped {[d for v, d in releases if v == later[0]][0]}",
        ))
    return [row for _, row in sorted(faults)]


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
            label = (section.group(2) or "").strip()
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
    # Rows in the window whose coverage predates NVD publication. Excluded from
    # n/median/p90 for the same reason the doc excludes them: there is no
    # turnaround to measure when the rule was already there. Surfaced so the
    # page can say so rather than quietly dropping them.
    pre_covered_n: int
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

    # Same three-way split as `render`, so the page and the doc cannot disagree
    # about what the median describes.
    pre_covered = [r for r in in_window if r.days < _PRE_COVERED_DAYS]
    days = sorted(r.days for r in in_window if r.days >= _PRE_COVERED_DAYS)
    if not days:
        return None
    return WindowStats(
        window_days=window_days,
        n=len(days),
        median_days=round(statistics.median(days), 1),
        p90_days=percentile_nearest_rank(days, 90),
        backlog_n=sum(1 for d in days if d > _BACKLOG_DAYS),
        pre_covered_n=len(pre_covered),
        computed_on=when,
    )


# --------------------------------------------------------------------------
# The open queue: disclosures that have not reached a disposition yet.
#
# Sourced from the same issue list `check_cve_ageing.py` reads, through that
# module's own helpers rather than a second parser — two readers of the tracker
# would eventually disagree about what "open and undeferred" means, and the
# disagreement would surface as a published number nobody could reproduce.
#
# `cve-deferred` issues are excluded. A deferral is a disposition: somebody read
# it and named a date, and `check_cve_deferrals.py` judges it against that date.
# Counting it here would put one issue in two accounting systems.
# --------------------------------------------------------------------------

#: Machine-readable state for the open-queue row, so `--check` can reproduce the
#: committed page offline and `--check-queue` can compare it to the tracker
#: without parsing prose. Same marker convention as README's rule-count anchors.
_QUEUE_MARKER_RE = re.compile(
    r"<!--\s*cve-open-queue:\s*(?P<body>[^>]*?)\s*-->"
)


class OpenQueue(NamedTuple):
    """The undispositioned queue as of `asof`.

    `read` is the field that matters. False means the tracker could not be read
    on the run that produced the page — not that the queue is empty. The two
    render differently on purpose: an unread count is a stated gap, and printing
    it as zero would be the same flattering omission this row exists to close.
    """

    read: bool
    count: int = 0
    oldest_number: Optional[int] = None
    oldest_created: Optional[date] = None
    asof: Optional[date] = None

    @property
    def oldest_age_days(self) -> Optional[int]:
        if self.oldest_created is None or self.asof is None:
            return None
        return (self.asof - self.oldest_created).days

    def agrees_with(self, other: "OpenQueue") -> bool:
        """Do two readings describe the same queue?

        Compares the count and which issue is oldest — the facts that change
        only when the tracker changes. Deliberately NOT the age in days, which
        is a function of the date the page was rendered and would therefore
        differ every single day with nothing having happened. A guard that is
        red every morning is one nobody reads by the end of the week.
        """
        return (
            self.read == other.read
            and self.count == other.count
            and self.oldest_number == other.oldest_number
            and self.oldest_created == other.oldest_created
        )


def _load_ageing_module() -> Any:
    """Import the ageing gate as the single authority on the open queue."""
    import importlib.util

    script = Path(__file__).resolve().parent / "check_cve_ageing.py"
    spec = importlib.util.spec_from_file_location("check_cve_ageing", script)
    if spec is None or spec.loader is None:  # pragma: no cover - packaging error
        raise RuntimeError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("check_cve_ageing", module)
    spec.loader.exec_module(module)
    return module


def open_queue_from_issues(
    issues: list[dict[str, Any]], today: Optional[date] = None
) -> OpenQueue:
    """Build an `OpenQueue` from a `gh`-shaped issue list. Offline; testable."""
    ageing = _load_ageing_module()
    today = today or date.today()
    undeferred = [
        issue
        for issue in ageing.response_issues(issues)
        if ageing.DEFERRED_LABEL not in ageing._labels(issue)
    ]
    dated = [(ageing.created_on(i), i) for i in undeferred]
    dated = [(c, i) for c, i in dated if c is not None]
    # Tie-break on issue number, not list order. `created_on` returns a DATE, so
    # a wave opened in one batch — which is how the watcher opens them — ties on
    # every row, and `min` would then name whichever one `gh` happened to list
    # first. That is newest-first, so the "oldest" reported was the newest of
    # the tied set: #767 instead of #758. Issue numbers are monotonic with
    # creation, so they order a tie correctly and need no second timestamp.
    oldest_created, oldest = (
        min(dated, key=lambda pair: (pair[0], int(pair[1].get("number", 0))))
        if dated
        else (None, None)
    )
    return OpenQueue(
        read=True,
        count=len(undeferred),
        oldest_number=int(oldest["number"]) if oldest else None,
        oldest_created=oldest_created,
        asof=today,
    )


def read_open_queue(repo: Optional[str] = None, today: Optional[date] = None) -> OpenQueue:
    """The live queue, or an explicitly unread one when the tracker is closed.

    Any failure to reach the tracker — no `gh`, no token, a rate limit — yields
    `read=False` rather than an exception or a zero. The page then says so.
    """
    try:
        ageing = _load_ageing_module()
        return open_queue_from_issues(ageing.fetch_issues(repo), today)
    except Exception:
        return OpenQueue(read=False, asof=today or date.today())


def render_queue_marker(queue: OpenQueue) -> str:
    """The HTML comment carrying the row's machine-readable state."""
    if not queue.read:
        return "<!-- cve-open-queue: read=no -->"
    parts = [f"read=yes count={queue.count}"]
    if queue.oldest_number is not None:
        parts.append(f"oldest=#{queue.oldest_number}")
    if queue.oldest_created is not None:
        parts.append(f"created={queue.oldest_created.isoformat()}")
    if queue.asof is not None:
        parts.append(f"asof={queue.asof.isoformat()}")
    return f"<!-- cve-open-queue: {' '.join(parts)} -->"


def parse_open_queue(page: str) -> Optional[OpenQueue]:
    """Read the open-queue state back out of a rendered page.

    Returns None when the page carries no marker at all, which is how a page
    written before this row existed is told apart from one reporting an empty
    queue. `--check-queue` treats that difference as the whole point.
    """
    match = _QUEUE_MARKER_RE.search(page)
    if match is None:
        return None
    fields: dict[str, str] = {}
    for token in match.group("body").split():
        key, _, value = token.partition("=")
        if key:
            fields[key] = value
    if fields.get("read") != "yes":
        return OpenQueue(read=False)

    def _date(key: str) -> Optional[date]:
        raw = fields.get(key)
        try:
            return date.fromisoformat(raw) if raw else None
        except ValueError:
            return None

    number = fields.get("oldest", "").lstrip("#")
    return OpenQueue(
        read=True,
        count=int(fields["count"]) if fields.get("count", "").isdigit() else 0,
        oldest_number=int(number) if number.isdigit() else None,
        oldest_created=_date("created"),
        asof=_date("asof"),
    )


def _queue_phrase(queue: Optional[OpenQueue]) -> str:
    """The open queue as a noun phrase, or "" when there is nothing to say."""
    if queue is None or not queue.read:
        return ""
    if queue.count == 0:
        return "none are open and undispositioned"
    age = queue.oldest_age_days
    oldest = ""
    if queue.oldest_number is not None:
        oldest = f", the oldest (#{queue.oldest_number})"
        if age is not None:
            oldest += f" at {age} day{'s' if age != 1 else ''}"
    plural = "is" if queue.count == 1 else "are"
    return f"{queue.count} {plural} open and undispositioned{oldest}"


def render(
    rows: list[Row],
    missing: list[str],
    out_of_scope: set[str],
    queue: Optional[OpenQueue] = None,
) -> str:
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
        response = [
            r.days for r in rows
            if _PRE_COVERED_DAYS <= r.days <= _BACKLOG_DAYS
        ]
        backlog = [r.days for r in rows if r.days > _BACKLOG_DAYS]
        pre_covered = [r for r in rows if r.days < _PRE_COVERED_DAYS]

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

        # The scope of the figure, stated as a definition rather than a hedge.
        # Without it the median reads as "how fast we respond", when what it
        # measures is "how fast the cases that finished, finished" — and the
        # unfinished ones are exactly the slow ones.
        phrase = _queue_phrase(queue)
        if queue is not None and not queue.read:
            add(
                "These figures describe disclosures that reached a disposition. "
                "The open queue was not read on this run, so how many are "
                "waiting is unknown here — see the coverage table below."
            )
            add("")
        elif phrase and queue is not None and queue.count:
            asof = f" as of {queue.asof.isoformat()}" if queue.asof else ""
            add(
                f"These figures describe disclosures that reached a "
                f"disposition{asof}: {phrase}, and they are not in the numbers "
                f"above."
            )
            add("")
        elif phrase:
            asof = f" as of {queue.asof.isoformat()}" if queue and queue.asof else ""
            add(
                f"These figures describe disclosures that reached a "
                f"disposition, and{asof} {phrase} — so nothing is waiting "
                f"outside them."
            )
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

        if pre_covered:
            names = ", ".join(
                f"`{r.cve}`" for r in sorted(pre_covered, key=lambda r: r.cve)
            )
            lead = abs(max(r.days for r in pre_covered))
            lag = abs(min(r.days for r in pre_covered))
            if len(pre_covered) == 1:
                span = f"one CVE was already covered when NVD published it, by {lag} days"
            elif lead == lag:
                span = (
                    f"{len(pre_covered)} CVEs were already covered when NVD "
                    f"published them, each by {lag} days"
                )
            else:
                span = (
                    f"{len(pre_covered)} CVEs were already covered when NVD "
                    f"published them, by between {lead} and {lag} days"
                )
            add(
                f"Separately, {span}: {names}. A rule written from a vendor "
                f"advisory, or one general enough that the shape was already in "
                f"the registry, is in place before NVD enrichment lands. There is "
                f"no turnaround to measure, so these are kept out of the figures "
                f"above rather than reported as a negative fastest response."
            )
            add("")

        add(
            f"All populations together: {len(measured)} CVEs with a known "
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
    # The fourth row. Every row above it describes a CVE that already reached a
    # disposition, so without this one a disclosure sitting untriaged appears in
    # no population at all — and the figures can only improve by waiting.
    if queue is None:
        add("| Disclosed, open and not yet dispositioned | not read this run |")
    elif not queue.read:
        add("| Disclosed, open and not yet dispositioned | not read this run |")
    elif queue.count == 0:
        add(
            f"| Disclosed, open and not yet dispositioned | 0"
            f"{f' (as of {queue.asof.isoformat()})' if queue.asof else ''} |"
        )
    else:
        age = queue.oldest_age_days
        detail = ""
        if queue.oldest_number is not None:
            detail = f" — oldest `#{queue.oldest_number}`"
            if age is not None:
                detail += f" at {age} day{'s' if age != 1 else ''}"
            if queue.asof:
                detail += f", as of {queue.asof.isoformat()}"
        add(f"| Disclosed, open and not yet dispositioned | {queue.count}{detail} |")
    add("")
    # Machine-readable state, so `--check` reproduces this page offline and
    # `--check-queue` compares it to the tracker without parsing prose.
    add(render_queue_marker(queue if queue is not None else OpenQueue(read=False)))
    add("")
    if queue is not None and not queue.read:
        add(
            "The open queue could not be read on the run that produced this "
            "page, so the row above is a stated gap rather than a zero. "
            "`python scripts/cve_latency.py` re-reads it when the tracker is "
            "reachable."
        )
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
        "- **Days** is calendar days, `shipped - published`. A negative value "
        "means coverage landed before NVD published, which happens when a rule "
        "is written from a vendor advisory ahead of NVD enrichment, or when the "
        "shape was already covered generically. Those rows are a separate "
        "population and are excluded from the response figures: there is no "
        "turnaround to measure when the rule predates the disclosure."
    )
    add(
        "- A CVE appearing in several sections is counted from the earliest one "
        "that carried coverage."
    )
    add(
        "- **Disclosed, open and not yet dispositioned** counts open "
        "`cve-response` issues on the tracker, minus any labelled "
        "`cve-deferred` — a deferral is a disposition with a date of its own, "
        "judged by `check_cve_deferrals.py`. These CVEs have no shipped date "
        "yet, so they are in none of the rows above. That is the point of "
        "printing them: without this row a disclosure left sitting appears "
        "nowhere on the page, and the median can only improve by waiting. "
        "`python scripts/cve_latency.py --check-queue` fails when this row "
        "disagrees with the tracker; it runs on the daily CVE cron and blocks "
        "no release."
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


def _check_queue(committed: str, live: OpenQueue, out_path: Path) -> int:
    """Fail when the page's open-queue row disagrees with the tracker.

    Three distinct failures, kept distinct because the fixes differ:

    * the page carries no open-queue row at all while the tracker is non-empty —
      the original defect, where an untriaged disclosure appeared in no
      population and the median could only improve by waiting;
    * the page says the queue was not read, while it can be read now;
    * the page records a queue the tracker no longer agrees with.

    An unreadable tracker is *not* a failure. This has to be runnable where no
    token exists, and "I could not look" must never render as "nothing there" —
    that is the same substitution of a zero for a gap the row exists to stop.
    """
    if not committed:
        print(f"cve-latency: no page at {out_path} to check", file=sys.stderr)
        return 2

    if not live.read:
        print(
            "cve-latency: the tracker could not be read, so the open-queue row "
            "is unverified this run. Not a failure — an unread queue is a "
            "stated gap, not a clean bill.",
            file=sys.stderr,
        )
        return 0

    recorded = parse_open_queue(committed)
    fix = (
        "Run `python scripts/cve_latency.py` and commit the regenerated page. "
        "This is a published number, not a release gate: nothing is blocked "
        "while it is red."
    )

    if recorded is None:
        if live.count == 0:
            print("cve-latency: queue empty and the page predates the row — nothing to report.")
            return 0
        print(
            f"::error ::cve-latency: the page carries no open-queue row, but the "
            f"tracker holds {live.count} open, undispositioned cve-response "
            f"issue(s)"
            + (
                f" (oldest #{live.oldest_number}, {live.oldest_age_days}d)"
                if live.oldest_number is not None
                else ""
            )
            + ". Every population on that page describes a CVE that already "
            "reached a disposition, so those issues are published nowhere and "
            "the median can only improve while they wait. " + fix,
            file=sys.stderr,
        )
        return 1

    if not recorded.read:
        print(
            "::error ::cve-latency: the page says the open queue was not read, "
            f"but it reads fine now ({live.count} open). A stated gap is only "
            "honest until it can be closed. " + fix,
            file=sys.stderr,
        )
        return 1

    if not recorded.agrees_with(live):
        print(
            "::error ::cve-latency: the published open-queue row disagrees with "
            "the tracker.\n"
            f"  page:    {recorded.count} open, oldest "
            f"{('#' + str(recorded.oldest_number)) if recorded.oldest_number else 'n/a'}"
            f" created {recorded.oldest_created or 'n/a'}\n"
            f"  tracker: {live.count} open, oldest "
            f"{('#' + str(live.oldest_number)) if live.oldest_number else 'n/a'}"
            f" created {live.oldest_created or 'n/a'}\n"
            "  " + fix,
            file=sys.stderr,
        )
        return 1

    age = live.oldest_age_days
    print(
        f"cve-latency: open-queue row matches the tracker "
        f"({live.count} open"
        + (f", oldest #{live.oldest_number} at {age}d" if live.oldest_number else "")
        + ")."
    )
    return 0


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
    parser.add_argument(
        "--check-queue", action="store_true",
        help=(
            "Fail if the committed page's open-queue row disagrees with the live "
            "tracker (network). Separate from --check on purpose: --check runs in "
            "pytest and on every tag, and must stay offline and non-blocking."
        ),
    )
    parser.add_argument(
        "--repo", help="owner/name for the tracker read (passed to `gh`)."
    )
    parser.add_argument(
        "--issues-json",
        help="Read the queue from a JSON file instead of `gh` (offline; tests).",
    )
    parser.add_argument(
        "--today", help="ISO date to evaluate the queue against (testing)."
    )
    parser.add_argument("--ledger", default=str(LEDGER))
    parser.add_argument(
        "--changelog", default=str(RELEASES),
        help="CHANGELOG.md to read release dates from (testing).",
    )
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
    out_path = Path(args.out)
    committed = out_path.read_text(encoding="utf-8") if out_path.is_file() else ""
    today = date.fromisoformat(args.today) if args.today else date.today()

    def _tracker_queue() -> OpenQueue:
        """The queue as the tracker reports it right now."""
        if args.issues_json:
            with open(args.issues_json, encoding="utf-8") as handle:
                return open_queue_from_issues(json.load(handle), today)
        return read_open_queue(args.repo, today)

    if args.check_queue:
        return _check_queue(committed, _tracker_queue(), out_path)

    if args.check:
        # The Release column first. The byte comparison below cannot catch a
        # mislabelled one: it regenerates the page from the same ledger and
        # gets the same wrong label, so the file matches itself and passes.
        # That is how 66 of 102 rows came to read `unreleased` while PyPI had
        # been serving 0.3.78 through 0.6.7 for a month.
        changelog_path = Path(args.changelog)
        releases = (
            release_dates(changelog_path.read_text(encoding="utf-8"))
            if changelog_path.is_file()
            else []
        )
        unlabelled = find_unlabelled_shipped(shipped, releases)
        if unlabelled:
            print(
                f"::error ::cve-latency: {len(unlabelled)} row(s) say "
                f"'unreleased' although a release was cut after their ledger "
                f"section. The section heading in CHANGELOG.cves.md needs its "
                f"version label — `## YYYY-MM-DD (vX.Y.Z): ...`, or "
                f"`(vX.Y.Z, later)` where it already carries a qualifier:",
                file=sys.stderr,
            )
            for row in unlabelled[:20]:
                print(f"  {row}", file=sys.stderr)
            if len(unlabelled) > 20:
                print(f"  ... and {len(unlabelled) - 20} more", file=sys.stderr)
            return 1

        # Reproduce the committed page from the committed page's OWN queue
        # state, not a fresh tracker read. The byte comparison then stays
        # offline and deterministic, which its two callers require: pytest runs
        # it with no token, and release.yml runs it on every tag. Whether that
        # recorded state still matches the tracker is a different question, and
        # --check-queue is where it is asked.
        rendered = render(rows, missing, out_of_scope, parse_open_queue(committed))
        if committed != rendered:
            print(
                "cve-latency: docs/cve-latency.md is stale — "
                "run 'python scripts/cve_latency.py' and commit",
                file=sys.stderr,
            )
            return 1
        print("cve-latency: up to date")
        return 0

    rendered = render(rows, missing, out_of_scope, _tracker_queue())

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    # Mirror the doc: report the response population, disclose the backlog
    # separately. A mixed figure describes neither.
    response = [
        r.days for r in rows if _PRE_COVERED_DAYS <= r.days <= _BACKLOG_DAYS
    ]
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
