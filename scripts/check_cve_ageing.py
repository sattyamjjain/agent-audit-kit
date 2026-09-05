#!/usr/bin/env python3
"""Guard: no open ``cve-response`` issue may out-age its severity band.

The release gate (release.yml) asks one question: has every disclosed CVE been
*looked at*? That question is binary and it is deliberately easy to satisfy --
``cve-deferred`` answers it in one label. What the gate cannot ask is how long
the queue has been sitting, because the answer must never be "your tag is
blocked": a release blocked on queue depth is what produced the deferral label
in the first place, and a second gate with the same lever would produce the
second deferral label.

So this runs on its own schedule and goes red on its own. Nothing depends on
it, nothing is blocked by it, and that is the point -- it is a standing signal
about triage latency rather than a lock on shipping.

Bands and budgets
-----------------
Bands follow the CVSS v3.1 qualitative ratings, so ``sev/high`` here means what
it means everywhere else. Budgets are counted from issue creation:

    critical (>= 9.0)   3 days
    high     (7.0-8.9)  7 days
    medium   (4.0-6.9)  21 days
    low      (< 4.0)    60 days

An unparseable score gets ``sev/unknown`` and is held to the *critical* budget.
That is the strict reading on purpose: a disclosure nobody has classified is
exactly the one that should surface fastest, and the fix (correct the title) is
cheap. Being lenient here would let a malformed title age indefinitely with no
signal at all, which is the one outcome this script exists to prevent.

Deferral moves an issue between two accounting systems
------------------------------------------------------
A ``cve-deferred`` issue is exempt from its band's budget and judged against
the date it names instead. This is the whole content of a deferral: somebody
read it, decided it waits, and said until when. Holding a dated deferral to the
budget as well would mean #656 -- critical, correctly deferred to a stated date
-- fails on day four no matter what anyone does, which teaches that the honest
disposition and the dishonest one score the same.

The trade is that the named date now has teeth. ``check_cve_deferrals.py``
reports past-due deferrals without failing, because it runs at *tag* time and a
scheduling note must not kill an unrelated release. Here there is no tag to
protect, so past-due is fatal. Same fact, two readings, and the reason they
differ is which clock the caller is on.

Single source of truth for two callers:
    - tests/test_cve_ageing_gate.py
    - .github/workflows/cve-watcher.yml  (the daily `age-gate` job)

Usage:
    python scripts/check_cve_ageing.py --repo owner/name       # live via `gh`
    python scripts/check_cve_ageing.py --issues-json f.json    # offline, tests
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date, datetime
from typing import Any, Iterable, Optional

RESPONSE_LABEL = "cve-response"
DEFERRED_LABEL = "cve-deferred"
UNKNOWN_BAND = "unknown"

# CVSS v3.1 qualitative severity ratings, highest floor first.
_BAND_FLOORS: tuple[tuple[str, float], ...] = (
    ("critical", 9.0),
    ("high", 7.0),
    ("medium", 4.0),
    ("low", 0.0),
)

# Days from issue creation before the band is over budget.
AGE_BUDGET_DAYS: dict[str, int] = {
    "critical": 3,
    "high": 7,
    "medium": 21,
    "low": 60,
    # See the module docstring: unclassified is held to the strictest budget.
    UNKNOWN_BAND: 3,
}

# The score lives in the issue title, written by the watcher as
# `CVE-response: CVE-2026-85620 (HIGH CVSS 8.6)`.
#
# This regex is duplicated, deliberately and exactly, in the `github-script`
# step of .github/workflows/cve-watcher.yml, which applies the sev/* label at
# creation time. The label and the budget must be derived from the same string
# by the same pattern or an issue can carry `sev/high` while ageing as medium.
# tests/test_cve_ageing_gate.py reads the pattern back out of the workflow YAML
# and fails if the two ever drift.
CVSS_RE = re.compile(r"CVSS\s+(\d+(?:\.\d+)?)", re.IGNORECASE)


def parse_cvss(title: str) -> Optional[float]:
    """The CVSS base score named in an issue title, or None.

    Returns None rather than a default for `CVSS n/a`, an absent score, or a
    value outside 0.0-10.0. A score the scale does not define is not a score,
    and coercing it would put an issue in a band nobody chose.
    """
    match = CVSS_RE.search(title or "")
    if match is None:
        return None
    try:
        score = float(match.group(1))
    except ValueError:  # pragma: no cover - regex already constrains the shape
        return None
    return score if 0.0 <= score <= 10.0 else None


def band_for_score(score: Optional[float]) -> str:
    """`critical`/`high`/`medium`/`low`, or `unknown` when there is no score."""
    if score is None:
        return UNKNOWN_BAND
    for name, floor in _BAND_FLOORS:
        if score >= floor:
            return name
    return "low"  # pragma: no cover - the 0.0 floor already matches


def band_for_issue(issue: dict[str, Any]) -> str:
    return band_for_score(parse_cvss(str(issue.get("title") or "")))


def sev_label(band: str) -> str:
    """The repo label that carries a band. One place builds this string."""
    return f"sev/{band}"


def _labels(issue: dict[str, Any]) -> set[str]:
    """Label names, tolerating both `gh` shapes: [{"name": x}] and ["x"]."""
    out: set[str] = set()
    for label in issue.get("labels") or []:
        if isinstance(label, dict):
            name = label.get("name")
            if name:
                out.add(str(name))
        elif label:
            out.add(str(label))
    return out


def created_on(issue: dict[str, Any]) -> Optional[date]:
    """The issue's creation date, from `gh --json createdAt` (ISO 8601, UTC)."""
    raw = str(issue.get("createdAt") or "")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def age_days(issue: dict[str, Any], today: Optional[date] = None) -> Optional[int]:
    created = created_on(issue)
    if created is None:
        return None
    return ((today or date.today()) - created).days


def response_issues(issues: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [issue for issue in issues if RESPONSE_LABEL in _labels(issue)]


def find_overdue(
    issues: Iterable[dict[str, Any]], today: Optional[date] = None
) -> list[str]:
    """``#N  band  Nd/Bd  title`` for every undeferred issue over its budget.

    Deferred issues are not judged here -- see the module docstring.
    """
    today = today or date.today()
    rows: list[tuple[int, str]] = []
    for issue in response_issues(issues):
        if DEFERRED_LABEL in _labels(issue):
            continue
        age = age_days(issue, today)
        if age is None:
            continue
        band = band_for_issue(issue)
        budget = AGE_BUDGET_DAYS[band]
        if age > budget:
            rows.append((
                -age,
                f"#{issue.get('number')}  sev/{band}  {age}d (budget {budget}d)  "
                f"{issue.get('title', '')}".rstrip(),
            ))
    return [row for _, row in sorted(rows)]


def find_undated_or_past_due(
    issues: Iterable[dict[str, Any]],
    today: Optional[date] = None,
    target_date_fn: Any = None,
) -> list[str]:
    """``#N  …`` for every deferral that names no date, or names a passed one.

    Date parsing is delegated to ``check_cve_deferrals.target_date`` so the two
    guards cannot disagree about what counts as a date -- including which
    spellings are accepted.
    """
    today = today or date.today()
    if target_date_fn is None:
        target_date_fn = _load_deferrals_module().target_date
    rows: list[str] = []
    for issue in response_issues(issues):
        if DEFERRED_LABEL not in _labels(issue):
            continue
        due = target_date_fn(issue)
        if due is None:
            rows.append(f"#{issue.get('number')}  no target date  {issue.get('title', '')}".rstrip())
        elif due < today:
            rows.append(
                f"#{issue.get('number')}  target {due} passed "
                f"({(today - due).days}d ago)  {issue.get('title', '')}".rstrip()
            )
    return rows


def _load_deferrals_module() -> Any:
    """Import the sibling deferral guard as the single date-parsing authority."""
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parent / "check_cve_deferrals.py"
    spec = importlib.util.spec_from_file_location("check_cve_deferrals", script)
    if spec is None or spec.loader is None:  # pragma: no cover - packaging error
        raise RuntimeError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("check_cve_deferrals", module)
    spec.loader.exec_module(module)
    return module


def queue_depth(issues: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Per-band counts of the open queue, plus the deferred subset."""
    counts: dict[str, int] = {}
    for issue in response_issues(issues):
        counts[band_for_issue(issue)] = counts.get(band_for_issue(issue), 0) + 1
    counts["deferred"] = sum(
        1 for issue in response_issues(issues) if DEFERRED_LABEL in _labels(issue)
    )
    return counts


def _gh_json(args: list[str]) -> Any:
    out = subprocess.run(["gh", *args], capture_output=True, text=True, check=True)
    return json.loads(out.stdout or "[]")


def fetch_issues(repo: Optional[str] = None) -> list[dict[str, Any]]:
    """Open `cve-response` issues, with comments on the deferred ones only.

    Comments are where a disposition date usually lands, but fetching them for
    the whole queue would be an N+1 against the API for issues this guard reads
    only the title and creation date of.
    """
    scope = ["--repo", repo] if repo else []
    issues: list[dict[str, Any]] = _gh_json([
        "issue", "list", *scope,
        "--label", RESPONSE_LABEL, "--state", "open", "--limit", "200",
        "--json", "number,title,labels,body,createdAt",
    ])
    for issue in issues:
        if DEFERRED_LABEL not in _labels(issue):
            continue
        detail = _gh_json([
            "issue", "view", str(issue["number"]), *scope, "--json", "comments",
        ])
        issue["comments"] = detail.get("comments") or []
    return issues


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="CVE queue ageing gate.")
    parser.add_argument(
        "--issues-json",
        help="Path to a JSON array of issues (offline; skips the `gh` fetch).",
    )
    parser.add_argument("--repo", help="owner/name, passed through to `gh`.")
    parser.add_argument(
        "--today",
        help="ISO date to evaluate against (testing; defaults to today).",
    )
    args = parser.parse_args(argv)

    if args.issues_json:
        with open(args.issues_json, encoding="utf-8") as handle:
            issues = json.load(handle)
    else:
        issues = fetch_issues(args.repo)

    today = date.fromisoformat(args.today) if args.today else date.today()

    overdue = find_overdue(issues, today)
    deferral_faults = find_undated_or_past_due(issues, today)

    depth = queue_depth(issues)
    summary = ", ".join(f"{k} {v}" for k, v in sorted(depth.items()) if v)
    print(f"cve queue: {len(response_issues(issues))} open ({summary or 'empty'}).")

    if overdue:
        print(
            f"::error ::cve ageing gate: {len(overdue)} issue(s) past their band's "
            f"age budget. Ship a rule, close it, or label it `cve-deferred` with a "
            f"target date:",
            file=sys.stderr,
        )
        for row in overdue:
            print(f"  {row}", file=sys.stderr)

    if deferral_faults:
        print(
            f"::error ::cve ageing gate: {len(deferral_faults)} deferral(s) are "
            f"undated or past their own target date. A deferral is only honest "
            f"while the date it names is still ahead:",
            file=sys.stderr,
        )
        for row in deferral_faults:
            print(f"  {row}", file=sys.stderr)

    if overdue or deferral_faults:
        return 1

    print("cve ageing gate: clean — every open issue is inside its budget.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
