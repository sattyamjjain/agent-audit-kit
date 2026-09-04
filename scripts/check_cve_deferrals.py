#!/usr/bin/env python3
"""Guard: every ``cve-deferred`` issue must name a target date.

``cve-deferred`` is the one label that turns the release gate off. It was added
on 2026-09-01 (docs/RELEASING.md §5) because the watcher's 6-hour cron outran the
triage rate and ``count == 0`` became a state the repo could not reach on
purpose. The exemption is correct -- "has this disclosure been looked at?" is a
different question from "is the queue empty?" -- but it was enforced on nothing.

RELEASING.md §5 asks for a disposition comment "naming what is queued and why".
Prose, checked by nobody. Every deferral in the 2026-08-31 wave did carry a
``**Target: YYYY-MM-DD.**`` line, so the convention was real; it was simply
unenforceable, and a label whose only obligation is a convention is one busy
afternoon away from being a mute button. A deferral with no date is not a
deferral, it is a silent drop with a label on it.

So: the label earns its exemption only on an issue that names a date. This is
the check that says so, and release.yml refuses to tag when it fails.

What is deliberately NOT enforced here
--------------------------------------
A date in the *past* does not fail. That looked tempting and is a trap: every
deferral in the tree would become a release blocker the morning its date passed,
turning a scheduling note into a time bomb that fires during an unrelated
release. Past-due deferrals are *listed* on stdout on every run instead, so they
are visible at the moment somebody is already looking at the queue, without
holding a tag hostage to a date somebody typed a month ago.

Single source of truth for two callers:
    - tests/test_cve_deferral_dates.py
    - .github/workflows/release.yml  (fails the tag on an undated deferral)

Usage:
    python scripts/check_cve_deferrals.py                    # fetch live via `gh`
    python scripts/check_cve_deferrals.py --issues-json f.json   # offline, for tests
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from typing import Any, Iterable, Optional

RESPONSE_LABEL = "cve-response"
DEFERRED_LABEL = "cve-deferred"

# Both spellings are accepted on purpose.
#
#   target date: 2026-09-30      <- the structured field this guard asks for
#   **Target: 2026-09-30.**      <- the prose form the 2026-08-31 wave used
#
# Rejecting the second would have marked ten correctly-dated deferrals as
# violations on the day this landed, which would teach the exact lesson a guard
# should never teach: that the guard is wrong and worth routing around. The
# obligation is "say when", not "say when in my preferred punctuation".
_TARGET_RE = re.compile(
    r"\btarget(?:\s+date)?\s*:\s*\**\s*(\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)


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


def _texts(issue: dict[str, Any]) -> list[str]:
    """The issue body plus every comment body, as plain strings.

    The date may live in either. The watcher writes the body from a fixed
    template, so a human dispositioning an issue puts the date in a comment --
    but a body edit is just as good and there is no reason to refuse it.
    """
    texts: list[str] = [str(issue.get("body") or "")]
    for comment in issue.get("comments") or []:
        if isinstance(comment, dict):
            texts.append(str(comment.get("body") or ""))
        elif comment:
            texts.append(str(comment))
    return texts


def target_date(issue: dict[str, Any]) -> Optional[date]:
    """The latest calendar-valid target date named anywhere on the issue.

    Latest rather than first: a re-deferred issue names a new date in a newer
    comment, and the honest reading of "we said September, then we said October"
    is October. A string that is merely date-shaped (``2026-13-45``) is not a
    date and is skipped, so a typo reads as "no date given" and fails the guard
    rather than passing it with a value nothing can order.
    """
    best: Optional[date] = None
    for text in _texts(issue):
        for match in _TARGET_RE.finditer(text):
            try:
                found = date.fromisoformat(match.group(1))
            except ValueError:
                continue
            if best is None or found > best:
                best = found
    return best


def deferred_issues(issues: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Open ``cve-response`` issues carrying ``cve-deferred`` -- the exempt set."""
    return [
        issue
        for issue in issues
        if {RESPONSE_LABEL, DEFERRED_LABEL} <= _labels(issue)
    ]


def find_undated_deferrals(issues: Iterable[dict[str, Any]]) -> list[str]:
    """``#N  title`` for every deferred issue that names no target date.

    Returns the violations, so an empty list means the queue is honest.
    """
    return [
        f"#{issue.get('number')}  {issue.get('title', '')}".rstrip()
        for issue in deferred_issues(issues)
        if target_date(issue) is None
    ]


def find_past_due(
    issues: Iterable[dict[str, Any]], today: Optional[date] = None
) -> list[str]:
    """``#N  YYYY-MM-DD  title`` for deferrals whose target date has passed.

    Reported, never fatal -- see the module docstring.
    """
    today = today or date.today()
    rows: list[tuple[date, str]] = []
    for issue in deferred_issues(issues):
        due = target_date(issue)
        if due is not None and due < today:
            rows.append((due, f"#{issue.get('number')}  {due}  {issue.get('title', '')}".rstrip()))
    return [row for _, row in sorted(rows)]


def _gh_json(args: list[str]) -> Any:
    out = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=True
    )
    return json.loads(out.stdout or "[]")


def fetch_issues(repo: Optional[str] = None) -> list[dict[str, Any]]:
    """Open ``cve-response`` issues via `gh`, with comments on the deferred ones.

    Comments are fetched only for issues carrying ``cve-deferred``: they are the
    only ones this guard judges, and they are a small minority of a queue that a
    per-issue fetch across the whole list would turn into an N+1 against the API.
    """
    scope = ["--repo", repo] if repo else []
    issues: list[dict[str, Any]] = _gh_json([
        "issue", "list", *scope,
        "--label", RESPONSE_LABEL, "--state", "open", "--limit", "200",
        "--json", "number,title,labels,body",
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--issues-json",
        help="Path to a JSON array of issues (offline; skips the `gh` fetch).",
    )
    parser.add_argument("--repo", help="owner/name, passed through to `gh`.")
    args = parser.parse_args(argv)

    if args.issues_json:
        with open(args.issues_json, encoding="utf-8") as handle:
            issues = json.load(handle)
    else:
        issues = fetch_issues(args.repo)

    undated = find_undated_deferrals(issues)
    past_due = find_past_due(issues)

    if past_due:
        print(f"cve-deferred: {len(past_due)} deferral(s) past their target date "
              f"(reported, not fatal):")
        for row in past_due:
            print(f"  {row}")

    if undated:
        print(
            f"::error ::cve-deferred gate: {len(undated)} deferred issue(s) name no "
            f"target date. `cve-deferred` exempts an issue from the release gate, so "
            f"it has to say when. Add `target date: YYYY-MM-DD` to each:",
            file=sys.stderr,
        )
        for row in undated:
            print(f"  {row}", file=sys.stderr)
        return 1

    total = len(deferred_issues(issues))
    print(f"cve-deferred gate: clean — {total} deferral(s), all dated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
