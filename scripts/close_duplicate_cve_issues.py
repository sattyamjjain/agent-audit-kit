"""Close duplicate `cve-response` issues, keeping the lowest-numbered one per CVE.

The watcher regression on 2026-04-20/21 opened five copies of
CVE-2026-6599, three of CVE-2025-66335, and two of CVE-2026-39861 over
48 hours. This script collapses the queue by CVE ID: the oldest
(lowest-numbered) issue is kept as the authoritative tracker; every
other issue referencing the same CVE is closed with a cross-reference
body pointing at the canonical issue.

Usage:
    GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo \\
        python3 scripts/close_duplicate_cve_issues.py [--dry-run]

Exit code: 0 regardless of how many issues are closed, so the script is
safe to wire into a CI step that "tries to tidy up".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _list_open_issues(owner_repo: str, token: str) -> list[dict]:
    url = (
        f"https://api.github.com/repos/{owner_repo}/issues"
        "?state=open&labels=cve-response&per_page=100"
    )
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "agent-audit-kit close-dup-cves",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_comment(owner_repo: str, number: int, body: str, token: str) -> None:
    url = f"https://api.github.com/repos/{owner_repo}/issues/{number}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "agent-audit-kit close-dup-cves",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"comment POST failed on #{number}: {exc}\n")


def _close(owner_repo: str, number: int, token: str) -> None:
    url = f"https://api.github.com/repos/{owner_repo}/issues/{number}"
    req = urllib.request.Request(
        url,
        data=json.dumps({"state": "closed", "state_reason": "not_planned"}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "agent-audit-kit close-dup-cves",
        },
        method="PATCH",
    )
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"PATCH close failed on #{number}: {exc}\n")


def _extract_cves(issue: dict) -> list[str]:
    blob = f"{issue.get('title') or ''}\n{issue.get('body') or ''}"
    return list(dict.fromkeys(_CVE_RE.findall(blob)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="List dups but do not mutate.")
    args = parser.parse_args(argv)

    owner_repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not owner_repo or not token:
        sys.stderr.write("GITHUB_REPOSITORY and GITHUB_TOKEN are required.\n")
        return 2

    try:
        issues = _list_open_issues(owner_repo, token)
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"list-issues failed: {exc}\n")
        return 1

    by_cve: dict[str, list[dict]] = defaultdict(list)
    for issue in issues:
        cves = _extract_cves(issue)
        if not cves:
            continue
        # Primary CVE = first one in the title; fall back to first in body.
        primary = cves[0]
        by_cve[primary].append(issue)

    closed_count = 0
    for cve_id, group in sorted(by_cve.items()):
        if len(group) < 2:
            continue
        group.sort(key=lambda i: i.get("number", 0))
        keeper = group[0]
        keeper_num = keeper.get("number")
        for dup in group[1:]:
            num = dup.get("number")
            msg = (
                f"Consolidating into **#{keeper_num}** as the canonical tracker "
                f"for {cve_id}. Closed by `scripts/close_duplicate_cve_issues.py` "
                "(watcher regression fix, v0.3.3)."
            )
            if args.dry_run:
                sys.stdout.write(f"[dry-run] would close #{num} (dup of #{keeper_num} for {cve_id})\n")
            else:
                _post_comment(owner_repo, num, msg, token)
                _close(owner_repo, num, token)
                sys.stdout.write(f"closed #{num} (dup of #{keeper_num} for {cve_id})\n")
            closed_count += 1

    sys.stdout.write(f"done. {'would close' if args.dry_run else 'closed'} {closed_count} duplicate(s).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
