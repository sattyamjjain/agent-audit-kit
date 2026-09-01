"""Poll NVD for MCP-related CVEs disclosed in the last 48 hours.

Writes a JSON list of CVEs to stdout that are NOT already tracked in
CHANGELOG.cves.md, already recorded in the persistent watcher state file,
or already present in the titles of existing open ``cve-response`` issues.
Exits 0 regardless of whether there are new CVEs; the caller branches on
whether stdout is non-empty.

Used by .github/workflows/cve-watcher.yml. Runs every 6 hours.

Uses the NVD REST API 2.0. An NVD API key (set via NVD_API_KEY env) is
recommended but optional — without it the rate limit is 5 req/30s.

Dedup strategy (three layers, any one suppresses):

1. ``CHANGELOG.cves.md`` — the canonical record of shipped coverage.
2. ``.aak/cve-watcher-state.json`` — persistent record of every CVE the
   watcher has filed, so a CVE sitting in the SLA queue without a rule
   does not get re-opened every cron run.
3. Open ``cve-response`` issue titles fetched from the GitHub REST API
   (``GITHUB_TOKEN`` + ``GITHUB_REPOSITORY`` env). Belt-and-braces
   guard in case state-file write fails.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORDS = (
    "mcp",
    "model context protocol",
    "claude code",
    "claude agent sdk",
    "langchain",
    "langgraph",
    "anthropic",
)
CHANGELOG_PATH = Path("CHANGELOG.cves.md")
STATE_PATH = Path(".aak/cve-watcher-state.json")

# ---------------------------------------------------------------------------
# Back-pressure (2026-09-01).
#
# This watcher runs every 6 hours and, until now, filed one release-gating issue
# per new CVE with no upper bound. Between 2026-08-26 and 2026-09-01 it opened 27
# -- eight of them one product's advisory batch landing in a single run -- and
# because the release gate blocked on any open cve-response issue, the queue
# outrunning the triage rate meant the repo could not ship at all. v0.3.91 sat
# written and unpublished for a day.
#
# The pre-filter is NOT the problem and was deliberately left alone: every one of
# those 27 was a genuine MCP CVE, so tightening `is_relevant` would have dropped
# true positives to fix a rate problem. An automated issue-opener needs a limit,
# not a narrower definition of what matters.
#
# Two limits, both env-overridable:
#   * MAX_NEW_PER_RUN  -- one advisory batch cannot become one day's backlog.
#   * MAX_OPEN_UNTRIAGED -- when the queue is already deep, stop adding to it.
#     Deferred issues do not count: they have been read and scheduled, and the
#     release gate ignores them too.
#
# Nothing is dropped. `state["filed_cves"]` only ever records what is actually
# emitted, so a CVE held back is simply found again on a later run and deduped
# against the ledger, the state file, and every open and closed issue. That is
# also why the NVD window widened from 48h to 7 days: a held-back CVE has to
# still be inside the query window when the queue drains, or back-pressure would
# quietly become data loss.
MAX_NEW_PER_RUN = int(os.environ.get("AAK_CVE_MAX_NEW_PER_RUN", "5"))
MAX_OPEN_UNTRIAGED = int(os.environ.get("AAK_CVE_MAX_OPEN_UNTRIAGED", "10"))
DEFERRED_LABEL = "cve-deferred"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _already_tracked() -> set[str]:
    if not CHANGELOG_PATH.is_file():
        return set()
    text = CHANGELOG_PATH.read_text(encoding="utf-8", errors="ignore")
    return set(_CVE_RE.findall(text))


def _load_state(state_path: Path) -> dict:
    if not state_path.is_file():
        return {"filed_cves": []}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"filed_cves": []}
    if not isinstance(data, dict):
        return {"filed_cves": []}
    data.setdefault("filed_cves", [])
    return data


def _save_state(state_path: Path, state: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _all_issue_cves(owner_repo: str | None, token: str | None) -> set[str]:
    """Return CVE IDs across **all** cve-response issues (open + closed).

    Fixes the v0.3.x daily re-fire pattern (tracking #163): the prior
    implementation queried only `state=open`, so a CVE closed with a
    class-coverage citation was forgotten and re-filed on the next
    watcher cycle. Now closed issues participate in dedup too, with
    pagination so the lookup remains complete as the closed-issue
    backlog grows past 100 entries.

    The state file (`filed_cves`) is still the durable primary source;
    this lookup is the fallback when the state file is missing (CI
    artifact lost, repo re-clone, etc.).
    """
    if not owner_repo or not token:
        return set()
    out: set[str] = set()
    page = 1
    while page <= 20:  # hard cap — 20 pages × 100 = 2000 issues
        url = (
            f"https://api.github.com/repos/{owner_repo}/issues"
            f"?state=all&labels=cve-response&per_page=100&page={page}"
        )
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "agent-audit-kit cve-watcher",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                issues = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError) as exc:
            sys.stderr.write(f"cve-watcher: all-issue check failed (page {page}): {exc}\n")
            return out
        if not issues:
            break
        for issue in issues:
            title = issue.get("title") or ""
            body = issue.get("body") or ""
            for m in _CVE_RE.findall(f"{title}\n{body}"):
                out.add(m)
        if len(issues) < 100:
            break
        page += 1
    return out


# Back-compat alias — the old name is still referenced in some tests.
_open_issue_cves = _all_issue_cves


# NVD's keywordSearch matches indexed fields, not just the description, and
# "mcp" is three letters that appear in unrelated hardware naming — NVIDIA
# nForce chipsets are literally "MCP" parts, so Linux kernel CVEs touching them
# come back as hits. CVE-2026-68456 (a `ueagle-atm` USB driver firmware-load
# race) arrived that way and opened a `cve-response` issue with the string "mcp"
# appearing zero times in its description.
#
# That is not merely noise: every filed issue blocks the release gate until a
# human dispositions it, so an unrelated kernel CVE stops a publish.
#
# So a hit must corroborate in the description before it is filed. Kept
# deliberately broad — a missed CVE is worse than a filed irrelevant one — and
# the watcher still logs what it dropped.
#
# Two words need care rather than a bare match:
#
#   "claude"  — CVE-2026-68456's kernel patch description ends with "(The latter
#               two were written by Claude...)": the maintainer credited the model
#               that wrote part of the commit. As AI-authored patches spread, an
#               attribution line in any project's commit message will keep
#               matching. So `claude` only counts next to a product word.
#   "agent"   — user agent, agent process, SNMP agent. Far too common in CVE text
#               to mean anything on its own; only the compound forms count.
_RELEVANCE_RE = re.compile(
    r"\bmcp\b"
    r"|model[- ]context[- ]protocol"
    r"|claude[- ](?:code|desktop|agent|sdk|mcp)"
    r"|claude\.ai"
    r"|\banthropic\b"
    r"|\blangchain\b"
    r"|\blanggraph\b"
    r"|\bllm\b"
    r"|\bai[- ]agent"
    r"|\bagentic\b"
    r"|\btool[- ]call"
    r"|\bagent (?:framework|runtime|pipeline|orchestrat)",
    re.IGNORECASE,
)


def is_relevant(description: str) -> bool:
    """Does the CVE text itself mention the ecosystem we track?

    Guards against NVD matching a keyword in a CPE name or reference URL rather
    than in the vulnerability text. See the note above `_RELEVANCE_RE`.
    """
    return bool(_RELEVANCE_RE.search(description or ""))


def open_untriaged_count(owner_repo: str | None, token: str | None) -> int:
    """Open ``cve-response`` issues that carry no ``cve-deferred`` label.

    The same population the release gate blocks on, so the watcher throttles
    against the number that actually stops a release rather than against the raw
    queue depth. Returns 0 when the API cannot be reached: back-pressure must
    never be the reason a disclosure goes unfiled.
    """
    if not owner_repo or not token:
        return 0
    count = 0
    page = 1
    while page <= 20:
        url = (
            f"https://api.github.com/repos/{owner_repo}/issues"
            f"?state=open&labels=cve-response&per_page=100&page={page}"
        )
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "agent-audit-kit cve-watcher",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"cve-watcher: cannot count open issues ({exc})\n")
            return 0
        if not batch:
            break
        for issue in batch:
            labels = {lbl.get("name") for lbl in (issue.get("labels") or [])}
            if DEFERRED_LABEL not in labels:
                count += 1
        page += 1
    return count


def _fetch(keyword: str, window_hours: int = 168) -> list[dict]:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=window_hours)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {
        "keywordSearch": keyword,
        "pubStartDate": start,
        "pubEndDate": end,
        "resultsPerPage": 50,
    }
    url = f"{NVD_SEARCH}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "agent-audit-kit cve-watcher"})
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"NVD fetch failed for keyword {keyword!r}: {exc}\n")
        return []
    return data.get("vulnerabilities", [])


def _extract(vuln: dict) -> dict:
    cve = vuln.get("cve") or {}
    metrics = (cve.get("metrics") or {}).get("cvssMetricV31") or []
    cvss = None
    severity = None
    if metrics:
        cvss_data = (metrics[0].get("cvssData") or {})
        cvss = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "cvss": cvss,
        "severity": severity,
        "description": desc,
    }


def collect_new_cves(
    *,
    changelog_path: Path = CHANGELOG_PATH,
    state_path: Path = STATE_PATH,
    github_token: str | None = None,
    owner_repo: str | None = None,
    fetcher=_fetch,
) -> tuple[list[dict], dict]:
    """Pure function that collects new CVEs with layered dedup.

    Returns ``(new_cve_entries, updated_state)``. The caller is responsible
    for persisting the updated state file (so dry-run tests stay clean).
    """

    # Rebind module-level paths so overrides take effect.
    global CHANGELOG_PATH, STATE_PATH
    CHANGELOG_PATH = changelog_path
    STATE_PATH = state_path

    tracked = _already_tracked()
    state = _load_state(state_path)
    filed = set(state.get("filed_cves", []))
    # As of v0.3.20 (#163 fix): query state=all so closed issues — including
    # those closed with class-coverage citations — also participate in dedup.
    # Pre-fix only `state=open` was checked, causing daily re-fires.
    all_issue_cves = _all_issue_cves(owner_repo, github_token)
    suppressed = tracked | filed | all_issue_cves

    seen: set[str] = set()
    results: list[dict] = []
    for keyword in KEYWORDS:
        for vuln in fetcher(keyword):
            entry = _extract(vuln)
            cve_id = entry["id"]
            if not cve_id or cve_id in suppressed or cve_id in seen:
                continue
            if not is_relevant(entry.get("description") or ""):
                # NVD matched the keyword in an indexed field (CPE names,
                # references) rather than the text. Filing it would open a
                # release-gating issue for something unrelated — see
                # is_relevant() for why this filter exists.
                seen.add(cve_id)
                continue
            seen.add(cve_id)
            results.append(entry)

    # --- back-pressure ------------------------------------------------------
    # Applied HERE, not in the workflow's issue-creating step, because
    # `filed_cves` below records everything this function returns. A cap applied
    # after the fact would mark held-back CVEs as filed and lose them silently --
    # the opposite of the intent.
    if results:
        backlog = open_untriaged_count(owner_repo, github_token)
        if backlog >= MAX_OPEN_UNTRIAGED:
            sys.stderr.write(
                f"cve-watcher: {backlog} untriaged cve-response issue(s) already "
                f"open (limit {MAX_OPEN_UNTRIAGED}); holding "
                f"{len(results)} new CVE(s) until the queue drains: "
                f"{', '.join(e['id'] for e in results)}\n"
            )
            return [], state
        if len(results) > MAX_NEW_PER_RUN:
            # Most severe first, so a cap keeps the ones worth waking up for.
            results.sort(key=lambda e: (e.get("cvss") or 0.0), reverse=True)
            held = results[MAX_NEW_PER_RUN:]
            results = results[:MAX_NEW_PER_RUN]
            sys.stderr.write(
                f"cve-watcher: capped at {MAX_NEW_PER_RUN} new issue(s) this run; "
                f"holding {len(held)} for a later run: "
                f"{', '.join(e['id'] for e in held)}\n"
            )

    if results:
        state["filed_cves"] = sorted(filed | {e["id"] for e in results})
    return results, state


def main() -> int:
    state_path = Path(os.environ.get("AAK_CVE_WATCHER_STATE", str(STATE_PATH)))
    token = os.environ.get("GITHUB_TOKEN")
    owner_repo = os.environ.get("GITHUB_REPOSITORY")
    results, state = collect_new_cves(
        state_path=state_path,
        github_token=token,
        owner_repo=owner_repo,
    )
    sys.stdout.write(json.dumps(results, indent=2))
    # Only write state if we are about to file something. The workflow
    # branches on stdout non-empty — if we crash between "stdout written"
    # and "issue filed" the state must still mark the CVE to prevent
    # another round of duplicates.
    if results:
        _save_state(state_path, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
