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


def _open_issue_cves(owner_repo: str | None, token: str | None) -> set[str]:
    if not owner_repo or not token:
        return set()
    url = (
        f"https://api.github.com/repos/{owner_repo}/issues"
        "?state=open&labels=cve-response&per_page=100"
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
        sys.stderr.write(f"cve-watcher: open-issue check failed: {exc}\n")
        return set()
    out: set[str] = set()
    for issue in issues or []:
        title = issue.get("title") or ""
        body = issue.get("body") or ""
        for m in _CVE_RE.findall(f"{title}\n{body}"):
            out.add(m)
    return out


def _fetch(keyword: str, window_hours: int = 48) -> list[dict]:
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
    open_issue_cves = _open_issue_cves(owner_repo, github_token)
    suppressed = tracked | filed | open_issue_cves

    seen: set[str] = set()
    results: list[dict] = []
    for keyword in KEYWORDS:
        for vuln in fetcher(keyword):
            entry = _extract(vuln)
            cve_id = entry["id"]
            if not cve_id or cve_id in suppressed or cve_id in seen:
                continue
            seen.add(cve_id)
            results.append(entry)

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
