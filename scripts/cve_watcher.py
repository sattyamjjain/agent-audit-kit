"""Poll NVD for MCP-related CVEs disclosed in the last 48 hours.

Writes a JSON list of CVEs to stdout that are NOT already tracked in
CHANGELOG.cves.md. Exits 0 regardless of whether there are new CVEs; the
caller branches on whether stdout is non-empty.

Used by .github/workflows/cve-watcher.yml. Runs every 6 hours.

Uses the NVD REST API 2.0. An NVD API key (set via NVD_API_KEY env) is
recommended but optional — without it the rate limit is 5 req/30s.
"""

from __future__ import annotations

import json
import os
import sys
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


def _already_tracked() -> set[str]:
    if not CHANGELOG_PATH.is_file():
        return set()
    text = CHANGELOG_PATH.read_text(encoding="utf-8", errors="ignore")
    return {
        token
        for line in text.splitlines()
        for token in line.split()
        if token.startswith("CVE-")
    }


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


def main() -> int:
    tracked = _already_tracked()
    seen: set[str] = set()
    results: list[dict] = []
    for keyword in KEYWORDS:
        for vuln in _fetch(keyword):
            entry = _extract(vuln)
            cve_id = entry["id"]
            if not cve_id or cve_id in tracked or cve_id in seen:
                continue
            seen.add(cve_id)
            results.append(entry)
    sys.stdout.write(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
