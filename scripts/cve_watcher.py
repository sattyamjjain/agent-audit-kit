"""Poll NVD for MCP-related CVEs, and OSV and NVD for every pinned package, disclosed in the last 7 days.

Three sources. NVD's keyword feed, filtered to records whose text names the
ecosystem (`is_relevant`), as before. OSV, queried by package for every npm,
PyPI and Maven name the pin tables already name (`pinned_packages`, read from
the scanner sources with `ast`), which returns the advisories and the `MAL-`
malicious-package records for those names whatever their text says. And every
NVD record published in the window whose CNA data names one of those npm or
PyPI packages (`nvd_package_records`), titled "pin floor stale" when its range
runs past what the package's pins report. A record from any of them joins one
list and the same dedup and caps; each carries its source, which the workflow
writes into the issue body.

Writes a JSON list of records to stdout that are NOT already tracked in
CHANGELOG.cves.md, already recorded in the persistent watcher state file,
or already present in the titles of existing ``cve-response`` issues.
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

import ast
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, NamedTuple

# The band word in a filed title comes from the ageing gate's own table, so the
# word, the `sev/` label the workflow reads back out of the title's number, and the
# budget the gate enforces on that number cannot disagree.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_cve_ageing import band_for_score  # noqa: E402

# The checkout's own package, for the NVD package source: this job installs
# nothing, and the modules read below import only the standard library.
sys.path.insert(1, str(Path(__file__).resolve().parent.parent))
from agent_audit_kit import nvd_feed  # noqa: E402
from agent_audit_kit.malicious_feed import canonical_name  # noqa: E402
from agent_audit_kit.scanners._versions import (  # noqa: E402
    TOP,
    ZERO,
    Span,
    Spans,
    intersect,
    interval_spans,
    subtract,
    union,
)

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
# Every id a filed issue or a ledger row can carry: an OSV record without a CVE
# alias is filed under its own id (GHSA-, MAL-, PYSEC-).
_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|MAL-\d{4}-\d+|PYSEC-\d{4}-\d+")


def _already_tracked() -> set[str]:
    if not CHANGELOG_PATH.is_file():
        return set()
    text = CHANGELOG_PATH.read_text(encoding="utf-8", errors="ignore")
    return set(_ID_RE.findall(text))


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
            for m in _ID_RE.findall(f"{title}\n{body}"):
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


# Which CVSS score a filed issue carries.
#
# `_extract` used to read `cvssMetricV31` and nothing else. A record whose only score
# was a CNA's CVSS 4.0 metric was filed "(unknown CVSS n/a)" with `sev/unknown` and
# retitled by hand at disposition: #917, #918 and #919, and #1026 for CVE-2026-96620,
# which GitHub scores 9.2. The cap in `collect_new_cves` sorted such a record as a
# 0.0, so a critical one was the first held back.
#
# An NVD record can carry NVD's own analysis (`type: Primary`, from nvd@nist.gov)
# beside a CNA's or CISA's (`type: Secondary`), and CVSS 2.0, 3.0, 3.1 and 4.0
# metrics side by side. The score comes from the first usable metric under two
# rules, applied in this order:
#
# 1. Source before version. A Primary metric is used over any Secondary one,
#    whatever their versions, because it is NVD's own analysis: the API schema marks
#    every metric one or the other, and each Primary metric in the records
#    tests/test_cve_watcher_cvss.py recorded comes from nvd@nist.gov. In the
#    watcher's seven-day window a record seldom has one yet, so a CNA's score is
#    what usually gets filed, as it was when only 3.1 was read.
# 2. Then version: 3.1, 3.0, 4.0, 2.0. A newer CVSS version is used only when the
#    older one is absent, so a record that carries 3.1 keeps the score it was
#    always filed at, and the ledger's CVSS column ("NVD's CVSS 3.1 score, or its
#    CVSS 4.0 score where NVD has only that") reads the same number. The order
#    changes labels: of the 137 records NVD published in the eight hours to 22:01Z
#    on 2026-10-16 that carried both 3.1 and 4.0, 34 put them in different bands.
#    3.0 is the same metric system as 3.1, so it comes before the switch to 4.0.
#    2.0 comes last: NVD stopped scoring new records in it in July 2022, and it has
#    no Critical rating.
#
# The band is never the metric's own `baseSeverity`. It comes from the chosen score
# through `band_for_score`, the ageing gate's table, because the workflow labels the
# issue from the number in the title and the gate ages it on that number. CVSS 2.0
# calls a 9.3 HIGH, and the gate would treat "CVSS 9.3" as critical.
_CVSS_KEYS: tuple[tuple[str, str], ...] = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)


def pick_cvss(metrics: object) -> dict | None:
    """The NVD metric a filed issue's score comes from, under the rules above.

    Args:
        metrics: The ``metrics`` object of an NVD API 2.0 CVE record.

    Returns:
        ``{"score", "version", "source", "type"}`` for the chosen metric, or None
        when the record carries no usable CVSS score. A metric whose base score is
        missing, not a number, or outside 0.0-10.0 is skipped, so a malformed entry
        falls through to the next candidate instead of costing the record its score.
    """
    if not isinstance(metrics, dict):
        return None
    for want_primary in (True, False):
        for key, key_version in _CVSS_KEYS:
            entries = metrics.get(key)
            if not isinstance(entries, list):
                continue
            for metric in entries:
                if not isinstance(metric, dict):
                    continue
                if (metric.get("type") == "Primary") is not want_primary:
                    continue
                data = metric.get("cvssData")
                if not isinstance(data, dict):
                    continue
                score = data.get("baseScore")
                if isinstance(score, bool) or not isinstance(score, (int, float)):
                    continue
                if not 0.0 <= score <= 10.0:  # NaN fails this too
                    continue
                return {
                    "score": float(score),
                    "version": str(data.get("version") or key_version),
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                }
    return None


def _extract(vuln: dict) -> dict:
    cve = vuln.get("cve") or {}
    picked = pick_cvss(cve.get("metrics") or {})
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "cvss": picked["score"] if picked else None,
        # The band of that score, as the ageing gate will read it from the title.
        "severity": band_for_score(picked["score"]).upper() if picked else None,
        # Which metric the score came from; the workflow names it in the body.
        "cvss_version": picked["version"] if picked else None,
        "cvss_source": picked["source"] if picked else None,
        "cvss_type": picked["type"] if picked else None,
        "description": desc,
    }


# ---------------------------------------------------------------------------
# The OSV source (2026-10-28).
#
# NVD's keyword feed finds a record only when its text says MCP, LangChain or
# the like. A flaw in a package AAK already pins, described without those words,
# and a malicious release of one (an OSV `MAL-` record never reaches NVD) passed
# it by. So the watcher also asks OSV, by package, about every name the pin
# tables name, and files what was published inside the same seven-day window.
#
# The names are read from the scanner sources with `ast`, not by importing the
# scanners: this job installs nothing, and the scanners import PyYAML. Read:
#
# - `_Pin(...)` rows (mcp_cve_pins_2026_07 and its users): the names tuple, and
#   the `ecosystem` keyword ("py" PyPI, "js" npm, None both);
# - `DependencyPin(...)` constants (langchain_vuln, neo4j_cve, dns_rebind,
#   ssrf_redirect, ssrf_toctou, transport_limits): the same;
# - `_JvmPin(...)` rows: Maven `group:artifact`;
# - supply_chain's older `_affected_pin(...)` floors, whose names carry no
#   registry, through `_LEGACY_REGISTRY` (checked on pypi.org and the npm
#   registry on 2026-10-28), plus `_LEGACY_EXTRA`, the floors that match by
#   pattern rather than through `_affected_pin`.
#
# Container image pins name images, and OSV has no image ecosystem, so an
# image-only platform stays with the NVD source; the ones that also ship a
# package (n8n-mcp, mcp-atlassian, ContextForge) are read through their `_Pin`.
# A project pinned only by its git repository (`_RepoPin`, agent-zero, DocsGPT)
# is not queried either.
# ---------------------------------------------------------------------------

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNERS = REPO_ROOT / "agent_audit_kit" / "scanners"
_OSV_BATCH = 500
_OSV_MAX_PAGES = 20
_ECOSYSTEMS = {"py": ("PyPI",), "js": ("npm",), None: ("PyPI", "npm")}
_LEGACY_REGISTRY = {
    "apache-doris-mcp-server": "PyPI",
    "mcp-gateway-registry": "PyPI",
    "serena-agent": "PyPI",
    "serena-mcp-server": "PyPI",
    "excel-mcp-server": "PyPI",
    "litellm": "PyPI",
}
_LEGACY_EXTRA = (
    ("npm", "astro-mcp-server"),
    ("npm", "chatgpt-mcp-server"),
    ("npm", "@anthropic-ai/claude-code"),
    ("PyPI", "gpt-researcher"),
    ("PyPI", "semantic-kernel"),
    ("PyPI", "mcp-calculate-server"),
)


def _call_name(node: ast.Call) -> str:
    func = node.func
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""


def _literal(node: ast.AST | None, constants: dict[str, object]) -> object:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return None


def _argument(node: ast.Call, index: int, keyword: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == keyword:
            return kw.value
    return node.args[index] if len(node.args) > index else None


def _names(value: object) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, (tuple, list)) else ()


def _scanner_calls(scanners: Path) -> Iterator[tuple[Path, dict[str, object], ast.Call]]:
    """Every call in the scanner sources, with its module's literal constants."""
    for path in sorted(scanners.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        constants: dict[str, object] = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                value = _literal(stmt.value, constants)
                if isinstance(value, (str, tuple)):
                    constants[stmt.targets[0].id] = value
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield path, constants, node


def pinned_packages(scanners: Path = SCANNERS) -> list[tuple[str, str]]:
    """(OSV ecosystem, package name) for every package a pin table names, sorted."""
    found: set[tuple[str, str]] = set()
    for path, constants, node in _scanner_calls(scanners):
        kind = _call_name(node)
        if kind in ("_Pin", "DependencyPin"):
            names = _names(_literal(_argument(node, 2 if kind == "_Pin" else 0, "names"), constants))
            ecosystem = _literal(_argument(node, 7 if kind == "_Pin" else 2, "ecosystem"), constants)
            for registry in _ECOSYSTEMS.get(ecosystem if isinstance(ecosystem, str) else None, ()):
                found.update((registry, n) for n in names)
        elif kind == "_JvmPin":
            artifacts = _names(_literal(_argument(node, 1, "artifacts"), constants))
            group = _literal(_argument(node, 4, "group"), constants) or constants.get("_GROUP")
            if isinstance(group, str):
                found.update(("Maven", f"{group}:{a}") for a in artifacts)
        elif kind == "_affected_pin" and path.name == "supply_chain.py":
            for n in _names(_literal(_argument(node, 2, "names"), constants)):
                registry = _LEGACY_REGISTRY.get(n)
                found.update((r, n) for r in ((registry,) if registry else ("PyPI", "npm")))
    found.update(_LEGACY_EXTRA)
    return sorted(n for n in found if n[1])


def _osv_json(url: str, payload: dict | None = None, timeout: int = 60) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": "agent-audit-kit cve-watcher", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _osv_ids(packages: list[tuple[str, str]], since: datetime, http=_osv_json) -> dict[str, tuple[str, str]]:
    """OSV id -> (ecosystem, package) for every record of the packages modified
    since `since` (a record published since then was modified since then too)."""
    out: dict[str, tuple[str, str]] = {}
    for start in range(0, len(packages), _OSV_BATCH):
        chunk = packages[start:start + _OSV_BATCH]
        pending = [(i, None) for i in range(len(chunk))]
        for _ in range(_OSV_MAX_PAGES):
            if not pending:
                break
            queries = []
            for i, token in pending:
                query: dict = {"package": {"ecosystem": chunk[i][0], "name": chunk[i][1]}}
                if token:
                    query["page_token"] = token
                queries.append(query)
            results = http(OSV_QUERYBATCH, {"queries": queries}).get("results") or []
            following = []
            for (i, _token), result in zip(pending, results):
                for vuln in (result or {}).get("vulns") or ():
                    if _when(vuln.get("modified")) >= since and vuln.get("id"):
                        out.setdefault(vuln["id"], chunk[i])
                if (result or {}).get("next_page_token"):
                    following.append((i, result["next_page_token"]))
            pending = following
    return out


def _when(stamp: object) -> datetime:
    """An OSV or NVD timestamp as an aware datetime; the epoch when unreadable."""
    if not isinstance(stamp, str):
        return datetime.fromtimestamp(0, timezone.utc)
    text = stamp.strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # OSV writes nanoseconds
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.fromtimestamp(0, timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _nvd_score(cve_id: str) -> dict | None:
    """NVD's metric for one CVE, as `pick_cvss` picks it; None when NVD has none yet."""
    url = f"{NVD_SEARCH}?{urllib.parse.urlencode({'cveId': cve_id})}"
    req = urllib.request.Request(url, headers={"User-Agent": "agent-audit-kit cve-watcher"})
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"cve-watcher: NVD score for {cve_id} unavailable ({exc})\n")
        return None
    vulns = data.get("vulnerabilities") or []
    return pick_cvss(((vulns[0] or {}).get("cve") or {}).get("metrics")) if vulns else None


def _github_token() -> str | None:
    """GITHUB_TOKEN, which the workflow sets for this step; None outside it."""
    return os.environ.get("GITHUB_TOKEN") or None


def _ghsa_score(ghsa_id: str) -> dict | None:
    """GitHub's score for an advisory that has no CVE yet, CVSS 3 before CVSS 4 as
    `pick_cvss` orders NVD's; None without a token or a score.

    GitHub reports a metric it does not have as score 0 with no vector, so a metric
    counts only with its vector, and the vector names its version (3.0 or 3.1).
    """
    token = _github_token()
    if not token:
        return None
    req = urllib.request.Request(
        f"https://api.github.com/advisories/{ghsa_id}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "User-Agent": "agent-audit-kit cve-watcher"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"cve-watcher: GitHub score for {ghsa_id} unavailable ({exc})\n")
        return None
    severities = data.get("cvss_severities") or {}
    for key in ("cvss_v3", "cvss_v4"):
        metric = severities.get(key) or {}
        score, vector = metric.get("score"), metric.get("vector_string")
        version = re.match(r"CVSS:(\d\.\d)/", vector) if isinstance(vector, str) else None
        if version and isinstance(score, (int, float)) and not isinstance(score, bool) and 0.0 <= score <= 10.0:
            return {"score": float(score), "version": version.group(1), "source": "GitHub advisory database",
                    "type": "Secondary"}
    return None


def osv_entry(record: dict, package: tuple[str, str], scorer=_nvd_score, ghsa_scorer=_ghsa_score) -> dict:
    """A watcher record for one OSV record, in the shape `_extract` gives an NVD one.

    It is filed under its CVE alias when it has one, so the ledger, the ageing gate
    and NVD's own record of it all name it alike, and under its OSV id otherwise.
    """
    osv_id = str(record.get("id"))
    aliases = [a for a in record.get("aliases") or () if isinstance(a, str)]
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    ghsa = next((i for i in (osv_id, *aliases) if i.startswith("GHSA-")), None)
    picked = scorer(cve) if cve else ghsa_scorer(ghsa) if ghsa else None
    summary = str(record.get("summary") or "").strip()
    details = str(record.get("details") or "").strip()
    text = summary + ("\n\n" if summary and details else "") + details
    return {
        "id": cve or osv_id,
        "published": record.get("published"),
        "cvss": picked["score"] if picked else None,
        "severity": band_for_score(picked["score"]).upper() if picked else None,
        "cvss_version": picked["version"] if picked else None,
        "cvss_source": picked["source"] if picked else None,
        "cvss_type": picked["type"] if picked else None,
        "description": text[:4000],
        "source": (
            f"OSV {osv_id} ({package[0]} `{package[1]}`, a package AAK's pin tables name); "
            f"aliases: {', '.join(aliases) or 'none'}"
        ),
        "url": f"https://osv.dev/vulnerability/{osv_id}",
        "aliases": sorted({osv_id, *aliases} - {cve or osv_id}),
    }


def osv_records(
    suppressed: set[str],
    *,
    packages: list[tuple[str, str]] | None = None,
    window_hours: int = 168,
    http=_osv_json,
    scorer=_nvd_score,
    ghsa_scorer=_ghsa_score,
    now: datetime | None = None,
) -> list[dict]:
    """New OSV records for the pinned packages, published inside the window.

    A record is skipped when its id or any alias is already tracked, filed or in
    an issue (`suppressed`), or when it is withdrawn. An OSV failure costs this
    source, not the run: NVD's records are still filed.
    """
    since = (now or datetime.now(timezone.utc)) - timedelta(hours=window_hours)
    try:
        ids = _osv_ids(packages if packages is not None else pinned_packages(), since, http)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"cve-watcher: OSV query failed ({exc}); NVD only this run\n")
        return []
    out: list[dict] = []
    for osv_id, package in sorted(ids.items()):
        if osv_id in suppressed:
            continue
        try:
            record = http(OSV_VULN.format(osv_id))
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"cve-watcher: OSV record {osv_id} unavailable ({exc})\n")
            continue
        if record.get("withdrawn") or _when(record.get("published")) < since:
            continue
        if {osv_id, *(record.get("aliases") or ())} & suppressed:
            continue
        out.append(osv_entry(record, package, scorer, ghsa_scorer))
    return out


# ---------------------------------------------------------------------------
# The NVD package source (2026-10-30).
#
# IBM's Langflow OSS CVEs of 28 and 29 Oct 2026 reached neither source above.
# Their text names neither MCP nor LangChain, so `is_relevant` dropped them, and
# OSV had no package record of them, so OSV had nothing to return. NVD's record
# of each carried IBM's own affected range, 1.0.0 through 1.12.8, past the
# langflow pin's 1.12.0 floor: AAK reported nothing for langflow 1.12.0 to
# 1.12.8, and nothing told anyone.
#
# So the watcher also reads every NVD record published in the window and keeps
# the ones whose CNA data names an npm or PyPI package the pin tables carry,
# mapped as `aak update` maps it (`agent_audit_kit.nvd_feed`: the CNA's
# packageURL, else a row of the reviewed data/cna_package_map.json, never a name
# alone). The text filter does not apply: the pinned package is the relevance.
# When the CNA's range admits a release at or above the floor of a `_Pin` row
# naming the package that none of those rows reports (their `introduced` bounds
# and `also` ranges counted, as `_fires` counts them), the issue is titled "pin
# floor stale: <rule id>, <CVE> (...)", and its body names that floor, the
# range's upper bound and the fixed release the record names. It is still a
# `cve-response` issue, so it holds the release like any other. A record the
# keyword feed or OSV found too is filed once, under the stale title when it
# has one.
#
# The `_Pin` rows are read with `ast`, as `pinned_packages` reads their names.
# Versions compare on release triples, as the pin table compares them
# (`scanners._versions`).
# ---------------------------------------------------------------------------

_PIN_REGISTRY = {"py": "PyPI", "js": "npm"}


def _triple(value: object) -> tuple[int, int, int] | None:
    if (isinstance(value, tuple) and len(value) == 3
            and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in value)):
        return value[0], value[1], value[2]
    return None


class PinRow(NamedTuple):
    """One `_Pin(...)` row of the pin table, as its source declares it. (A
    NamedTuple, not a dataclass: the tests load this script by path, without
    registering it as a module, which a dataclass needs.)"""

    rule_id: str
    names: tuple[str, ...]
    floor: tuple[int, int, int] | None     # None: presence-only, every release reported
    introduced: tuple[int, int, int] | None
    also: tuple[Span, ...]
    ecosystem: str | None                   # "py", "js", or None for both registries
    fix_label: str

    def names_package(self, registry: str, name: str) -> bool:
        if self.ecosystem is not None and _PIN_REGISTRY.get(self.ecosystem) != registry:
            return False
        key = canonical_name(registry, name)
        return any(canonical_name(registry, n) == key for n in self.names)

    def reports(self) -> Spans:
        """The releases this row reports (`_fires`, for a stated version)."""
        low = self.introduced or ZERO
        high = TOP if self.floor is None else self.floor
        return union(([(low, high)] if low < high else []) + list(self.also))


def pin_rows(scanners: Path = SCANNERS) -> list[PinRow]:
    """Every `_Pin(...)` row whose rule id, names and floor are literals.

    A floor written `None` is a presence-only pin; a floor that is not a literal
    triple cannot be compared, so its row is left out.
    """
    rows: list[PinRow] = []
    for _path, constants, node in _scanner_calls(scanners):
        if _call_name(node) != "_Pin":
            continue
        rule_id = _literal(_argument(node, 0, "rule_id"), constants)
        names = _names(_literal(_argument(node, 2, "names"), constants))
        floor_node = _argument(node, 3, "floor")
        presence_only = isinstance(floor_node, ast.Constant) and floor_node.value is None
        floor = None if presence_only else _triple(_literal(floor_node, constants))
        if not isinstance(rule_id, str) or not rule_id or not names or (floor is None and not presence_only):
            continue
        also_value = _literal(_argument(node, 8, "also"), constants)
        also: list[Span] = []
        for span in also_value if isinstance(also_value, tuple) else ():
            low, high = (_triple(span[0]), _triple(span[1])) if isinstance(span, tuple) and len(span) == 2 else (None, None)
            if low is not None and high is not None and low < high:
                also.append((low, high))
        ecosystem = _literal(_argument(node, 7, "ecosystem"), constants)
        fix_label = _literal(_argument(node, 5, "fix_label"), constants)
        rows.append(PinRow(
            rule_id=rule_id,
            names=names,
            floor=floor,
            introduced=_triple(_literal(_argument(node, 4, "introduced"), constants)),
            also=tuple(also),
            ecosystem=ecosystem if ecosystem in _PIN_REGISTRY else None,
            fix_label=fix_label if isinstance(fix_label, str) else "",
        ))
    return rows


def _dotted(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def _range_text(row: dict) -> str:
    """One CNA range as the ledger words one: "1.0.0 through 1.12.8", "7.2.0 up to 11.0.0"."""
    start = "the first release" if row.get("introduced") == "0" else str(row.get("introduced"))
    if row.get("last_affected"):
        return f"{start} through {row['last_affected']}"
    if row.get("fixed"):
        return f"{start} up to {row['fixed']}"
    return f"{start} onward, with no end"


def stale_pin(entry: dict, pins: list[PinRow]) -> tuple[PinRow, str] | None:
    """(the pin to raise, the note the issue body carries) when the CNA range of one
    package admits a release at or above a pin's floor that no pin naming the
    package reports; None when the pins report every release it admits, or none
    of them has a floor.

    The pin named is the one with the highest floor at or below the lowest such
    release: the floor the range runs past.
    """
    named = [pin for pin in pins if pin.names_package(entry["ecosystem"], entry["name"])]
    floors = [pin.floor for pin in named if pin.floor is not None]
    if not floors:
        return None
    affected = interval_spans(
        ((r.get("introduced"), r.get("fixed"), r.get("last_affected")) for r in entry.get("ranges") or ()),
        entry.get("versions") or (),
    )
    reported = union([span for pin in named for span in pin.reports()])
    missed = intersect(subtract(affected, reported), ((min(floors), TOP),))
    if not missed:
        return None
    lowest = missed[0][0]
    pin = max((p for p in named if p.floor is not None and p.floor <= lowest), key=lambda p: (p.floor, p.rule_id))
    assert pin.floor is not None
    fixed = ", ".join(entry.get("fixed") or ()) or "none named in the record"
    note = (
        f"`{pin.rule_id}` reports {entry['ecosystem']} `{entry['name']}` "
        + (f"from {_dotted(pin.introduced)} " if pin.introduced else "")
        + f"below {_dotted(pin.floor)}, its floor. This record's affected range, as its CNA wrote it: "
        + "; ".join(_range_text(r) for r in entry.get("ranges") or ()) + f". Fixed release: {fixed}. "
        + f"AAK reports no release of it from {_dotted(lowest)} up to the range's end: raise the floor "
          "to the release the vendor names as fixed, or add a pin."
    )
    return pin, note


def nvd_package_records(
    suppressed: set[str],
    *,
    packages: list[tuple[str, str]] | None = None,
    pins: list[PinRow] | None = None,
    rows: Iterable[nvd_feed.MapRow] | None = None,
    window_hours: int = 168,
    pages: Callable[[dict[str, str]], Iterable[dict]] | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """NVD records published inside the window whose CNA data names a pinned package.

    A record already tracked, filed or in an issue (`suppressed`) is skipped, and
    so is a rejected one. An NVD failure costs this source, not the run.

    Args:
        suppressed: Ids not to file again.
        packages: (registry, name) pairs; `pinned_packages()` by default.
        pins: The `_Pin` rows; `pin_rows()` by default.
        rows: The reviewed map; `nvd_feed.load_package_map()` by default.
        window_hours: How far back `pubStartDate` reaches.
        pages: Reads one NVD query page by page; `nvd_feed.iter_pages` by default.
        now: The end of the window (tests pin it).
    """
    end = now or datetime.now(timezone.utc)
    query = {"pubStartDate": nvd_feed.stamp(end - timedelta(hours=window_hours)), "pubEndDate": nvd_feed.stamp(end)}
    read = pages or (lambda params: nvd_feed.iter_pages(params, api_key=os.environ.get("NVD_API_KEY") or None))
    pinned = {(registry, canonical_name(registry, name))
              for registry, name in (packages if packages is not None else pinned_packages())
              if registry in ("PyPI", "npm")}
    pin_list = pins if pins is not None else pin_rows()
    map_rows = nvd_feed.load_package_map() if rows is None else tuple(rows)
    out: list[dict] = []
    try:
        for page in read(query):
            for vuln in page.get("vulnerabilities") or ():
                cve = vuln.get("cve") if isinstance(vuln, dict) else None
                ident = cve.get("id") if isinstance(cve, dict) else None
                if not isinstance(ident, str) or not ident.startswith("CVE-") or ident in suppressed:
                    continue
                named = [p for p in nvd_feed.record_packages(vuln, map_rows)
                         if (p[0], canonical_name(p[0], p[1])) in pinned]
                if named:
                    out.append(_package_entry(vuln, ident, named, map_rows, pin_list))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"cve-watcher: NVD package read failed ({exc}); this source files nothing this run\n")
        return []
    return out


def _package_entry(vuln: dict, ident: str, named: list[tuple[str, str, str]],
                   map_rows: tuple, pins: list[PinRow]) -> dict:
    """A watcher record for one NVD record naming a pinned package."""
    entry = _extract(vuln)
    cna = str(vuln["cve"].get("sourceIdentifier") or "an unnamed CNA")
    keys = {(registry, canonical_name(registry, name)) for registry, name, _ in named}
    read = [e for e in nvd_feed.record_entries(vuln, map_rows)
            if (e["ecosystem"], canonical_name(e["ecosystem"], e["name"])) in keys]
    entry.update(
        source=(f"NVD CNA record from {cna} naming "
                + ", ".join(f"{registry} `{name}` (by its {'packageURL' if how == 'packageURL' else 'reviewed map row'})"
                            for registry, name, how in named)
                + ", a package AAK's pin tables name"),
        url=f"https://nvd.nist.gov/vuln/detail/{ident}",
        aliases=[],
    )
    if len(read) < len(named):
        unread = sorted({name for _, name, _ in named} - {e["name"] for e in read})
        entry["source"] += f"; its versions for {', '.join(unread)} could not be read"
    for package in read:
        found = stale_pin(package, pins)
        if found is None:
            continue
        pin, note = found
        score = f"{entry['cvss']:g}" if entry.get("cvss") is not None else "n/a"
        entry["title"] = f"pin floor stale: {pin.rule_id}, {ident} ({entry.get('severity') or 'unknown'} CVSS {score})"
        entry["pin_note"] = note
        break
    return entry


def collect_new_cves(
    *,
    changelog_path: Path = CHANGELOG_PATH,
    state_path: Path = STATE_PATH,
    github_token: str | None = None,
    owner_repo: str | None = None,
    fetcher=_fetch,
    osv_source=None,
    nvd_source=None,
) -> tuple[list[dict], dict]:
    """Pure function that collects new CVEs with layered dedup.

    Returns ``(new_cve_entries, updated_state)``. The caller is responsible
    for persisting the updated state file (so dry-run tests stay clean).
    ``osv_source`` (``osv_records`` in ``main``) adds the OSV records for the
    pinned packages, and ``nvd_source`` (``nvd_package_records``) the NVD records
    whose CNA data names one; without them only the keyword feed is read, as
    before.
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

    if osv_source is not None:
        for entry in osv_source(suppressed | seen):
            ids = {entry["id"], *entry.get("aliases", ())}
            if ids & (suppressed | seen):
                continue
            seen.update(ids)
            results.append(entry)

    if nvd_source is not None:
        by_id = {e["id"]: e for e in results}
        for entry in nvd_source(suppressed):
            if entry["id"] in suppressed:
                continue
            if entry["id"] in by_id:
                # The keyword feed or OSV found it too: one issue, under the stale
                # title when the pins fall short of the CNA's range.
                if entry.get("title"):
                    by_id[entry["id"]].update(title=entry["title"], pin_note=entry["pin_note"])
                continue
            # A keyword hit whose text named nothing is in `seen` but was not
            # filed; naming a pinned package is relevance enough.
            seen.add(entry["id"])
            by_id[entry["id"]] = entry
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
        state["filed_cves"] = sorted(filed | {i for e in results for i in (e["id"], *e.get("aliases", ()))})
    return results, state


def main() -> int:
    state_path = Path(os.environ.get("AAK_CVE_WATCHER_STATE", str(STATE_PATH)))
    token = os.environ.get("GITHUB_TOKEN")
    owner_repo = os.environ.get("GITHUB_REPOSITORY")
    results, state = collect_new_cves(
        state_path=state_path,
        github_token=token,
        owner_repo=owner_repo,
        osv_source=osv_records,
        nvd_source=nvd_package_records,
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
