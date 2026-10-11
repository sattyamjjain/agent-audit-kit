"""Deterministic retrieval: NVD, the GitHub advisory, and OSV, cached on disk.

No model is involved anywhere in this module. Given a CVE id (or a
`cve-response` issue number, resolved to its CVE from the issue title), it
fetches three public records and hands them to `context.build_context`:

* **NVD API 2.0**, `cves/2.0?cveId=...`, without an API key. The public limit is
  5 requests in any rolling 30 seconds, enforced by `SlidingWindowLimiter`
  before every NVD request (retries included), with backoff on 403/429/5xx,
  which is how NVD signals throttling.
* **The GitHub advisory**, through `gh api` REST only: `/advisories?cve_id=...`
  for the global database, plus `/repos/O/R/security-advisories/GHSA-...` for a
  repository advisory NVD cites but the global database does not carry yet
  (Obot's GHSA-q5wf-87f5-cxgq was in that state on 2026-10-12). Never GraphQL:
  a Claude Code routine's GitHub proxy blocks it, and the nightly job this feeds
  must run there.
* **OSV**, `api.osv.dev/v1/vulns/<id>`, for the CVE's own record and for every
  GHSA / PYSEC id the other sources name. OSV is where the structured
  ECOSYSTEM ranges live.

Everything is cached under `cache_dir()` (outside the repository, like the
instruction-file benchmark's corpus) as `{"status": ..., "data": ...}`, so a
404 is remembered too and a re-run is offline. Downloaded text is data: it is
parsed as JSON and never executed or interpreted as instructions.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from benchmarks.cve_prescreen.context import build_context

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API = "https://api.osv.dev/v1/vulns/"
DEFAULT_REPO = "sattyamjjain/agent-audit-kit"
USER_AGENT = "agent-audit-kit-cve-prescreen (+https://github.com/sattyamjjain/agent-audit-kit)"

#: NVD's documented public rate limit without an API key.
NVD_MAX_REQUESTS = 5
NVD_WINDOW_SECONDS = 30.0
#: Slack added to every computed wait, because NVD's window and ours are
#: measured on different clocks.
NVD_MARGIN_SECONDS = 1.0
#: NVD answers a throttled client with 403 as well as 429, so 403 is retried
#: there. GitHub's 403 can be a permanent refusal, so it is not retried.
NVD_RETRY_STATUSES = frozenset({0, 403, 429, 500, 502, 503, 504})
OTHER_RETRY_STATUSES = frozenset({0, 429, 500, 502, 503, 504})
RETRY_DELAYS = (6.0, 15.0, 30.0)
MAX_OSV_RECORDS = 6

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_CVE_EXACT = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_GHSA_ID = re.compile(r"^GHSA(?:-[0-9a-z]{4}){3}$")
_OSV_ALIAS = re.compile(r"^(?:GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d{1,7})$")
#: `https://github.com/<owner>/<repo>/security/advisories/<GHSA>`, anchored.
_REPO_ADVISORY_URL = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})"
    r"/security/advisories/(GHSA(?:-[0-9a-z]{4}){3})/?$"
)

Fetched = tuple[int, Any]
HttpGet = Callable[[str], Fetched]
GhApi = Callable[[str], Fetched]


def cache_dir() -> Path:
    """Where raw responses live: outside the repo, so no scan or `git add` sees them."""
    override = os.environ.get("AAK_CVE_PRESCREEN_CACHE")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "agent-audit-kit" / "cve-prescreen"


class SlidingWindowLimiter:
    """At most `max_calls` in any rolling `window` seconds.

    Injectable clock and sleep so the limit itself is unit-tested, offline,
    rather than trusted.
    """

    def __init__(
        self,
        max_calls: int = NVD_MAX_REQUESTS,
        window: float = NVD_WINDOW_SECONDS,
        margin: float = NVD_MARGIN_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.max_calls = max_calls
        self.window = window
        self.margin = margin
        self._clock = clock
        self._sleep = sleep
        self._stamps: deque[float] = deque()

    def _prune(self, now: float) -> None:
        while self._stamps and now - self._stamps[0] >= self.window:
            self._stamps.popleft()

    def acquire(self) -> float:
        """Block until a call is allowed; return the seconds waited."""
        now = self._clock()
        self._prune(now)
        waited = 0.0
        if len(self._stamps) >= self.max_calls:
            delay = self.window - (now - self._stamps[0]) + self.margin
            if delay > 0:
                self._sleep(delay)
                waited = delay
            now = self._clock()
            self._prune(now)
        self._stamps.append(now)
        return waited


def http_get_json(url: str, timeout: float = 30.0) -> Fetched:
    """`(status, parsed JSON or None)`. A transport failure is status 0."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return int(resp.status), json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        return int(exc.code), None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def gh_api_json(api_path: str, timeout: float = 60.0) -> Fetched:
    """`gh api <path>` (REST, GET). 404 is reported as 404, not as an error."""
    try:
        proc = subprocess.run(
            ["gh", "api", api_path],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0, None
    if proc.returncode == 0:
        try:
            return 200, json.loads(proc.stdout) if proc.stdout.strip() else None
        except ValueError:
            return 0, None
    match = re.search(r"HTTP (\d{3})", proc.stderr or "")
    return (int(match.group(1)) if match else 0), None


class DiskCache:
    """One JSON file per answer, `{cache dir}/{kind}/{key}.json`.

    Each holds `{"status", "fetched_at", "data"}`.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, kind: str, key: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", key)[:180]
        return self.root / kind / f"{safe}.json"

    def get(self, kind: str, key: str) -> dict[str, Any] | None:
        path = self._path(kind, key)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return entry if isinstance(entry, dict) and "status" in entry else None

    def put(self, kind: str, key: str, status: int, data: Any) -> dict[str, Any]:
        entry = {
            "status": status,
            "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "data": data,
        }
        path = self._path(kind, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
        return entry


def _status_word(status: int) -> str:
    if status == 200:
        return "ok"
    if status == 404:
        return "not-found"
    if status == -1:
        return "not-cached"  # offline, and the cache holds no answer
    return f"error-{status}" if status else "error-transport"


@dataclass
class RawBundle:
    """The raw responses for one CVE, before compaction."""

    cve_id: str
    nvd: dict[str, Any] | None = None
    ghsa_global: list[dict[str, Any]] = field(default_factory=list)
    ghsa_repository: list[dict[str, Any]] = field(default_factory=list)
    osv: list[dict[str, Any]] = field(default_factory=list)
    status: dict[str, str] = field(default_factory=dict)

    def context(self) -> dict[str, Any]:
        return build_context(
            self.cve_id, self.nvd, self.ghsa_global, self.ghsa_repository, self.osv, self.status
        )


class Retriever:
    """Fetch-or-cache for the three sources. Network callables are injectable."""

    def __init__(
        self,
        cache: DiskCache,
        http_get: HttpGet = http_get_json,
        gh_api: GhApi = gh_api_json,
        limiter: SlidingWindowLimiter | None = None,
        sleep: Callable[[float], None] = time.sleep,
        refresh: bool = False,
        offline: bool = False,
    ) -> None:
        self.cache = cache
        self.http_get = http_get
        self.gh_api = gh_api
        self.limiter = limiter or SlidingWindowLimiter()
        self.sleep = sleep
        self.refresh = refresh
        self.offline = offline
        self.network_calls = 0

    def _cached_or(self, kind: str, key: str, fetch: Callable[[], Fetched]) -> dict[str, Any]:
        if not self.refresh:
            hit = self.cache.get(kind, key)
            # A transport error is never cached as an answer; retry it next run.
            if hit is not None and hit["status"] in (200, 404):
                return hit
        if self.offline:
            return {"status": -1, "data": None}
        status, data = fetch()
        self.network_calls += 1
        if status in (200, 404):
            return self.cache.put(kind, key, status, data)
        return {"status": status, "data": None}

    def _with_retries(self, call: Callable[[], Fetched], nvd: bool) -> Fetched:
        """Retry throttling and transport failures; every NVD attempt is rate limited."""
        retry_on = NVD_RETRY_STATUSES if nvd else OTHER_RETRY_STATUSES
        status, data = 0, None
        for attempt in range(len(RETRY_DELAYS) + 1):
            if nvd:
                self.limiter.acquire()
            status, data = call()
            if status not in retry_on:
                return status, data
            if attempt < len(RETRY_DELAYS):
                self.sleep(RETRY_DELAYS[attempt])
        return status, data

    def nvd(self, cve_id: str) -> dict[str, Any]:
        url = f"{NVD_API}?{urllib.parse.urlencode({'cveId': cve_id})}"
        entry = self._cached_or("nvd", cve_id, lambda: self._with_retries(lambda: self.http_get(url), True))
        data = entry.get("data")
        # NVD answers 200 with zero results for an id it does not hold.
        if entry["status"] == 200 and isinstance(data, dict) and not data.get("vulnerabilities"):
            return {"status": 404, "data": None}
        return entry

    def ghsa_global(self, cve_id: str) -> dict[str, Any]:
        path = f"/advisories?{urllib.parse.urlencode({'cve_id': cve_id})}"
        return self._cached_or("ghsa", cve_id, lambda: self._with_retries(lambda: self.gh_api(path), False))

    def ghsa_repository(self, owner: str, repo: str, ghsa_id: str) -> dict[str, Any]:
        path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
        key = f"{owner}__{repo}__{ghsa_id}"
        return self._cached_or("ghsa-repo", key, lambda: self._with_retries(lambda: self.gh_api(path), False))

    def osv(self, vuln_id: str) -> dict[str, Any]:
        url = OSV_API + urllib.parse.quote(vuln_id)
        return self._cached_or("osv", vuln_id, lambda: self._with_retries(lambda: self.http_get(url), False))

    def bundle(self, cve_id: str) -> RawBundle:
        if not _CVE_EXACT.match(cve_id):
            raise ValueError(f"not a CVE id: {cve_id!r}")
        out = RawBundle(cve_id)

        nvd = self.nvd(cve_id)
        out.status["nvd"] = _status_word(nvd["status"])
        out.nvd = nvd.get("data") if nvd["status"] == 200 else None

        ghsa = self.ghsa_global(cve_id)
        out.status["ghsa"] = _status_word(ghsa["status"])
        if ghsa["status"] == 200 and isinstance(ghsa.get("data"), list):
            out.ghsa_global = [a for a in ghsa["data"] if isinstance(a, dict)]
            if not out.ghsa_global:
                out.status["ghsa"] = "none"

        known = {a.get("ghsa_id") for a in out.ghsa_global}
        repo_refs = []
        for ref in ((out.nvd or {}).get("vulnerabilities") or [{}])[0].get("cve", {}).get("references") or []:
            match = _REPO_ADVISORY_URL.match(str(ref.get("url") or ""))
            if match and match.group(3) not in known:
                repo_refs.append(match.groups())
        repo_status = []
        for owner, repo, ghsa_id in sorted(set(repo_refs)):
            entry = self.ghsa_repository(owner, repo, ghsa_id)
            repo_status.append(_status_word(entry["status"]))
            if entry["status"] == 200 and isinstance(entry.get("data"), dict):
                out.ghsa_repository.append(entry["data"])
        if repo_status:
            out.status["ghsa_repository"] = ",".join(repo_status)

        osv_ids = [cve_id]
        for adv in out.ghsa_global + out.ghsa_repository:
            gid = adv.get("ghsa_id")
            if isinstance(gid, str) and _GHSA_ID.match(gid):
                osv_ids.append(gid)
        osv_status = []
        fetched: dict[str, dict[str, Any]] = {}
        attempted: set[str] = set()
        queue = list(dict.fromkeys(osv_ids))
        while queue and len(attempted) < MAX_OSV_RECORDS:
            vid = queue.pop(0)
            if vid in attempted:
                continue
            attempted.add(vid)
            entry = self.osv(vid)
            osv_status.append(f"{vid}:{_status_word(entry['status'])}")
            if entry["status"] == 200 and isinstance(entry.get("data"), dict):
                record = entry["data"]
                fetched[vid] = record
                for alias in record.get("aliases") or []:
                    if isinstance(alias, str) and _OSV_ALIAS.match(alias) and alias not in attempted:
                        queue.append(alias)
        out.osv = list(fetched.values())
        out.status["osv"] = ";".join(osv_status) if osv_status else "none"
        return out


def cve_for_issue(number: int, repo: str = DEFAULT_REPO, gh_api: GhApi = gh_api_json) -> str:
    """The CVE a `cve-response` issue is about, read from its title (REST)."""
    status, data = gh_api(f"/repos/{repo}/issues/{int(number)}")
    if status != 200 or not isinstance(data, dict):
        raise LookupError(f"issue #{number}: HTTP {status}")
    found: list[str] = CVE_RE.findall(str(data.get("title") or ""))
    if len(set(found)) != 1:
        raise LookupError(f"issue #{number}: title names {len(set(found))} CVE ids")
    return found[0]
