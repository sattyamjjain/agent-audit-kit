"""Add the takeovers among GitHub's latest malware advisories to the bundled feed.

`agent_audit_kit/data/malicious_releases.json` is the malicious-release feed a
scan reads when `agent-audit-kit update` has not built a cached copy: every
fresh install, and every GitHub Action run that does not refresh the feeds. It
lists established packages that were taken over (litellm, axios,
@ethersphere/bee-js), not the typosquats the full OSV list from `update` carries.
On 2026-11-18 it was six days old and passed agent-framework 1.26.2, published
as malware that day. This script keeps it current, and
`.github/workflows/malicious-feed-bundle.yml` runs it every day:

1. GitHub's global advisories of type `malware` for pip, npm, rust and go
   published in the last `--days` days (default 3, so a day the job does not run
   is caught up), paged through the Link header, with `GITHUB_TOKEN` or
   `GH_TOKEN` when one is set.
2. For each package an advisory names, the registry's own release dates (PyPI's
   JSON upload times, npm's `time`, crates.io's `created_at`, the Go module
   proxy's `.info` times). A package is kept only when the registry shows a
   release published at least `ESTABLISHED_DAYS` (30) days before the advisory
   that the advisory does not list: the shape of a takeover. A package whose
   only releases are the malicious ones, or that the registry no longer serves,
   is a typosquat, left to the full list `update` builds.
3. For each kept package, the OSV `MAL-` record behind the advisory, found
   through `https://api.osv.dev/v1/query` by package and matched by alias: the
   record that lists the GHSA id among its aliases, or whose id the advisory's
   references name (OSV's malware records seldom alias the GHSA GitHub later
   derives from them). The entry is `malicious_feed.osv_entries` of the record
   as `https://api.osv.dev/v1/vulns/<id>` returns it, as `update` would read it,
   with the GHSA id added to its aliases. With no OSV record, the advisory itself
   is written (`malicious_feed.github_entries`): its GHSA id as `id`, its URL as
   `url`.

Existing entries are never dropped or changed. When an entry is added, the new
entries are appended, `generated_at` is set to the run's time, and a sentence
naming the date and the ids is appended to `source`. Every run that decided every
package (no lookup failed) and is not a dry run also sets `checked_at` to the
run's time, entry or not: `generated_at` alone stood still after quiet days, and
a scan read a bundled copy that had been checked that morning as stale.
`malicious_feed.feed_staleness` measures from the later of the two. Every other
byte of the file is kept.

Network: GitHub, the four registries and OSV, each through the opener the
caller passes (`refresh_bundled(opener=...)`), so the tests stub all of it.

Usage:
    python scripts/refresh_bundled_malicious.py [--days N] [--dry-run] [--feed PATH]

Exit status: 0 when every package was decided (whether or not the file
changed), 1 when a registry or OSV lookup failed for some package (the others
are still written), 2 when the advisory listing or the write failed (nothing
written).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple

# The checkout's own package: the workflow installs nothing, and the module read
# below imports only the standard library.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent_audit_kit.malicious_feed import (  # noqa: E402
    BUNDLED_FEED,
    canonical_name,
    github_entries,
    osv_entries,
    version_key,
    version_order,
)

Opener = Callable[..., Any]

#: How many days before the advisory a release must have been published to show
#: the package was established before it was taken over.
ESTABLISHED_DAYS = 30
DEFAULT_DAYS = 3

GITHUB_ADVISORIES = "https://api.github.com/advisories?type=malware&ecosystem={ecosystem}&published={published}&per_page=100"
#: GitHub's REST ecosystem names, and the registry each is in the feed.
GITHUB_ECOSYSTEMS = {"pip": "PyPI", "npm": "npm", "rust": "crates.io", "go": "Go"}
PYPI_JSON = "https://pypi.org/pypi/{name}/json"
NPM_DOCUMENT = "https://registry.npmjs.org/{name}"
CRATES_CRATE = "https://crates.io/api/v1/crates/{name}"
GO_LIST = "https://proxy.golang.org/{module}/@v/list"
GO_INFO = "https://proxy.golang.org/{module}/@v/{version}.info"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/{ident}"

_MAX_PAGES = 200  # GitHub listing pages per ecosystem; 3 days of npm is about 10
_MAX_OSV_PAGES = 10
_LINK_NEXT_RE = re.compile(r'<(https://api\.github\.com/[^>]+)>;\s*rel="next"')
_CLAUSE_RE = re.compile(r"^(>=|<=|>|<|=)\s*(\S+)$")
_MAL_ID_RE = re.compile(r"\bMAL-\d{4}-\d+\b")
_TIME_KEYS = frozenset({"created", "modified", "unpublished"})
_SECURITY_PLACEHOLDER_RE = re.compile(r"-security(?:\.\d+)?$")


class RefreshError(RuntimeError):
    """A failure that leaves the bundled feed as it was."""


class Decision(NamedTuple):
    """What the script decided about one package an advisory names."""

    ecosystem: str
    name: str
    advisory: str       # the GHSA id
    outcome: str        # "kept", "dropped", "skipped" or "error"
    reason: str
    entry: dict[str, Any] | None = None

    def line(self) -> str:
        return f"{self.outcome:<7} {self.ecosystem} {self.name} ({self.advisory}): {self.reason}"


class Outcome(NamedTuple):
    """What a run decided and wrote."""

    decisions: list[Decision]
    added: list[dict[str, Any]]
    written: bool          # entries were added and the file written
    checked: bool = False  # `checked_at` was set: every package was decided


# ---- HTTP -------------------------------------------------------------------------------


def _user_agent() -> str:
    from agent_audit_kit import __version__

    return f"agent-audit-kit/{__version__} (bundled malicious-release feed refresh)"


def _request(url: str, headers: dict[str, str] | None = None, body: bytes | None = None) -> urllib.request.Request:
    merged = {"User-Agent": _user_agent(), "Accept": "application/json", **(headers or {})}
    if body is not None:
        merged["Content-Type"] = "application/json"
    return urllib.request.Request(url, data=body, headers=merged, method="POST" if body is not None else "GET")


def _fetch(opener: Opener, request: urllib.request.Request, timeout: float) -> tuple[Any, str] | None:
    """(parsed JSON body, Link header) of one response; None for a 404 or 410,
    which a registry answers for a package it removed."""
    try:
        with opener(request, timeout=timeout) as response:
            body = response.read()
            link = (response.headers.get("Link", "") if response.headers is not None else "") or ""
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise
    return json.loads(body.decode("utf-8")) if body.strip() else None, link


def _fetch_text(opener: Opener, request: urllib.request.Request, timeout: float) -> str | None:
    try:
        with opener(request, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            return None
        raise


# ---- the advisories ---------------------------------------------------------------------


def list_advisories(opener: Opener, since: str, token: str | None, timeout: float = 60.0) -> list[dict[str, Any]]:
    """GitHub's malware advisories for the four ecosystems published on or after
    `since` (YYYY-MM-DD), oldest page last as GitHub returns them."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out: list[dict[str, Any]] = []
    for ecosystem in GITHUB_ECOSYSTEMS:
        url: str | None = GITHUB_ADVISORIES.format(ecosystem=ecosystem, published=urllib.parse.quote(f">={since}"))
        pages = 0
        while url:
            pages += 1
            if pages > _MAX_PAGES:
                raise RefreshError(f"GitHub advisories: more than {_MAX_PAGES} pages of {ecosystem}")
            fetched = _fetch(opener, _request(url, headers), timeout)
            if fetched is None or not isinstance(fetched[0], list):
                raise RefreshError(f"GitHub advisories: no list for {ecosystem} ({url})")
            out.extend(a for a in fetched[0] if isinstance(a, dict))
            found = _LINK_NEXT_RE.search(fetched[1])
            url = found.group(1) if found else None
    return out


def _published(advisory: dict[str, Any]) -> datetime | None:
    text = advisory.get("published_at")
    if not isinstance(text, str):
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def packages(advisory: dict[str, Any]) -> dict[tuple[str, str], list[str]]:
    """`{(feed ecosystem, package name): [vulnerable_version_range, ...]}` for one advisory."""
    out: dict[tuple[str, str], list[str]] = {}
    for vuln in advisory.get("vulnerabilities") or ():
        if not isinstance(vuln, dict) or not isinstance(vuln.get("package"), dict):
            continue
        ecosystem = GITHUB_ECOSYSTEMS.get(str(vuln["package"].get("ecosystem")))
        name = vuln["package"].get("name")
        spec = vuln.get("vulnerable_version_range")
        if ecosystem and isinstance(name, str) and name and isinstance(spec, str):
            out.setdefault((ecosystem, name), []).append(spec)
    return out


def listed(ecosystem: str, specs: Iterable[str], version: str) -> bool:
    """Does any of an advisory's `vulnerable_version_range`s list `version`?

    A clause that cannot be read, or a version that cannot be ordered against a
    bound, counts as listed: such a release cannot show the package was clean
    before, so it never keeps a package by itself.
    """
    key = version_key(ecosystem, version)
    order = version_order(ecosystem, version)
    for spec in specs:
        admitted = True
        for clause in (c.strip() for c in spec.split(",") if c.strip()):
            found = _CLAUSE_RE.match(clause)
            if found is None:
                return True
            op, bound = found.groups()
            if op == "=":
                admitted = admitted and version_key(ecosystem, bound) == key
                continue
            if op == ">=" and bound == "0":
                continue
            limit = version_order(ecosystem, bound)
            if limit is None or order is None:
                return True
            admitted = admitted and {">=": order >= limit, ">": order > limit,
                                     "<=": order <= limit, "<": order < limit}[op]
        if admitted:
            return True
    return False


# ---- the registries ---------------------------------------------------------------------


def _time(text: object) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        when = datetime.fromisoformat(re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6],
                                             text.strip().replace("Z", "+00:00"), count=1))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _go_escape(module: str) -> str:
    """A module path as the Go module proxy spells it (an upper-case letter is `!` and the letter)."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)


def release_times(opener: Opener, ecosystem: str, name: str, timeout: float = 60.0,
                  wanted: Callable[[str], bool] = lambda _v: True) -> dict[str, datetime] | None:
    """`{version: first upload time}` the registry shows for a package, or None
    when it does not serve the package. `wanted` filters versions before a
    per-version request (only the Go proxy makes one)."""
    if ecosystem == "PyPI":
        fetched = _fetch(opener, _request(PYPI_JSON.format(name=urllib.parse.quote(name, safe=""))), timeout)
        if fetched is None or not isinstance(fetched[0], dict):
            return None
        out: dict[str, datetime] = {}
        for version, files in (fetched[0].get("releases") or {}).items():
            times = [t for t in (_time(f.get("upload_time_iso_8601")) for f in files or () if isinstance(f, dict)) if t]
            if times:
                out[version] = min(times)
        return out
    if ecosystem == "npm":
        fetched = _fetch(opener, _request(NPM_DOCUMENT.format(name=urllib.parse.quote(name, safe="@"))), timeout)
        if fetched is None or not isinstance(fetched[0], dict):
            return None
        stamps = fetched[0].get("time") if isinstance(fetched[0].get("time"), dict) else {}
        return {v: t for v, t in ((v, _time(s)) for v, s in stamps.items() if v not in _TIME_KEYS) if t}
    if ecosystem == "crates.io":
        fetched = _fetch(opener, _request(CRATES_CRATE.format(name=urllib.parse.quote(name, safe=""))), timeout)
        if fetched is None or not isinstance(fetched[0], dict):
            return None
        rows = fetched[0].get("versions") or ()
        return {str(r["num"]): t for r in rows if isinstance(r, dict) and "num" in r
                for t in [_time(r.get("created_at"))] if t}
    if ecosystem == "Go":
        module = _go_escape(name)
        text = _fetch_text(opener, _request(GO_LIST.format(module=module), {"Accept": "text/plain"}), timeout)
        if text is None:
            return None
        out = {}
        for version in (v.strip() for v in text.splitlines() if v.strip()):
            if not wanted(version):
                continue
            info = _fetch(opener, _request(GO_INFO.format(module=module, version=version)), timeout)
            when = _time(info[0].get("Time")) if info and isinstance(info[0], dict) else None
            if when:
                out[version] = when
        return out
    return None


def established_release(times: dict[str, datetime], ecosystem: str, specs: list[str],
                        published: datetime) -> tuple[str, datetime] | None:
    """The oldest release in `times` the advisory does not list that was published
    at least `ESTABLISHED_DAYS` days before the advisory, or None. The
    placeholder npm publishes over a removed package (`0.0.1-security`, and
    `0.0.1-security.0`, `.1`, ... when it does so again) is never one."""
    cutoff = published - timedelta(days=ESTABLISHED_DAYS)
    clean = sorted((when, version) for version, when in times.items()
                   if when <= cutoff and not _SECURITY_PLACEHOLDER_RE.search(version)
                   and not listed(ecosystem, specs, version))
    return (clean[0][1], clean[0][0]) if clean else None


# ---- OSV --------------------------------------------------------------------------------


def osv_record(opener: Opener, ecosystem: str, name: str, ghsa: str, references: Iterable[str],
               timeout: float = 60.0) -> dict[str, Any] | None:
    """The OSV `MAL-` record behind a GitHub malware advisory, as
    `/v1/vulns/<id>` returns it, or None when OSV has none for the package."""
    named = set(_MAL_ID_RE.findall(" ".join(r for r in references if isinstance(r, str))))
    query: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
    match: str | None = None
    for _page in range(_MAX_OSV_PAGES):
        fetched = _fetch(opener, _request(OSV_QUERY, body=json.dumps(query).encode("utf-8")), timeout)
        page = fetched[0] if fetched and isinstance(fetched[0], dict) else {}
        for vuln in page.get("vulns") or ():
            ident = vuln.get("id") if isinstance(vuln, dict) else None
            if isinstance(ident, str) and ident.startswith("MAL-") and not vuln.get("withdrawn") and (
                    ghsa in (vuln.get("aliases") or ()) or ident in named):
                match = ident
                break
        token = page.get("next_page_token")
        if match or not token:
            break
        query["page_token"] = token
    if match is None:
        return None
    fetched = _fetch(opener, _request(OSV_VULN.format(ident=match)), timeout)
    return fetched[0] if fetched and isinstance(fetched[0], dict) else None


def entry_for(opener: Opener, ecosystem: str, name: str, advisory: dict[str, Any],
              timeout: float = 60.0) -> dict[str, Any] | None:
    """The feed entry for one kept package: from its OSV `MAL-` record, with the
    GHSA id among its aliases, else from the GitHub advisory itself."""
    ghsa = str(advisory.get("ghsa_id"))
    want = canonical_name(ecosystem, name)
    record = osv_record(opener, ecosystem, name, ghsa, advisory.get("references") or (), timeout)
    if record is not None:
        rows = [e for e in osv_entries(record, ecosystem) if canonical_name(ecosystem, e["name"]) == want]
        # A record that lists every version would report the clean releases this
        # package was kept for; the advisory's own versions are written instead.
        if rows and not rows[0].get("all_versions"):
            entry = rows[0]
            entry["aliases"] = sorted(set(entry["aliases"]) | {ghsa})
            return entry
    rows = [e for e in github_entries([advisory])
            if e["ecosystem"] == ecosystem and canonical_name(ecosystem, e["name"]) == want]
    if not rows:
        return None
    entry = dict(rows[0])
    for other in rows[1:]:  # one advisory, one entry per package: merge its version lines
        entry["versions"] = sorted(set(entry["versions"]) | set(other["versions"]))
    return entry


# ---- the run ------------------------------------------------------------------------------


def decide_package(opener: Opener, advisory: dict[str, Any], ecosystem: str, name: str,
                   specs: list[str], known: set[str], timeout: float = 60.0) -> Decision:
    """Keep, drop or skip one package one advisory names; a kept package's entry
    ids and aliases join `known`."""
    ghsa, published = str(advisory.get("ghsa_id")), _published(advisory)
    if advisory.get("withdrawn_at") or published is None:
        return Decision(ecosystem, name, ghsa, "skipped", "the advisory was withdrawn or has no publication time")
    if ghsa in known:
        return Decision(ecosystem, name, ghsa, "skipped", "already bundled")
    if all(s.strip() == ">= 0" for s in specs):
        return Decision(ecosystem, name, ghsa, "dropped",
                        "the advisory lists every version (>= 0), so no clean release is outside it")
    try:
        times = release_times(opener, ecosystem, name, timeout, wanted=lambda v: not listed(ecosystem, specs, v))
        if times is None:
            return Decision(ecosystem, name, ghsa, "dropped", "the registry does not serve the package (404)")
        found = established_release(times, ecosystem, specs, published)
        if found is None:
            return Decision(ecosystem, name, ghsa, "dropped", f"no release at least {ESTABLISHED_DAYS} days "
                            f"before the advisory outside the versions it lists ({len(times)} on the registry)")
        entry = entry_for(opener, ecosystem, name, advisory, timeout)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return Decision(ecosystem, name, ghsa, "error", f"{type(exc).__name__}: {exc}")
    if entry is None:
        return Decision(ecosystem, name, ghsa, "error", "no entry could be written from OSV or the advisory")
    if entry["id"] in known:
        return Decision(ecosystem, name, ghsa, "skipped", f"already bundled as {entry['id']}")
    known.update([entry["id"], *entry["aliases"]])
    version, when = found
    lists = ", ".join(entry["versions"]) or "a range"
    return Decision(ecosystem, name, ghsa, "kept",
                    f"{version} was released {when:%Y-%m-%d}; {entry['id']} lists {lists}", entry)


def decide(opener: Opener, advisories: list[dict[str, Any]], known: set[str],
           timeout: float = 60.0) -> list[Decision]:
    """A decision per (advisory, package), oldest advisory first."""
    decisions: list[Decision] = []
    for advisory in sorted(advisories, key=lambda a: (str(a.get("published_at")), str(a.get("ghsa_id")))):
        if not isinstance(advisory.get("ghsa_id"), str):
            continue
        for (ecosystem, name), specs in packages(advisory).items():
            decisions.append(decide_package(opener, advisory, ecosystem, name, specs, known, timeout))
    return decisions


def _entry_text(entry: dict[str, Any]) -> str:
    """One entry as the bundled file writes them: a key a line, lists inline."""
    body = ",\n".join(f"      {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}" for k, v in entry.items())
    return "    {\n" + body + "\n    }"


def render(text: str, data: dict[str, Any], added: list[dict[str, Any]], generated: str, source: str,
           checked: str | None = None) -> str:
    """The bundled file with `added` appended to `entries`, `generated_at` and
    `source` replaced and, given `checked`, `checked_at` set (written on the line
    after `generated_at` the first time), every other byte as it was; a plain
    re-dump when the file is not laid out as expected."""
    expected = {**data, "generated_at": generated, "source": source, "entries": [*data["entries"], *added]}
    if checked is not None:
        expected["checked_at"] = checked
    try:
        out = _with_checked(text, data, checked) if checked is not None else text
        out = out.replace(f'"generated_at": {json.dumps(data["generated_at"])}',
                          f'"generated_at": {json.dumps(generated)}', 1)
        out = out.replace(f'"source": {json.dumps(data["source"], ensure_ascii=False)}',
                          f'"source": {json.dumps(source, ensure_ascii=False)}', 1)
        if added:
            start = out.index('"entries": [')
            close = out.index("\n  ]", start)
            tail = ",\n" if data["entries"] else "\n"
            inserted = tail + ",\n".join(_entry_text(e) for e in added)
            out = out[:close] + inserted + out[close:]
        if json.loads(out) == expected:
            return out
    except (ValueError, KeyError):
        pass
    return json.dumps(expected, indent=2, ensure_ascii=False) + "\n"


def _with_checked(text: str, data: dict[str, Any], checked: str) -> str:
    """`text` with `checked_at` set to `checked`: its value replaced where the file
    has one, else a line inserted after `generated_at`'s."""
    if "checked_at" in data:
        return text.replace(f'"checked_at": {json.dumps(data["checked_at"])}', f'"checked_at": {json.dumps(checked)}', 1)
    line = f'"generated_at": {json.dumps(data["generated_at"])},'
    at = text.index(line) + len(line)
    indent = text[text.rindex("\n", 0, at) + 1:at].split('"', 1)[0]
    return text[:at] + f'\n{indent}"checked_at": {json.dumps(checked)},' + text[at:]


def _write(feed: Path, rendered: str) -> None:
    temporary = feed.with_name(feed.name + ".tmp")
    try:
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, feed)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise RefreshError(f"writing {feed}: {exc}") from exc


def refresh_bundled(
    feed: Path = BUNDLED_FEED,
    opener: Opener | None = None,
    now: datetime | None = None,
    days: int = DEFAULT_DAYS,
    token: str | None = None,
    dry_run: bool = False,
    timeout: float = 60.0,
) -> Outcome:
    """Decide on every malware advisory published in the last `days` days and
    append the kept packages to `feed`. Unless `dry_run`, a run that decided every
    package also sets `checked_at`, so the file changes even when nothing is
    kept; a run where a lookup failed and nothing was kept leaves it untouched.

    Raises:
        RefreshError: The advisory listing failed, or the file is not a feed.
            Nothing was written.
    """
    opener = opener or urllib.request.urlopen
    now = now or datetime.now(timezone.utc)
    text = feed.read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise RefreshError(f"{feed} has no `entries` list")
    known = {str(e.get("id")) for e in data["entries"] if isinstance(e, dict)}
    known |= {str(a) for e in data["entries"] if isinstance(e, dict) for a in e.get("aliases") or ()}
    since = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    try:
        advisories = list_advisories(opener, since, token, timeout)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise RefreshError(f"GitHub advisories: {type(exc).__name__}: {exc}") from exc
    decisions = decide(opener, advisories, known, timeout)
    added = [d.entry for d in decisions if d.outcome == "kept" and d.entry is not None]
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Checked means every package was decided: a lookup that failed checked nothing.
    checked = None if any(d.outcome == "error" for d in decisions) else stamp
    if dry_run or (not added and checked is None):
        return Outcome(decisions, added, False)
    if not added:
        _write(feed, render(text, data, [], data["generated_at"], data.get("source", ""), checked))
        return Outcome(decisions, added, False, checked=True)
    generated = stamp
    ids = [e["id"] for e in added]
    named = ", ".join(ids[:-1]) + f" and {ids[-1]}" if len(ids) > 1 else ids[0]
    source = (
        f"{data.get('source', '').rstrip()} On {now:%Y-%m-%d}, scripts/refresh_bundled_malicious.py added "
        f"{named}, takeovers of established packages among GitHub's malware advisories published since "
        f"{since}, each as https://api.osv.dev/v1/vulns/<id> gave it (the GitHub advisory where OSV had no record)."
    )
    _write(feed, render(text, data, added, generated, source, checked))
    return Outcome(decisions, added, True, checked=checked is not None)


def _github_token() -> str | None:
    """GITHUB_TOKEN, else GH_TOKEN, else None (GitHub then allows 60 requests an
    hour, enough for a few days of advisories)."""
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help=f"read advisories published in the last N days (default {DEFAULT_DAYS})")
    parser.add_argument("--feed", type=Path, default=BUNDLED_FEED, help="the bundled feed file to update")
    parser.add_argument("--dry-run", action="store_true", help="print the decisions and write nothing")
    args = parser.parse_args(argv)
    if args.days < 1:
        parser.error("--days must be 1 or more")
    try:
        outcome = refresh_bundled(args.feed, days=args.days, token=_github_token(), dry_run=args.dry_run)
    except RefreshError as exc:
        print(f"refresh failed, {args.feed} unchanged: {exc}", file=sys.stderr)
        return 2
    for decision in outcome.decisions:
        print(decision.line())
    kept = [d for d in outcome.decisions if d.outcome == "kept"]
    errors = [d for d in outcome.decisions if d.outcome == "error"]
    state = ("written" if outcome.written else "checked_at set" if outcome.checked
             else "not written (--dry-run)" if args.dry_run and kept else "unchanged")
    print(f"{len(outcome.decisions)} packages: {len(kept)} kept, {len(errors)} could not be checked; "
          f"{args.feed.name} {state}.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
