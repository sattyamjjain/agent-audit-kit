"""NVD's records of CNA version data, for the advisory feed AAK-KNOWN-VULN-001 reads.

On 0.6.29 a project that locked langflow 1.12.8 passed every rule. IBM's
Langflow OSS bulletin of 28 Oct 2026 names 1.0.0 through 1.12.8 (CVE-2026-110186,
CVSS 9.8), but OSV had no record for it, and the advisory feed read only OSV.
The one machine-readable range was the CNA's own, in NVD's record of the CVE.
This module reads those records into the same feed, for the CVEs OSV has no
package record of.

What NVD carries
----------------
NVD's CVE API 2.0 returns, beside the CPE `configurations` NVD adds once it has
analysed a record, the CNA's affected data:
`vulnerabilities[].cve.affected[].affectedData[]`, each with `vendor`, `product`,
an optional `packageURL`, `repo` and `defaultStatus`, and `versions[]` of
`version`, `lessThan` or `lessThanOrEqual`, `versionType` and `status`. That is
the shape of the four records saved under tests/fixtures/nvd_cna on 2026-10-30.
A block whose `source` is the record's CNA (`sourceIdentifier`) is read; one
added by another source (an ADP) only when no block names the CNA. A record with
no affected data, CPE `configurations` only, is not read here and is counted.

Which package a record names
----------------------------
In this order, never from a name alone:

1. the CNA's `packageURL` when it is `pkg:pypi/<name>` or `pkg:npm/<name>`
   (`pkg:npm/%40scope/name` is `@scope/name`). A packageURL of another registry
   (`pkg:maven/...`) names a package AAK does not read, and the entry is dropped;
2. else a row of the reviewed map, `data/cna_package_map.json`, whose `repo` is
   the CNA's `repo`, or whose `vendor` and `product` are the CNA's (compared
   without case or surrounding space). A row is added only after checking that
   the package's own page on pypi.org or npmjs.com names the same project.

An entry that maps to neither, and to no launch row (below), is dropped, and the
record counted unmapped; `Tally.unmapped_pairs` counts the (vendor, product)
pairs such records name, which `aak update` prints so the map grows from them.

What a project launches
-----------------------
A record can name software that is on neither registry: MoLing, a Go MCP server
shipped as a binary (CVE-2026-62863, CVSS 9.6), or TAKO, an agent app shipped as
the image `fctrid/ai-agent-for-okta` (CVE-2026-63377, 9.8), both of 30 Oct 2026
and both left unmapped. A launch row of the same map (`launch`) names the ways a
project starts such software, as the project's own repository shows them: the
`commands` an MCP config runs, the Go `go_modules` it starts with `go run`, and
the `images` a compose file or `docker run` names. It maps a record as a package
row does, by `repo`, else by vendor and product, and never by a name alone. Such
an entry goes to a third list of the feed, `launch`, in the package entries'
shape plus `repo` and `match` (`commands`, `go_modules`, `images`); its versions
are read on semver 2.0 with a leading `v` dropped (`LAUNCH`): a Go module
version is semver, a Go pseudo-version a semver pre-release, and GitHub writes
their ranges in it. AAK-KNOWN-VULN-002 matches it against what a project launches.

Which versions
--------------
`status: affected` entries, read on the registry's own order (`malicious_feed.
version_order`: PEP 440 for PyPI, semver for npm), whatever `versionType` says
of `semver`, `custom` or `python`; another type (a git commit) is not read:

* `version` with `lessThan` is `[version, lessThan)`, with `lessThanOrEqual`
  `[version, lessThanOrEqual]`; a `version` of "0" or "*" starts at the first
  release, and an end of "*" is open. `changes` split the range where the
  status moves.
* `version` alone is one listed release when it is one. Otherwise it is read as
  GitHub's advisory grammar, the only way GitHub's CNA writes a range: one or
  more of `< x`, `<= x`, `> x`, `>= x` and `= x`, comma-separated, each x a
  version of the registry (`"< 0.5.0"`, `">= 2.2.0, < 3.0.1"`). Of the 5,650
  records GitHub's CNA published in the 120 days to 2026-10-31, none carried a
  `lessThan`, 4,270 versions read `< x` and 3,621 `>= x, < x`. One lower and one
  upper bound at most, or `= x` alone. `> x` starts at the first version after
  x, which semver has (3.0.1-0 after 3.0.0) and PEP 440 does not, so on PyPI it
  is not read (5 of the 8,210 versions used it). Other text (`"1.0 to 1.8.0"`,
  `">= 12.0.0 < 15.5.21"` with no comma) is not read.
* `defaultStatus: affected` makes every release affected but the ones the
  entries exclude. That is read when each exclusion is a range ending before a
  version (`lessThan`) or open-ended, since a feed interval starts inclusively;
  an excluded single release, an inclusive end or `changes` leave the record
  unread rather than reported wider than the CNA wrote it.

Severity is the record's CVSS 3.x score computed from its vector
(`advisory_feed.cvss3_base_score`, NVD's own Primary metric before a CNA's),
else the 4.0 metric's `baseSeverity` label, else MEDIUM; `scored_by` says which
(`nvd-cvss3`, `nvd-label`, or "").

What `aak update` reads
-----------------------
Every record modified in the last N days (`--nvd-days`, 120 by default, the
API's longest window), 2,000 a page, with `NVD_API_KEY` when it is set, pausing
between requests as NVD asks (six seconds without a key) and backing off on a
rate-limit or server error. On 2026-10-30 a 120-day window held 100,047 records:
51 pages of about 4 MB that NVD served at about 20 s each. A failure costs this
half only: `aak update` keeps the NVD entries it cached before and rebuilds the
OSV half. A scan never touches the network.
"""

from __future__ import annotations

import http.client
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from agent_audit_kit.advisory_feed import LAUNCH, _dicts, _interval, bucket, cvss3_base_score
from agent_audit_kit.malicious_feed import (
    _SEMVER_RE,
    ECOSYSTEMS,
    Range,
    canonical_name,
    version_key,
    version_order,
)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PACKAGE_MAP: Path = Path(__file__).parent / "data" / "cna_package_map.json"
#: The longest lastModified window NVD's API accepts, and `aak update`'s default.
MAX_WINDOW_DAYS = 120
DEFAULT_DAYS = 120
#: The largest page NVD serves.
PAGE_SIZE = 2000
#: Seconds between requests: NVD asks for six without an API key; a key allows 50 in 30 s.
REQUEST_INTERVAL = 6.0
REQUEST_INTERVAL_WITH_KEY = 0.6
#: Attempts per page, and the first back-off in seconds (doubled each time).
ATTEMPTS = 5
BACKOFF = 6.0
#: A bound on pages, so a query that never ends cannot run on: 500 x 2,000 records.
MAX_PAGES = 500
TIMEOUT = 180.0
_RETRY_STATUSES = frozenset({403, 429, 500, 502, 503, 504})
_PURL_REGISTRIES = {"pypi": "PyPI", "npm": "npm"}
_READ_VERSION_TYPES = frozenset({"", "semver", "custom", "python"})
_LABELS = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "MEDIUM", "NONE": "MEDIUM"}
_START = "0"
#: (vendor, product) pairs that say nothing, left out of `Tally.unmapped_pairs`.
_NAMELESS = frozenset({"", "n/a", "na", "unknown", "-"})

Opener = Callable[..., Any]


class NvdUpdateError(RuntimeError):
    """An NVD read that failed; what was cached before is kept."""


def _default_opener() -> Opener:
    """`urllib.request.urlopen`, looked up at call time (the tests replace it)."""
    return urllib.request.urlopen


def _default_sleep(seconds: float) -> None:
    time.sleep(seconds)


# ---- the reviewed map ------------------------------------------------------------------------


@dataclass(frozen=True)
class MapRow:
    """One reviewed mapping from a CNA's naming to a package."""

    vendor: str
    product: str
    repo: str        # normalised (`_repo_key`); "" when the row names none
    ecosystem: str   # "PyPI" or "npm"
    name: str
    reviewed: str


def _fold(value: object) -> str:
    return " ".join(value.split()).casefold() if isinstance(value, str) else ""


def _repo_key(value: object) -> str:
    """A repository URL as rows and records compare it: `github.com/owner/repo`,
    without scheme, `www.`, `.git` or a trailing slash, lower case."""
    if not isinstance(value, str) or not value.strip():
        return ""
    text = value.strip().lower()
    for prefix in ("git+", "https://", "http://", "git://", "ssh://", "git@"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = text.replace(":", "/", 1) if text.startswith("github.com:") else text
    text = text.removeprefix("www.").split("#", 1)[0].split("?", 1)[0].rstrip("/")
    return text[:-4] if text.endswith(".git") else text


def load_package_map(path: Path = PACKAGE_MAP) -> tuple[MapRow, ...]:
    """The reviewed rows. A row without a vendor and product, a registry the feed
    reads, a name or a review date is skipped, so one bad row costs only itself."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    rows: list[MapRow] = []
    for raw in _dicts(data.get("rows") if isinstance(data, dict) else None):
        values = {key: raw.get(key) for key in ("vendor", "product", "ecosystem", "name", "reviewed")}
        if not all(isinstance(v, str) and v.strip() for v in values.values()):
            continue
        if values["ecosystem"] not in ECOSYSTEMS:
            continue
        rows.append(MapRow(
            vendor=str(values["vendor"]).strip(),
            product=str(values["product"]).strip(),
            repo=_repo_key(raw.get("repo")),
            ecosystem=str(values["ecosystem"]),
            name=str(values["name"]).strip(),
            reviewed=str(values["reviewed"]).strip(),
        ))
    return tuple(rows)


@dataclass(frozen=True)
class LaunchRow:
    """One reviewed launch row: what a project runs to start a piece of software
    that is on neither registry."""

    vendor: str
    product: str
    repo: str                    # normalised (`_repo_key`); "" when the row names none
    commands: tuple[str, ...]    # file names an MCP config's `command` runs, lower case
    go_modules: tuple[str, ...]  # Go module paths, lower case
    images: tuple[str, ...]      # image names as the project's docs write them, lower case
    reviewed: str


def _names(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict.fromkeys(v.strip().lower() for v in value if isinstance(v, str) and v.strip()))


def load_launch_map(path: Path = PACKAGE_MAP) -> tuple[LaunchRow, ...]:
    """The reviewed launch rows. A row without a vendor, a product and a review
    date, or naming nothing to match, is skipped, so one bad row costs only itself."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    rows: list[LaunchRow] = []
    for raw in _dicts(data.get("launch") if isinstance(data, dict) else None):
        values = {key: raw.get(key) for key in ("vendor", "product", "reviewed")}
        if not all(isinstance(v, str) and v.strip() for v in values.values()):
            continue
        row = LaunchRow(
            vendor=str(values["vendor"]).strip(),
            product=str(values["product"]).strip(),
            repo=_repo_key(raw.get("repo")),
            commands=_names(raw.get("commands")),
            go_modules=_names(raw.get("go_modules")),
            images=_names(raw.get("images")),
            reviewed=str(values["reviewed"]).strip(),
        )
        if row.repo or row.commands or row.go_modules or row.images:
            rows.append(row)
    return tuple(rows)


def map_launch(affected: dict[str, Any], rows: Iterable[LaunchRow]) -> LaunchRow | None:
    """The launch row one CNA affected entry names, by its `repo`, else by its
    vendor and product, as `map_package` reads a package row; None for none."""
    rows = tuple(rows)
    repo = _repo_key(affected.get("repo"))
    if repo:
        for row in rows:
            if row.repo and row.repo == repo:
                return row
    vendor, product = _fold(affected.get("vendor")), _fold(affected.get("product"))
    if vendor and product:
        for row in rows:
            if _fold(row.vendor) == vendor and _fold(row.product) == product:
                return row
    return None


def purl_package(purl: object) -> tuple[str, str] | None:
    """(registry, name) for a `pkg:pypi/...` or `pkg:npm/...` packageURL, else None.

    The version, qualifiers and subpath are dropped and each segment is
    percent-decoded, so `pkg:npm/%40scope/name@2.11.0` is npm `@scope/name`.
    Anything else, a PyPI name with a namespace or an npm name of more than scope
    and name, is not read.
    """
    if not isinstance(purl, str) or not purl.strip().lower().startswith("pkg:"):
        return None
    rest = purl.strip()[4:].lstrip("/").split("#", 1)[0].split("?", 1)[0]
    kind, _, path = rest.partition("/")
    registry = _PURL_REGISTRIES.get(kind.strip().lower())
    if registry is None:
        return None
    name = "/".join(urllib.parse.unquote(segment) for segment in path.split("/") if segment).strip()
    head, _, _ = name.rpartition("@")
    if head:  # `name@version`; a scoped name's own `@` is its first character
        name = head
    parts = name.split("/")
    if registry == "npm" and name.startswith("@"):
        scoped = len(parts) == 2 and len(parts[0]) > 1 and bool(parts[1])
        return (registry, name) if scoped else None
    return (registry, name) if name and len(parts) == 1 and "@" not in name else None


def map_package(affected: dict[str, Any], rows: Iterable[MapRow]) -> tuple[str, str, str] | None:
    """(registry, name, how it was mapped) for one CNA affected entry, or None.

    Its packageURL decides when it has one; a packageURL of a registry the feed
    does not read is not overridden by the map. Else a reviewed row matching its
    `repo`, else one matching its vendor and product.
    """
    purl = affected.get("packageURL")
    if isinstance(purl, str) and purl.strip():
        found = purl_package(purl)
        return (found[0], found[1], "packageURL") if found else None
    rows = tuple(rows)
    repo = _repo_key(affected.get("repo"))
    if repo:
        for row in rows:
            if row.repo and row.repo == repo:
                return row.ecosystem, row.name, "map"
    vendor, product = _fold(affected.get("vendor")), _fold(affected.get("product"))
    if vendor and product:
        for row in rows:
            if _fold(row.vendor) == vendor and _fold(row.product) == product:
                return row.ecosystem, row.name, "map"
    return None


# ---- versions ----------------------------------------------------------------------------------


def _key(ecosystem: str, version: str) -> tuple[Any, ...]:
    """A bound's place in the registry's order; the first release sorts lowest."""
    return () if version == _START else (version_order(ecosystem, version) or ())


def _start(value: object, ecosystem: str) -> str | None:
    """A range's first release: "0" from the first release, else a version of the
    registry; None when it is neither."""
    text = str(value).strip() if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ""
    if text in ("0", "*"):
        return _START
    return text if text and version_order(ecosystem, text) is not None else None


def _status(entry: dict[str, Any]) -> str:
    value = entry.get("status")
    return value.strip().lower() if isinstance(value, str) else ""


def _end(entry: dict[str, Any], ecosystem: str) -> tuple[str, str] | None:
    """("fixed" | "last" | "open", the bound) of a range entry; None when unreadable."""
    for key, kind in (("lessThan", "fixed"), ("lessThanOrEqual", "last")):
        if key in entry:
            value = entry.get(key)
            text = str(value).strip() if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ""
            if text in ("*", ""):
                return ("open", "") if text == "*" else None
            return (kind, text) if version_order(ecosystem, text) is not None else None
    return None


#: One clause of GitHub's advisory grammar: an operator, then a version.
_CLAUSE_RE = re.compile(r"\s*(<=|>=|<|>|=)\s*(\S+)\s*")


def _after(version: str, ecosystem: str) -> str | None:
    """The first version after `version`, where `> version` starts.

    Semver 2.0 has one: a release's pre-releases sort below it and a longer
    pre-release above its prefix, so 3.0.1-0 follows 3.0.0, and
    4.0.0-canary.0.0 follows 4.0.0-canary.0. PEP 440 has none: below any local
    version of 1.0 sorts another (1.0+0a below 1.0+a, 1.0+00a below 1.0+0a), so
    on PyPI this is None and `> x` is not read.
    """
    if ecosystem == "PyPI":
        return None
    m = _SEMVER_RE.match(version_key(ecosystem, version))
    if m is None:
        return None
    major, minor, patch, pre = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{major}.{minor}.{patch}-{pre}.0" if pre else f"{major}.{minor}.{int(patch) + 1}-0"


def comparator_ranges(text: object, ecosystem: str) -> tuple[list[Range], list[str]] | None:
    """(intervals, listed releases) for a version written in GitHub's advisory
    grammar (see the module's "Which versions"), read on `ecosystem`'s order; None
    for text that is not that grammar, or names no release.

    `< 0.5.0` is [first release, 0.5.0), `>= 2.2.0, < 3.0.1` is [2.2.0, 3.0.1),
    `<= 1.2` includes 1.2, `>= 1.0.0` has no end and `= 1.4.2` is one release.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    lower: tuple[str, str] | None = None
    upper: tuple[str, str] | None = None
    exact: str | None = None
    for clause in text.split(","):
        m = _CLAUSE_RE.fullmatch(clause)
        if m is None or version_order(ecosystem, m.group(2)) is None:
            return None
        op, version = m.group(1), m.group(2)
        if op == "=":
            if exact is not None:
                return None
            exact = version
        elif op in (">", ">="):
            if lower is not None:
                return None
            lower = (op, version)
        elif upper is not None:
            return None
        else:
            upper = (op, version)
    if exact is not None:
        return ([], [exact]) if lower is None and upper is None else None
    introduced: str | None = _START
    if lower is not None:
        introduced = lower[1] if lower[0] == ">=" else _after(lower[1], ecosystem)
    if introduced is None:
        return None
    fixed = upper[1] if upper is not None and upper[0] == "<" else None
    last = upper[1] if upper is not None and upper[0] == "<=" else None
    row = Range(introduced, fixed, last, ecosystem)
    bounds = row.bounds
    if bounds is None:
        return None
    low, end, last_key = bounds
    if low is not None and ((end is not None and low >= end) or (last_key is not None and low > last_key)):
        return None  # `>= 2.0, < 1.0` admits nothing
    return [row], []


def _affected_segments(entry: dict[str, Any], ecosystem: str) -> list[Range] | None:
    """The affected intervals of one range entry, its `changes` applied; None when
    a bound or a change cannot be placed in the registry's order."""
    start = _start(entry.get("version"), ecosystem)
    end = _end(entry, ecosystem)
    if start is None or end is None:
        return None
    kind, bound = end
    points: list[tuple[str, str]] = [(start, _status(entry))]
    for change in _dicts(entry.get("changes")):
        at = change.get("at")
        if not isinstance(at, str) or version_order(ecosystem, at.strip()) is None:
            return None
        at = at.strip()
        if _key(ecosystem, at) < _key(ecosystem, start):
            continue  # before the range begins
        if kind != "open":
            beyond = _key(ecosystem, at) > _key(ecosystem, bound) if kind == "last" else (
                _key(ecosystem, at) >= _key(ecosystem, bound))
            if beyond:
                continue
        points.append((at, _status(change)))
    points.sort(key=lambda point: _key(ecosystem, point[0]))
    out: list[Range] = []
    for index, (at, status) in enumerate(points):
        if status != "affected":
            continue
        if index + 1 < len(points):
            out.append(Range(at, points[index + 1][0], None, ecosystem))
        elif kind == "open":
            out.append(Range(at, None, None, ecosystem))
        elif kind == "fixed":
            out.append(Range(at, bound, None, ecosystem))
        else:
            out.append(Range(at, None, bound, ecosystem))
    return out


def _excluded(entry: dict[str, Any], ecosystem: str) -> tuple[str, str] | None:
    """(start, end) of a release range a `defaultStatus: affected` block excludes,
    end "" when open; None when a feed interval cannot express what is left."""
    if "lessThan" not in entry and "lessThanOrEqual" not in entry:
        return None  # one excluded release: a hole an interval cannot express
    if entry.get("changes"):
        return None
    start = _start(entry.get("version"), ecosystem)
    end = _end(entry, ecosystem)
    if start is None or end is None or end[0] == "last":
        return None  # an inclusive end leaves an exclusive start, which no interval has
    return start, end[1]


def _gaps(excluded: list[tuple[str, str]], ecosystem: str) -> list[Range]:
    """Every release outside the excluded ranges, as intervals."""
    out: list[Range] = []
    cursor: str | None = _START
    for start, end in sorted(excluded, key=lambda span: _key(ecosystem, span[0])):
        if cursor is None:
            break
        if _key(ecosystem, start) > _key(ecosystem, cursor):
            out.append(Range(cursor, start, None, ecosystem))
        if end == "":
            cursor = None
        elif _key(ecosystem, end) > _key(ecosystem, cursor):
            cursor = end
    if cursor is not None:
        out.append(Range(cursor, None, None, ecosystem))
    return out


def cna_ranges(affected: dict[str, Any], ecosystem: str) -> tuple[list[Range], list[str]] | None:
    """(intervals, listed releases) one CNA affected entry declares affected, read on
    `ecosystem`'s order; None when its `defaultStatus: affected` exceptions cannot be
    expressed. An affected entry that cannot be read is skipped, which can only
    under-report."""
    default = str(affected.get("defaultStatus") or "unknown").strip().lower()
    ranges: list[Range] = []
    listed: list[str] = []
    excluded: list[tuple[str, str]] = []
    for entry in _dicts(affected.get("versions")):
        version_type = entry.get("versionType")
        if (version_type.strip().lower() if isinstance(version_type, str) else "") not in _READ_VERSION_TYPES:
            if default == "affected":
                return None
            continue
        ranged = "lessThan" in entry or "lessThanOrEqual" in entry
        if _status(entry) == "affected" or (ranged and entry.get("changes")):
            if ranged:
                if default == "affected" and entry.get("changes"):
                    return None
                ranges.extend(_affected_segments(entry, ecosystem) or ())
            else:
                text = entry.get("version")
                if isinstance(text, str) and version_order(ecosystem, text.strip()) is not None:
                    listed.append(text.strip())
                else:
                    read = comparator_ranges(text, ecosystem)
                    if read is not None:
                        ranges.extend(read[0])
                        listed.extend(read[1])
        elif default == "affected":
            span = _excluded(entry, ecosystem)
            if span is None:
                return None
            excluded.append(span)
    if default == "affected":
        ranges = _gaps(excluded, ecosystem) + ranges
    return list(dict.fromkeys(ranges)), sorted(set(listed))


# ---- severity --------------------------------------------------------------------------------


def nvd_severity(metrics: object) -> tuple[str, float | None, str]:
    """(bucket, CVSS 3.x base score or None, "nvd-cvss3" | "nvd-label" | "") for an
    NVD record's `metrics`: a 3.1 or 3.0 vector (NVD's Primary metric before a
    CNA's Secondary one), else a 4.0 metric's `baseSeverity`, else MEDIUM."""
    if not isinstance(metrics, dict):
        return "MEDIUM", None, ""
    for primary in (True, False):
        for key in ("cvssMetricV31", "cvssMetricV30"):
            for metric in _dicts(metrics.get(key)):
                if (metric.get("type") == "Primary") is not primary:
                    continue
                data = metric.get("cvssData")
                vector = data.get("vectorString") if isinstance(data, dict) else None
                score = cvss3_base_score(vector) if isinstance(vector, str) else None
                if score is not None:
                    return bucket(score), score, "nvd-cvss3"
    for primary in (True, False):
        for metric in _dicts(metrics.get("cvssMetricV40")):
            if (metric.get("type") == "Primary") is not primary:
                continue
            data = metric.get("cvssData")
            label = data.get("baseSeverity") if isinstance(data, dict) else None
            if isinstance(label, str) and label.strip().upper() in _LABELS:
                return _LABELS[label.strip().upper()], None, "nvd-label"
    return "MEDIUM", None, ""


# ---- records to feed entries -----------------------------------------------------------------


@dataclass
class Tally:
    """What a read found, record by record."""

    records: int = 0
    rejected: int = 0
    no_cna: int = 0       # no CNA affected data: CPE configurations only, or nothing
    with_cna: int = 0
    mapped: int = 0       # records that gave the feed at least one entry
    unmapped: int = 0     # records whose CNA data named nothing a row maps
    no_range: int = 0     # records that mapped, but whose versions could not be read
    entries: int = 0      # entries of either kind
    launch: int = 0       # of them, launch entries
    #: (vendor, product) as the CNA wrote them, per unmapped record naming them.
    unmapped_pairs: Counter[tuple[str, str]] = field(default_factory=Counter)


def _cna_data(cve: dict[str, Any]) -> list[dict[str, Any]]:
    blocks = _dicts(cve.get("affected"))
    cna = cve.get("sourceIdentifier")
    own = [block for block in blocks if block.get("source") == cna]
    return [data for block in (own or blocks) for data in _dicts(block.get("affectedData"))]


def record_packages(vuln: dict[str, Any], rows: Iterable[MapRow]) -> list[tuple[str, str, str]]:
    """(registry, name, how it was mapped) for each package one NVD record's CNA
    data names, sorted, whether or not its versions can be read; nothing for a
    rejected record. scripts/cve_watcher.py files a record on its package."""
    inner = vuln.get("cve")
    cve: dict[str, Any] = inner if isinstance(inner, dict) else vuln
    if str(cve.get("vulnStatus") or "").strip().lower() == "rejected":
        return []
    rows = tuple(rows)
    found: dict[tuple[str, str], tuple[str, str, str]] = {}
    for affected in _cna_data(cve):
        mapped = map_package(affected, rows)
        if mapped is not None:
            found.setdefault((mapped[0], canonical_name(mapped[0], mapped[1])), mapped)
    return [found[key] for key in sorted(found)]


def _count_unmapped(data: list[dict[str, Any]], tally: Tally) -> None:
    pairs = set()
    for affected in data:
        vendor, product = affected.get("vendor"), affected.get("product")
        pair = (vendor.strip() if isinstance(vendor, str) else "", product.strip() if isinstance(product, str) else "")
        if not (pair[0].lower() in _NAMELESS and pair[1].lower() in _NAMELESS):
            pairs.add(pair)
    tally.unmapped_pairs.update(pairs)


def _launch_entries(launched: dict[tuple[str, str], tuple[LaunchRow, list[Range], list[str]]],
                    common: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for _, (row, found, listed) in sorted(launched.items()):
        unique = list(dict.fromkeys(found))
        out.append({
            "id": common["id"],
            "aliases": [],
            "ecosystem": LAUNCH,
            "name": f"{row.vendor}/{row.product}",
            "ranges": [_interval(r) for r in unique],
            "versions": sorted(set(listed)),
            "fixed": [r.fixed for r in unique if r.fixed is not None],
            **{key: common[key] for key in ("severity", "score", "scored_by", "modified", "url", "source", "cna")},
            "mapped_by": "map",
            "repo": row.repo,
            "match": {"commands": list(row.commands), "go_modules": list(row.go_modules), "images": list(row.images)},
        })
    return out


def record_entries(vuln: dict[str, Any], rows: Iterable[MapRow], tally: Tally | None = None,
                   launch_rows: Iterable[LaunchRow] = ()) -> list[dict[str, Any]]:
    """Feed entries for one NVD record (a `vulnerabilities[]` item, or its `cve`
    object), counted into `tally`: one per package a package row or packageURL
    names, and one per launch row (`launch_rows`) the record names, which carries
    `match`."""
    tally = tally if tally is not None else Tally()
    inner = vuln.get("cve")
    cve: dict[str, Any] = inner if isinstance(inner, dict) else vuln
    ident = cve.get("id")
    if not isinstance(ident, str) or not ident.startswith("CVE-"):
        return []
    tally.records += 1
    if str(cve.get("vulnStatus") or "").strip().lower() == "rejected":
        tally.rejected += 1
        return []
    data = _cna_data(cve)
    if not data:
        tally.no_cna += 1
        return []
    tally.with_cna += 1
    rows = tuple(rows)
    launch_rows = tuple(launch_rows)
    packages: dict[tuple[str, str], tuple[str, str, list[Range], list[str]]] = {}
    launched: dict[tuple[str, str], tuple[LaunchRow, list[Range], list[str]]] = {}
    any_mapped = False
    for affected in data:
        mapped = map_package(affected, rows)
        if mapped is not None:
            any_mapped = True
            ecosystem, name, how = mapped
            read = cna_ranges(affected, ecosystem)
            if read is not None and (read[0] or read[1]):
                key = (ecosystem, canonical_name(ecosystem, name))
                _, _, found, listed = packages.setdefault(key, (name, how, [], []))
                found.extend(read[0])
                listed.extend(read[1])
        launch = map_launch(affected, launch_rows) if launch_rows else None
        if launch is not None:
            any_mapped = True
            read = cna_ranges(affected, LAUNCH)
            if read is not None and (read[0] or read[1]):
                _, found_l, listed_l = launched.setdefault((_fold(launch.vendor), _fold(launch.product)),
                                                           (launch, [], []))
                found_l.extend(read[0])
                listed_l.extend(read[1])
    if not packages and not launched:
        if any_mapped:
            tally.no_range += 1
        else:
            tally.unmapped += 1
            _count_unmapped(data, tally)
        return []
    severity, score, scored_by = nvd_severity(cve.get("metrics"))
    common: dict[str, Any] = {
        "id": ident,
        "aliases": [],
        "severity": severity,
        "score": score,
        "scored_by": scored_by,
        "modified": str(cve.get("lastModified") or ""),
        "url": f"https://nvd.nist.gov/vuln/detail/{ident}",
        "source": "nvd",
        "cna": str(cve.get("sourceIdentifier") or ""),
    }
    out: list[dict[str, Any]] = []
    for (ecosystem, _), (name, how, found, listed) in sorted(packages.items()):
        unique = list(dict.fromkeys(found))
        out.append({
            "id": ident,
            "aliases": [],
            "ecosystem": ecosystem,
            "name": name,
            "ranges": [_interval(row) for row in unique],
            "versions": sorted(set(listed)),
            "fixed": [row.fixed for row in unique if row.fixed is not None],
            "severity": severity,
            "score": score,
            "scored_by": scored_by,
            "modified": common["modified"],
            "url": common["url"],
            "source": "nvd",
            "cna": common["cna"],
            "mapped_by": how,
        })
    launch_out = _launch_entries(launched, common)
    tally.mapped += 1
    tally.entries += len(out) + len(launch_out)
    tally.launch += len(launch_out)
    return out + launch_out


def merged(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per package and CVE, the most recently modified (a record modified
    while it was paged appears twice), sorted."""
    best: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in entries:
        key = (entry["ecosystem"], canonical_name(entry["ecosystem"], entry["name"]), entry["id"])
        if key not in best or str(entry.get("modified") or "") > str(best[key].get("modified") or ""):
            best[key] = entry
    return [best[key] for key in sorted(best)]


# ---- reading NVD -------------------------------------------------------------------------------


def stamp(moment: datetime) -> str:
    """A time as NVD's API takes it: `2026-10-30T09:21:55.000`, UTC."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _get_json(query: dict[str, str], headers: dict[str, str], opener: Opener, sleep: Callable[[float], None],
              timeout: float) -> dict[str, Any]:
    """One page of NVD's CVE API for `query`, retried on a rate limit, a server
    error or a broken read."""
    request = urllib.request.Request(f"{NVD_API}?{urllib.parse.urlencode(query)}", headers=headers)
    for attempt in range(ATTEMPTS):
        try:
            with opener(request, timeout=timeout) as response:
                data = json.loads(response.read())
            if not isinstance(data, dict):
                raise ValueError("an NVD page that is not a JSON object")
            return data
        except urllib.error.HTTPError as exc:
            if exc.code not in _RETRY_STATUSES or attempt == ATTEMPTS - 1:
                raise NvdUpdateError(f"NVD answered HTTP {exc.code}") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            if attempt == ATTEMPTS - 1:
                raise NvdUpdateError(f"{type(exc).__name__}: {exc}") from exc
        sleep(BACKOFF * 2 ** attempt)
    raise NvdUpdateError("NVD could not be read")  # pragma: no cover - the loop returns or raises


def iter_pages(
    params: dict[str, str],
    *,
    api_key: str | None = None,
    opener: Opener | None = None,
    sleep: Callable[[float], None] | None = None,
    page_size: int = PAGE_SIZE,
    timeout: float = TIMEOUT,
) -> Iterator[dict[str, Any]]:
    """Every page of one NVD query, in order, paced and retried.

    Raises:
        NvdUpdateError: A page could not be read after `ATTEMPTS` tries, a page was
            not NVD's shape, or the query ran past `MAX_PAGES`.
    """
    from agent_audit_kit import __version__

    opener = opener or _default_opener()
    pause = sleep or _default_sleep
    headers = {"User-Agent": f"agent-audit-kit/{__version__}"}
    if api_key:
        headers["apiKey"] = api_key
    interval = REQUEST_INTERVAL_WITH_KEY if api_key else REQUEST_INTERVAL
    start, total, pages = 0, None, 0
    while total is None or start < total:
        if pages >= MAX_PAGES:
            raise NvdUpdateError(f"more than {MAX_PAGES} pages")
        if pages:
            pause(interval)
        query = {**params, "resultsPerPage": str(page_size), "startIndex": str(start)}
        page = _get_json(query, headers, opener, pause, timeout)
        vulnerabilities = page.get("vulnerabilities")
        found = page.get("totalResults")
        if not isinstance(vulnerabilities, list) or isinstance(found, bool) or not isinstance(found, int):
            raise NvdUpdateError("an NVD page without `vulnerabilities` and `totalResults`")
        pages += 1
        total = found
        yield page
        if not vulnerabilities:
            break
        start += len(vulnerabilities)


@dataclass(frozen=True)
class Fetched:
    """What one read of NVD gave the feed."""

    entries: list[dict[str, Any]]
    tally: Tally
    window: dict[str, Any]
    pages: int = 0


def fetch(
    days: int = DEFAULT_DAYS,
    *,
    api_key: str | None = None,
    opener: Opener | None = None,
    sleep: Callable[[float], None] | None = None,
    now: datetime | None = None,
    rows: Iterable[MapRow] | None = None,
    progress: Callable[[int, int], None] | None = None,
    page_size: int = PAGE_SIZE,
    launch_rows: Iterable[LaunchRow] | None = None,
) -> Fetched:
    """Read every NVD record modified in the last `days` days into feed entries.

    Network; called by `aak update`, never by a scan.

    Args:
        days: The window, 1 to `MAX_WINDOW_DAYS`.
        api_key: NVD's API key, sent as the `apiKey` header; None reads without one.
        opener: Opens a request; `urllib.request.urlopen` by default.
        sleep: Waits between requests and before a retry; `time.sleep` by default.
        now: The end of the window (tests pin it).
        rows: The reviewed map; `load_package_map()` by default.
        progress: Called with (pages read, pages expected) after each page.
        page_size: Records a page.
        launch_rows: The reviewed launch rows; `load_launch_map()` by default.

    Raises:
        ValueError: `days` is outside the API's window.
        NvdUpdateError: NVD could not be read; nothing is returned.
    """
    if not 1 <= days <= MAX_WINDOW_DAYS:
        raise ValueError(f"days must be 1 to {MAX_WINDOW_DAYS}, not {days}")
    end = now or datetime.now(timezone.utc)
    begin = end - timedelta(days=days)
    rows = load_package_map() if rows is None else tuple(rows)
    launch_rows = load_launch_map() if launch_rows is None else tuple(launch_rows)
    tally = Tally()
    entries: list[dict[str, Any]] = []
    pages = 0
    params = {"lastModStartDate": stamp(begin), "lastModEndDate": stamp(end)}
    for page in iter_pages(params, api_key=api_key, opener=opener, sleep=sleep, page_size=page_size):
        pages += 1
        for vuln in _dicts(page.get("vulnerabilities")):
            entries.extend(record_entries(vuln, rows, tally, launch_rows))
        if progress is not None:
            progress(pages, max(1, math.ceil(int(page.get("totalResults") or 0) / page_size)))
    window = {
        "field": "lastModified",
        "start": begin.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end": end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days": days,
    }
    return Fetched(entries=merged(entries), tally=tally, window=window, pages=pages)


__all__ = [
    "DEFAULT_DAYS",
    "Fetched",
    "LAUNCH",
    "LaunchRow",
    "MAX_WINDOW_DAYS",
    "MapRow",
    "NvdUpdateError",
    "PACKAGE_MAP",
    "Tally",
    "cna_ranges",
    "comparator_ranges",
    "fetch",
    "iter_pages",
    "load_launch_map",
    "load_package_map",
    "map_launch",
    "map_package",
    "merged",
    "nvd_severity",
    "purl_package",
    "record_entries",
    "record_packages",
    "stamp",
]
