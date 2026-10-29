"""The offline advisory feed read by AAK-KNOWN-VULN-001.

On 0.6.28 a project that locked vLLM 0.31.1, MLflow 3.16.0 or OpenHands SDK
1.51.0 passed every rule, although each had an advisory published that week: a
scan knew a vulnerable release only through a hand-written pin, the bundled
`vuln_db.json` held no Python entries, and `aak update` downloaded OSV's complete
PyPI and npm exports for the malicious-release feed and kept nothing but their
`MAL-` records. This feed keeps the advisory records from the same downloads,
and AAK-KNOWN-VULN-001 matches them against every version a scan resolves.

Load order, as `malicious_feed` reads its feed: the cached feed at
`~/.agent-audit-kit/advisories.json` when it exists and parses, else the bundled
`data/advisories.json`. A scan never touches the network. `aak update` rebuilds
the cached copy with a `Collector` fed by `malicious_feed.refresh(on_record=...)`,
so each export is downloaded and read once for both feeds.

What is kept
------------
A record that is not `MAL-`, not withdrawn, and has, for the export's registry,
an `ECOSYSTEM` or `SEMVER` range or a list of affected versions (a GIT range
names commits, which no lockfile records). For each package a record names:

* `id`, `aliases` (CVE, GHSA and PYSEC ids), `modified` and the osv.dev `url`;
* `ranges`: every range's events sorted by version, as OSV's specification
  evaluates them, and read into intervals: from an `introduced` to the next
  `fixed` (exclusive) or `last_affected` (inclusive), or open. The order a
  record writes is not trusted: PYSEC records list `last_affected` 7.2.0, 6.1.0,
  5.3.0 (instack), which read in that order would admit every 6.x and 7.x.
* `versions`: the record's listed affected versions that no interval covers. A
  record whose only range is a git range lists its versions only there. On
  2026-10-29 the two exports listed 1.40 million versions, nearly all inside a
  range: keeping them made the cached file 22.7 MB, leaving them out 9.2 MB.
* `fixed`: the intervals' fixed releases.
* `severity`, `score` and `scored_by`: the CVSS 3.x base score computed from the
  record's vector, CRITICAL at 9.0 or more, HIGH from 7.0, else MEDIUM; without
  a 3.x vector, GitHub's label (`database_specific.severity`: CRITICAL and HIGH
  as they are, MODERATE and LOW as MEDIUM); without either, MEDIUM. A CVSS 4.0
  vector is not scored. The score is the record's: vLLM's GHSA-h3rc-j82p-2c3h
  carries GitHub's 8.1 (AC:H), while NVD scored the same CVE 9.8.

A cached file larger than `MAX_FEED_BYTES` keeps only HIGH and CRITICAL records
and records that in `severity_floor`. The bundled file holds the records exactly
as OSV returned them (`records`), read through the same conversion.

One flaw, several ids
---------------------
A PYSEC record and its GHSA twin describe one flaw, and both are in the PyPI
export. On lookup a record that is not GHSA is dropped when a GHSA record for
the same package names it, is named by it or shares a CVE id with it, and its id
joins that GHSA record's aliases. A GHSA record is never merged into another:
grouping every record that shares any id, transitively, folded distinct GitHub
advisories together through a PYSEC record that named two of them (21 groups on
2026-10-29; python-jose's GHSA-6c5p-j8vq-pqhj was reported only as
GHSA-3qf3-8w2g-rqmx, so its own range was never read).
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import AbstractSet, Any

from agent_audit_kit.malicious_feed import (
    ECOSYSTEMS,
    OSV_EXPORT,
    FeedError,
    Range,
    _optional,
    _strings,
    canonical_name,
    version_key,
    version_order,
)

BUNDLED_FEED: Path = Path(__file__).parent / "data" / "advisories.json"
FEED_FILE_NAME = "advisories.json"
#: A cached feed larger than this keeps only HIGH and CRITICAL records.
MAX_FEED_BYTES = 60_000_000
#: The severity buckets, lowest first.
SEVERITIES = ("MEDIUM", "HIGH", "CRITICAL")
_GITHUB_LABELS = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "MEDIUM"}
_RANGE_TYPES = ("ECOSYSTEM", "SEMVER")


def cache_path() -> Path:
    """Where `aak update` keeps the rebuilt feed (read at call time, so a changed
    HOME, as the tests set one, is honoured)."""
    return Path.home() / ".agent-audit-kit" / FEED_FILE_NAME


# ---- severity ------------------------------------------------------------------------------

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required weighs more when the scope changes.
_CVSS3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(value: float, version: str) -> float:
    """CVSS's Roundup: the smallest number with one decimal not below `value`.
    3.1 defines it on integers to avoid floating-point error; 3.0 used a plain
    ceiling."""
    if version == "3.0":
        return math.ceil(value * 10) / 10
    whole = round(value * 100_000)
    if whole % 10_000 == 0:
        return whole / 100_000
    return (math.floor(whole / 10_000) + 1) / 10


def cvss3_base_score(vector: str) -> float | None:
    """The base score of a CVSS 3.0 or 3.1 vector (`CVSS:3.1/AV:N/...`), or None
    when it is not one."""
    parts = vector.strip().split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep:
            return None
        metrics[key] = value
    try:
        scope = metrics["S"]
        weight = {key: table[metrics[key]] for key, table in _CVSS3_WEIGHTS.items()}
        privileges = _CVSS3_PR[scope][metrics["PR"]]
    except KeyError:
        return None
    iss = 1 - (1 - weight["C"]) * (1 - weight["I"]) * (1 - weight["A"])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * weight["AV"] * weight["AC"] * privileges * weight["UI"]
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return _roundup(min(total, 10.0), parts[0][5:])


def bucket(score: float) -> str:
    """The severity bucket of a CVSS base score."""
    return "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM"


def record_severity(record: dict[str, Any]) -> tuple[str, float | None, str]:
    """(bucket, CVSS 3.x base score or None, what decided it: "cvss3", "github"
    or "") for one OSV record."""
    for entry in _dicts(record.get("severity")):
        if entry.get("type") == "CVSS_V3" and isinstance(entry.get("score"), str):
            score = cvss3_base_score(entry["score"])
            if score is not None:
                return bucket(score), score, "cvss3"
    specific = record.get("database_specific")
    label = specific.get("severity") if isinstance(specific, dict) else None
    if isinstance(label, str) and label.upper() in _GITHUB_LABELS:
        return _GITHUB_LABELS[label.upper()], None, "github"
    return "MEDIUM", None, ""


# ---- converting OSV records -------------------------------------------------------------------


def intervals(events: object, ecosystem: str) -> list[Range]:
    """One OSV range's events as intervals, evaluated as OSV's specification does.

    The events are sorted by version ("0" first); an `introduced` opens an
    interval unless one is open, the next `fixed` (exclusive) or `last_affected`
    (inclusive) closes it, and one still open at the end stays open. `limit`
    events, which only git ranges use, are not read. When a version cannot be
    placed in the registry's order the events are read as written.
    """
    rows: list[tuple[str, str]] = []
    for event in events if isinstance(events, list) else ():
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected"):
            value = event.get(kind)
            if isinstance(value, str) and value.strip():
                rows.append((kind, value.strip()))
                break
    keys = [None if value == "0" else version_order(ecosystem, value) for _, value in rows]
    if all(key is not None or value == "0" for key, (_, value) in zip(keys, rows)):
        order = sorted(range(len(rows)), key=lambda i: (keys[i] is not None, keys[i] or ()))
        rows = [rows[i] for i in order]
    out: list[Range] = []
    start: str | None = None
    for kind, value in rows:
        if kind == "introduced":
            if start is None:
                start = value
        elif start is not None:
            fixed, last = (value, None) if kind == "fixed" else (None, value)
            out.append(Range(start, fixed, last, ecosystem))
            start = None
    if start is not None:
        out.append(Range(start, None, None, ecosystem))
    return out


def _dicts(value: object) -> list[dict[str, Any]]:
    """The objects of a JSON list; nothing for anything else, so one odd field costs
    only its record."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _interval(row: Range) -> dict[str, str]:
    out = {"introduced": row.introduced}
    if row.fixed is not None:
        out["fixed"] = row.fixed
    if row.last_affected is not None:
        out["last_affected"] = row.last_affected
    return out


def advisory_entries(record: object, ecosystem: str) -> list[dict[str, Any]]:
    """Feed entries, one per package, for one OSV advisory record on `ecosystem`.

    A `MAL-` record belongs to the malicious-release feed, and a withdrawn
    record gives none; so does a package with neither a readable range nor a
    listed version. A record that names one package in several `affected`
    blocks (one per release line) gives one entry with all their intervals.
    """
    if not isinstance(record, dict) or record.get("withdrawn"):
        return []
    ident = record.get("id")
    if not isinstance(ident, str) or not ident.strip() or ident.startswith("MAL-"):
        return []
    severity, score, scored_by = record_severity(record)
    aliases = sorted({a for a in _strings(record.get("aliases")) if a.strip() and a != ident})
    packages: dict[str, tuple[str, list[Range], set[str]]] = {}
    for affected in _dicts(record.get("affected")):
        package = affected.get("package")
        name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
            continue
        if not isinstance(name, str) or not name.strip():
            continue
        _, found, listed = packages.setdefault(canonical_name(ecosystem, name), (name.strip(), [], set()))
        for spec in _dicts(affected.get("ranges")):
            if spec.get("type") in _RANGE_TYPES:
                found.extend(intervals(spec.get("events"), ecosystem))
        listed.update(v.strip() for v in _strings(affected.get("versions")) if v.strip())
    out: list[dict[str, Any]] = []
    for name, found, listed in packages.values():
        unique = list(dict.fromkeys(found))
        extra = sorted(v for v in listed if not any(row.admits(v) for row in unique))
        if not (unique or extra):
            continue
        out.append({
            "id": ident,
            "aliases": aliases,
            "ecosystem": ecosystem,
            "name": name,
            "ranges": [_interval(row) for row in unique],
            "versions": extra,
            "fixed": [row.fixed for row in unique if row.fixed is not None],
            "severity": severity,
            "score": score,
            "scored_by": scored_by,
            "modified": str(record.get("modified") or ""),
            "url": f"https://osv.dev/vulnerability/{ident}",
        })
    return out


# ---- the feed ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Advisory:
    """One flaw in one package, as the feed lists it."""

    id: str
    aliases: tuple[str, ...]
    ecosystem: str
    name: str
    ranges: tuple[Range, ...]
    versions: frozenset[str]          # version keys (`version_key`) of the listed versions
    fixed: tuple[str, ...]
    severity: str                     # "CRITICAL", "HIGH" or "MEDIUM"
    score: float | None
    scored_by: str                    # "cvss3", "github" or ""
    modified: str
    url: str

    @property
    def ids(self) -> frozenset[str]:
        return frozenset((self.id,) + self.aliases)

    @property
    def cves(self) -> tuple[str, ...]:
        """The CVE ids among the advisory's id and aliases, sorted."""
        return tuple(sorted(i for i in self.ids if i.startswith("CVE-")))

    def matches(self, version: str) -> bool:
        """Is `version` (as a lockfile, a pin or a dist-info writes it) affected?"""
        if version_key(self.ecosystem, version) in self.versions:
            return True
        key = version_order(self.ecosystem, version)
        return key is not None and any(row.admits_key(key) for row in self.ranges)

    def fix_for(self, version: str) -> str | None:
        """The release that fixes `version`: the fixed end of the interval it falls
        in, else the lowest fixed release above it, else None (none is listed)."""
        key = version_order(self.ecosystem, version)
        if key is None:
            return None
        for row in self.ranges:
            if row.fixed is not None and row.admits_key(key):
                return row.fixed
        above: list[tuple[tuple[Any, ...], str]] = []
        for fixed in self.fixed:
            fixed_key = version_order(self.ecosystem, fixed)
            if fixed_key is not None and fixed_key > key:
                above.append((fixed_key, fixed))
        return min(above)[1] if above else None

    def label(self) -> str:
        """The advisory's ids and score as a finding names them:
        `GHSA-h3rc-j82p-2c3h (CVE-2026-115915, CVSS 3.x 8.1)`."""
        if self.scored_by == "cvss3" and self.score is not None:
            rated = f"CVSS 3.x {self.score:.1f}"
        elif self.scored_by == "github":
            rated = f"GitHub rates it {self.severity}"
        else:
            rated = "unscored"
        ids = sorted(self.aliases, key=lambda i: (not i.startswith("CVE-"), i))
        return f"{self.id} ({', '.join(ids + [rated])})"


def _grouped(rows: list[Advisory]) -> tuple[Advisory, ...]:
    """One report per flaw, never two GitHub advisories as one (see the module's
    "One flaw, several ids"): a record that is not GHSA and twins a GHSA record
    adds its id to that record's aliases and is not reported itself."""
    ghsa = [row for row in rows if row.id.startswith("GHSA-")]
    twins: dict[str, set[str]] = {row.id: set() for row in ghsa}
    out: list[Advisory] = []
    for row in rows:
        if row.id.startswith("GHSA-"):
            continue
        cves = set(row.cves)
        matched = [g for g in ghsa if row.id in g.ids or g.id in row.ids or cves & set(g.cves)]
        for g in matched:
            twins[g.id].add(row.id)
        if not matched:
            out.append(row)
    out.extend(replace(g, aliases=tuple(sorted(set(g.aliases) | twins[g.id]))) for g in ghsa)
    return tuple(sorted(out, key=lambda a: a.id))


def _advisory(ecosystem: str, raw: dict[str, Any]) -> Advisory:
    score = raw.get("score")
    severity = raw.get("severity")
    return Advisory(
        id=str(raw["id"]),
        aliases=_strings(raw.get("aliases")),
        ecosystem=ecosystem,
        name=str(raw["name"]),
        ranges=tuple(
            Range(r["introduced"], _optional(r.get("fixed")), _optional(r.get("last_affected")), ecosystem)
            for r in raw.get("ranges") or ()
            if isinstance(r, dict) and isinstance(r.get("introduced"), str)
        ),
        versions=frozenset(version_key(ecosystem, v) for v in _strings(raw.get("versions"))),
        fixed=_strings(raw.get("fixed")),
        severity=severity if severity in SEVERITIES else "MEDIUM",
        score=float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
        scored_by=str(raw.get("scored_by") or ""),
        modified=str(raw.get("modified") or ""),
        url=str(raw.get("url") or ""),
    )


@dataclass(frozen=True)
class AdvisoryFeed:
    """A loaded advisory feed: where it came from, and its entries by package.

    As `malicious_feed.Feed` does, the index holds each entry as parsed and
    builds a package's advisories the first time the package is looked up.
    """

    generated_at: str
    source: str
    origin: str          # "cached" or "bundled"
    path: Path
    severity_floor: str  # "" for every record, "HIGH" when a large feed was cut
    raw: dict[str, dict[str, list[dict[str, Any]]]] = field(default_factory=dict)
    _built: dict[tuple[str, str], tuple[Advisory, ...]] = field(default_factory=dict, compare=False, repr=False)

    def names(self, ecosystem: str) -> AbstractSet[str]:
        """The canonical package names the feed has advisories for on one registry."""
        return self.raw.get(ecosystem, {}).keys()

    def advisories(self, ecosystem: str, name: str) -> tuple[Advisory, ...]:
        """Every advisory for one package (any spelling of its name), one per flaw."""
        key = (ecosystem, canonical_name(ecosystem, name))
        built = self._built.get(key)
        if built is None:
            built = _grouped([_advisory(ecosystem, raw) for raw in self.raw.get(ecosystem, {}).get(key[1], ())])
            self._built[key] = built
        return built

    def match(self, ecosystem: str, name: str, version: str) -> list[Advisory]:
        """The advisories that list `version` of `name` as affected."""
        return [row for row in self.advisories(ecosystem, name) if row.matches(version)]

    def summary(self) -> dict[str, str]:
        """What a report says about the feed a scan read."""
        out = {"generatedAt": self.generated_at, "source": self.source, "origin": self.origin}
        if self.severity_floor:
            out["severityFloor"] = self.severity_floor
        return out


def parse_feed(data: object, origin: str, path: Path) -> AdvisoryFeed:
    """A feed from its parsed JSON; FeedError when it is not one.

    A document lists converted `entries` (the cached form) or OSV `records` as
    OSV returned them (the bundled form). An entry for a registry the feed does
    not cover, or without an id or a name, is skipped, so one bad entry costs
    only itself.
    """
    if not isinstance(data, dict):
        raise FeedError("not an advisory feed")
    if isinstance(data.get("entries"), list):
        rows = [row for row in data["entries"] if isinstance(row, dict)]
    elif isinstance(data.get("records"), list):
        rows = [row for record in data["records"] for e in ECOSYSTEMS for row in advisory_entries(record, e)]
    else:
        raise FeedError("no `entries` or `records` list")
    index: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for raw in rows:
        ecosystem, name = raw.get("ecosystem"), raw.get("name")
        if ecosystem not in ECOSYSTEMS or not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(raw.get("id"), str) or not raw["id"]:
            continue
        index.setdefault(ecosystem, {}).setdefault(canonical_name(ecosystem, name), []).append(raw)
    floor = data.get("severity_floor")
    return AdvisoryFeed(
        generated_at=str(data.get("generated_at") or ""),
        source=str(data.get("source") or ""),
        origin=origin,
        path=path,
        severity_floor=floor if floor in SEVERITIES else "",
        raw=index,
    )


_LOADED: dict[tuple[str, int, int], AdvisoryFeed] = {}


def _load(path: Path, origin: str) -> AdvisoryFeed:
    st = path.stat()
    key = (str(path), st.st_mtime_ns, st.st_size)
    cached = _LOADED.get(key)
    if cached is not None:
        return cached
    with path.open("r", encoding="utf-8") as handle:
        feed = parse_feed(json.load(handle), origin, path)
    if len(_LOADED) >= 2:
        _LOADED.clear()
    _LOADED[key] = feed
    return feed


def load_feed() -> AdvisoryFeed:
    """The cached feed when it exists and parses, else the bundled one.

    Never touches the network. Each file is parsed once per process for as long
    as it is unchanged.
    """
    cached = cache_path()
    if cached.is_file():
        try:
            return _load(cached, "cached")
        except (OSError, ValueError):
            pass
    return _load(BUNDLED_FEED, "bundled")


def feed_summary() -> dict[str, str]:
    """`AdvisoryFeed.summary()` for the feed a scan reads (see `load_feed`)."""
    return load_feed().summary()


# ---- rebuilding the cached feed (`aak update`) -------------------------------------------------


@dataclass(frozen=True)
class Written:
    """What a rebuild wrote."""

    path: Path
    generated_at: str
    counts: dict[str, int]   # entries per registry
    packages: int
    size: int                # bytes written
    full_size: int           # bytes before a cut to HIGH and CRITICAL; == size when none
    severity_floor: str


class Collector:
    """Gathers advisory entries as `malicious_feed.refresh` reads the exports.

    `add` is the `on_record` hook; `write` turns what was gathered into the
    cached feed, once the downloads have all been read.
    """

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def add(self, ecosystem: str, record: dict[str, Any]) -> None:
        self.entries.extend(advisory_entries(record, ecosystem))

    def write(self, now: datetime | None = None, limit: int = MAX_FEED_BYTES) -> Written:
        """Write the cached feed atomically; the old one stays on any failure.

        Args:
            now: The time recorded as `generated_at` (tests pin it).
            limit: The size above which only HIGH and CRITICAL records are kept.

        Raises:
            OSError: The file could not be written; nothing was replaced.
        """
        entries = sorted(self.entries, key=lambda e: (e["ecosystem"], canonical_name(e["ecosystem"], e["name"]), e["id"]))
        generated = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        source = ("OSV advisory records, every one but MAL- and withdrawn ones ("
                  + ", ".join(OSV_EXPORT.format(ecosystem=e) for e in ECOSYSTEMS) + ")")
        document: dict[str, Any] = {"generated_at": generated, "source": source, "severity_floor": "", "entries": entries}
        body = json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        full_size = len(body)
        if full_size > limit:
            kept = [e for e in entries if e["severity"] in ("HIGH", "CRITICAL")]
            document.update(severity_floor="HIGH", entries=kept,
                            source=source + f"; HIGH and CRITICAL only, the full feed being {full_size:,} bytes")
            body = json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        target = cache_path()
        parse_feed(json.loads(body), "cached", target)  # refuse to write what a scan could not read
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".advisories-", suffix=".json", dir=target.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(body)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        kept_entries = document["entries"]
        counts = {e: sum(1 for row in kept_entries if row["ecosystem"] == e) for e in ECOSYSTEMS}
        packages = len({(row["ecosystem"], canonical_name(row["ecosystem"], row["name"])) for row in kept_entries})
        return Written(target, generated, counts, packages, len(body), full_size, document["severity_floor"])


__all__ = [
    "Advisory",
    "AdvisoryFeed",
    "BUNDLED_FEED",
    "Collector",
    "MAX_FEED_BYTES",
    "Written",
    "advisory_entries",
    "bucket",
    "cache_path",
    "cvss3_base_score",
    "feed_summary",
    "intervals",
    "load_feed",
    "parse_feed",
    "record_severity",
]
