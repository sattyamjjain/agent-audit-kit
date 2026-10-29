"""The known-malicious-release feed read by AAK-MALICIOUS-RELEASE-001.

A malicious release is a published artifact, not a flaw in a version range, and
nothing else in AAK knew one: litellm 1.107.0 (21 Oct 2026) sat above every
pinned floor, so every rule passed it. This feed lists releases a source has
called malicious, by package version (PyPI and npm) and by image digest.

Load order, as `vuln_db.load_database` reads its database: the cached feed at
`~/.agent-audit-kit/malicious_releases.json` when it exists and parses, else the
bundled `data/malicious_releases.json`. A scan never touches the network.
`aak update` rebuilds the cached copy (`refresh`), from:

* OSV's per-ecosystem exports for PyPI and npm (`<ECOSYSTEM>/all.zip`, the
  location https://google.github.io/osv.dev/data/ gives), keeping only `MAL-`
  records, the OpenSSF Malicious Packages data. On 2026-10-28 the PyPI export was
  37 MB with 11,960 such records and the npm export 219 MB with 222,857. The
  same walk over each export (`export_records`) hands every other record to
  the advisory feed (`agent_audit_kit.advisory_feed`), so `aak update`
  downloads and reads each export once for both.
* GitHub's global advisories of type `malware` for npm and pip, with
  `aak update --github-malware` and a token (`GITHUB_TOKEN` or `GH_TOKEN`). On
  2026-10-28 GitHub listed 109,402 for npm and 11,915 for pip, 1,215 pages of
  100 that took 16.5 minutes to page, so this is opt-in: a token is in the
  environment of most CI jobs, and paging them would add that to every update.
  An advisory OSV already lists under an alias is not added twice.

The bundled entries and the image digests, which neither source carries, are
kept in every rebuilt copy. A failed rebuild leaves the cached copy as it was and
writes nothing: the new file is written beside it and renamed over it only once
it is complete.

What a feed entry means
-----------------------
An entry names one package on one registry and either the versions that are
malicious, or every version (an OSV range opened at 0 and never closed, the shape
of most typosquats), or, for npm, semver ranges. A version matches exactly, after
PEP 440 normalisation for PyPI (`1.107` is `1.107.0`; `1.107.0rc1` is not) and as
written for npm. npm's own `0.0.1-security` placeholder, which replaces a removed
package, is never matched. An image entry names digests; a tag is listed for the
record and never matched, because a tag moves and a digest does not.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path
from typing import AbstractSet, Any, Callable, Iterable, Iterator

BUNDLED_FEED: Path = Path(__file__).parent / "data" / "malicious_releases.json"
FEED_FILE_NAME = "malicious_releases.json"
OSV_EXPORT = "https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip"
GITHUB_ADVISORIES = "https://api.github.com/advisories?type=malware&ecosystem={ecosystem}&per_page=100"
#: The registries the feed covers, as OSV names them, and as GitHub does.
ECOSYSTEMS = ("PyPI", "npm")
_GITHUB_ECOSYSTEMS = {"npm": "npm", "pip": "PyPI"}
_DOWNLOAD_CHUNK = 1 << 20


def cache_path() -> Path:
    """Where `aak update` keeps the rebuilt feed (read at call time, so a
    changed HOME, as the tests set one, is honoured)."""
    return Path.home() / ".agent-audit-kit" / FEED_FILE_NAME


# ---- names and versions ---------------------------------------------------------

_PEP503_RE = re.compile(r"[-_.]+")
_PEP440_RE = re.compile(
    r"^v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?P<pre>[-_.]?(?:alpha|beta|preview|pre|rc|a|b|c)[-_.]?\d*)?"
    r"(?P<post>-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*)?"
    r"(?P<dev>[-_.]?dev[-_.]?\d*)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$"
)
_PRE_NAMES = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def canonical_name(ecosystem: str, name: str) -> str:
    """A package name as its registry compares it: PEP 503 for PyPI, lower case for npm."""
    name = name.strip()
    return _PEP503_RE.sub("-", name).lower() if ecosystem == "PyPI" else name.lower()


def _digits(text: str | None) -> int:
    found = re.sub(r"[^0-9]", "", text or "")
    return int(found) if found else 0


def pep440_key(version: str) -> str:
    """A PyPI version in PEP 440 normal form, so equal versions compare equal.

    `1.107` and `1.107.0` are one version, `1.107.0-rc1` is `1.107.0rc1`, and a
    leading `v` is dropped. Text that is not a PEP 440 version is kept as
    written, lower case, and matches only itself.
    """
    text = version.strip().lower()
    m = _PEP440_RE.match(text)
    if m is None:
        return text
    release = [int(part) for part in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    out = ".".join(str(part) for part in release)
    epoch = int(m.group("epoch") or 0)
    if epoch:
        out = f"{epoch}!{out}"
    if m.group("pre"):
        letters = re.sub(r"[^a-z]", "", m.group("pre"))
        out += f"{_PRE_NAMES.get(letters, letters)}{_digits(m.group('pre'))}"
    if m.group("post"):
        out += f".post{_digits(m.group('post'))}"
    if m.group("dev"):
        out += f".dev{_digits(m.group('dev'))}"
    if m.group("local"):
        out += "+" + re.sub(r"[-_]", ".", m.group("local"))
    return out


_PRE_RANK = {"a": 0, "b": 1, "rc": 2}


def pep440_order(version: str) -> tuple[Any, ...] | None:
    """A PyPI version as a tuple that orders as PEP 440 orders versions, or None
    for text that is not a PEP 440 version.

    The release compares without its trailing zeros (`3.12` is `3.12.0`); a
    development release of a final release sorts before its pre-releases
    (`1.0.dev1` < `1.0a1`), a pre-release before the release (`3.12.0rc0` <
    `3.12.0`), a post-release after it, and a local label after the public
    version. An advisory range such as MLflow's `>=3.12.0rc0, <3.17.0` needs
    this: `pep440_key` only says whether two versions are equal.
    """
    m = _PEP440_RE.match(version.strip().lower())
    if m is None:
        return None
    release = [int(part) for part in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_text, post_text, dev_text = m.group("pre"), m.group("post"), m.group("dev")
    if pre_text:
        letters = re.sub(r"[^a-z]", "", pre_text)
        pre = (_PRE_RANK[_PRE_NAMES.get(letters, letters)], _digits(pre_text))
    elif dev_text and not post_text:
        pre = (-1, 0)  # `1.0.dev1` sorts before `1.0a1`
    else:
        pre = (3, 0)   # a release sorts after its pre-releases
    post = _digits(post_text) if post_text else -1
    dev = (0, _digits(dev_text)) if dev_text else (1, 0)
    local = m.group("local")
    local_key = tuple(
        (1, int(part), "") if part.isdigit() else (0, 0, part) for part in re.split(r"[-_.]", local)
    ) if local else ()
    return int(m.group("epoch") or 0), tuple(release), pre, post, dev, local_key


def version_key(ecosystem: str, version: str) -> str:
    """A version as the feed compares it for this registry."""
    if ecosystem == "PyPI":
        return pep440_key(version)
    return version.strip().lstrip("=v").strip().lower()


def version_order(ecosystem: str, version: str) -> tuple[Any, ...] | None:
    """A version as a tuple that orders as its registry orders versions: PEP 440
    for PyPI, semver 2.0 for npm. None when the text is not such a version."""
    if ecosystem == "PyPI":
        return pep440_order(version)
    return _semver(version_key(ecosystem, version))


def _semver(version: str) -> tuple[Any, ...] | None:
    """A semver version as a tuple that orders as semver 2.0 orders versions."""
    m = _SEMVER_RE.match(version.strip())
    if m is None:
        return None
    pre = m.group(4)
    if pre is None:
        tail: tuple[Any, ...] = (1,)
    else:
        tail = (0,) + tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")
        )
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), tail)


# ---- the feed -----------------------------------------------------------------------


@dataclass(frozen=True)
class Range:
    """One interval of an entry: from `introduced` (inclusive; "0" is the first
    release) to `fixed` (exclusive) or `last_affected` (inclusive), compared as
    the entry's registry orders versions (`version_order`): semver for npm, the
    malicious feed's only ranges, and PEP 440 for the advisory feed's PyPI ones."""

    introduced: str
    fixed: str | None = None
    last_affected: str | None = None
    ecosystem: str = "npm"

    @cached_property
    def bounds(self) -> tuple[tuple[Any, ...] | None, tuple[Any, ...] | None, tuple[Any, ...] | None] | None:
        """(introduced, fixed, last_affected) as `version_order` keys, None for an
        end that is open; None altogether when a bound is not a version of this
        registry, since such a range cannot be evaluated. Read once per range."""
        keys: list[tuple[Any, ...] | None] = []
        for value in (None if self.introduced == "0" else self.introduced, self.fixed, self.last_affected):
            key = None if value is None else version_order(self.ecosystem, value)
            if value is not None and key is None:
                return None
            keys.append(key)
        return keys[0], keys[1], keys[2]

    def admits_key(self, v: tuple[Any, ...]) -> bool:
        """Does the range admit a version, given as its `version_order` key?"""
        bounds = self.bounds
        if bounds is None:
            return False
        low, fixed, last = bounds
        return (low is None or v >= low) and (fixed is None or v < fixed) and (last is None or v <= last)

    def admits(self, version: str) -> bool:
        v = version_order(self.ecosystem, version)
        return v is not None and self.admits_key(v)


@dataclass(frozen=True)
class Release:
    """One feed entry: a package whose listed releases are malicious."""

    id: str
    aliases: tuple[str, ...]
    ecosystem: str
    name: str
    versions: frozenset[str]          # version keys (see `version_key`)
    all_versions: bool
    ranges: tuple[Range, ...]
    modified: str
    url: str

    def matches(self, version: str | None) -> bool:
        """Does a declaration of `version` (None: no exact version) install a
        release this entry lists?"""
        if self.all_versions:
            return version is None or not version_key(self.ecosystem, version).endswith("-security")
        if version is None:
            return False
        key = version_key(self.ecosystem, version)
        return key in self.versions or any(r.admits(key) for r in self.ranges)

    def describe(self, version: str | None) -> str:
        """`{id}` and its aliases, then what of the package it lists."""
        ids = self.id + (f" ({', '.join(self.aliases)})" if self.aliases else "")
        if self.all_versions:
            return f"{ids}, which lists every release of {self.name}"
        return f"{ids}, which lists {self.name} {version}"


@dataclass(frozen=True)
class Image:
    """One feed image entry: digests of malicious image indexes or manifests."""

    id: str
    image: str
    digests: frozenset[str]
    tags: tuple[str, ...]
    url: str


@dataclass(frozen=True)
class Feed:
    """A loaded feed: where it came from, and its entries indexed by name.

    The index holds each entry as parsed and builds its `Release` the first
    time its package is looked up: a rebuilt feed lists about 234,000 packages,
    and building them all took 1.4 s of a 1.8 s load, where a project names a
    few hundred at most.
    """

    generated_at: str
    source: str
    origin: str      # "cached" or "bundled"
    path: Path
    raw: dict[str, dict[str, list[dict[str, Any]]]] = field(default_factory=dict)
    images: dict[str, Image] = field(default_factory=dict)
    _built: dict[tuple[str, str], tuple[Release, ...]] = field(
        default_factory=dict, compare=False, repr=False
    )

    def names(self, ecosystem: str) -> AbstractSet[str]:
        """The canonical package names the feed lists on one registry."""
        return self.raw.get(ecosystem, {}).keys()

    def releases(self, ecosystem: str, name: str) -> tuple[Release, ...]:
        """Every entry for one package (any spelling of its name)."""
        key = (ecosystem, canonical_name(ecosystem, name))
        built = self._built.get(key)
        if built is None:
            built = tuple(_release(ecosystem, raw) for raw in self.raw.get(ecosystem, {}).get(key[1], ()))
            self._built[key] = built
        return built

    def match(self, ecosystem: str, name: str, version: str | None) -> list[Release]:
        """The entries a declaration of `name` at `version` (None: no exact
        version) matches."""
        return [row for row in self.releases(ecosystem, name) if row.matches(version)]

    def image(self, digest: str) -> Image | None:
        """The entry listing an image digest (`sha256:<64 hex>`), if any."""
        return self.images.get(digest.lower())

    def summary(self) -> dict[str, str]:
        """What a report says about the feed a scan read."""
        return {
            "generatedAt": self.generated_at,
            "source": self.source,
            "origin": self.origin,
        }


class FeedError(ValueError):
    """A feed file that is not a feed."""


def _strings(value: object) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


def _release(ecosystem: str, raw: dict[str, Any]) -> Release:
    ranges = tuple(
        Range(str(r["introduced"]), _optional(r.get("fixed")), _optional(r.get("last_affected")))
        for r in raw.get("ranges") or ()
        if isinstance(r, dict) and isinstance(r.get("introduced"), str)
    ) if ecosystem == "npm" else ()
    return Release(
        id=str(raw["id"]),
        aliases=_strings(raw.get("aliases")),
        ecosystem=ecosystem,
        name=str(raw["name"]),
        versions=frozenset(version_key(ecosystem, v) for v in _strings(raw.get("versions"))),
        all_versions=raw.get("all_versions") is True,
        ranges=ranges,
        modified=str(raw.get("modified") or ""),
        url=str(raw.get("url") or ""),
    )


def _optional(value: object) -> str | None:
    return value if isinstance(value, str) else None


def parse_feed(data: object, origin: str, path: Path) -> Feed:
    """A feed from its parsed JSON; FeedError when it is not one.

    Entries for a registry the feed does not cover, or without an id or a name,
    are skipped, so one bad entry costs only itself.
    """
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise FeedError("no `entries` list")
    index: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for raw in data["entries"]:
        if not isinstance(raw, dict):
            continue
        ecosystem, name = raw.get("ecosystem"), raw.get("name")
        if ecosystem not in ECOSYSTEMS or not isinstance(name, str) or not name or not isinstance(raw.get("id"), str):
            continue
        index.setdefault(ecosystem, {}).setdefault(canonical_name(ecosystem, name), []).append(raw)
    images: dict[str, Image] = {}
    for raw in data.get("oci") or ():
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            continue
        entry = Image(
            id=raw["id"],
            image=str(raw.get("image") or ""),
            digests=frozenset(d.lower() for d in _strings(raw.get("digests"))),
            tags=_strings(raw.get("tags")),
            url=str(raw.get("url") or ""),
        )
        for digest in entry.digests:
            images[digest] = entry
    return Feed(
        generated_at=str(data.get("generated_at") or ""),
        source=str(data.get("source") or ""),
        origin=origin,
        path=path,
        raw=index,
        images=images,
    )


_LOADED: dict[tuple[str, int, int], Feed] = {}


def _load(path: Path, origin: str) -> Feed:
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


def load_feed() -> Feed:
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
    """`Feed.summary()` for the feed a scan reads (see `load_feed`)."""
    return load_feed().summary()


# ---- rebuilding the cached feed (`aak update`) ---------------------------------------


class FeedUpdateError(RuntimeError):
    """A rebuild that failed. The cached feed, if any, was left as it was."""


@dataclass(frozen=True)
class Refreshed:
    """What a rebuild wrote."""

    path: Path
    generated_at: str
    counts: dict[str, int]  # entries taken from each source
    github: str             # "read", or why it was skipped


Opener = Callable[..., Any]

#: A bound on GitHub pages per ecosystem, so a pagination loop cannot run away.
_GITHUB_MAX_PAGES = 2000
#: A bound on one OSV record's size inside an export (a record is a few KB).
_MAX_RECORD_BYTES = 1_000_000
_LINK_NEXT_RE = re.compile(r'<(https://api\.github\.com/[^>]+)>;\s*rel="next"')


def _intervals(events: object) -> tuple[bool, list[dict[str, str]]]:
    """(every version, the other intervals) of one OSV range's events, in order."""
    intervals: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for event in events if isinstance(events, list) else ():
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            current = {"introduced": str(event["introduced"])}
            intervals.append(current)
        elif current is not None and ("fixed" in event or "last_affected" in event):
            key = "fixed" if "fixed" in event else "last_affected"
            current[key] = str(event[key])
            current = None
    every = {"introduced": "0"} in intervals
    return every, [i for i in intervals if i != {"introduced": "0"}]


def osv_entries(record: object, ecosystem: str) -> list[dict[str, Any]]:
    """Feed entries for one OSV `MAL-` record's packages on `ecosystem`.

    A withdrawn record gives none. An npm SEMVER range is kept as intervals; a
    PyPI range other than "every version" is read through the record's version
    list, which every `MAL-` record read on 2026-10-28 carried.
    """
    if not isinstance(record, dict) or record.get("withdrawn"):
        return []
    ident = record.get("id")
    if not isinstance(ident, str) or not ident.startswith("MAL-"):
        return []
    out: list[dict[str, Any]] = []
    for affected in record.get("affected") or ():
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem or not isinstance(name, str):
            continue
        versions = sorted({v for v in affected.get("versions") or () if isinstance(v, str)})
        every, ranges = False, []
        for found in affected.get("ranges") or ():
            if not isinstance(found, dict):
                continue
            all_of_it, intervals = _intervals(found.get("events"))
            every = every or all_of_it
            if ecosystem == "npm" and found.get("type") == "SEMVER":
                ranges.extend(intervals)
        if not (versions or every or ranges):
            continue
        entry: dict[str, Any] = {
            "id": ident,
            "aliases": [a for a in record.get("aliases") or () if isinstance(a, str)],
            "ecosystem": ecosystem,
            "name": name,
            "versions": versions,
            "modified": str(record.get("modified") or ""),
            "url": f"https://osv.dev/vulnerability/{ident}",
        }
        if every:
            entry["all_versions"] = True
        elif ranges:
            entry["ranges"] = ranges
        out.append(entry)
    return out


def _download(url: str, directory: Path, opener: Opener, timeout: float) -> Path:
    """`url` streamed to a new file in `directory`; removed again on failure."""
    from agent_audit_kit import __version__

    fd, name = tempfile.mkstemp(prefix=".osv-export-", suffix=".zip", dir=directory)
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as out:
            request = urllib.request.Request(url, headers={"User-Agent": f"agent-audit-kit/{__version__}"})
            with opener(request, timeout=timeout) as response:
                shutil.copyfileobj(response, out, _DOWNLOAD_CHUNK)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def _is_malicious_record(file_name: str) -> bool:
    return file_name.startswith("MAL-")


def export_records(archive: Path, want: Callable[[str], bool] | None = None) -> Iterator[dict[str, Any]]:
    """Every OSV record in one per-ecosystem export, parsed, in archive order.

    The one walk over an export: the malicious-release feed takes its `MAL-`
    records from it and the advisory feed every other one, so `aak update`
    reads each export once for both. `want` is given a record's file name
    (`MAL-2026-2144.json`) and says whether to parse it at all; a record over
    `_MAX_RECORD_BYTES`, or one that is not a JSON object, is skipped. A record
    that is not JSON raises, and fails the rebuild, as it always has.
    """
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            base = info.filename.rsplit("/", 1)[-1]
            if not base.endswith(".json") or info.file_size > _MAX_RECORD_BYTES:
                continue
            if want is not None and not want(base):
                continue
            record = json.loads(bundle.read(info))
            if isinstance(record, dict):
                yield record


def _github_interval(spec: str) -> tuple[bool, list[str], dict[str, str] | None]:
    """(every version, exact versions, interval) for one GitHub
    `vulnerable_version_range` (`>= 0`, `= 1.2.3`, `>= 1.0.0, < 1.2.0`)."""
    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    if clauses == [">= 0"]:
        return True, [], None
    if len(clauses) == 1 and clauses[0].startswith("= "):
        return False, [clauses[0][2:].strip()], None
    interval: dict[str, str] = {"introduced": "0"}
    for clause in clauses:
        op, _, value = clause.partition(" ")
        value = value.strip()
        if op == ">=":
            interval["introduced"] = value
        elif op == "<":
            interval["fixed"] = value
        elif op == "<=":
            interval["last_affected"] = value
        else:
            return False, [], None  # `>` has no inclusive form; not read
    return False, [], interval


def github_entries(advisories: Iterable[object]) -> list[dict[str, Any]]:
    """Feed entries for GitHub malware advisories (the REST `GET /advisories` shape)."""
    out: list[dict[str, Any]] = []
    for advisory in advisories:
        if not isinstance(advisory, dict) or advisory.get("withdrawn_at"):
            continue
        ident = advisory.get("ghsa_id")
        if not isinstance(ident, str):
            continue
        aliases = sorted({
            str(i.get("value")) for i in advisory.get("identifiers") or ()
            if isinstance(i, dict) and i.get("value") and i.get("value") != ident
        })
        for vuln in advisory.get("vulnerabilities") or ():
            if not isinstance(vuln, dict):
                continue
            package = vuln.get("package") or {}
            ecosystem = _GITHUB_ECOSYSTEMS.get(str(package.get("ecosystem")))
            name = package.get("name")
            spec = vuln.get("vulnerable_version_range")
            if ecosystem is None or not isinstance(name, str) or not isinstance(spec, str):
                continue
            every, versions, interval = _github_interval(spec)
            if interval is not None and ecosystem != "npm":
                continue  # a PyPI range other than every version is not evaluated
            if not (every or versions or interval):
                continue
            entry: dict[str, Any] = {
                "id": ident,
                "aliases": aliases,
                "ecosystem": ecosystem,
                "name": name,
                "versions": versions,
                "modified": str(advisory.get("updated_at") or ""),
                "url": str(advisory.get("html_url") or f"https://github.com/advisories/{ident}"),
            }
            if every:
                entry["all_versions"] = True
            elif interval is not None:
                entry["ranges"] = [interval]
            out.append(entry)
    return out


def _github_advisories(token: str, opener: Opener, timeout: float) -> Iterable[object]:
    from agent_audit_kit import __version__

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": f"agent-audit-kit/{__version__}",
    }
    for github_ecosystem in _GITHUB_ECOSYSTEMS:
        url: str | None = GITHUB_ADVISORIES.format(ecosystem=github_ecosystem)
        pages = 0
        while url:
            pages += 1
            if pages > _GITHUB_MAX_PAGES:
                raise FeedUpdateError(f"GitHub advisories: more than {_GITHUB_MAX_PAGES} pages of {github_ecosystem}")
            with opener(urllib.request.Request(url, headers=headers), timeout=timeout) as response:
                page = json.load(response)
                link = response.headers.get("Link", "") or ""
            if not isinstance(page, list):
                raise FeedUpdateError("GitHub advisories: a page that is not a list")
            yield from page
            found = _LINK_NEXT_RE.search(link)
            url = found.group(1) if found else None


def _write_atomically(path: Path, document: dict[str, Any]) -> None:
    fd, name = tempfile.mkstemp(prefix=".malicious-releases-", suffix=".json", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(document, out, separators=(",", ":"), ensure_ascii=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def refresh(
    github_token: str | None = None,
    opener: Opener | None = None,
    timeout: float = 300.0,
    now: datetime | None = None,
    on_record: Callable[[str, dict[str, Any]], None] | None = None,
) -> Refreshed:
    """Rebuild the cached feed. Network; called by `aak update`, never by a scan.

    Args:
        github_token: A GitHub token, to add GitHub's malware advisories; None
            skips them (60 unauthenticated requests an hour cannot page them).
        opener: Opens a request; `urllib.request.urlopen`, looked up at call time, by default.
        timeout: Seconds per request.
        now: The time recorded as `generated_at` (tests pin it).
        on_record: Called with (ecosystem, record) for every record of every
            export, `MAL-` or not, as the export is read: `aak update` builds the
            advisory feed this way from the same downloads. None reads only the
            `MAL-` records.

    Returns:
        What was written.

    Raises:
        FeedUpdateError: Any download, parse or write failed, `on_record`'s
            included. Nothing was written; the cached feed, if any, is as it was.
    """
    opener = opener or urllib.request.urlopen
    target = cache_path()
    downloads: list[Path] = []
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        entries: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        for ecosystem in ECOSYSTEMS:
            archive = _download(OSV_EXPORT.format(ecosystem=ecosystem), target.parent, opener, timeout)
            downloads.append(archive)
            rows: list[dict[str, Any]] = []
            for record in export_records(archive, None if on_record else _is_malicious_record):
                rows.extend(osv_entries(record, ecosystem))
                if on_record is not None:
                    on_record(ecosystem, record)
            counts[f"OSV {ecosystem}"] = len(rows)
            entries.extend(rows)
        known = {e["id"] for e in entries} | {alias for e in entries for alias in e["aliases"]}
        github = "skipped (add them with --github-malware and a GITHUB_TOKEN or GH_TOKEN)"
        if github_token:
            rows = [r for r in github_entries(_github_advisories(github_token, opener, timeout)) if r["id"] not in known]
            counts["GitHub"] = len(rows)
            entries.extend(rows)
            github = "read"
        bundled = json.loads(BUNDLED_FEED.read_text(encoding="utf-8"))
        ids = {e["id"] for e in entries}
        kept = [e for e in bundled.get("entries", ()) if isinstance(e, dict) and e.get("id") not in ids]
        counts["bundled"] = len(kept)
        entries.extend(kept)
        entries.sort(key=lambda e: (e["ecosystem"], canonical_name(e["ecosystem"], e["name"]), e["id"]))
        generated = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        source = "OSV MAL- records (" + ", ".join(OSV_EXPORT.format(ecosystem=e) for e in ECOSYSTEMS) + ")"
        if github == "read":
            source += ", GitHub malware advisories (api.github.com/advisories?type=malware)"
        source += ", and the entries and image digests bundled with agent-audit-kit"
        document = {"generated_at": generated, "source": source, "entries": entries, "oci": bundled.get("oci", [])}
        parse_feed(document, "cached", target)  # refuse to write what a scan could not read
        _write_atomically(target, document)
    except FeedUpdateError:
        raise
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        raise FeedUpdateError(f"{type(exc).__name__}: {exc}") from exc
    finally:
        for archive in downloads:
            archive.unlink(missing_ok=True)
    return Refreshed(target, generated, counts, github)
