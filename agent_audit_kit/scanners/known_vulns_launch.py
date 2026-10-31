"""AAK-KNOWN-VULN-002: a launched MCP server, binary or image an NVD advisory lists as affected.

On 0.6.29, and on main after AAK-KNOWN-VULN-001 learned NVD's CNA records, a
project whose `.mcp.json` launched MoLing 0.4.0 scanned clean. MoLing is a Go MCP
server shipped as a binary, and before 0.5.0 its SSE endpoints took no
authentication (CVE-2026-62863, CVSS 9.6). NVD's record names vendor `gojue` and
product `moling`, no PyPI or npm package, so no package row could map it. TAKO, an
Okta agent app shipped as the image `fctrid/ai-agent-for-okta`, was in the same
place (CVE-2026-63377, 9.8). The advisory feed now keeps such records in its
`launch` list, mapped by the reviewed launch rows of `data/cna_package_map.json`,
each with the names a project starts the software by (`nvd_feed`'s "What a
project launches"). This module matches them against what a project starts. A
scan never touches the network; without `aak update` the feed holds the bundled
launch entries alone.

What it reads, outside `SKIP_DIRS`, through `container_image_pins`' walk:

* JSON MCP client configs (`*mcp*.json`, `claude_desktop_config.json`), parsed as
  JSONC, every server of `mcpServers` or VS Code's `servers` (`iter_mcp_servers`):
  its `command` by file name (`/usr/local/bin/moling` is `moling`, `.exe` and the
  like dropped); `go run <module>@<version>`, the module matched at a path
  boundary; the image a `docker`, `podman` or `nerdctl` `run` starts; an argument
  that is a `github.com/<owner>/<repo>` URL, with the release its `@`, `#`,
  `/releases/tag/`, `/releases/download/`, `/tree/` or `/archive/` part names; and
  a command line behind `sh -c`, `bash -c`, `cmd /c` or PowerShell's `-Command`,
  two levels deep. A server named only by a URL starts nothing and is not read.
* YAML (compose files, Kubernetes manifests, Helm values) and Dockerfiles: every
  reference to a launch row's image, read where `container_image_pins` reads one
  (an `image:` value, a `FROM` line, a whole quoted string, a Helm `repository`
  with its `tag`; a commented-out line skipped), with the `docker.io/` spellings
  of a Docker Hub image too.

How a release is read
---------------------
As semver 2.0 with a leading `v` dropped (`advisory_feed.LAUNCH`), the order
GitHub writes these ranges in: a Go pseudo-version is a pre-release of the
release after it, and `3.0.1-alpha` sorts below `3.0.1-beta`. TAKO's own compose
file at v3.0.1-beta runs the tag `3.0.1-alpha`, which Docker Hub received an hour
before the fix commit, so that order is the right one for it. It also makes any
tag suffix a pre-release: `1.2.3-alpine` sorts below 1.2.3. A two-part tag or Go
query (`3.1`, `@v0.4`) floats over its line and is a release in the range only
when every release on the line is. A launch that names no release could not be
read: a bare command, `latest`, an untagged or digest-only image, a branch, a
commit, text that is not a version, or a two-part tag whose line holds affected
and fixed releases.

One finding per file and advisory: at the record's severity on the first launch
whose release is in the range, saying how many more are; else MEDIUM on the first
launch whose release could not be read, naming the range and the fixed release.
A launch whose release is outside the range gives none. The evidence names the
advisory's CVE ids, so where another rule reports them on the same line of the
same file at or above this finding's severity, the engine keeps that rule's
finding alone (`engine._drop_known_vulns_a_rule_reports`), as for
AAK-KNOWN-VULN-001.

Every reader is one pass over its file: matches come in order, and a line's
bounds, its first comment and its `FROM` image are found once per line, so a
crafted file with many references on one line costs what its length does.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from agent_audit_kit.advisory_feed import LAUNCH, Advisory, AdvisoryFeed, LaunchAdvisory, load_feed
from agent_audit_kit.malicious_feed import version_order
from agent_audit_kit.models import Finding, Severity

from ._helpers import iter_mcp_servers, linear_find, loads_jsonc, make_finding, placed, read_text_capped
from ._launchers import basename, shell_tokens
from .container_image_pins import _COMMENT_RE, _TAG_RE, _candidates, _helm_refs
from .known_vulns import _feed_note, _fix

RULE = "AAK-KNOWN-VULN-002"
#: Files over this many bytes are not read, as `container_image_pins` reads them.
MAX_FILE_BYTES = 2_000_000
#: How much of a launch a finding quotes.
_SHOWN = 160
_LEVEL = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM}
_RUNNERS = frozenset({"docker", "podman", "nerdctl"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "cmd", "powershell", "pwsh"})
_SHELL_FLAGS = frozenset({"-c", "/c", "/k", "-command"})
_MAX_DEPTH = 2
_GO_QUERIES = frozenset({"latest", "upgrade", "patch"})
_DOCKER_HUB = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")
# `container_image_pins._COMMENT_RE`, matched from a line start inside the whole text.
_LINE_COMMENT_RE = re.compile(_COMMENT_RE.pattern, re.M)
_URL_PREFIXES = ("git+", "https://", "http://", "git://", "ssh://", "git@", "www.")
_REPO_RE = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+)", re.I)
_REF_RE = re.compile(r"(?:@|#|/releases/tag/|/releases/download/|/tree/|/archive/refs/tags/|/archive/)([^/@#?\s]+)")
_ARCHIVE_RE = re.compile(r"\.(?:tar\.gz|tgz|zip)$", re.I)
_TWO_PART_RE = re.compile(r"v?(\d+)\.(\d+)")
_DIGEST_RE = re.compile(r"@[A-Za-z0-9_+.-]+:[0-9a-fA-F]{32,}")
# A `FROM` line up to its image, as `container_image_pins._in_image_slot` splits it.
_FROM_RE = re.compile(r"\s*FROM\s+(?:--\S*\s+)*(?=\S)", re.I)


@dataclass(frozen=True)
class _Launch:
    """One launch of a launch row's software, as a file writes it."""

    shown: str               # quoted in the finding
    version: str | None      # the release it names, None for none
    why: str = ""            # why no release is read, when it names none
    key: str | None = None   # text that places an MCP config's launch on its line
    line: int | None = None  # its line, when the reader knows it


@dataclass
class _Index:
    """The feed's launch entries by each way they are launched."""

    commands: dict[str, list[LaunchAdvisory]] = field(default_factory=dict)
    modules: list[tuple[str, LaunchAdvisory]] = field(default_factory=list)
    images: dict[str, list[LaunchAdvisory]] = field(default_factory=dict)
    repos: dict[str, list[LaunchAdvisory]] = field(default_factory=dict)
    needles: set[str] = field(default_factory=set)
    image_res: list[tuple[re.Pattern[str], list[LaunchAdvisory]]] = field(default_factory=list)


def _image_name(name: str) -> str:
    """An image name as rows and references compare it: lower case, a Docker Hub
    registry spelling dropped."""
    name = name.strip().lower()
    for prefix in _DOCKER_HUB:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _index(launches: tuple[LaunchAdvisory, ...]) -> _Index:
    index = _Index()
    for entry in launches:
        for command in entry.commands:
            index.commands.setdefault(command, []).append(entry)
            index.needles.add(command)
        for module in entry.go_modules:
            index.modules.append((module, entry))
            index.needles.add(module)
        for image in entry.images:
            index.images.setdefault(_image_name(image), []).append(entry)
            index.needles.add(_image_name(image))
        if entry.repo:
            index.repos.setdefault(entry.repo, []).append(entry)
            index.needles.add(entry.repo.split("/", 1)[-1])  # owner/repo, also in `github.com:owner/repo`
    index.image_res = _image_res(index)
    return index


# ---- what a release is ------------------------------------------------------------------------


def _line_reach(advisory: Advisory, major: int, minor: int) -> tuple[bool, bool]:
    """(every release on the major.minor line is affected, some release on it is),
    on semver keys: the line is [major.minor.0-0, major.(minor+1).0-0)."""
    low = version_order(LAUNCH, f"{major}.{minor}.0-0")
    high = version_order(LAUNCH, f"{major}.{minor + 1}.0-0")
    assert low is not None and high is not None
    whole = some = False
    for row in advisory.ranges:
        bounds = row.bounds
        if bounds is None:
            continue
        start, fixed, last = bounds
        opens_below = start is None or start <= low
        if (start is None or start < high) and (fixed is None or fixed > low) and (last is None or last >= low):
            some = True
            if opens_below and ((fixed is None and last is None) or (fixed is not None and fixed >= high)
                                or (last is not None and last >= high)):
                whole = True
    for listed in advisory.versions:
        key = version_order(LAUNCH, listed)
        if key is not None and low <= key < high:
            some = True
    return whole, some


def _judge(advisory: Advisory, version: str) -> tuple[str, str, str]:
    """("affected", the release as shown, the version its fix is judged at),
    ("clear", "", ""), or ("unread", why, "")."""
    text = version.strip()
    if version_order(LAUNCH, text) is not None:
        return ("affected", text, text) if advisory.matches(text) else ("clear", "", "")
    two = _TWO_PART_RE.fullmatch(text)
    if two is not None:
        major, minor = int(two.group(1)), int(two.group(2))
        whole, some = _line_reach(advisory, major, minor)
        if whole:
            return "affected", f"{text} (any {major}.{minor} release)", f"{major}.{minor}.0"
        if some:
            return "unread", f"`{text}` floats over the {major}.{minor} line, which holds affected and fixed releases", ""
        return "clear", "", ""
    return "unread", f"`{text[:40]}` is not a release", ""


# ---- MCP client configs ---------------------------------------------------------------------------


def _image_token(token: str) -> tuple[str, str | None, bool] | None:
    """(name, tag or None, has a digest) for an argument that reads as an image
    reference, None for one that cannot be one (an option, text with spaces)."""
    text = token.strip()
    if not text or text.startswith("-") or any(c.isspace() for c in text):
        return None
    name, at, _digest = text.partition("@")
    tag: str | None = None
    slash, colon = name.rfind("/"), name.rfind(":")
    if colon > slash:
        name, tag = name[:colon], name[colon + 1:]
    return name, tag or None, bool(at)


def _image_launch(shown: str, tag: str | None, digest: bool, key: str | None = None,
                  line: int | None = None) -> _Launch:
    if tag is None:
        why = "it is pinned by digest, which names no release" if digest else "it names no tag, so `latest`"
        return _Launch(shown, None, why, key, line)
    if tag.lower() == "latest":
        return _Launch(shown, None, "it is tagged `latest`", key, line)
    return _Launch(shown, tag, "", key, line)


def _module_launch(token: str, version: str | None) -> _Launch:
    shown = f"go run {token}"
    if version is None:
        return _Launch(shown, None, "it names no version, so the calling module or the newest release decides", token)
    if version.lower() in _GO_QUERIES:
        return _Launch(shown, None, f"it asks for `@{version[:20]}`, which names no release", token)
    return _Launch(shown, version, "", token)


def _repo_launch(token: str, rest: str) -> _Launch | None:
    """A launch from an argument that is a repository URL, by what follows the
    repository's name; None for a link into it (`/blob/...`, `/issues/...`)."""
    if rest in ("", "/", ".git"):
        return _Launch(token, None, "it names the repository and no release", token)
    m = _REF_RE.match(rest)
    if m is None:
        return None
    ref = _ARCHIVE_RE.sub("", m.group(1))
    if "=" in ref:  # pip's `#egg=name` fragment
        return _Launch(token, None, "it names the repository and no release", token)
    return _Launch(token, ref, "", token)


def _repo_launches(token: str, index: _Index) -> Iterator[tuple[LaunchAdvisory, _Launch]]:
    """The launches an argument makes when it is itself a GitHub repository URL."""
    lowered = token.strip().lower()
    head = lowered
    for prefix in _URL_PREFIXES:
        if head.startswith(prefix):
            head = head[len(prefix):]
    m = _REPO_RE.match(head)
    if m is None:
        return
    name = m.group(2)[:-4] if m.group(2).endswith(".git") else m.group(2)
    entries = index.repos.get(f"github.com/{m.group(1)}/{name}", ())
    if not entries:
        return
    offset = len(lowered) - len(head) + len(token) - len(token.lstrip())
    launch = _repo_launch(token, token[offset + m.end():].strip())
    if launch is not None:
        for entry in entries:
            yield entry, launch


def _argv_launches(argv: list[str], index: _Index, depth: int = 0) -> Iterator[tuple[LaunchAdvisory, _Launch]]:
    """The launches one server's argv makes, in order."""
    if not argv:
        return
    head = basename(argv[0]).lower()
    rest = argv[1:]
    for entry in index.commands.get(head, ()):
        yield entry, _Launch(argv[0], None, f"it starts the installed `{head}` binary, whose release the config "
                             "does not state", argv[0])
    if head == "go" and rest[:1] == ["run"]:
        for token in rest[1:]:
            module, at, version = token.partition("@")
            lowered = module.lower()
            for path, entry in index.modules:
                if lowered == path or lowered.startswith(path + "/"):
                    yield entry, _module_launch(token, version if at else None)
    if head in _RUNNERS and "run" in rest:
        for token in rest[rest.index("run") + 1:]:
            parsed = _image_token(token)
            if parsed is None:
                continue
            name, tag, digest = parsed
            for entry in index.images.get(_image_name(name), ()):
                yield entry, _image_launch(token, tag, digest, token)
    for token in rest:
        yield from _repo_launches(token, index)  # matches the repository anchored, after the URL scheme
    if depth < _MAX_DEPTH and head in _SHELLS:
        for i, token in enumerate(rest[:-1]):
            if token.lower() in _SHELL_FLAGS:
                yield from _argv_launches(shell_tokens(rest[i + 1]), index, depth + 1)
                break


def _argvs(server: dict[str, object]) -> Iterator[list[str]]:
    """The argv a server starts, and, for a `command` that holds a whole command
    line, that line split as a shell splits it."""
    command, args = server.get("command"), server.get("args")
    if isinstance(command, str) and command.strip():
        head = [command]
    elif isinstance(command, list):
        head = [part for part in command if isinstance(part, str)]
    else:
        return
    tail = [arg for arg in args if isinstance(arg, str)] if isinstance(args, list) else []
    yield head + tail
    if len(head) == 1 and any(c.isspace() for c in head[0].strip()):
        yield shell_tokens(head[0]) + tail


def _config_launches(path: Path, text: str, index: _Index) -> Iterator[tuple[LaunchAdvisory, _Launch]]:
    try:
        data = loads_jsonc(text, path)
    except json.JSONDecodeError:
        return  # no client loads it; a refused file is filed by the engine
    for _name, server in iter_mcp_servers(data):
        for argv in _argvs(server):
            yield from _argv_launches(argv, index)


# ---- YAML and Dockerfiles ---------------------------------------------------------------------------


class _Lines:
    """Line numbers, bounds and per-line facts for increasing offsets into one
    text, each line looked at once."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.line = 1
        self.start = 0
        self.end = self._end_of(0)
        self._comment: int | None = None
        self._from: int | None = None
        self._read = 0  # facts of this line read: 1 comment, 2 FROM slot

    def _end_of(self, offset: int) -> int:
        end = self.text.find("\n", offset)
        return len(self.text) if end < 0 else end

    def seek(self, offset: int) -> None:
        if offset <= self.end:
            return
        self.line += self.text.count("\n", self.end, offset)
        self.start = self.text.rfind("\n", self.end, offset) + 1
        self.end = self._end_of(offset)
        self._read = 0

    def commented_before(self, offset: int) -> bool:
        if not self._read & 1:
            m = _LINE_COMMENT_RE.search(self.text, self.start, self.end)
            self._comment = None if m is None else m.end() - 1
            self._read |= 1
        return self._comment is not None and self._comment < offset

    def from_slot(self) -> int | None:
        """Where a `FROM` line's image starts, past any `--platform=...` flags
        (`container_image_pins._in_image_slot`'s second case)."""
        if not self._read & 2:
            m = _FROM_RE.match(self.text, self.start, self.end)
            self._from = None if m is None else m.end()
            self._read |= 2
        return self._from

    def key_before(self, offset: int, key: str) -> bool:
        """Does the line read `<key> : ["']` right before `offset`, `key` a whole
        word in any case: `container_image_pins`' `\\b<key>\\s*:\\s*["']?$` on
        the line's prefix, read backwards over the whitespace before `offset`
        alone, which no other reference on the line shares."""
        text, i = self.text, offset
        if i > self.start and text[i - 1] in "\"'":
            i -= 1
        while i > self.start and text[i - 1].isspace():
            i -= 1
        if i <= self.start or text[i - 1] != ":":
            return False
        i -= 1
        while i > self.start and text[i - 1].isspace():
            i -= 1
        j = i - len(key)
        if j < self.start or text[j:i].lower() != key:
            return False
        return j == self.start or not (text[j - 1].isalnum() or text[j - 1] == "_")


def _image_res(index: _Index) -> list[tuple[re.Pattern[str], list[LaunchAdvisory]]]:
    """A pattern per launch image: its name between boundaries, as
    `container_image_pins._ref_re` reads one, and a Docker Hub name with any of the
    registry's spellings before it."""
    out: list[tuple[re.Pattern[str], list[LaunchAdvisory]]] = []
    for name, entries in sorted(index.images.items()):
        first = name.partition("/")[0]
        hub = not ("." in first or ":" in first or first == "localhost")
        spellings = r"(?:(?:docker\.io|index\.docker\.io|registry-1\.docker\.io)/)?" if hub else ""
        out.append((re.compile(r"(?<![\w./-])" + spellings + re.escape(name) + r"(?![\w./-])", re.I), entries))
    return out


def _inline_refs(text: str, kind: str, pattern: re.Pattern[str]) -> Iterator[tuple[str, str | None, bool, int]]:
    """(reference as written, tag or None, pinned by digest, line) for each
    reference to one image, read where `container_image_pins._inline_hit` reads
    one, plus a digest-only one in an image's place, in one pass."""
    lines = _Lines(text)
    for m in pattern.finditer(text):
        lines.seek(m.start())
        if lines.commented_before(m.start()):
            continue
        if kind == "yaml" and lines.key_before(m.start(), "repository"):
            continue  # a Helm `repository:` value, read with its `tag` by `_helm_refs`
        nxt = text[m.end():m.end() + 1]
        tag: str | None = None
        digest = False
        end = m.end()
        if nxt == ":":
            tag_m = _TAG_RE.match(text, m.end())
            if tag_m is None:
                continue  # `:${VAR}`: the file states no release
            tag, end = tag_m.group(1), tag_m.end()
        else:
            before = text[m.start() - 1:m.start()]
            if nxt == "@":
                digest_m = _DIGEST_RE.match(text, m.end())
                if digest_m is None:
                    continue
                digest, end = True, digest_m.end()
            quoted = before in ("'", '"') and text[end:end + 1] == before
            if not (quoted or lines.key_before(m.start(), "image") or lines.from_slot() == m.start()):
                continue  # a sentence naming the image is not a deployment
        yield text[m.start():end][:_SHOWN], tag, digest, lines.line


def _text_launches(path: Path, text: str, kind: str, index: _Index) -> Iterator[tuple[LaunchAdvisory, _Launch]]:
    for pattern, entries in index.image_res:
        for shown, tag, digest, line in _inline_refs(text, kind, pattern):
            for entry in entries:
                yield entry, _image_launch(shown, tag, digest, line=line)
    if kind == "yaml":
        for name, tag, line in sorted(_helm_refs(text, path), key=lambda ref: ref[2]):
            for entry in index.images.get(_image_name(name), ()):
                yield entry, _image_launch(f"{name}:{tag}"[:_SHOWN], tag, False, line=line)


# ---- findings ---------------------------------------------------------------------------------------


def _range_text(advisory: Advisory) -> str:
    """The advisory's affected releases as GitHub writes a range: `< 0.5.0`."""
    parts: list[str] = []
    for row in advisory.ranges:
        clauses = [] if row.introduced == "0" else [f">= {row.introduced}"]
        if row.fixed is not None:
            clauses.append(f"< {row.fixed}")
        elif row.last_affected is not None:
            clauses.append(f"<= {row.last_affected}")
        parts.append(", ".join(clauses) or "every release")
    parts.extend(f"= {version}" for version in sorted(advisory.versions))
    return "; ".join(parts) or "no release"


def _quote(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _SHOWN else text[:_SHOWN] + "..."


def _finding(rel: str, evidence: str, line: int | None, level: str) -> Finding:
    finding = make_finding(RULE, rel, evidence, line)
    severity = _LEVEL[level]
    return finding if finding.severity is severity else dataclasses.replace(finding, severity=severity)


def _decide(rel: str, name: str, feed: AdvisoryFeed, entry: LaunchAdvisory,
            launches: list[_Launch]) -> tuple[Finding, _Launch] | None:
    """The finding one advisory makes in one file, and the launch it is placed at."""
    advisory = entry.advisory
    affected: list[tuple[_Launch, str, str]] = []
    unread: list[tuple[_Launch, str]] = []
    for launch in launches:
        if launch.version is None:
            unread.append((launch, launch.why))
            continue
        verdict, said, fix_at = _judge(advisory, launch.version)
        if verdict == "affected":
            affected.append((launch, said, fix_at))
        elif verdict == "unread":
            unread.append((launch, said))
    if affected:
        launch, said, fix_at = affected[0]
        more = len(affected) - 1
        tail = f" (and {more} more launch{'es' if more > 1 else ''} in its range)" if more else ""
        evidence = (f"`{_quote(launch.shown)}` in {name} launches {advisory.name} {said}{tail}, which "
                    f"{advisory.label()} lists as affected{_fix(advisory, fix_at)}{_feed_note(feed, advisory)}")
        return _finding(rel, evidence, launch.line, advisory.severity), launch
    if unread:
        launch, why = unread[0]
        fixed = f"; it is fixed in {', '.join(advisory.fixed)}" if advisory.fixed else (
            "; the advisory lists no fixed release")
        evidence = (f"`{_quote(launch.shown)}` in {name} launches {advisory.name}, but {why}, so its version could "
                    f"not be read: {advisory.label()} lists {_range_text(advisory)} as affected{fixed}"
                    f"{_feed_note(feed, advisory)}")
        return _finding(rel, evidence, launch.line, "MEDIUM"), launch
    return None


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return read_text_capped(path, MAX_FILE_BYTES, errors="replace")
    except OSError:
        return None


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report launched MCP servers, binaries and images an NVD advisory lists as affected.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    feed = load_feed()
    if not feed.launch:
        return [], set()
    index = _index(feed.launch)
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path, kind in _candidates(project_root):
        text = _read(path)
        if text is None:
            continue
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        lowered = text.lower()
        if not any(linear_find(lowered, needle) >= 0 for needle in sorted(index.needles)):
            continue
        found = _config_launches(path, text, index) if kind == "json" else _text_launches(path, text, kind, index)
        per: dict[LaunchAdvisory, list[_Launch]] = {}
        seen: set[tuple[int, str, int | None]] = set()
        for entry, launch in found:
            mark = (id(entry), launch.key or launch.shown, launch.line)
            if mark not in seen:
                seen.add(mark)
                per.setdefault(entry, []).append(launch)
        unplaced: list[tuple[Finding, object]] = []
        for entry, launches in per.items():
            decided = _decide(rel, path.name, feed, entry, launches)
            if decided is None:
                continue
            finding, launch = decided
            if launch.key is not None:
                unplaced.append((finding, json.dumps(launch.key)[1:-1]))
            else:
                findings.append(finding)
        findings.extend(placed(text, unplaced))
    return findings, scanned


__all__ = ["MAX_FILE_BYTES", "RULE", "scan"]
