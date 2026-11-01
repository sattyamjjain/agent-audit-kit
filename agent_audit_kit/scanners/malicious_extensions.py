"""AAK-MALICIOUS-EXTENSION-001: an agent host's editor extension the feed lists as malware.

On 29 Oct 2026, from about 09:27 to 20:35 UTC, Cursor's extension marketplace
served tampered builds of Anthropic's Claude Code extension, `anthropic.claude-code`
2.1.312 and 2.1.313, under Anthropic's publisher id. Their `extension.js` added
an SSH key to `~/.ssh/authorized_keys` and installed a LaunchAgent, a scheduled
task or a crontab line (Cursor's notice,
https://cursor.com/blog/claude-code-extension-security-notice). AAK read MCP
configs in `.vscode/` and had no notion of the extensions an editor installs, so
a machine or image that carried the build scanned clean.

VS Code and the editors built on it (Cursor among them) install an extension
into `<home>/<data folder>/extensions/<publisher>.<name>-<version>[-<platform>]/`
and list the installs in an `extensions.json` index beside the folders (VS Code's
`ExtensionKey` and `extensionsProfileScannerService`; Cursor's own remediation
script globs `~/.*/extensions/anthropic.claude-code-*/extension.js`). This
module reads those folders and that index against the malicious-release feed's
`extensions` entries (see `agent_audit_kit.malicious_feed.ExtensionRelease`):

* An extension folder whose `publisher.name` and version an entry lists, under
  the host folders the entry names (`.cursor` is `cursor`, `.vscode` is
  `vscode`, a remote server's `.cursor-server` is `cursor`; `*` is every host).
* A folder of any version whose file the entry names (`extension.js`) has a
  SHA-256 the entry lists: a tampered build can carry the number of a real
  release, as the tampered 2.1.312 did, and only its content tells them apart.
* An `extensions.json` index entry whose id and version an entry lists, where
  its folder is gone; the index alone cannot be checked for content.
* A workspace's `.vscode/extensions.json` recommending an id an entry lists in
  every version. A recommendation names no version, so an entry that lists
  particular versions is not reported for it, as a range is not for
  AAK-MALICIOUS-RELEASE-001.

Where: the extension folders of the scan root itself (a home directory, a dev
container home), of `root/`, and of every `home/*/` and `Users/*/` below it (an
unpacked image root filesystem); with `include_user_config`
(`aak scan --include-user-config`) also this user's own home. Recommendations
are read anywhere under the root outside AAK's skip directories.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Iterator

from agent_audit_kit.malicious_feed import ExtensionRelease, Feed, load_feed
from agent_audit_kit.models import Finding

from ._dependency_pins import read_text
from ._helpers import SKIP_DIRS, in_skip_dir, loads_json, loads_jsonc, make_finding

RULE = "AAK-MALICIOUS-EXTENSION-001"

# VS Code's `ExtensionKey` folder name: `<publisher>.<name>-<x.y.z>[-<target platform>]`.
# A folder name is at most 255 bytes, which bounds the backtracking.
_FOLDER_RE = re.compile(r"^([^.]+\..+)-(\d+\.\d+\.\d+)(?:-(.+))?$")
_INDEX = "extensions.json"
_INDEX_BYTES = 8_000_000
_PACKAGE_JSON_BYTES = 1_000_000
_RECOMMENDATIONS_BYTES = 1_000_000
#: The largest file a digest is computed for. Claude Code's `extension.js` is a
#: few MB; a file past this is not hashed, and the limitation says so.
MAX_HASHED_BYTES = 64 * 1024 * 1024
_CHUNK = 1 << 20
_VERSION_KEY_RE = re.compile(r'^\s*"version"\s*:')


def host_of(folder: str) -> str | None:
    """The host an editor data folder belongs to: `.cursor` is `cursor`,
    `.vscode-insiders` is `vscode-insiders`, and a remote server's copy
    (`.vscode-server`, `.cursor-server-insiders`) the editor's own. None for a
    name that is not a dot folder."""
    if not folder.startswith(".") or len(folder) < 2:
        return None
    return folder[1:].lower().replace("-server", "", 1)


def _subdirs(directory: Path) -> list[os.DirEntry[str]]:
    """The directories directly inside one, sorted, symlinks left out; none when unreadable."""
    try:
        with os.scandir(directory) as it:
            return sorted((e for e in it if e.is_dir(follow_symlinks=False)), key=lambda e: e.name)
    except OSError:
        return []


def _homes(root: Path) -> list[Path]:
    """The scan root, and the home directories an image root filesystem keeps
    below it: `root/`, `home/*/` and `Users/*/`."""
    homes = [root]
    candidate = root / "root"
    if candidate.is_dir() and not candidate.is_symlink():
        homes.append(candidate)
    for parent in ("home", "Users"):
        base = root / parent
        if base.is_dir() and not base.is_symlink():
            homes.extend(Path(e.path) for e in _subdirs(base))
    return homes


def extension_dirs(home: Path) -> Iterator[tuple[str, Path]]:
    """(host, extensions directory) for every editor data folder in one home."""
    for entry in _subdirs(home):
        host = host_of(entry.name)
        if host is None:
            continue
        extensions = Path(entry.path) / "extensions"
        if extensions.is_dir() and not extensions.is_symlink():
            yield host, extensions


def _sha256(path: Path) -> str | None:
    """The SHA-256 of a regular file up to `MAX_HASHED_BYTES`, else None."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_HASHED_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _why(entry: ExtensionRelease, folder: Path | None, version: str) -> str | None:
    """Why `entry` lists this install, or None when it does not."""
    if entry.lists_version(version):
        return f"{entry.id} lists {entry.extension} {version} as malicious"
    if folder is None:
        return None
    for relative, digests in entry.sha256:
        digest = _sha256(folder / relative)
        if digest is not None and digest in digests:
            return f"its {relative} has SHA-256 {digest}, which {entry.id} lists as a malicious build's"
    return None


def _advice(entry: ExtensionRelease, feed: Feed) -> str:
    fixed = f", update to {entry.fixed} or later" if entry.fixed else ""
    url = f" ({entry.url})" if entry.url else ""
    note = f" {entry.note}" if entry.note else ""
    return (
        f"{url}. Remove the extension{fixed}, and check the machine for the persistence the "
        f"advisory names; removing the extension may not remove it.{note} An install says the "
        "build was on disk, not whether it ran. "
        f"Feed: the {feed.origin} copy generated {feed.generated_at}."
    )


def _package_json_line(path: Path) -> int | None:
    text = read_text(path, _PACKAGE_JSON_BYTES)
    if text is None:
        return None
    return next((n for n, row in enumerate(text.splitlines(), 1) if _VERSION_KEY_RE.match(row)), None)


def _shown(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()


def _line_of(lowered: str, needle: str) -> int | None:
    """The 1-based line of the first `needle` in already lower-cased text, or None.
    Called once per reported (id, version), never per entry, so a crafted index
    of many entries costs one parse."""
    at = lowered.find(needle.lower())
    return None if at < 0 else lowered.count("\n", 0, at) + 1


def _index_entries(index: Path) -> tuple[list[tuple[str, str, str]], str]:
    """(id, version, folder name) for each entry of one extensions.json index, and
    the index's text lower-cased, to place the few that are reported."""
    text = read_text(index, _INDEX_BYTES)
    if text is None:
        return [], ""
    try:
        data = loads_json(text, index)
    except ValueError:
        return [], ""
    out: list[tuple[str, str, str]] = []
    for item in data if isinstance(data, list) else ():
        if not isinstance(item, dict):
            continue
        identifier = item.get("identifier")
        ident = identifier.get("id") if isinstance(identifier, dict) else None
        version = item.get("version")
        if not isinstance(ident, str) or not isinstance(version, str):
            continue
        folder = item.get("relativeLocation")
        if not isinstance(folder, str) or not folder:
            location = item.get("location")
            path = location.get("path") if isinstance(location, dict) else location
            folder = path if isinstance(path, str) else ""
        # Only the folder's name: the index sits beside the folders it lists.
        folder = folder.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        out.append((ident, version.strip(), folder))
    return out, text.lower()


def _installed_findings(host: str, extensions: Path, root: Path, feed: Feed, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in _subdirs(extensions):
        m = _FOLDER_RE.match(entry.name)
        if m is None:
            continue
        ident, version, platform = m.group(1), m.group(2), m.group(3)
        candidates = [e for e in feed.extension(ident) if e.on_host(host)]
        if not candidates:
            continue
        folder = Path(entry.path)
        reported: set[str] = set()
        for candidate in candidates:
            why = _why(candidate, folder, version)
            if why is None or candidate.id in reported:
                continue
            reported.add(candidate.id)
            package_json = folder / "package.json"
            where = package_json if package_json.is_file() else folder
            shown = _shown(where, root)
            scanned.add(shown)
            build = f"{version} ({platform})" if platform else version
            findings.append(make_finding(
                RULE, shown,
                f"`{_shown(folder, root)}` is an installed {ident} {build} for {host}, and {why}"
                f"{_advice(candidate, feed)}",
                _package_json_line(package_json) if where is package_json else None,
            ))
    index = extensions / _INDEX
    if not index.is_file():
        return findings
    shown_index = _shown(index, root)
    scanned.add(shown_index)
    entries, lowered = _index_entries(index)
    reported_pairs: set[tuple[str, str, str]] = set()
    for ident, version, folder_name in entries:
        if folder_name and (extensions / folder_name).is_dir():
            continue  # the folder is there, and was judged above by its name and content
        for candidate in feed.extension(ident):
            pair = (candidate.id, ident.lower(), version.lower())
            if not candidate.on_host(host) or pair in reported_pairs:
                continue
            why = _why(candidate, None, version)
            if why is None:
                continue
            reported_pairs.add(pair)
            findings.append(make_finding(
                RULE, shown_index,
                f"{shown_index} lists {ident} {version} as installed for {host}, and {why}; its "
                f"folder is not there to check{_advice(candidate, feed)}",
                _line_of(lowered, f'"{ident}"'),
            ))
    return findings


def _recommendation_findings(root: Path, feed: Feed, scanned: set[str]) -> list[Finding]:
    """Ids a workspace's `.vscode/extensions.json` recommends that an entry lists in
    every version: a recommendation names no version, so nothing narrower is judged."""
    if not feed.extensions:
        return []
    findings: list[Finding] = []
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        here = Path(dirpath)
        if here.name != ".vscode" or in_skip_dir(here, root):
            continue
        path = here / _INDEX
        if not path.is_file():
            continue
        text = read_text(path, _RECOMMENDATIONS_BYTES)
        if text is None:
            continue
        try:
            data = loads_jsonc(text, path)
        except ValueError:
            continue
        rel = path.relative_to(root).as_posix()
        scanned.add(rel)
        recommended = data.get("recommendations") if isinstance(data, dict) else None
        lowered = text.lower()
        reported: set[tuple[str, str]] = set()
        for ident in recommended if isinstance(recommended, list) else ():
            if not isinstance(ident, str):
                continue
            for candidate in feed.extension(ident):
                if not candidate.all_versions or (candidate.id, ident.lower()) in reported:
                    continue
                reported.add((candidate.id, ident.lower()))
                findings.append(make_finding(
                    RULE, rel,
                    f"{rel} recommends {ident}, and {candidate.id} lists every release of "
                    f"{candidate.extension} as malicious{_advice(candidate, feed)}",
                    _line_of(lowered, f'"{ident}"'),
                ))
    return findings


def scan(project_root: Path, include_user_config: bool = False) -> tuple[list[Finding], set[str]]:
    """Report installed or recommended editor extensions the feed lists as malicious.

    Args:
        project_root: The scan root: a project, a home directory, or an unpacked
            image root filesystem.
        include_user_config: Also read this user's own editor extension folders
            (`~/.cursor/extensions`, `~/.vscode/extensions`, ...). Off by default.

    Returns:
        A tuple of (list of findings, set of scanned file paths: relative to the
        root, absolute for this user's home outside it).
    """
    feed = load_feed()
    findings: list[Finding] = []
    scanned: set[str] = set()
    if not feed.extensions:
        return findings, scanned
    homes = _homes(project_root)
    if include_user_config:
        home = Path.home()
        if home.is_dir() and not any(home == h for h in homes):
            homes.append(home)
    seen: set[Path] = set()
    for home in homes:
        for host, extensions in extension_dirs(home):
            key = extensions.resolve()
            if key in seen:
                continue
            seen.add(key)
            findings.extend(_installed_findings(host, extensions, project_root, feed, scanned))
    findings.extend(_recommendation_findings(project_root, feed, scanned))
    return findings, scanned


__all__ = ["RULE", "scan", "host_of", "extension_dirs", "MAX_HASHED_BYTES"]
