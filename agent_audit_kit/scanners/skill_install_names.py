"""AAK-SKILL-INSTALL-MALICIOUS-001 / AAK-SKILL-INSTALL-UNPINNED-002: what a skill tells the agent to install.

A skill is instructions the agent follows, so an install line in one is a command
that will run. On 17 Nov 2026 GitHub and OSV listed `mcp-aevo-server` on PyPI as
malware (GHSA-g97f-vppp-p428, MAL-2026-20068): it had registered a name the
aevo-trading-skills skill told agents to install, and it took credentials from the
environment and waited for remote commands. The same launch in an MCP config was
AAK-MALICIOUS-RELEASE-002; in the skill nothing read it, since no skill scanner
asked the malicious-release feed.

For every bundle `agentic_skills._bundles` finds, this module reads the SKILL.md
body, a README.md and an INSTALL.md beside it, and the string values of the
bundle's manifests (SKILL.md frontmatter, skill.json, manifest.json, package.json).
In the Markdown it takes commands from fenced code blocks, inline code spans and
lines starting `$ ` or `> `; prose is not read. Each command is split as a shell
line and read at every token: first as a launcher (`_launchers._launch_at`: npx,
bunx, pnpm dlx, uvx, uv tool run, pipx run, ...), then as an install verb (pip,
pip3 and `python -m pip` install, uv pip install, uv add, pipx install, npm
i/install/add, pnpm, yarn and bun add). Each package is matched against
`malicious_feed.load_feed()`, the same offline feed AAK-MALICIOUS-RELEASE-001
reads, through that module's own `exact_pin` and `_unpinned_risk`:

* 001, CRITICAL: an entry that lists every release of the package, or a pin to a
  listed release. HIGH: no exact version, and an entry lists some releases the
  command's range admits.
* 002, MEDIUM: a launcher run (`uvx pkg`, `npx -y pkg`) with no exact version,
  which fetches whatever the registry serves as newest on every run; not reported
  where 001 reports the same package on the same line.

A scan never touches the network. What each rule reads, and where it stops, is in
the registry's limitations.
"""

from __future__ import annotations

import dataclasses
import re
import shlex
from pathlib import Path
from typing import Any, Iterator, NamedTuple

from agent_audit_kit.malicious_feed import Feed, Release, load_feed
from agent_audit_kit.models import Finding, Severity

from ._helpers import SOURCE_MAX_BYTES, find_line_numbers, make_finding, read_text_capped
from ._launchers import Launched, _launch_at, npm_spec, pin_problem, py_spec
from ._manifest_deps import Declaration
from .agentic_skills import _Bundle, _bundles
from .malicious_releases import _feed_note, _shown_versions, _unpinned_risk, exact_pin

RULE = "AAK-SKILL-INSTALL-MALICIOUS-001"
RULE_UNPINNED = "AAK-SKILL-INSTALL-UNPINNED-002"

_DOCS = ("README.md", "INSTALL.md")
_REGISTRY = {"py": "PyPI", "js": "npm"}
# The command quoted in evidence, at most this long.
_SHOWN = 160
# How many string values of one manifest are read, and how deep, so a manifest
# built to be large costs a bounded walk.
_MAX_VALUES = 2_000
_MAX_DEPTH = 32

_FENCE_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")
_SPAN_RE = re.compile(r"`([^`\n]+)`")
_PROMPT_RE = re.compile(r"^\s*[$>][ \t]+")
_CONTROL = frozenset({"&&", "||", ";", ";;", "|", "|&", "&", "(", ")", ">", ">>", "<", "<<", "&>"})

# Install verbs: (first word, the words after it) -> ecosystem. The first word is
# compared by its basename, lower case, `pip3.12` read as `pip3`.
_VERBS: dict[tuple[str, ...], str] = {
    ("pip", "install"): "py",
    ("pip3", "install"): "py",
    ("python", "-m", "pip", "install"): "py",
    ("python3", "-m", "pip", "install"): "py",
    ("py", "-m", "pip", "install"): "py",
    ("uv", "pip", "install"): "py",
    ("uv", "add"): "py",
    ("pipx", "install"): "py",
    ("npm", "i"): "js",
    ("npm", "install"): "js",
    ("npm", "add"): "js",
    ("pnpm", "add"): "js",
    ("yarn", "add"): "js",
    ("bun", "add"): "js",
}
_VERB_HEADS = frozenset(words[0] for words in _VERBS)
_VERSIONED_HEAD_RE = re.compile(r"^(pip3?|python3?)\.\d+$")
# Options whose value is not a package: requirement and constraint files, an
# editable path (`-r`, `-e`), indexes, targets, and the like. Any other option is
# read as a flag.
_PY_VALUE_OPTIONS = frozenset({
    "-r", "--requirement", "-e", "--editable", "-c", "--constraint", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root", "--src",
    "--python", "-p", "--index", "--default-index", "--upgrade-package", "-P", "--platform",
    "--python-version", "--implementation", "--abi", "--only-binary", "--no-binary", "--log",
    "--cache-dir", "--trusted-host", "--proxy", "--timeout", "--retries", "--exists-action",
    "--config-settings", "-C", "--group", "--optional", "--extra", "--package", "--directory",
    "--project", "--progress-bar", "--global-option", "--suffix", "--pip-args",
})
_JS_VALUE_OPTIONS = frozenset({
    "--registry", "--prefix", "-w", "--workspace", "--tag", "--cache", "--userconfig",
    "--save-prefix", "--omit", "--include", "--install-strategy", "--loglevel", "--filter",
    "--cwd", "--modules-folder", "--network-timeout",
})


class _Command(NamedTuple):
    """A command a skill gives, where it is written."""

    file: str   # project-relative path of the file it is in
    line: int   # 1-based line
    text: str   # the command as written
    where: str  # "README.md:3 in skill `skills/aevo`": the file relative to its bundle


class _Package(NamedTuple):
    """One package a command fetches."""

    declaration: Declaration
    launched: Launched | None   # set for a launcher run, None for an install verb


def _read(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
    except OSError:
        return None


def markdown_commands(text: str) -> Iterator[tuple[int, str]]:
    """`(line, command)` for each command a Markdown text gives: every line of a
    fenced code block, each inline code span, and a line starting `$ ` or `> `,
    with a leading `$ ` or `> ` prompt taken off. Prose is not read."""
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), 1):
        opened = _FENCE_RE.match(line)
        if fence is not None:
            if opened and opened.group(1)[0] == fence[0] and len(opened.group(1)) >= len(fence) \
                    and not line.strip().lstrip(fence[0]):
                fence = None
            elif line.strip():
                yield number, _PROMPT_RE.sub("", line, count=1).strip()
            continue
        if opened:
            fence = opened.group(1)
            continue
        if _PROMPT_RE.match(line):
            yield number, _PROMPT_RE.sub("", line, count=1).strip()
            continue
        for span in _SPAN_RE.finditer(line):
            yield number, span.group(1).strip()


def _manifest_strings(data: Any) -> Iterator[str]:
    """The string values of a parsed manifest, depth first, bounded."""
    stack: list[tuple[Any, int]] = [(data, 0)]
    seen = 0
    while stack and seen < _MAX_VALUES:
        value, depth = stack.pop()
        if isinstance(value, str):
            seen += 1
            yield value
        elif depth < _MAX_DEPTH and isinstance(value, dict):
            stack.extend((v, depth + 1) for v in reversed(list(value.values())))
        elif depth < _MAX_DEPTH and isinstance(value, list):
            stack.extend((v, depth + 1) for v in reversed(value))


def _commands(bundle: _Bundle, project_root: Path, scanned: set[str]) -> Iterator[_Command]:
    """Every command a bundle gives, in its Markdown and in its manifests' strings."""
    docs: list[tuple[Path, str]] = []
    if bundle.skill_md is not None:
        docs.append((bundle.skill_md, bundle.body))
    for name in _DOCS:
        text = _read(bundle.root / name)
        if text is not None:
            docs.append((bundle.root / name, text))
    def where(path: Path, line: int) -> str:
        return f"{path.relative_to(bundle.root).as_posix()}:{line} in skill `{bundle.rel}`"

    for path, text in docs:
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        for number, command in markdown_commands(text):
            yield _Command(rel, number, command, where(path, number))
    for _name, (path, data) in sorted(bundle.manifests.items()):
        raw = bundle.body if path == bundle.skill_md else (_read(path) or "")
        rel = path.relative_to(project_root).as_posix()
        scanned.add(rel)
        pieces = [piece.strip() for value in _manifest_strings(data) for piece in value.splitlines() if piece.strip()]
        # One pass over the file places every piece: a search per piece read a manifest
        # of many long strings once for each of them.
        lines = find_line_numbers(raw, pieces)
        for piece in pieces:
            number = lines.get(piece) or 1
            yield _Command(rel, number, piece, where(path, number))


def _tokens(command: str) -> list[str]:
    """Shell words, with `;`, `&&`, `|` and redirections as words of their own
    (`shlex.split` leaves `b;` one word, and an install read on past it); whitespace
    when quoting does not close. `#` is part of a word: `pkg#egg=name` is one."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return command.split()


def _verb_at(tokens: list[str], i: int) -> tuple[str, int] | None:
    """`(ecosystem, index after the verb)` when an install verb starts at `tokens[i]`."""
    head = tokens[i].rsplit("/", 1)[-1].lower()
    versioned = _VERSIONED_HEAD_RE.match(head)
    if versioned:
        head = versioned.group(1)
    if head not in _VERB_HEADS:
        return None
    for words, ecosystem in _VERBS.items():
        if words[0] == head and [t.lower() for t in tokens[i + 1:i + len(words)]] == list(words[1:]):
            return ecosystem, i + len(words)
    return None


def _installed(tokens: list[str], start: int, ecosystem: str, verb: str) -> tuple[list[_Package], int]:
    """The packages an install verb names from `tokens[start]` to the next control
    token, and the index it stops at."""
    values = _PY_VALUE_OPTIONS if ecosystem == "py" else _JS_VALUE_OPTIONS
    found: list[_Package] = []
    i = start
    while i < len(tokens) and tokens[i] not in _CONTROL:
        token = tokens[i]
        if token.startswith("-"):
            name = token.split("=", 1)[0]
            i += 2 if name in values and "=" not in token else 1
            continue
        declaration = _declaration(ecosystem, token, f"{verb} {token}")
        if declaration is not None:
            found.append(_Package(declaration, None))
        i += 1
    return found, i


def _declaration(ecosystem: str, spec: str, text: str) -> Declaration | None:
    """A registry package as a declaration `malicious_releases` reads; None for a
    path, a URL or a git reference."""
    parts = py_spec(spec) if ecosystem == "py" else npm_spec(spec)
    if parts.kind != "registry" or not parts.name:
        return None
    dialect = "pep440" if ecosystem == "py" else "npm"
    return Declaration(parts.name, parts.version, dialect, ecosystem, "install", text, spec=spec)


def packages(command: str) -> list[_Package]:
    """Every registry package one command line fetches, launcher runs and installs."""
    tokens = _tokens(command)
    found: list[_Package] = []
    i = 0
    while i < len(tokens):
        hit = _launch_at(tokens, i)
        if hit is not None:
            launched, resume, _command_at = hit
            for one in launched:
                declaration = _declaration(one.ecosystem, one.spec, f"{one.launcher} {one.spec}")
                if declaration is not None:
                    found.append(_Package(dataclasses.replace(declaration, kind="launch"), one))
            i = max(resume, i + 1)
            continue
        verb = _verb_at(tokens, i)
        if verb is not None:
            ecosystem, start = verb
            installed, i = _installed(tokens, start, ecosystem, " ".join(tokens[i:start]))
            found.extend(installed)
            continue
        i += 1
    return found


def _shown(command: str) -> str:
    return command if len(command) <= _SHOWN else command[:_SHOWN - 3] + "..."


def _listed_finding(command: _Command, package: _Package, release: Release, version: str | None,
                    feed: Feed) -> Finding:
    declaration = package.declaration
    registry = _REGISTRY[declaration.ecosystem or ""]
    return make_finding(
        RULE, command.file,
        f"{command.where}: `{_shown(command.text)}` has the agent install {registry} "
        f"{declaration.name}: {release.describe(version)}{_feed_note(feed, release.url)}",
        command.line,
    )


def _unpinned_finding(command: _Command, package: _Package, releases: list[Release], feed: Feed) -> Finding:
    declaration = package.declaration
    registry = _REGISTRY[declaration.ecosystem or ""]
    listing = "; ".join(
        f"{r.id}{' (' + ', '.join(r.aliases) + ')' if r.aliases else ''} lists {r.name} {_shown_versions(r)}"
        for r in releases
    )
    finding = make_finding(
        RULE, command.file,
        f"{command.where}: `{_shown(command.text)}` has the agent install {registry} "
        f"{declaration.name} with no exact version, so it gets whatever release the registry serves, and "
        f"{listing}{_feed_note(feed, releases[0].url)}",
        command.line,
    )
    return dataclasses.replace(finding, severity=Severity.HIGH)


def _run_finding(command: _Command, package: _Package, problem: str) -> Finding:
    launched = package.launched
    assert launched is not None
    registry = _REGISTRY[launched.ecosystem]
    return make_finding(
        RULE_UNPINNED, command.file,
        f"{command.where}: `{_shown(command.text)}` runs {registry} {package.declaration.name} "
        f"through `{launched.launcher}` ({problem}), so the agent fetches whatever release is newest each "
        "time the skill runs it",
        command.line,
    )


def _findings(command: _Command, feed: Feed) -> list[Finding]:
    """001 for each package of the command the feed lists; else 002 for a launcher
    run with no exact version."""
    findings: list[Finding] = []
    for package in packages(command.text):
        declaration = package.declaration
        registry = _REGISTRY[declaration.ecosystem or ""]
        version = exact_pin(declaration)
        matched = feed.match(registry, declaration.name, version)
        reported = [_listed_finding(command, package, release, version, feed) for release in matched]
        if not matched and version is None:
            risky = _unpinned_risk(declaration, feed.releases(registry, declaration.name))
            if risky:
                reported.append(_unpinned_finding(command, package, risky, feed))
        if not reported and package.launched is not None:
            problem = pin_problem(package.launched)
            if problem is not None:
                reported.append(_run_finding(command, package, problem))
        findings.extend(reported)
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report skill install lines that name a package the malicious-release feed
    lists (AAK-SKILL-INSTALL-MALICIOUS-001) and launcher runs with no version
    (AAK-SKILL-INSTALL-UNPINNED-002).

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    scanned: set[str] = set()
    findings: list[Finding] = []
    bundles = _bundles(project_root)
    if not bundles:
        return findings, scanned
    feed = load_feed()
    seen: set[tuple[str, str, int | None, str]] = set()
    for bundle in bundles:
        for command in _commands(bundle, project_root, scanned):
            for finding in _findings(command, feed):
                key = (finding.rule_id, finding.file_path, finding.line_number, finding.evidence)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
    return findings, scanned


__all__ = ["RULE", "RULE_UNPINNED", "markdown_commands", "packages", "scan"]
