"""How a version pin outside the CVE pin table reads a dependency.

Six modules keep a version pin of their own beside a code check:
langchain_vuln (AAK-LANGCHAIN-001 and -003), neo4j_cve (AAK-NEO4J-001),
ssrf_redirect (AAK-LANGCHAIN-SSRF-REDIR-001), ssrf_toctou (AAK-SSRF-TOCTOU-001),
transport_limits (AAK-MCPFRAME-001 and AAK-NEXT-AI-DRAW-001) and dns_rebind
(AAK-DNS-REBIND-002). A seventh, log_token_leak's pin on `splunk-mcp-server`,
is gone: it could only match the wrong package (see that module). Each read its
manifests with a regex of its own and took the first number after the package
name as the version in use, the flaw `_versions` retired from the pin table:

- An upper bound read as the version. `langchain-core<1.2.22` admits only
  releases CVE-2026-34070 affects, and it read as 1.2.22, the fix, so it was
  silent; `pkg<2.0.0,>=1.0.0` read as 2.0.0 while `pkg>=1.0.0,<2.0.0` read as
  1.0.0; and `mcp>=1.0` fired in pyproject.toml and not in requirements.txt,
  whose pattern acted on `==`, `<` and `<=` only.
- Other text sat where the version was looked for. Extras
  (`mcp[cli]==1.22.0`, the MCP SDK's own install line) hid it from a pattern
  with no place for them, and one that took any number after the name read
  `langchain-text-splitters[x]==1.1.2` as a name with no version.
- A format went unread. langchain_vuln listed every pyproject.toml and never
  matched one, because its pattern was anchored at the start of a requirement
  line and a TOML string starts with a quote; neo4j_cve's docstring promised
  pyproject.toml and read four requirements files; and a Poetry table entry
  (`mcp = "1.22.0"`) matched no module's pattern.

A module now parses each manifest into the declarations it makes, with the
reader the pin table uses (`_manifest_deps`): requirement lines with comments,
markers, extras and continuations handled, the PEP 621, dependency-group and
Poetry tables of pyproject.toml, and package.json's dependency maps and
overrides. The commands a package.json script runs are dropped, because none
of these rules ever read them. What the declarations allow is judged with the
pin table's own policy (`mcp_cve_pins_2026_07._deciding_declaration`), so the
two cannot drift apart:

- A range is reported when it admits an affected version, however its bounds
  are written: `<1.2.22`, `>=1.0,<2` and `<2,>=1.0` read alike, and so does a
  lower bound below the fix (`mcp>=1.2.0`), which a resolver may satisfy with
  an affected release. AAK-MCP-SDK-CVE-2026-52869-001 already reports that line.
- The declarations of one install (a requirements file, a PEP 621 list, an
  extra, a dependency group, a package.json section) are intersected, as pip
  merges them; an override (npm `overrides`, uv `override-dependencies`)
  replaces the regular entries; and a patched pin in another section does not
  clear a range in this one.
- A declaration that states no version AAK can read (a bare name, `*`,
  `latest`, a git or file reference) is reported only by a rule that always
  reported one (`report_unversioned`).

One finding per rule per file, on the line of the declaration that decided it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agent_audit_kit.scanners._manifest_deps import (
    Declaration,
    declaration_lines,
    declarations,
    package_json_declarations,
    requirements_declarations,
)
from agent_audit_kit.scanners._versions import NONE, TOP, Ver, exact_version, intersect, parse_range
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import (
    _admits_affected,
    _deciding_declaration,
    _names_match,
    _Pin,
    _pin_applies,
)
from agent_audit_kit.scanners.supply_chain import _lockfile_index, _lockfile_lookup


@dataclass(frozen=True)
class DependencyPin:
    """One package and the first release that fixes it."""

    names: tuple[str, ...]          # the package as its registry names it
    fixed: Ver                      # every release below this one is affected
    ecosystem: str | None = None    # "py", "js", or None for either registry
    # Report a declaration that states no readable version. Off for most of
    # these rules: their old patterns needed a number, and an unpinned
    # reference usually installs a fixed release.
    report_unversioned: bool = False

    def as_table_pin(self) -> _Pin:
        """The same pin as the CVE table states one, for its policy to judge."""
        return _Pin("", self.names[0], self.names, self.fixed, ecosystem=self.ecosystem,
                    requires_version=not self.report_unversioned)


@dataclass(frozen=True)
class PinnedDependency:
    """The declaration that puts a project on an affected release."""

    declaration: Declaration
    line: int | None
    fixed: Ver

    @property
    def quoted(self) -> str:
        """The declaration as written, and what it admits, for evidence."""
        return self.quote()

    def quote(self, where: str = "") -> str:
        """The declaration as written, then `where` (" in devDependencies"), then
        what it admits.

        An exact pin needs no gloss. A range says that it admits releases below
        the fix: a lower bound such as `mcp>=1.2.0` pins nothing, and is reported
        because a resolver may still pick an affected release. A declaration
        whose version AAK cannot read says so.
        """
        declaration = self.declaration
        spans = parse_range(declaration.version, declaration.dialect)
        if spans is None:
            how = ", which states no version AAK can read"
        elif exact_version(spans) is not None:
            how = ""
        else:
            how = f", which admits releases below {_dotted(self.fixed)}"
        return f"{declaration.text!r}{where}{how}"


def manifest_declarations(path: Path, text: str) -> list[Declaration]:
    """The dependencies `path` declares, without the commands its scripts run.

    Every requirements file is read as one, whatever its name, so
    `dev-requirements.txt` counts though it does not start with "requirements".

    A package.json loses its `scripts` before it is read, not after. None of
    these rules reads the commands a script runs, and tokenising them was the
    costly part of reading the file: with shlex, quadratic in the length of one
    word, a 300 KB script word took 3.5 s to read for launches that were then
    thrown away.
    """
    name = path.name.lower()
    if name.endswith(".txt"):
        return requirements_declarations(text)
    if name == "package.json":
        # The same failures `declarations` reads as "no declarations": invalid
        # JSON, and nesting deep enough to exhaust the stack.
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                return []
            return package_json_declarations({k: v for k, v in data.items() if k != "scripts"})
        except (ValueError, RecursionError):
            return []
    return [d for d in declarations(path, text) if d.kind != "launch"]


def pinned_dependency(
    path: Path, text: str, pin: DependencyPin, found: list[Declaration] | None = None
) -> PinnedDependency | None:
    """The declaration in `path` that admits an affected release, or None.

    Args:
        path: The manifest; its name selects the format.
        text: The manifest's contents.
        pin: The package and its fix.
        found: The file's declarations, when the caller has parsed them already
            for another pin.

    Returns:
        The deciding declaration and its line, or None when the file declares
        no affected release of the package.
    """
    if found is None:
        found = manifest_declarations(path, text)
    declaration = _deciding_declaration(pin.as_table_pin(), found)
    if declaration is None:
        return None
    return PinnedDependency(declaration, declaration_lines(path, text)(declaration), pin.fixed)


def locked_affected_versions(path: Path, text: str, pin: DependencyPin) -> list[Ver]:
    """The affected versions a lockfile resolves the package to, lowest first.

    Read with the CVE pin table's lockfile reader (`supply_chain._lockfile_index`),
    so Pipfile.lock's JSON, the `[[package]]` blocks of poetry.lock and uv.lock,
    and a PEP 503 spelling of the name all read as the pins read them. The
    pattern this replaced wanted a TOML `name =` line followed by a `version =`
    line, so it never matched a Pipfile.lock, though both modules listed one.
    """
    filename = path.name.lower()
    resolved = _lockfile_lookup(_lockfile_index(text, filename), filename, pin.names)
    return [v for v in resolved if v < pin.fixed]


def _dotted(version: Ver) -> str:
    return ".".join(str(n) for n in version)


@dataclass(frozen=True)
class Raised:
    """What raising one package's declarations in one manifest came to."""

    text: str      # the manifest to write: the input, unchanged, when anything was refused
    raised: int    # declarations rewritten; 0 when anything was refused
    # (line, why) for each declaration that admits an affected release and cannot
    # be rewritten where it is written.
    refused: tuple[tuple[int | None, str], ...] = ()


def raise_to_fix(path: Path, text: str, pin: DependencyPin) -> Raised:
    """`text` with every declaration that admits an affected release raised to the fix.

    `aak fix` uses this, so a fix reads the manifest exactly as the rule does
    and rewrites what the rule reports and nothing else. Its bumps used to match
    `name op version` at the start of a requirement line and judge the first
    number, so they left `langchain-core<1.2.22` alone (the first number is the
    fix), could not see a pin with extras, and refused pyproject.toml, all of
    which the rules report.

    Each declaration that admits an affected release keeps what it admitted
    from the fix up: `>=1.0,<2` becomes `>=1.2.22,<2.0.0`, and `~=1.2.0` becomes
    `>=1.2.22,<1.3.0`. One that admitted nothing at or above the fix
    (`<1.2.22`, `==1.2.21`), or several ranges, becomes `>=<fix>`. Extras,
    markers, comments and the file's line endings stay as they were. The
    result is read again with the rule's policy before it is returned.

    A manifest is rewritten whole or not at all. A declaration that spans
    several lines, keeps its version on a line of its own (a Poetry sub-table)
    or carries a `--hash` (which pip checks against the pinned release, so a
    range would fail the install) is refused, and then nothing is rewritten:
    raising the other lines alone could leave a file that no resolver can
    satisfy, such as `>=1.2.22` beside a hashed `==1.2.21`.
    """
    table_pin = pin.as_table_pin()
    targets = [
        d for d in manifest_declarations(path, text)
        if _pin_applies(table_pin, d.ecosystem) and _names_match(table_pin, d)
        and _admits_affected(table_pin, d)
    ]
    if not targets:
        return Raised(text, 0)
    # Lines are counted in `\n`s, as `declaration_lines` counts them; splitlines()
    # also breaks on rarer separators. The positions are read once for the file.
    line_of = declaration_lines(path, text)
    lines = text.split("\n")
    refused: list[tuple[int | None, str]] = []
    for declaration in targets:
        number = line_of(declaration)
        if number is None:
            refused.append((None, f"{declaration.text!r} is not written where AAK read it"))
            continue
        line, why = _raised_line(lines, number - 1, declaration, _raised_spec(declaration, pin.fixed))
        if why:
            refused.append((number, why))
        else:
            lines[number - 1] = line
    if refused:
        return Raised(text, 0, tuple(refused))
    raised = "\n".join(lines)
    if pinned_dependency(path, raised, pin) is not None:
        return Raised(text, 0, ((None, "the rewritten file would still admit a release below the fix"),))
    return Raised(raised, len(targets))


def _raised_spec(declaration: Declaration, fixed: Ver) -> str:
    """What `declaration` admitted from `fixed` up, as a specifier, or `>=fixed`."""
    spans = parse_range(declaration.version, declaration.dialect)
    kept = intersect(spans, ((fixed, TOP),)) if spans is not None else NONE
    if len(kept) == 1:
        lo, hi = kept[0]
        joiner = " " if declaration.dialect == "npm" else ","
        return f">={_dotted(lo)}" + ("" if hi == TOP else f"{joiner}<{_dotted(hi)}")
    return f">={_dotted(fixed)}"


def _raised_line(lines: list[str], index: int, declaration: Declaration, spec: str) -> tuple[str, str]:
    """`lines[index]` with the declaration's version replaced by `spec`, and "".

    Or the line unchanged and why it cannot be rewritten. A requirement string
    as written (a requirements line, a PEP 621 entry) is found on the line and
    its version replaced inside it; a TOML value (`name = "^1.2"`, `{ version =
    "<1.2" }`) is found as the quoted version.
    """
    line = lines[index]
    if declaration.section == "requirements":
        logical = [line]
        while logical[-1].rstrip("\r").endswith("\\") and index + len(logical) < len(lines):
            logical.append(lines[index + len(logical)])
        if any("--hash" in part for part in logical):
            return line, "has a --hash, which pip checks against the pinned release; re-lock it instead"
    at = line.find(declaration.text)
    if at != -1:
        start = declaration.text.find(declaration.version, len(declaration.name))
        if start == -1:
            return line, "states its version in a form AAK does not rewrite"
        requirement = declaration.text[:start] + spec + declaration.text[start + len(declaration.version):]
        return line[:at] + requirement + line[at + len(declaration.text):], ""
    for quote in ('"', "'"):
        token = quote + declaration.version + quote
        at = line.find(token)
        if at != -1:
            return line[:at] + quote + spec + quote + line[at + len(token):], ""
    if declaration.section == "requirements":
        return line, "continues onto the next line"
    return line, "keeps its version on another line"
