"""How a version pin outside the CVE pin table reads a dependency.

Seven modules keep a version pin of their own beside a code check:
langchain_vuln (AAK-LANGCHAIN-001 and -003), neo4j_cve (AAK-NEO4J-001),
ssrf_redirect (AAK-LANGCHAIN-SSRF-REDIR-001), ssrf_toctou (AAK-SSRF-TOCTOU-001),
log_token_leak (AAK-SPLUNK-TOKLOG-001), transport_limits (AAK-MCPFRAME-001 and
AAK-NEXT-AI-DRAW-001) and dns_rebind (AAK-DNS-REBIND-002). Each read its
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
    declaration_line,
    declarations,
    package_json_declarations,
    requirements_declarations,
)
from agent_audit_kit.scanners._versions import Ver, exact_version, parse_range
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _deciding_declaration, _Pin


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
            how = f", which admits releases below {'.'.join(str(n) for n in self.fixed)}"
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
    return PinnedDependency(declaration, declaration_line(text, declaration, path.name), pin.fixed)
