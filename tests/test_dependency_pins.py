"""The version pins outside the CVE pin table read a dependency one way.

langchain_vuln, neo4j_cve, ssrf_redirect, ssrf_toctou, transport_limits and
dns_rebind each took the first number after the package name as the version in
use, with a regex of its own per manifest. So an upper bound read as the version
(`pkg<FIXED` admits only affected releases and was silent), the order of a
range's bounds decided the answer, extras and markers hid the version, and
pyproject.toml and Poetry tables went unread. They now read `_manifest_deps`
declarations and judge them with the CVE pin table's own policy
(`_dependency_pins`). Every shape below runs through every pin, so a module that
drifts from the shared reading fails here.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

from agent_audit_kit.scanners import (
    dns_rebind,
    langchain_vuln,
    mcp_cve_pins_2026_07,
    neo4j_cve,
    ssrf_redirect,
    ssrf_toctou,
    transport_limits,
)


@dataclass(frozen=True)
class _Pin:
    rule_id: str
    module: ModuleType
    package: str
    affected: str      # an affected release just below the fix
    fixed: str
    unversioned: bool  # does the rule report a declaration that states no version?

    def fires(self, root: Path) -> bool:
        findings, _ = self.module.scan(root)
        return any(f.rule_id == self.rule_id for f in findings)

    def fill(self, template: str) -> str:
        """`{p}` the package, `{u}` another PEP 503 spelling of it, `{a}` and `{f}` the versions."""
        return (template.replace("{p}", self.package)
                .replace("{u}", self.package.replace("-", "_").upper())
                .replace("{a}", self.affected).replace("{f}", self.fixed))

    def __str__(self) -> str:
        return f"{self.rule_id}:{self.package}"


_PY_PINS = (
    _Pin("AAK-LANGCHAIN-001", langchain_vuln, "langchain-core", "1.2.21", "1.2.22", False),
    _Pin("AAK-NEO4J-001", neo4j_cve, "mcp-neo4j-cypher", "0.5.0", "0.6.0", False),
    _Pin("AAK-LANGCHAIN-SSRF-REDIR-001", ssrf_redirect, "langchain-text-splitters", "1.1.1", "1.1.2", True),
    _Pin("AAK-SSRF-TOCTOU-001", ssrf_toctou, "langchain-openai", "1.1.13", "1.1.14", True),
    _Pin("AAK-DNS-REBIND-002", dns_rebind, "mcp", "1.22.0", "1.23.0", False),
)
_NPM_PINS = (
    _Pin("AAK-MCPFRAME-001", transport_limits, "mcp-framework", "0.2.21", "0.2.22", True),
    _Pin("AAK-NEXT-AI-DRAW-001", transport_limits, "next-ai-draw-io", "0.4.14", "0.4.15", True),
    _Pin("AAK-DNS-REBIND-002", dns_rebind, "@modelcontextprotocol/sdk", "1.21.0", "1.21.1", False),
    _Pin("AAK-DNS-REBIND-002", dns_rebind, "@apollo/mcp-server", "1.6.0", "1.7.0", False),
)

# (label, file contents, fires?). None: fires only for a rule that reports an
# unversioned reference.
_REQUIREMENTS: tuple[tuple[str, str, bool | None], ...] = (
    ("exact affected", "{p}=={a}", True),
    ("exact fixed", "{p}=={f}", False),
    ("upper bound at the fix", "{p}<{f}", True),
    ("upper bound below the fix", "{p}<={a}", True),
    ("upper bound first", "{p}<99.0.0,>={a}", True),
    ("lower bound first", "{p}>={a},<99.0.0", True),
    ("lower bound below the fix", "{p}>={a}", True),
    ("lower bound at the fix", "{p}>={f}", False),
    ("range of fixed releases", "{p}>={f},<99.0.0", False),
    ("compatible release", "{p}~={a}", True),
    ("exclusion of the fix", "{p}!={f}", True),
    ("extras, affected", "{p}[cli,extra]=={a}", True),
    ("extras, fixed", "{p}[cli]=={f}", False),
    ("extras after a space", "{p} [cli] == {a}", True),
    ("marker", '{p}=={a} ; python_version >= "3.8"', True),
    ("marker, fixed", '{p}=={f} ; python_version >= "3.8"', False),
    ("trailing comment naming the affected release", "{p}=={f}  # was {a}", False),
    ("trailing comment naming the fix", "{p}=={a}  # upgrade to {f}", True),
    ("commented-out pin above the fix", "# {p}=={a}\n{p}=={f}", False),
    ("hash option", "{p}=={a} --hash=sha256:0123abcd", True),
    ("one install, intersected", "{p}>={a}\n{p}=={f}", False),
    # Stated in the limitations: no release satisfies both, and pip refuses the file too.
    ("conflicting pins admit nothing", "{p}=={f}\n{p}=={a}", False),
    ("PEP 503 spelling", "{u}=={a}", True),
    ("prefix match on the affected release", "{p}=={a}.*", True),
    ("prefix match on the fix", "{p}=={f}.*", False),
    ("prefix exclusion of the fix", "{p}>=0.1,!={f}.*", True),
    ("bare name", "{p}", None),
)

_HEAD = '[project]\nname = "demo"\nversion = "0.1.0"\n'
_POETRY = '[tool.poetry]\nname = "demo"\n\n[tool.poetry.dependencies]\npython = "^3.10"\n'

_PYPROJECT: tuple[tuple[str, str, bool | None], ...] = (
    ("PEP 621 exact affected", _HEAD + 'dependencies = ["{p}=={a}"]\n', True),
    ("PEP 621 exact fixed", _HEAD + 'dependencies = ["{p}=={f}"]\n', False),
    ("PEP 621 upper bound", _HEAD + 'dependencies = ["{p}<{f}"]\n', True),
    ("PEP 621 upper bound first", _HEAD + 'dependencies = ["{p}<99.0.0,>={a}"]\n', True),
    ("PEP 621 lower bound below the fix", _HEAD + 'dependencies = ["{p}>={a}"]\n', True),
    ("PEP 621 lower bound at the fix", _HEAD + 'dependencies = ["{p}>={f}"]\n', False),
    ("PEP 621 extras", _HEAD + 'dependencies = ["{p}[cli]=={a}"]\n', True),
    ("PEP 621 marker", _HEAD + "dependencies = [\"{p}=={a}; python_version >= '3.9'\"]\n", True),
    ("PEP 621 bare name", _HEAD + 'dependencies = ["{p}"]\n', None),
    ("optional dependency", _HEAD + 'dependencies = []\n\n[project.optional-dependencies]\n'
     'extra = ["{p}<{f}"]\n', True),
    ("dependency group", _HEAD + '\n[dependency-groups]\ndev = ["{p}=={a}"]\n', True),
    ("a description is not a declaration", '[project]\nname = "demo"\n'
     'description = "needs {p}=={a} or newer"\ndependencies = ["{p}=={f}"]\n', False),
    ("Poetry exact affected", _POETRY + '{p} = "{a}"\n', True),
    ("Poetry caret on the fix", _POETRY + '{p} = "^{f}"\n', False),
    ("Poetry table with extras", _POETRY + '{p} = { version = "<{f}", extras = ["cli"] }\n', True),
    # Stated in the limitations. It cannot be a committed fixture: ruff parses every
    # pyproject.toml under the paths it lints and fails on one that does not parse.
    ("a pyproject.toml that does not parse", _HEAD + 'dependencies = ["{p}=={a}"\n', False),
)

# (label, package.json dependency value, fires?).
_PACKAGE_JSON: tuple[tuple[str, str, bool | None], ...] = (
    ("exact affected", "{a}", True),
    ("exact fixed", "{f}", False),
    ("upper bound at the fix", "<{f}", True),
    ("upper bound first", "<99.0.0 >={a}", True),
    ("lower bound first", ">={a} <99.0.0", True),
    ("caret on the affected release", "^{a}", True),
    ("caret on the fix", "^{f}", False),
    ("tilde on the affected release", "~{a}", True),
    ("either release", "{a} || {f}", True),
    ("dist-tag", "latest", None),
)


def _expect(fires: bool | None, pin: _Pin) -> bool:
    return pin.unversioned if fires is None else fires


def _ids(cases: tuple[tuple[str, str, bool | None], ...]) -> list[str]:
    return [label for label, _, _ in cases]


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
@pytest.mark.parametrize(("label", "template", "fires"), _REQUIREMENTS, ids=_ids(_REQUIREMENTS))
def test_requirements_file(tmp_path: Path, pin: _Pin, label: str, template: str, fires: bool | None) -> None:
    (tmp_path / "requirements.txt").write_text(pin.fill(template) + "\n", encoding="utf-8")
    assert pin.fires(tmp_path) is _expect(fires, pin), label


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
@pytest.mark.parametrize(("label", "template", "fires"), _PYPROJECT, ids=_ids(_PYPROJECT))
def test_pyproject(tmp_path: Path, pin: _Pin, label: str, template: str, fires: bool | None) -> None:
    (tmp_path / "pyproject.toml").write_text(pin.fill(template), encoding="utf-8")
    assert pin.fires(tmp_path) is _expect(fires, pin), label


@pytest.mark.parametrize("pin", _NPM_PINS, ids=str)
@pytest.mark.parametrize(("label", "spec", "fires"), _PACKAGE_JSON, ids=_ids(_PACKAGE_JSON))
@pytest.mark.parametrize("section", ["dependencies", "devDependencies"])
def test_package_json(tmp_path: Path, pin: _Pin, label: str, spec: str, fires: bool | None, section: str) -> None:
    body = {"name": "app", "version": "1.0.0", section: {pin.package: pin.fill(spec)}}
    (tmp_path / "package.json").write_text(json.dumps(body, indent=2), encoding="utf-8")
    assert pin.fires(tmp_path) is _expect(fires, pin), label


@pytest.mark.parametrize("pin", _NPM_PINS, ids=str)
def test_package_json_override_replaces_the_declared_range(tmp_path: Path, pin: _Pin) -> None:
    """npm installs what `overrides` names, so a caret on an affected release beside
    an override to the fix installs the fix."""
    body = {"dependencies": {pin.package: "^" + pin.affected}, "overrides": {pin.package: pin.fixed}}
    (tmp_path / "package.json").write_text(json.dumps(body), encoding="utf-8")
    assert not pin.fires(tmp_path)
    body["overrides"] = {pin.package: pin.affected}
    (tmp_path / "package.json").write_text(json.dumps(body), encoding="utf-8")
    assert pin.fires(tmp_path)


@pytest.mark.parametrize("pin", _NPM_PINS, ids=str)
def test_package_json_script_launch_is_not_a_dependency(tmp_path: Path, pin: _Pin) -> None:
    """None of these rules read the commands a script runs, and they still do not."""
    body = {"scripts": {"start": f"npx -y {pin.package}@{pin.affected}"}}
    (tmp_path / "package.json").write_text(json.dumps(body), encoding="utf-8")
    assert not pin.fires(tmp_path)


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
def test_requirements_line_is_the_declaration_line(tmp_path: Path, pin: _Pin) -> None:
    (tmp_path / "requirements.txt").write_text(
        pin.fill("# {p}=={a} was the old pin\nflask\n\n{p}<{f}\n"), encoding="utf-8")
    findings, _ = pin.module.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == pin.rule_id] == [4]


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
def test_pyproject_line_is_the_declaration_line(tmp_path: Path, pin: _Pin) -> None:
    (tmp_path / "pyproject.toml").write_text(
        pin.fill(_HEAD + '# was "{p}<{f}"\ndependencies = [\n  "flask",\n  "{p}<{f}",\n]\n'), encoding="utf-8")
    findings, _ = pin.module.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == pin.rule_id] == [7]


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
def test_poetry_line_is_the_key_line(tmp_path: Path, pin: _Pin) -> None:
    (tmp_path / "pyproject.toml").write_text(pin.fill(_POETRY + '{p} = "{a}"\n'), encoding="utf-8")
    findings, _ = pin.module.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == pin.rule_id] == [6]


@pytest.mark.parametrize("pin", _PY_PINS + _NPM_PINS, ids=str)
@pytest.mark.parametrize(("spec", "gloss"), [
    # A range says what it admits; it is not a pin. An exact pin needs no gloss.
    (">={a}", ", which admits releases below {f}"),
    ("<{f}", ", which admits releases below {f}"),
    ("=={a}", ""),
])
def test_evidence_quotes_the_declaration(tmp_path: Path, pin: _Pin, spec: str, gloss: str) -> None:
    if pin in _PY_PINS:
        (tmp_path / "requirements.txt").write_text(pin.fill("{p}" + spec + "\n"), encoding="utf-8")
        written, where = pin.fill("{p}" + spec), ""
    else:
        npm_spec = pin.fill(spec.lstrip("="))
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {pin.package: npm_spec}}), encoding="utf-8")
        written, where = f'"{pin.package}": "{npm_spec}"', " in dependencies"
    findings, _ = pin.module.scan(tmp_path)
    [finding] = [f for f in findings if f.rule_id == pin.rule_id]
    assert repr(written) + where + pin.fill(gloss) + " — " in finding.evidence
    assert "pinned at" not in finding.evidence


@pytest.mark.parametrize("pin", tuple(p for p in _PY_PINS + _NPM_PINS if p.unversioned), ids=str)
def test_unversioned_reference_says_so(tmp_path: Path, pin: _Pin) -> None:
    if pin in _PY_PINS:
        (tmp_path / "requirements.txt").write_text(pin.package + "\n", encoding="utf-8")
    else:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {pin.package: "latest"}}), encoding="utf-8")
    findings, _ = pin.module.scan(tmp_path)
    [finding] = [f for f in findings if f.rule_id == pin.rule_id]
    assert "states no version AAK can read" in finding.evidence


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
def test_a_crafted_pyproject_reads_in_linear_time(tmp_path: Path, pin: _Pin) -> None:
    """A comment repeating the declaration 50,000 times above the real one, under
    the 2 MB limit: the line comes from the parsed document's positions, so the
    repetitions cost one pass. The bound is loose for slow CI runners."""
    declaration = pin.fill("{p}=={a}")
    (tmp_path / "pyproject.toml").write_text(
        _HEAD + "# " + f'"{declaration}" ' * 50_000 + f'\ndependencies = ["{declaration}"]\n',
        encoding="utf-8")
    started = time.perf_counter()
    findings, _ = pin.module.scan(tmp_path)
    assert time.perf_counter() - started < 5.0
    assert any(f.rule_id == pin.rule_id for f in findings)


@pytest.mark.parametrize("pin", _NPM_PINS, ids=str)
def test_a_crafted_package_json_script_reads_in_linear_time(tmp_path: Path, pin: _Pin) -> None:
    """These rules never read scripts, so a package.json drops them before it is
    read. Tokenising them with shlex, quadratic in the length of one word, took
    3.5 s for a 300 KB word. The bound is loose for slow CI runners."""
    body = {"dependencies": {pin.package: pin.affected}, "scripts": {"build": "a" * 1_000_000}}
    (tmp_path / "package.json").write_text(json.dumps(body), encoding="utf-8")
    started = time.perf_counter()
    assert pin.fires(tmp_path)
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize("text", [
    "[1, 2]",
    '{"dependencies": {',
    '{"overrides": ' + '{"a": ' * 5_000 + '"1"' + "}" * 5_001,   # deeper than the stack
])
@pytest.mark.parametrize("pin", _NPM_PINS, ids=str)
def test_an_unreadable_package_json_declares_nothing(tmp_path: Path, pin: _Pin, text: str) -> None:
    (tmp_path / "package.json").write_text(text, encoding="utf-8")
    assert not pin.fires(tmp_path)


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
@pytest.mark.parametrize("shape", ["one line", "one line each"])
def test_a_crafted_exclusion_list_reads_in_linear_time(tmp_path: Path, pin: _Pin, shape: str) -> None:
    """Exclusions used to be intersected one at a time, on one line or across lines:
    8,000 of them took 29 s on one line and 38 s on 8,000 lines. The bound is loose
    for slow CI runners."""
    exclusions = [f"!=0.{i}.0" for i in range(8_000)]
    if shape == "one line":
        text = pin.package + ",".join(exclusions) + "\n"
    else:
        text = "".join(f"{pin.package}{e}\n" for e in exclusions)
    (tmp_path / "requirements.txt").write_text(text, encoding="utf-8")
    started = time.perf_counter()
    assert pin.fires(tmp_path)
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize(("rule_id", "module", "text", "line"), [
    # A patched dev group above the affected main entry: the line is the main entry's.
    ("AAK-DNS-REBIND-002", dns_rebind,
     '[tool.poetry.group.dev.dependencies]\nmcp = "1.23.0"\n\n[tool.poetry.dependencies]\nmcp = "1.22.0"\n', 5),
    # A longer name that holds the same text, one line above.
    ("AAK-DNS-REBIND-002", dns_rebind,
     '[project]\nname = "x"\ndependencies = [\n  "fastmcp==1.22.0",\n  "mcp==1.22.0",\n]\n', 5),
    ("AAK-LANGCHAIN-001", langchain_vuln,
     '[project]\nname = "x"\ndependencies = [\n  "my-langchain-core==0.3.13",\n  "langchain-core==0.3.13",\n]\n', 5),
])
def test_a_finding_is_on_the_line_of_the_declaration_that_decides_it(
    tmp_path: Path, rule_id: str, module: ModuleType, text: str, line: int
) -> None:
    """The line used to be found by searching the text, so a longer name holding the
    declaration (`fastmcp==1.22.0`) or the same key in an earlier table took it. The
    lines now come from where each declaration sits in the parsed document."""
    (tmp_path / "pyproject.toml").write_text(text, encoding="utf-8")
    findings, _ = module.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == rule_id] == [line]


_PYPROJECT_MODULES = (langchain_vuln, neo4j_cve, ssrf_redirect, ssrf_toctou, dns_rebind)


def _big_pyproject(entries: int) -> str:
    return (_HEAD + "dependencies = [\n" + "".join(f'  "pkg{i}>=1.0",\n' for i in range(entries))
            + '  "langchain-core==0.3.13",\n  "mcp==1.22.0",\n]\n')


def test_one_pyproject_is_parsed_once_for_every_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Five modules read the root pyproject.toml, and each used to parse it alone: a
    1.9 MB file cost 3.6 s of CPU across them. They share one parse now. The bound
    is loose for slow CI runners."""
    from agent_audit_kit.scanners import _dependency_pins

    (tmp_path / "pyproject.toml").write_text(_big_pyproject(100_000), encoding="utf-8")
    assert (tmp_path / "pyproject.toml").stat().st_size < 2_000_000
    parses: list[str] = []
    real = _dependency_pins.manifest_declarations

    def counting(path: Path, text: str) -> list:
        parses.append(path.name)
        return real(path, text)

    monkeypatch.setattr(_dependency_pins, "manifest_declarations", counting)
    started = time.process_time()
    fired = {f.rule_id for module in _PYPROJECT_MODULES for f in module.scan(tmp_path)[0]}
    assert time.process_time() - started < 5.0
    assert parses == ["pyproject.toml"]
    assert {"AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003", "AAK-DNS-REBIND-002"} <= fired


def test_each_pin_reads_only_the_declarations_of_its_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each pin filtered every declaration of the file by name, so on the same 1.9 MB
    file the six pins cost more than the parse. A manifest files its declarations by
    package name once, as the pin table does, and a pin reads only its own package's."""
    from agent_audit_kit.scanners import _dependency_pins

    (tmp_path / "pyproject.toml").write_text(_big_pyproject(100_000), encoding="utf-8")
    seen: list[int] = []
    real = _dependency_pins._deciding_declaration

    def counting(pin: object, found: list) -> object:
        seen.append(len(found))
        return real(pin, found)

    monkeypatch.setattr(_dependency_pins, "_deciding_declaration", counting)
    fired = {f.rule_id for module in _PYPROJECT_MODULES for f in module.scan(tmp_path)[0]}
    assert len(seen) == 6 and max(seen) == 1
    assert {"AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003", "AAK-DNS-REBIND-002"} <= fired


def test_a_manifest_over_the_limit_is_not_read(tmp_path: Path) -> None:
    """A manifest over 2 MB, the CVE pin table's limit, is skipped unread, so a
    crafted 8 MB pyproject.toml costs nothing (19 s across these modules before)."""
    (tmp_path / "pyproject.toml").write_text(_big_pyproject(400_000), encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("x\n" * 1_100_000 + "mcp==1.22.0\n", encoding="utf-8")
    started = time.process_time()
    fired = {f.rule_id for module in _PYPROJECT_MODULES for f in module.scan(tmp_path)[0]}
    assert time.process_time() - started < 2.0
    assert not fired & {"AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003", "AAK-DNS-REBIND-002"}


# A git reference, a tarball and a workspace spec state a version in the tag, the
# file name or the range after `workspace:`. The first-number readers took it from
# there; read as unversioned, AAK-DNS-REBIND-002 (HIGH) lost them, and the two
# langchain SSRF pins reported a patched git requirement as stating no version.
_PY_REFS: tuple[tuple[str, str, bool | None], ...] = (
    ("pip VCS tag", "git+https://github.com/o/r@v{a}#egg={p}", True),
    ("pip VCS tag, fixed", "git+https://github.com/o/r@v{f}#egg={p}", False),
    ("editable, monorepo tag", "-e git+https://github.com/o/r@{p}=={a}#egg={p}&subdirectory=libs/x", True),
    ("editable, monorepo tag, fixed", "-e git+https://github.com/o/r@{p}=={f}#egg={p}&subdirectory=libs/x", False),
    ("PEP 508 direct reference", "{p} @ git+https://github.com/o/r@v{a}", True),
    ("PEP 508 direct reference, fixed", "{p} @ git+https://github.com/o/r@v{f}", False),
    ("sdist URL", "{p} @ https://files.example/{s}-{a}.tar.gz", True),
    ("sdist URL, fixed", "{p} @ https://files.example/{s}-{f}.tar.gz", False),
    ("commit", "git+https://github.com/o/r@4f2c1d9e8b7a#egg={p}", None),
)

_NPM_REFS: tuple[tuple[str, str, bool | None], ...] = (
    ("GitHub tag", "github:o/r#v{a}", True),
    ("GitHub tag, fixed", "github:o/r#v{f}", False),
    ("git URL tag", "git+https://github.com/o/r.git#{a}", True),
    ("git URL tag, fixed", "git+https://github.com/o/r.git#{f}", False),
    ("git semver range", "o/r#semver:^{a}", True),
    ("registry tarball", "https://registry.npmjs.org/{p}/-/{b}-{a}.tgz", True),
    ("registry tarball, fixed", "https://registry.npmjs.org/{p}/-/{b}-{f}.tgz", False),
    ("workspace range", "workspace:^{a}", True),
    ("workspace range, fixed", "workspace:^{f}", False),
    ("workspace, any", "workspace:*", None),
    ("commit", "github:o/r#4f2c1d9e8b7a", None),
    ("file: tarball", "file:../vendor/{b}-{a}.tgz", True),
    ("file: tarball, fixed", "file:../vendor/{b}-{f}.tgz", False),
    ("file: directory", "file:../vendor/{b}", None),
)


def _ref(template: str, pin: _Pin) -> str:
    return pin.fill(template.replace("{s}", pin.package.replace("-", "_"))
                    .replace("{b}", pin.package.rsplit("/", 1)[-1]))


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
@pytest.mark.parametrize(("label", "template", "fires"), _PY_REFS, ids=_ids(_PY_REFS))
def test_a_python_reference_states_its_version(
    tmp_path: Path, pin: _Pin, label: str, template: str, fires: bool | None
) -> None:
    (tmp_path / "requirements.txt").write_text(_ref(template, pin) + "\n", encoding="utf-8")
    assert pin.fires(tmp_path) is _expect(fires, pin), label


@pytest.mark.parametrize("pin", _PY_PINS, ids=str)
@pytest.mark.parametrize(("table", "fires"), [
    ('{ git = "https://github.com/o/r.git", tag = "v{a}" }', True),
    ('{ git = "https://github.com/o/r.git", tag = "v{f}" }', False),
    ('{ git = "https://github.com/o/r.git", tag = "{p}=={a}", subdirectory = "libs/x" }', True),
    ('{ git = "https://github.com/o/r.git", rev = "4f2c1d9e8b7a" }', None),
    ('{ url = "https://files.example/{s}-{a}.tar.gz" }', True),
    ('{ url = "https://files.example/{s}-{f}.tar.gz" }', False),
])
def test_a_poetry_reference_states_its_version(tmp_path: Path, pin: _Pin, table: str, fires: bool | None) -> None:
    (tmp_path / "pyproject.toml").write_text(_ref(_POETRY + "{p} = " + table + "\n", pin), encoding="utf-8")
    assert pin.fires(tmp_path) is _expect(fires, pin)


@pytest.mark.parametrize("pin", _NPM_PINS, ids=str)
@pytest.mark.parametrize(("label", "template", "fires"), _NPM_REFS, ids=_ids(_NPM_REFS))
def test_an_npm_reference_states_its_version(
    tmp_path: Path, pin: _Pin, label: str, template: str, fires: bool | None
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {pin.package: _ref(template, pin)}}), encoding="utf-8")
    assert pin.fires(tmp_path) is _expect(fires, pin), label


def test_a_token_in_a_git_url_stays_out_of_the_evidence(tmp_path: Path) -> None:
    secret = "QZX" + "9f3a7b21Zq7Wm2Kd"
    (tmp_path / "requirements.txt").write_text(
        f"-e git+https://x-access-token:{secret}@github.com/o/r@v1.1.13#egg=langchain-openai\n", encoding="utf-8")
    findings, _ = ssrf_toctou.scan(tmp_path)
    [finding] = [f for f in findings if f.rule_id == "AAK-SSRF-TOCTOU-001"]
    assert secret not in finding.evidence
    assert "states no version" not in finding.evidence


@pytest.mark.parametrize(("spec", "fires"), [
    ("mcp==1.22.0.*", True),
    ("mcp>=1.0,!=1.22.0.*", True),
    ("mcp==99.0.0.*", False),
])
def test_the_pin_table_reads_a_prefix_match_too(tmp_path: Path, spec: str, fires: bool) -> None:
    """The CVE pin table reads ranges with the same reader, so it gains `==X.Y.Z.*` too."""
    (tmp_path / "requirements.txt").write_text(spec + "\n", encoding="utf-8")
    fired = {f.rule_id for f in mcp_cve_pins_2026_07.scan(tmp_path)[0]}
    assert ("AAK-MCP-SDK-CVE-2026-52869-001" in fired) is fires
