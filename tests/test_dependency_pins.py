"""The seven version pins outside the CVE pin table read a dependency one way.

langchain_vuln, neo4j_cve, ssrf_redirect, ssrf_toctou, log_token_leak,
transport_limits and dns_rebind each took the first number after the package
name as the version in use, with a regex of its own per manifest. So an upper
bound read as the version (`pkg<FIXED` admits only affected releases and was
silent), the order of a range's bounds decided the answer, extras and markers
hid the version, and pyproject.toml and Poetry tables went unread. They now
read `_manifest_deps` declarations and judge them with the CVE pin table's own
policy (`_dependency_pins`). Every shape below runs through every pin, so a
module that drifts from the shared reading fails here.
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
    log_token_leak,
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
    _Pin("AAK-SPLUNK-TOKLOG-001", log_token_leak, "splunk-mcp-server", "1.0.2", "1.0.3", False),
    _Pin("AAK-DNS-REBIND-002", dns_rebind, "mcp", "1.22.0", "1.23.0", False),
)
_NPM_PINS = (
    _Pin("AAK-MCPFRAME-001", transport_limits, "mcp-framework", "0.2.21", "0.2.22", True),
    _Pin("AAK-NEXT-AI-DRAW-001", transport_limits, "next-ai-draw-io", "0.4.14", "0.4.15", True),
    _Pin("AAK-DNS-REBIND-002", dns_rebind, "@modelcontextprotocol/sdk", "1.21.0", "1.21.1", False),
    _Pin("AAK-DNS-REBIND-002", dns_rebind, "@apollo/mcp-server", "1.6.0", "1.7.0", False),
    _Pin("AAK-SPLUNK-TOKLOG-001", log_token_leak, "splunk-mcp-server", "1.0.2", "1.0.3", False),
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
    ("PEP 503 spelling", "{u}=={a}", True),
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
    """A comment repeating the declaration 100,000 times above the real one, which
    the line lookup reads match by match with a bounded look-back. The bound is
    loose for slow CI runners."""
    declaration = pin.fill("{p}=={a}")
    (tmp_path / "pyproject.toml").write_text(
        _HEAD + "# " + f'"{declaration}" ' * 100_000 + f'\ndependencies = ["{declaration}"]\n',
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
