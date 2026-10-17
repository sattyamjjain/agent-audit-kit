"""Tests for scanners/_manifest_deps.py: the declarations a file really makes.

The pin table used to search file text for a package name, so comments,
descriptions, server names, paths and images all read as declarations. These
cases fix what each format yields, and what it never yields.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.scanners._manifest_deps import declarations

GIT = "gi" + "t+https://github.com/o/r.git"


def _decls(name: str, text: str) -> list[tuple[str, str, str]]:
    return [(d.kind, d.name, d.version) for d in declarations(Path(name), text)]


def test_requirements_lines() -> None:
    text = (
        "# gateway needs litellm 1.90 or newer\n"
        "litellm[proxy]==1.90.0 ; python_version >= '3.9'  # pinned\n"
        "requests>=2.0 \\\n    --hash=sha256:abc\n"
        "-e " + GIT + "#egg=mcp-atlassian\n"
        "--index-url https://example.test/simple\n"
        "-r other.txt\n"
        + GIT + "#egg=langflow\n"
        + GIT + "\n"
        "./local/pkg\n"
    )
    assert _decls("requirements.txt", text) == [
        ("dependency", "litellm", "==1.90.0"),
        ("dependency", "requests", ">=2.0"),
        ("dependency", "mcp-atlassian", ""),
        ("dependency", "langflow", ""),
    ]


def test_pyproject_tables() -> None:
    text = (
        '[project]\nname = "litellm"\ndescription = "a litellm 1.90 gateway"\n'
        'dependencies = ["litellm==1.0.0"]\n'
        '[project.optional-dependencies]\nproxy = ["litellm[proxy]>=1.84"]\n'
        '[dependency-groups]\ndev = ["pytest", {include-group = "x"}]\n'
        '[build-system]\nrequires = ["hatchling"]\n'
        '[tool.poetry.dependencies]\npython = "^3.9"\ncline = "^3.0.20"\n'
        'mcp-atlassian = {version = "^0.21.0", extras = ["x"]}\n'
        'n8n = {git = "https://example.test/n8n.git"}\n'
        '[tool.poetry.group.dev.dependencies]\nruflo = "3.0.0"\n'
        '[tool.uv]\noverride-dependencies = ["litellm==1.90.0"]\n'
    )
    assert _decls("pyproject.toml", text) == [
        ("dependency", "litellm", "==1.0.0"),
        ("dependency", "litellm", ">=1.84"),
        ("dependency", "pytest", ""),
        ("dependency", "hatchling", ""),
        ("dependency", "cline", "^3.0.20"),
        ("dependency", "mcp-atlassian", "^0.21.0"),
        ("dependency", "n8n", ""),
        ("dependency", "ruflo", "3.0.0"),
        ("override", "litellm", "==1.90.0"),
    ]


def test_pipfile_categories() -> None:
    text = (
        '[[source]]\nurl = "https://pypi.org/simple"\n'
        '[packages]\nlitellm = "==1.90.0"\nrequests = "*"\n'
        'mcp-atlassian = {version = ">=0.21", extras = ["a"]}\n'
        '[dev-packages]\nletta = {path = "."}\n'
    )
    assert _decls("Pipfile", text) == [
        ("dependency", "litellm", "==1.90.0"),
        ("dependency", "requests", "*"),
        ("dependency", "mcp-atlassian", ">=0.21"),
        ("dependency", "letta", ""),
    ]


def test_package_json_sections_overrides_and_scripts() -> None:
    data = {
        "name": "repomix",
        "description": "uses repomix 9.0",
        "dependencies": {"cline": "^3.0.20", "my-alias": "npm:repomix@1.0.0"},
        "devDependencies": {"@agenticmail/openclaw": "0.9.9"},
        "overrides": {"cline": "3.0.31", "parent": {".": "1.0.0", "ruflo": "3.0.0"}},
        "resolutions": {"**/n8n": "2.0.0"},
        "pnpm": {"overrides": {"a>k8s@<2": "1.0.0"}},
        "scripts": {"mcp": "cross-env X=1 npx -y repomix@1.0.0 --mcp && next dev"},
    }
    assert _decls("package.json", json.dumps(data)) == [
        ("dependency", "cline", "^3.0.20"),
        ("dependency", "repomix", "1.0.0"),
        ("dependency", "@agenticmail/openclaw", "0.9.9"),
        ("override", "cline", "3.0.31"),
        ("override", "parent", "1.0.0"),
        ("override", "ruflo", "3.0.0"),
        ("override", "n8n", "2.0.0"),
        ("override", "k8s", "1.0.0"),
        ("launch", "repomix", "1.0.0"),
    ]


def test_mcp_config_reads_launches_not_labels() -> None:
    config = {
        "mcpServers": {
            "n8n": {"url": "https://n8n.example.test/mcp"},
            "k": {"command": "npx", "args": ["-y", "mcp-server-kubernetes"]},
            "r": {"command": "ruflo", "args": ["mcp", "start"]},
            "w": {"command": "uv", "args": ["--directory", "/opt/whatsapp-mcp", "run", "main.py"]},
            "d": {"command": "docker", "args": ["run", "-i", "flux159/mcp-server-kubernetes:3.8.0"]},
            "u": {"command": "uvx", "args": ["--from", "mcp-atlassian==0.22.0", "mcp-atlassian"]},
        },
        "nested": {"deep": [{"command": "uvx litellm==1.0.0"}]},
    }
    found = [(d.name, d.version, d.ecosystem) for d in declarations(Path(".mcp.json"), json.dumps(config))]
    assert found == [
        ("mcp-server-kubernetes", "", "js"),
        ("ruflo", "", None),
        ("docker", "", None),
        ("mcp-atlassian", "==0.22.0", "py"),
        ("litellm", "==1.0.0", "py"),
    ]


def test_mcp_config_jsonc_and_yaml() -> None:
    jsonc = '{\n  // a comment\n  "mcpServers": {"a": {"command": "npx", "args": ["x@1.0.0",],},},\n}\n'
    assert _decls(".mcp.json", jsonc) == [("launch", "x", "1.0.0")]
    yaml_text = "servers:\n  a:\n    command: npx\n    args: ['-y', 'repomix@1.0.0']\n"
    assert _decls("team.mcp.yaml", yaml_text) == [("launch", "repomix", "1.0.0")]


def test_a_file_that_does_not_parse_declares_nothing() -> None:
    assert declarations(Path("pyproject.toml"), "[project\n") == []
    assert declarations(Path("package.json"), "{not json") == []
    assert declarations(Path(".mcp.json"), '{"mcpServers": ') == []
    assert declarations(Path("Pipfile"), "= =") == []


def test_declarations_record_their_section_and_marker() -> None:
    """A pin constrains only its own install, so the reader keeps where it sits."""
    pyproject = (
        '[project]\nname = "x"\ndependencies = ["litellm>=1.0 ; python_version < \\"3.9\\""]\n'
        '[project.optional-dependencies]\nproxy = ["litellm==1.90.0"]\n'
        '[dependency-groups]\ndev = ["litellm==1.90.0"]\n'
        '[tool.poetry.dependencies]\nlitellm = [{version = "^1.0", python = "<3.9"}, "1.90.0"]\n'
        '[tool.uv]\nconstraint-dependencies = ["litellm==1.90.0"]\n'
    )
    found = [(d.kind, d.section, d.marker) for d in declarations(Path("pyproject.toml"), pyproject)]
    assert found == [
        ("dependency", "project.dependencies", 'python_version < "3.9"'),
        ("dependency", "project.optional-dependencies.proxy", ""),
        ("dependency", "dependency-groups.dev", ""),
        ("dependency", "tool.poetry.dependencies#0", "python <3.9"),
        ("dependency", "tool.poetry.dependencies#1", ""),
        ("constraint", "tool.uv.constraint-dependencies", ""),
    ]
    package = {"dependencies": {"repomix": "^1.0.0"}, "devDependencies": {"repomix": "1.14.1"},
               "overrides": {"repomix": "1.14.1"}}
    found = [(d.kind, d.section) for d in declarations(Path("package.json"), json.dumps(package))]
    assert found == [("dependency", "dependencies"), ("dependency", "devDependencies"),
                     ("override", "overrides")]


# --- where each declaration is written ---------------------------------------

def _lines(name: str, text: str) -> list[tuple[str, str, int | None]]:
    from agent_audit_kit.scanners._manifest_deps import declaration_lines

    found = declarations(Path(name), text)
    line = declaration_lines(Path(name), text)
    return [(d.name, d.version, line(d)) for d in found]


def test_every_format_gives_each_declaration_its_own_line() -> None:
    """Lines come from where each declaration sits in the parsed document, so
    two declarations of one package get two lines and a comment gets none."""
    pyproject = (
        "# litellm==1.0.0 is not a declaration\n"   # 1
        "[project]\n"                               # 2
        'name = "x"\n'                              # 3
        "dependencies = [\n"                        # 4
        '    "requests",\n'                         # 5
        '    "litellm==1.0.0",\n'                   # 6
        "]\n"                                       # 7
        "[project.optional-dependencies]\n"         # 8
        'proxy = ["litellm==1.90.0"]\n'             # 9
        "[tool.poetry.dependencies]\n"              # 10
        'litellm = """\n1.2.0"""\n'                 # 11-12, a multi-line string
        '"quoted.key" = "*"\n'                      # 13
        "[tool.poetry.group.dev.dependencies]\n"    # 14
        "litellm = { version = '^1.3', optional = true }\n"  # 15
    )
    assert _lines("pyproject.toml", pyproject) == [
        ("requests", "", 5), ("litellm", "==1.0.0", 6), ("litellm", "==1.90.0", 9),
        ("litellm", "1.2.0", 11), ("quoted.key", "*", 13), ("litellm", "^1.3", 15),
    ]
    package = json.dumps({"dependencies": {"a": "1.0.0"}, "overrides": {"b": {".": "2.0.0"}},
                          "scripts": {"go": "npx -y c@3.0.0"}}, indent=2)
    lines = package.splitlines()
    assert _lines("package.json", package) == [
        ("a", "1.0.0", lines.index('    "a": "1.0.0"') + 1),
        ("b", "2.0.0", lines.index('      ".": "2.0.0"') + 1),
        ("c", "3.0.0", lines.index('    "go": "npx -y c@3.0.0"') + 1),
    ]
    yaml_text = "servers:\n  c:\n    command: npx\n    args:\n      - -y\n      - c@3.0.0\n"
    assert _lines("team.mcp.yaml", yaml_text) == [("c", "3.0.0", 6)]


def test_a_requirements_line_is_its_physical_line() -> None:
    text = "# deps\nrequests==2.0 \\\n    --hash=sha256:abc\nlitellm==1.0.0\n"
    assert _lines("requirements.txt", text) == [("requests", "==2.0", 2), ("litellm", "==1.0.0", 4)]


def test_a_lockfile_package_source_resolves_its_array_of_tables() -> None:
    from agent_audit_kit.scanners._manifest_deps import _toml_positions

    text = ('[[package]]\nname = "a"\n\n[[package]]\nname = "b"\n\n[package.source]\n'
            'type = "git"\nurl = "https://example.test/b.git"\n')
    positions = _toml_positions(text)
    assert positions[("package", 1, "name")] == 5
    assert positions[("package", 1, "source", "url")] == 9


def test_a_self_referencing_yaml_document_ends() -> None:
    """A YAML alias can make a document contain itself; the command walk read
    such a document forever."""
    text = "a: &x\n  - command: npx\n    args: [-y, c@3.0.0]\n  - *x\n"
    assert [(d.name, d.version) for d in declarations(Path("x.mcp.yaml"), text)] == [("c", "3.0.0")]


# A YAML anchor makes one node reachable by many paths. Seven levels of anchors,
# ten aliases each, is 449 bytes and reaches the same ten servers by 10^7 paths;
# the walk followed every path, and the pin table took 26 s of CPU time on it.
# supply_chain reads MCP configs through the same walk for its older pins.
_ALIAS_BOMB = "a: &a [" + ", ".join(["{command: npx}"] * 10) + "]\n" + "".join(
    f"{level}: &{level} [{', '.join([f'*{prev}'] * 10)}]\n"
    for prev, level in zip("abcdef", "bcdefg")
)


def test_a_shared_yaml_node_is_walked_once() -> None:
    import time

    import yaml

    from agent_audit_kit.scanners._manifest_deps import _command_entries

    assert len(_ALIAS_BOMB) == 449
    started = time.perf_counter()
    entries = _command_entries(yaml.safe_load(_ALIAS_BOMB))
    # Each shared entry keeps the first path it was reached by, breadth first
    # in document order: the anchor's.
    assert [where for _, where in entries] == [("a", index) for index in range(10)]
    assert declarations(Path("x.mcp.yaml"), _ALIAS_BOMB) == []
    assert time.perf_counter() - started < 5.0


def test_an_alias_bomb_config_scans_in_linear_time(tmp_path: Path) -> None:
    import time

    from agent_audit_kit.scanners import mcp_cve_pins_2026_07, supply_chain

    (tmp_path / "x.mcp.yaml").write_text(_ALIAS_BOMB, encoding="utf-8")
    for scanner in (mcp_cve_pins_2026_07, supply_chain):
        started = time.perf_counter()
        scanner.scan(tmp_path)
        assert time.perf_counter() - started < 5.0, scanner.__name__
