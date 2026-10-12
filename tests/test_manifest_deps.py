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
