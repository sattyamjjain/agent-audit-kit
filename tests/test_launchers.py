"""Tests for scanners/_launchers.py: which packages a launch command fetches."""

from __future__ import annotations

import pytest

from agent_audit_kit.scanners._launchers import (
    basename,
    invocation,
    launched_packages,
    npm_spec,
    py_spec,
    shell_tokens,
    starts_with_launcher,
)

GIT = "gi" + "t+https://github.com/o/r"


def _specs(argv: list[str]) -> list[tuple[str, str, bool]]:
    return [(x.ecosystem, x.spec, x.extra) for x in launched_packages(argv)]


@pytest.mark.parametrize(("argv", "expected"), [
    # The package is the first positional; its own arguments are not packages.
    (["npx", "-y", "mcp-remote@0.1.30", "https://example.test/mcp"],
     [("js", "mcp-remote@0.1.30", False)]),
    (["npx", "-y", "some-mcp-server", "--port", "3000"], [("js", "some-mcp-server", False)]),
    (["uvx", "some-mcp-server==1.2.3"], [("py", "some-mcp-server==1.2.3", False)]),
    # Option values are skipped, and an option can name the package.
    (["uvx", "--python", "3.12", "mcp-server-fetch"], [("py", "mcp-server-fetch", False)]),
    (["uvx", "--env-file", "/path/to/.env", "zscaler-mcp-server"],
     [("py", "zscaler-mcp-server", False)]),
    (["uvx", "--from", "x==1.0", "x"], [("py", "x==1.0", False)]),
    (["uvx", "--from=x==1.0", "x"], [("py", "x==1.0", False)]),
    (["uvx", "--with", "requests", "srv==1.0"],
     [("py", "requests", True), ("py", "srv==1.0", False)]),
    (["npx", "-p", "a", "-p", "b@2.0.0", "cmd"], [("js", "a", False), ("js", "b@2.0.0", False)]),
    (["npx", "-y", "--", "pkg@1.0.0"], [("js", "pkg@1.0.0", False)]),
    # A value with spaces is one argument.
    (["uvx", "--from", "name @ " + GIT + "@abcdef1", "cmd"],
     [("py", "name @ " + GIT + "@abcdef1", False)]),
    # Relatives of npx and uvx.
    (["pnpm", "dlx", "create-x@latest", "mcp"], [("js", "create-x@latest", False)]),
    (["yarn", "dlx", "-p", "a@1.0.0", "a"], [("js", "a@1.0.0", False)]),
    (["npm", "exec", "--package=a@1", "--", "cmd"], [("js", "a@1", False)]),
    (["bun", "x", "a@1.0.0"], [("js", "a@1.0.0", False)]),
    (["uv", "tool", "run", "--from", "x@latest", "x.exe"], [("py", "x@latest", False)]),
    (["/usr/bin/uv", "--directory", "/x", "run", "--with", "fastmcp==2.0", "fastmcp", "run"],
     [("py", "fastmcp==2.0", True)]),
    (["pipx", "run", "--spec", "pkg==1.0", "app"], [("py", "pkg==1.0", False)]),
    (["C:\\tools\\npx.cmd", "-y", "x@1.0.0"], [("js", "x@1.0.0", False)]),
    # Behind a shell, or nested in another server's arguments.
    (["cmd", "/c", "npx", "-y", "meta-ads-mcp@latest"], [("js", "meta-ads-mcp@latest", False)]),
    (["bash", "-c", "cd /x && npx -y a@1 && uvx b"], [("js", "a@1", False), ("py", "b", False)]),
    (["npx", "-y", "supergateway", "--stdio", "npx -y @scope/server /tmp"],
     [("js", "supergateway", False), ("js", "@scope/server", False)]),
    # Not a launcher: nothing is fetched.
    (["node", "/abs/node_modules/@zosmaai/pi-llm-wiki/dist/mcp/index.js"], []),
    (["docker", "run", "-i", "--rm", "image:latest"], []),
    (["npx"], []),
])
def test_launched_packages(argv: list[str], expected: list) -> None:
    assert _specs(argv) == expected


@pytest.mark.parametrize(("argv", "packages", "command"), [
    # The positional is the package, whose own command runs.
    (["npx", "husky", "install"], [("js", "husky", False)], []),
    # An option named the package, so the positional is the command it runs.
    (["npx", "-p", "husky", "sh", "./evil.sh"], [("js", "husky", False)], ["sh", "./evil.sh"]),
    (["npm", "exec", "--package=husky", "--", "sh", "./evil.sh"], [("js", "husky", False)],
     ["sh", "./evil.sh"]),
    (["uvx", "--from", "x==1.0", "x", "--port", "1"], [("py", "x==1.0", False)], ["x", "--port", "1"]),
    # `uv run` runs the project's own command; only `--with` fetches.
    (["uv", "run", "--with", "requests", "--directory", "../serena", "serena-mcp-server"],
     [("py", "requests", True)], ["serena-mcp-server"]),
    # The command ends at a control operator.
    (["npx", "-p", "a", "cmd", "&&", "sh", "x"], [("js", "a", False)], ["cmd"]),
    (["node", "x.js"], [], []),
])
def test_invocation_reads_the_command_a_launcher_runs(
    argv: list[str], packages: list, command: list[str],
) -> None:
    found, runs = invocation(argv)
    assert [(x.ecosystem, x.spec, x.extra) for x in found] == packages
    assert runs == command


def test_launcher_detection_and_basename() -> None:
    assert starts_with_launcher(["npx", "x"])
    assert starts_with_launcher(["uv", "run", "x"])
    assert not starts_with_launcher(["uv", "pip", "install", "x"])
    assert not starts_with_launcher(["ruflo", "mcp", "start"])
    assert basename("C:\\Program Files\\nodejs\\npx.cmd") == "npx"
    assert basename("/usr/local/bin/uvx") == "uvx"


def test_shell_tokens_keep_a_commit_fragment_and_split_operators() -> None:
    assert shell_tokens("npx github:org/repo#abc1234 && echo 'a b'") == [
        "npx", "github:org/repo#abc1234", "&&", "echo", "a b",
    ]
    assert shell_tokens("npx 'unbalanced") == ["npx", "'unbalanced"]


@pytest.mark.parametrize(("spec", "expected"), [
    ("pkg", ("registry", "pkg", "")),
    ("pkg@^1.2", ("registry", "pkg", "^1.2")),
    ("@scope/pkg@1.2.3", ("registry", "@scope/pkg", "1.2.3")),
    ("@scope/pkg", ("registry", "@scope/pkg", "")),
    ("npm:repomix@1.0.0", ("registry", "repomix", "1.0.0")),
    ("github:org/repo#abc1234", ("vcs", "", "github:org/repo#abc1234")),
    ("org/repo#abc1234", ("vcs", "", "org/repo#abc1234")),
    ("./local", ("local", "", "")),
])
def test_npm_spec(spec: str, expected: tuple[str, str, str]) -> None:
    parts = npm_spec(spec)
    assert (parts.kind, parts.name, parts.version) == expected


@pytest.mark.parametrize(("spec", "expected"), [
    ("litellm[proxy]==1.90.0 ; python_version >= '3.9'", ("registry", "litellm", "==1.90.0")),
    ("litellm [proxy] >= 1.0", ("registry", "litellm", ">= 1.0")),
    ("pkg (>=1.0)", ("registry", "pkg", ">=1.0")),
    ("awslabs.healthlake-mcp-server@0.0.5", ("registry", "awslabs.healthlake-mcp-server", "==0.0.5")),
    ("pkg@latest", ("registry", "pkg", "latest")),
    ("name @ " + GIT + "@abcdef1", ("vcs", "name", GIT + "@abcdef1")),
    (GIT + "@abcdef1", ("vcs", "", GIT + "@abcdef1")),
    ("./local", ("local", "", "")),
])
def test_py_spec(spec: str, expected: tuple[str, str, str]) -> None:
    parts = py_spec(spec)
    assert (parts.kind, parts.name, parts.version) == expected
