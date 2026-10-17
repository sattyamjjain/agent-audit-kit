"""`aak install-precommit` adds its entry to the repos list and changes nothing else.

The command judged `.pre-commit-config.yaml` by substring. A file without `repos:` in
it was replaced by the entry, so a config holding only settings lost them, and so did
a JSON-style config, whose key reads `"repos":`. A config whose last key was not
`repos` (pre-commit.ci's `ci:` block) got the entry under that key and stopped
parsing. A comment naming agent-audit-kit read as the hook being configured. The file
is parsed now: the entry goes after the repos list's last item, the result must parse
to the old file plus that entry, and anything else is refused with the file as it was.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

import agent_audit_kit
from agent_audit_kit import __version__
from agent_audit_kit.cli import cli

REPO_ROOT = Path(__file__).resolve().parent.parent
_ENTRY = {
    "repo": "https://github.com/sattyamjjain/agent-audit-kit",
    "rev": f"v{__version__}",
    "hooks": [{"id": "agent-audit-kit"}],
}
_ADDED = "added agent-audit-kit pre-commit hook to .pre-commit-config.yaml\nnext: run `pre-commit install`\n"
_CONFIGURED = "agent-audit-kit hook already configured in .pre-commit-config.yaml\n"
_BLACK = "repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n    hooks:\n      - id: black\n"
_ZERO = "repos:\n- repo: https://github.com/psf/black\n  rev: 24.1.0\n  hooks:\n  - id: black\n"
_BLOCK_SCALAR = (
    "repos:\n  - repo: local\n    hooks:\n      - id: check\n        entry: |\n          one\n          # two\n\n"
)


def _hook(indent: str = "  ", newline: str = "\n") -> str:
    lines = [
        "- repo: https://github.com/sattyamjjain/agent-audit-kit",
        f"  rev: v{__version__}",
        "  hooks:",
        "    - id: agent-audit-kit",
    ]
    return "".join(f"{indent}{line}{newline}" for line in lines)


def _install(tmp_path: Path, config: bytes | None) -> tuple[int, str, Path]:
    project = tmp_path / "proj"
    project.mkdir()
    path = project / ".pre-commit-config.yaml"
    if config is not None:
        path.write_bytes(config)
    result = CliRunner().invoke(cli, ["install-precommit", str(project)])
    return result.exit_code, result.output, path


@pytest.mark.parametrize(
    ("before", "after"),
    [
        pytest.param(None, "repos:\n" + _hook(), id="created"),
        pytest.param("", "repos:\n" + _hook(), id="empty"),
        pytest.param("# hooks\n# none yet\n", "# hooks\n# none yet\nrepos:\n" + _hook(), id="comments-only"),
        pytest.param(
            "default_stages: [pre-commit]\nfail_fast: true\n# hooks go here\n",
            "default_stages: [pre-commit]\nfail_fast: true\n# hooks go here\nrepos:\n" + _hook(),
            id="settings-without-repos",
        ),
        pytest.param(_BLACK, _BLACK + _hook(), id="repos-last"),
        pytest.param(
            _BLACK + "ci:\n  autofix_prs: false\n", _BLACK + _hook() + "ci:\n  autofix_prs: false\n", id="ci-after-repos"
        ),
        pytest.param(
            _BLACK + "\n# pre-commit.ci\nci:\n  skip: [black]\n",
            _BLACK + _hook() + "\n# pre-commit.ci\nci:\n  skip: [black]\n",
            id="the-next-keys-comments-stay-with-it",
        ),
        pytest.param(
            _BLACK + "      # - id: black-jupyter\nci: {}\n",
            _BLACK + "      # - id: black-jupyter\n" + _hook() + "ci: {}\n",
            id="a-comment-under-the-last-item-stays-with-it",
        ),
        pytest.param(_ZERO + "ci: {}\n", _ZERO + _hook("") + "ci: {}\n", id="zero-indent-items"),
        pytest.param(_BLACK.rstrip("\n"), _BLACK + _hook(), id="no-final-newline"),
        pytest.param(
            _BLACK.replace("repos:\n", "repos:\n  # agent-audit-kit, once it is released\n"),
            _BLACK.replace("repos:\n", "repos:\n  # agent-audit-kit, once it is released\n") + _hook(),
            id="a-comment-naming-the-hook",
        ),
        pytest.param(
            "repos:\n# - repo: https://github.com/psf/black\n",
            "repos:\n" + _hook() + "# - repo: https://github.com/psf/black\n",
            id="every-item-commented-out",
        ),
        pytest.param(
            _BLOCK_SCALAR + "# after\nci: {}\n", _BLOCK_SCALAR + _hook() + "# after\nci: {}\n", id="block-scalar-last"
        ),
    ],
)
def test_the_entry_goes_at_the_end_of_repos_and_nothing_else_changes(
    tmp_path: Path, before: str | None, after: str
) -> None:
    code, output, path = _install(tmp_path, None if before is None else before.encode())

    assert (code, output) == (0, _ADDED)
    written = path.read_bytes().decode()
    assert written == (after if before else after.replace("\n", os.linesep))
    old = yaml.safe_load(before or "") or {}
    assert yaml.safe_load(written) == {**old, "repos": [*(old.get("repos") or []), _ENTRY]}


def test_a_crlf_config_keeps_its_line_ends(tmp_path: Path) -> None:
    """`read_text` and `write_text` turned every CRLF into the platform's line end; the
    file is read and written as bytes now, and the entry takes the file's own breaks."""
    before = (_BLACK + "ci:\n  autofix_prs: false\n").replace("\n", "\r\n")

    code, output, path = _install(tmp_path, before.encode())

    assert (code, output) == (0, _ADDED)
    assert path.read_bytes().decode() == (_BLACK + _hook() + "ci:\n  autofix_prs: false\n").replace("\n", "\r\n")


def test_the_repos_own_config_takes_the_entry(tmp_path: Path) -> None:
    before = (REPO_ROOT / ".pre-commit-config.yaml").read_bytes()

    code, output, path = _install(tmp_path, before)

    assert (code, output) == (0, _ADDED)
    old = yaml.safe_load(before)
    assert yaml.safe_load(path.read_bytes()) == {**old, "repos": [*old["repos"], _ENTRY]}
    assert path.read_bytes().startswith(before.rstrip(b"\n"))


@pytest.mark.parametrize(
    "config",
    [
        pytest.param(_BLACK + _hook(), id="installed-before"),
        pytest.param(
            "repos:\n  - repo: https://github.com/sattyamjjain/agent-audit-kit.git\n    rev: v0.5.0\n"
            "    hooks:\n      - id: agent-audit-kit\n",
            id="url-with-dot-git",
        ),
        pytest.param(
            "repos:\n- repo: https://github.com/SattyamJjain/agent-audit-kit/\n  rev: v0.5.0\n  hooks: []\n",
            id="url-with-a-slash-in-another-case",
        ),
        pytest.param(
            "repos:\n- repo: local\n  hooks:\n  - id: agent-audit-kit\n    name: aak\n    entry: aak scan\n"
            "    language: system\n",
            id="the-hook-id-under-another-repo",
        ),
        pytest.param(
            '{"repos": [{"repo": "https://github.com/sattyamjjain/agent-audit-kit", "rev": "v1", '
            '"hooks": [{"id": "agent-audit-kit"}]}]}\n',
            id="json-style-that-has-it",
        ),
    ],
)
def test_already_configured_is_read_from_the_parsed_file(tmp_path: Path, config: str) -> None:
    code, output, path = _install(tmp_path, config.encode())

    assert (code, output) == (0, _CONFIGURED)
    assert path.read_bytes() == config.encode()


def _refused(reason: str) -> str:
    return (
        f"Cannot add the hook: .pre-commit-config.yaml {reason}. .pre-commit-config.yaml was not changed.\n"
        "Add this entry under repos: by hand:\n" + _hook()
    )


@pytest.mark.parametrize(
    ("config", "reason"),
    [
        pytest.param(
            b'{"repos": [{"repo": "https://github.com/psf/black", "rev": "24.1.0", "hooks": [{"id": "black"}]}]}\n',
            "is written in flow style, like JSON",
            id="json-style",
        ),
        pytest.param(b"repos: []\n", "does not write repos as a block list", id="flow-repos"),
        pytest.param(b"repos:\n  black: {}\n", "does not write repos as a block list", id="repos-a-mapping"),
        pytest.param(b"- repo: https://github.com/psf/black\n", "is not a YAML mapping", id="a-list"),
        pytest.param(
            b"repos:\n- repo: a\nrepos:\n- repo: b\n",
            "does not parse as YAML (found the key 'repos' twice on line 3)",
            id="a-key-written-twice",
        ),
        pytest.param(b"repos:\n# caf\xe9\n", "is not UTF-8", id="not-utf-8"),
        pytest.param(b"repos: ~\nci: {}\n", "would change beyond its repos list", id="an-explicit-null"),
        pytest.param(
            b"base: &shared\n  - repo: a\nrepos: *shared\n", "would change beyond its repos list", id="an-aliased-list"
        ),
    ],
)
def test_a_file_it_cannot_add_to_is_refused_and_left_as_it_was(tmp_path: Path, config: bytes, reason: str) -> None:
    code, output, path = _install(tmp_path, config)

    assert (code, output) == (2, _refused(reason))
    assert path.read_bytes() == config


def test_an_unparseable_file_is_refused_and_left_as_it_was(tmp_path: Path) -> None:
    config = b"repos:\n  - repo: [unclosed\n"

    code, output, path = _install(tmp_path, config)

    assert code == 2
    assert output.startswith("Cannot add the hook: .pre-commit-config.yaml does not parse as YAML (")
    assert output.endswith(". .pre-commit-config.yaml was not changed.\nAdd this entry under repos: by hand:\n" + _hook())
    assert path.read_bytes() == config


@pytest.mark.parametrize(("size", "added"), [(1_000_000, True), (1_000_001, False)], ids=["at-the-cap", "past-it"])
def test_a_config_over_a_megabyte_is_refused(tmp_path: Path, size: int, added: bool) -> None:
    """The parse is pure Python, so the read stops one byte past 1,000,000 bytes."""
    tail = _BLACK.encode()
    config = b"#" * (size - len(tail) - 1) + b"\n" + tail

    code, output, path = _install(tmp_path, config)

    if added:
        assert (code, output) == (0, _ADDED)
        assert path.read_bytes() == config + _hook().encode()
    else:
        assert (code, output) == (2, _refused("is over 1 MB, which AAK does not edit"))
        assert path.read_bytes() == config


# The check runs in a child process, so a comparison that walks every path through the
# aliases fails the test on its timeout instead of holding the suite.
_ALIAS_CHILD = (
    "import sys\n"
    "from click.testing import CliRunner\n"
    "from agent_audit_kit.cli import cli\n"
    "result = CliRunner().invoke(cli, ['install-precommit', sys.argv[1]])\n"
    "print(result.exit_code, result.output.splitlines()[0])\n"
)


@pytest.mark.parametrize("levels", [40, 5_000], ids=["2**40-paths", "5000-deep"])
def test_nested_aliases_are_compared_in_linear_time(tmp_path: Path, levels: int) -> None:
    """`a<n>: &a<n> [*a<n-1>, *a<n-1>]` over forty levels gives 2**40 paths through the
    file, and a comparison of the old and new data that followed each one would not
    end; each shared list is compared once. Over 5,000 levels a recursive comparison
    would pass the interpreter's recursion limit; the comparison keeps its own stack."""
    lines = ["a0: &a0 [x, x]"] + [f"a{n}: &a{n} [*a{n - 1}, *a{n - 1}]" for n in range(1, levels + 1)]
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".pre-commit-config.yaml").write_text("\n".join(lines) + "\n" + _BLACK)
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent

    done = subprocess.run(
        [sys.executable, "-c", _ALIAS_CHILD, str(project)],
        capture_output=True, text=True, timeout=60, env={**os.environ, "PYTHONPATH": str(package_root)},
    )

    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "0 added agent-audit-kit pre-commit hook to .pre-commit-config.yaml"
