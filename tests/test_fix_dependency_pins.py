"""`aak fix` raises a version pin the way its rule reads it.

The bumps for AAK-LANGCHAIN-001, AAK-LANGCHAIN-003 and AAK-NEO4J-001 matched
`name op version` at the start of a requirement line and judged the first
number, as the rules did before they moved onto `_dependency_pins`. So the fix
answered "No langchain-core pin below the fix" for `langchain-core<1.2.22`, which
the rule reports, could not see a pin with extras, and refused pyproject.toml,
where the rules read PEP 621 and Poetry tables. The fix now reads the file with
the rule's own reader, raises every declaration that admits an affected release,
and checks that the rule no longer fires before it writes anything.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import agent_audit_kit
from agent_audit_kit import fix
from agent_audit_kit.scanners import langchain_vuln, neo4j_cve

_HEAD = '[project]\nname = "app"\nversion = "0.1.0"\n'
_POETRY = '[tool.poetry]\nname = "app"\n\n[tool.poetry.dependencies]\npython = "^3.10"\n'


def _fires(root: Path, rule_id: str) -> bool:
    module = neo4j_cve if rule_id == "AAK-NEO4J-001" else langchain_vuln
    return any(f.rule_id == rule_id for f in module.scan(root)[0])


def _fixed(root: Path, name: str, rule_id: str) -> tuple[fix.FixAction | None, str]:
    action = fix._apply_fix(root, rule_id, name, dry_run=False)
    return action, (root / name).read_bytes().decode("utf-8")


@pytest.mark.parametrize(("name", "before", "after"), [
    # The shapes the old bump left alone or broke.
    ("requirements.txt", "langchain-core<1.2.22\n", "langchain-core>=1.2.22\n"),
    ("requirements.txt", "langchain-core<2,>=1\n", "langchain-core>=1.2.22,<2.0.0\n"),
    ("requirements.txt", "langchain-core>=1.0.0,<2.0.0\n", "langchain-core>=1.2.22,<2.0.0\n"),
    ("requirements.txt", "langchain-core~=1.2.0\n", "langchain-core>=1.2.22,<1.3.0\n"),
    ("requirements.txt", "langchain-core[all]==1.2.21\n", "langchain-core[all]>=1.2.22\n"),
    ("requirements.txt", 'langchain-core==1.2.21 ; python_version >= "3.9"  # pinned\n',
     'langchain-core>=1.2.22 ; python_version >= "3.9"  # pinned\n'),
    ("requirements.txt", "LangChain_Core==1.2.21\n", "LangChain_Core>=1.2.22\n"),
    # One install's lines are raised together; a fixed line and other packages stay.
    ("requirements.txt", "# langchain-core==1.0.0 was here\nlangchain-core>=1.0\nlangchain-core<2\nlangchain==1.1.5\n",
     "# langchain-core==1.0.0 was here\nlangchain-core>=1.2.22\nlangchain-core>=1.2.22,<2.0.0\nlangchain==1.1.5\n"),
    ("requirements-dev.txt", "pytest\r\nlangchain-core==1.2.21\r\n", "pytest\r\nlangchain-core>=1.2.22\r\n"),
    # pyproject.toml: PEP 621 strings, an extra, a dependency group, Poetry values.
    ("pyproject.toml", _HEAD + 'dependencies = ["fastapi", "langchain-core<1.2.22"]\n',
     _HEAD + 'dependencies = ["fastapi", "langchain-core>=1.2.22"]\n'),
    ("pyproject.toml", _HEAD + "dependencies = [\n  \"langchain-core[all]==1.2.21; python_version >= '3.9'\",\n]\n",
     _HEAD + "dependencies = [\n  \"langchain-core[all]>=1.2.22; python_version >= '3.9'\",\n]\n"),
    ("pyproject.toml", _HEAD + '\n[project.optional-dependencies]\nai = ["langchain-core>=1.0"]\n',
     _HEAD + '\n[project.optional-dependencies]\nai = ["langchain-core>=1.2.22"]\n'),
    ("pyproject.toml", _HEAD + '\n[dependency-groups]\ndev = ["langchain-core==1.2.0"]\n',
     _HEAD + '\n[dependency-groups]\ndev = ["langchain-core>=1.2.22"]\n'),
    ("pyproject.toml", _POETRY + 'langchain-core = "^1.2.0"\n', _POETRY + 'langchain-core = ">=1.2.22,<2.0.0"\n'),
    ("pyproject.toml", _POETRY + "langchain-core = '1.2.21'\n", _POETRY + "langchain-core = '>=1.2.22'\n"),
    ("pyproject.toml", _POETRY + 'langchain-core = { version = "<1.2.22", extras = ["all"] }\n',
     _POETRY + 'langchain-core = { version = ">=1.2.22", extras = ["all"] }\n'),
])
def test_langchain_core_fix_clears_the_rule(tmp_path: Path, name: str, before: str, after: str) -> None:
    (tmp_path / name).write_bytes(before.encode("utf-8"))  # as written: CRLF stays CRLF
    assert _fires(tmp_path, "AAK-LANGCHAIN-001")
    action, text = _fixed(tmp_path, name, "AAK-LANGCHAIN-001")
    assert action is not None and action.applied, action
    assert text == after
    assert not _fires(tmp_path, "AAK-LANGCHAIN-001")
    assert "Raised" in action.description and ">=1.2.22" in action.description


def test_both_langchain_core_fixes_leave_the_higher_floor(tmp_path: Path) -> None:
    """AAK-LANGCHAIN-003 runs after -001 has raised the line, and finds nothing to do."""
    (tmp_path / "requirements.txt").write_text("langchain-core==0.3.10\nrequests==2.31.0\n", encoding="utf-8")
    for rule_id in ("AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003"):
        fix._apply_fix(tmp_path, rule_id, "requirements.txt", dry_run=False)
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == "langchain-core>=1.2.22\nrequests==2.31.0\n"
    for rule_id in ("AAK-LANGCHAIN-003", "AAK-LANGCHAIN-001"):
        (tmp_path / "requirements.txt").write_text("langchain-core==0.3.10\n", encoding="utf-8")
        fix._apply_fix(tmp_path, rule_id, "requirements.txt", dry_run=False)
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == "langchain-core>=1.2.22\n"


@pytest.mark.parametrize(("name", "before", "after"), [
    ("requirements.txt", "mcp-neo4j-cypher[all]==0.5.0\n", "mcp-neo4j-cypher[all]>=0.6.0\n"),
    ("dev-requirements.txt", "mcp-neo4j-cypher<0.6.0\n", "mcp-neo4j-cypher>=0.6.0\n"),
    ("pyproject.toml", _HEAD + 'dependencies = ["mcp-neo4j-cypher>=0.4,<1"]\n',
     _HEAD + 'dependencies = ["mcp-neo4j-cypher>=0.6.0,<1.0.0"]\n'),
    ("pyproject.toml", _POETRY + 'mcp-neo4j-cypher = "^0.5.0"\n', _POETRY + 'mcp-neo4j-cypher = ">=0.6.0"\n'),
])
def test_neo4j_fix_clears_the_rule(tmp_path: Path, name: str, before: str, after: str) -> None:
    (tmp_path / name).write_text(before, encoding="utf-8")
    assert _fires(tmp_path, "AAK-NEO4J-001")
    action, text = _fixed(tmp_path, name, "AAK-NEO4J-001")
    assert action is not None and action.applied, action
    assert text == after
    assert not _fires(tmp_path, "AAK-NEO4J-001")


@pytest.mark.parametrize(("name", "before", "why"), [
    # pip refuses a range for a hashed requirement, and the hash names the old release.
    ("requirements.txt", "langchain-core==1.2.21 --hash=sha256:00ff\n", "--hash"),
    # The declaration spans two physical lines.
    ("requirements.txt", "langchain-core \\\n    ==1.2.21\n", "continues onto the next line"),
    # The version sits on a line of its own, below the table header.
    ("pyproject.toml", '[tool.poetry.dependencies.langchain-core]\nversion = "1.2.21"\n', "on another line"),
    # A reference names its release in a tag or a file name, which a range cannot replace.
    ("requirements.txt", "-e git+https://github.com/langchain-ai/langchain@langchain-core==1.2.21"
     "#egg=langchain-core&subdirectory=libs/core\n", "git reference or URL"),
    ("requirements.txt", "langchain-core @ https://files.example/langchain_core-1.2.21.tar.gz\n",
     "git reference or URL"),
    ("pyproject.toml", _POETRY + 'langchain-core = { git = "https://github.com/langchain-ai/langchain.git", '
     'tag = "langchain-core==1.2.21" }\n', "git reference or URL"),
])
def test_a_declaration_it_cannot_rewrite_is_left_and_named(tmp_path: Path, name: str, before: str, why: str) -> None:
    (tmp_path / name).write_text(before, encoding="utf-8")
    assert _fires(tmp_path, "AAK-LANGCHAIN-001")
    action, text = _fixed(tmp_path, name, "AAK-LANGCHAIN-001")
    assert action is not None and not action.applied
    assert text == before
    assert why in action.description
    assert _fires(tmp_path, "AAK-LANGCHAIN-001")


def test_one_declaration_it_cannot_rewrite_leaves_the_whole_file(tmp_path: Path) -> None:
    """Raising line 1 alone would leave `>=1.2.22` beside `==1.2.21`, a file pip cannot
    install, so a manifest is rewritten whole or not at all."""
    before = "langchain-core>=1.0\nlangchain-core==1.2.21 --hash=sha256:00ff\n"
    (tmp_path / "requirements.txt").write_text(before, encoding="utf-8")
    action, text = _fixed(tmp_path, "requirements.txt", "AAK-LANGCHAIN-001")
    assert action is not None and not action.applied
    assert text == before
    assert "line 2" in action.description and "--hash" in action.description


def test_dry_run_proposes_without_writing(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain-core<1.2.22\n", encoding="utf-8")
    action = fix._apply_fix(tmp_path, "AAK-LANGCHAIN-001", "requirements.txt", dry_run=True)
    assert action is not None and not action.applied
    assert "Raised 1" in action.description
    assert (tmp_path / "requirements.txt").read_text(encoding="utf-8") == "langchain-core<1.2.22\n"


@pytest.mark.parametrize(("name", "body"), [
    ("requirements.txt", "langchain-core>=1.2.22\nlangchain==1.1.5\n"),
    ("requirements.txt", "langchain-core\n"),     # states no version; the rule does not report it
    ("requirements.txt", "langchain-core @ git+https://github.com/o/r@v1.2.22\n"),   # a fixed tag
    ("package.json", '{"dependencies": {"@langchain/core": "0.3.10"}}'),
    ("app.py", "from langchain_core.prompts import load_prompt\n"),
])
def test_nothing_to_raise_writes_nothing(tmp_path: Path, name: str, body: str) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")
    action, text = _fixed(tmp_path, name, "AAK-LANGCHAIN-001")
    assert action is not None and not action.applied
    assert text == body


def test_run_fixes_agrees_with_the_rules(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "langchain-core[all]<1.2.22\nmcp-neo4j-cypher>=0.4\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(_POETRY + 'langchain-core = "^1.2.0"\n', encoding="utf-8")
    fix.run_fixes(tmp_path)
    for rule_id in ("AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003", "AAK-NEO4J-001"):
        assert not _fires(tmp_path, rule_id), rule_id


def test_a_crafted_requirements_file_raises_in_linear_time(tmp_path: Path) -> None:
    """8,000 lines that each exclude a release: every one admits an affected release
    and is raised, and the result is checked against the rule once. The bound is
    loose for slow CI runners."""
    (tmp_path / "requirements.txt").write_text(
        "".join(f"langchain-core!=0.{i}.0\n" for i in range(8_000)), encoding="utf-8")
    started = time.perf_counter()
    action, text = _fixed(tmp_path, "requirements.txt", "AAK-LANGCHAIN-001")
    assert time.perf_counter() - started < 5.0
    assert action is not None and action.applied
    assert text == "langchain-core>=1.2.22\n" * 8_000


def test_a_manifest_over_the_limit_is_left_alone(tmp_path: Path) -> None:
    """The rules do not read a manifest over 2 MB, so the fix does not rewrite one."""
    before = "x\n" * 1_100_000 + "langchain-core==1.2.21\n"
    (tmp_path / "requirements.txt").write_text(before, encoding="utf-8")
    action, text = _fixed(tmp_path, "requirements.txt", "AAK-LANGCHAIN-001")
    assert action is not None and not action.applied
    assert "over 2 MB" in action.description
    assert text == before


@pytest.mark.parametrize("target", ["outside the project", "inside the project"])
def test_a_symlinked_manifest_is_refused_and_its_target_left_alone(tmp_path: Path, target: str) -> None:
    """The rule reads a requirements.txt through a link, so `aak fix` reaches one, and
    writing through it rewrote whatever it named, inside the project or not. The write
    goes through `_write_inside_project`, which refuses a link, and a dry run reports
    the refusal too."""
    project = tmp_path / "proj"
    project.mkdir()
    real = tmp_path / "outside.txt" if target == "outside the project" else project / "base.txt"
    real.write_bytes(b"langchain-core==1.2.21\n")
    (project / "requirements.txt").symlink_to(real)
    assert _fires(project, "AAK-LANGCHAIN-001")
    for dry_run in (True, False):
        action = fix._apply_fix(project, "AAK-LANGCHAIN-001", "requirements.txt", dry_run=dry_run)
        assert action is not None and not action.applied
        assert action.description == "Failed to fix: requirements.txt is a symlink"
    assert real.read_bytes() == b"langchain-core==1.2.21\n"


# A child process runs the fix, so a read or write that blocks on a FIFO fails the
# test on its timeout instead of hanging the suite. "look" lets the FIFO through the
# look before the read, and "swap" replaces the manifest with a FIFO after it is
# read, as a change in between would.
_FIX_CHILD = (
    "import os, sys\n"
    "from pathlib import Path\n"
    "from agent_audit_kit import fix\n"
    "from agent_audit_kit.scanners import _dependency_pins\n"
    "root, how = Path(sys.argv[1]), sys.argv[2]\n"
    "path = root / 'requirements.txt'\n"
    "if how == 'look':\n"
    "    real, looks = fix._write_refusal, []\n"
    "    fix._write_refusal = lambda *args: looks.append(1) if not looks else real(*args)\n"
    "if how == 'swap':\n"
    "    real = _dependency_pins.raise_to_fix\n"
    "    def swapping(*args):\n"
    "        result = real(*args)\n"
    "        path.unlink()\n"
    "        os.mkfifo(path)\n"
    "        return result\n"
    "    _dependency_pins.raise_to_fix = swapping\n"
    "action = fix._fix_raised_pin(path, 'AAK-LANGCHAIN-001', root, dry_run=False)\n"
    "print(action.applied, action.description)\n"
)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
@pytest.mark.parametrize(("how", "said"), [
    ("fifo", "Failed to fix: requirements.txt is not a regular file"),
    ("look", "Unable to read file"),
    ("swap", "Failed to fix: requirements.txt is not a regular file"),
], ids=["fifo", "look", "swap"])
def test_a_fifo_named_like_the_manifest_is_refused_without_blocking(tmp_path: Path, how: str, said: str) -> None:
    """A FIFO blocks the open that would read or write it until the other end comes.
    The fix read the manifest after checking only its size, 0 for a FIFO, and wrote it
    with `open(path, "w")`; both waited forever. A FIFO is refused before it is read;
    one that gets past that look is refused by the read, which takes only a regular
    file; and one put in the manifest's place after the read is refused by the write."""
    if how != "swap":
        os.mkfifo(tmp_path / "requirements.txt")
    else:
        (tmp_path / "requirements.txt").write_text("langchain-core==1.2.21\n", encoding="utf-8")
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    done = subprocess.run(
        [sys.executable, "-c", _FIX_CHILD, str(tmp_path), how], capture_output=True, text=True, timeout=30,
        env={**os.environ, "PYTHONPATH": str(package_root)},
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == f"False {said}"
