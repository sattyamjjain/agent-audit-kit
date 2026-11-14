"""The Docker build context holds what the image is built from, and nothing else.

The Dockerfile's `COPY . /app` had no `.dockerignore` behind it, so the image
carried the whole checkout: tests, benchmarks, docs, research. Trivy scans the
image, and it reported the CVEs of a fake mlflow 3.16.0 install under
`tests/fixtures/known_vulns/` as the image's own (#1060). `.dockerignore` now
keeps only what `pip install .` builds the wheel from and the Action bridge.

These tests read `.dockerignore` as Docker does (the last matching pattern
decides, a pattern that matches a directory matches everything in it, `!`
takes a match back) and check it against the tracked files: no test fixture
reaches the context, every file the package ships does, and a wheel built from
the filtered context is the wheel built from the checkout.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    """Docker's pattern syntax (moby/patternmatcher): `**` spans directories,
    `*` and `?` stay within one, and the match is anchored at both ends."""
    out, i = "", 0
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**", i):
            i += 2
            if pattern.startswith("/", i):
                i += 1
            out += ".*" if i >= len(pattern) else "(.*/)?"
            continue
        out += "[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch)
        i += 1
    return re.compile(f"^{out}$")


def _rules() -> list[tuple[re.Pattern[str], bool]]:
    """(pattern, exception) for each line of `.dockerignore`, in order."""
    rules: list[tuple[re.Pattern[str], bool]] = []
    for raw in (REPO / ".dockerignore").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        exception = line.startswith("!")
        line = line[1:].strip() if exception else line
        rules.append((_pattern_regex(line.lstrip("/")), exception))
    return rules


def _excluded(path: str, rules: list[tuple[re.Pattern[str], bool]]) -> bool:
    """Whether Docker leaves `path` out: the last pattern that matches it, or a
    directory above it, decides."""
    parts = path.split("/")
    candidates = ["/".join(parts[: n + 1]) for n in range(len(parts))]
    excluded = False
    for regex, exception in rules:
        if any(regex.match(c) for c in candidates):
            excluded = not exception
    return excluded


def _tracked() -> list[str]:
    try:
        out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return out.stdout.splitlines()


def test_the_matcher_reads_patterns_as_docker_does() -> None:
    rules = [(_pattern_regex(p), False) for p in ("*", "**/__pycache__")]
    rules.insert(1, (_pattern_regex("pkg"), True))
    assert _excluded("tests/a.py", rules)
    assert not _excluded("pkg/a.py", rules)
    assert _excluded("pkg/sub/__pycache__/a.pyc", rules)
    assert _excluded("README.md", rules)


def test_no_test_fixture_or_other_tree_reaches_the_build_context() -> None:
    rules = _rules()
    kept = [p for p in _tracked() if not _excluded(p, rules)]
    assert kept, ".dockerignore leaves nothing to build from"
    tops = {p.split("/")[0] for p in kept}
    assert tops == {".gitignore", "LICENSE", "README.md", "agent_audit_kit", "entrypoint.sh", "pyproject.toml"}
    assert not [p for p in kept if p.endswith("CLAUDE.md")]
    assert all(_excluded(p, rules) for p in (
        "tests/fixtures/known_vulns/firing/lib/python3.12/site-packages/mlflow-3.16.0.dist-info/METADATA",
        ".claude/worktrees/x/agent_audit_kit/__init__.py", ".git/HEAD", "benchmarks/data/x.json",
    ))


def test_every_file_the_package_ships_reaches_the_build_context() -> None:
    rules = _rules()
    package = [p for p in _tracked() if p.startswith("agent_audit_kit/") and not p.endswith("/CLAUDE.md")]
    assert package
    assert [p for p in package if _excluded(p, rules)] == []


def _wheel_entries(source: Path, out: Path) -> dict[str, bytes]:
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "-q", "-w", str(out), str(source)],
        check=True, capture_output=True, text=True,
    )
    [wheel] = out.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        return {
            name: archive.read(name)
            for name in archive.namelist()
            if not name.endswith(".dist-info/RECORD")
        }


def test_a_wheel_built_from_the_context_is_the_wheel_built_from_the_checkout(tmp_path: Path) -> None:
    pytest.importorskip("hatchling")
    rules = _rules()
    context = tmp_path / "context"
    for rel in _tracked():
        if _excluded(rel, rules):
            continue
        dest = context / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dest)
    checkout = tmp_path / "checkout"
    for rel in _tracked():
        dest = checkout / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dest)
    built = _wheel_entries(context, tmp_path / "from-context")
    assert built == _wheel_entries(checkout, tmp_path / "from-checkout")
    assert "agent_audit_kit/__init__.py" in built


def test_the_dockerfile_comment_names_its_base_image() -> None:
    """The digest comment said python:3.11-slim after the FROM line moved to 3.15-slim."""
    text = (REPO / "Dockerfile").read_text(encoding="utf-8")
    image = re.search(r"^FROM (python:[\w.-]+)@sha256:", text, re.MULTILINE)
    assert image, "the base image is no longer a digest-pinned python image"
    comments = re.findall(r"^#.*\bpython:[\w.-]+", text, re.MULTILINE)
    assert comments and all(image.group(1) in c for c in comments), comments
