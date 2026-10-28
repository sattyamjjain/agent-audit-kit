"""startup_hooks: Python startup files and npm install scripts that run unasked.

litellm 1.107.0 (21 Oct 2026, OSV MAL-2026-2144) put `cook.pth`, `cook.py` and
`sitecustomize.py` at the top of site-packages and ran at every Python start.
These tests pin each route the scanner reports, the files it must leave alone
(path-only `.pth`, the allowlisted setuptools file), where it looks (inside
virtualenvs, never in node_modules, down to the depth cap) and how it reads a
`.pth` (as CPython 3.9 to 3.15 do). Every fixture is a placeholder: the `.pth`
imports a module that does nothing.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import startup_hooks
from agent_audit_kit.scanners._site_packages import MAX_SITE_DEPTH
from agent_audit_kit.scanners.startup_hooks import normalised_sha256, scan, startup_lines

FIXTURE = Path(__file__).parent / "fixtures" / "startup_hooks" / "project"
SITE = "lib/python3.12/site-packages"
PTH, CUSTOMIZE = "AAK-STARTUP-HOOK-PTH-001", "AAK-STARTUP-HOOK-SITECUSTOMIZE-001"
DOCKERFILE, NPM = "AAK-STARTUP-HOOK-DOCKERFILE-001", "AAK-STARTUP-HOOK-NPM-INSTALL-001"
RULE_IDS = (PTH, CUSTOMIZE, DOCKERFILE, NPM)
SETUPTOOLS_PTH = (
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
    "enabled and __import__('_distutils_hack').add_shim(); \n"
)


def _found(root: Path) -> set[tuple[str, str, int | None]]:
    findings, _ = scan(root)
    return {(f.rule_id, f.file_path, f.line_number) for f in findings}


def _site(root: Path, *parts: str) -> Path:
    site = root.joinpath(*parts) if parts else root / ".venv" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    return site


# ---- the committed fixture ---------------------------------------------------------


def test_the_fixture_reports_each_route_once_and_nothing_else() -> None:
    assert _found(FIXTURE) == {
        (PTH, f"{SITE}/cook.pth", 1),
        (CUSTOMIZE, f"{SITE}/sitecustomize.py", 2),
        (PTH, "vendor/site-packages/distutils-precedence.pth", 1),
        (DOCKERFILE, "Dockerfile", 4),
        (NPM, "package-lock.json", 21),
    }


def test_the_pth_evidence_names_the_file_the_line_and_its_text() -> None:
    findings, _ = scan(FIXTURE)
    cook = next(f for f in findings if f.file_path.endswith("cook.pth"))
    assert "`cook.pth`" in cook.evidence
    assert "line 1, `import aak_placeholder_noop`" in cook.evidence
    assert cook.severity is Severity.HIGH


def test_a_path_only_pth_and_the_allowlisted_setuptools_file_are_quiet() -> None:
    reported = {path for _, path, _ in _found(FIXTURE)}
    assert f"{SITE}/aak_paths_only.pth" not in reported
    assert f"{SITE}/distutils-precedence.pth" not in reported
    # The same name with other content is not the allowlisted file.
    assert "vendor/site-packages/distutils-precedence.pth" in reported


def test_the_allowlist_matches_by_content_not_by_name() -> None:
    raw = SETUPTOOLS_PTH.encode()
    assert normalised_sha256(raw) == normalised_sha256(b"\xef\xbb\xbf" + raw.replace(b"\n", b"\r\n"))
    assert normalised_sha256(b"# comment\n" + raw) == normalised_sha256(raw)
    assert normalised_sha256(b"import aak_placeholder_noop\n") != normalised_sha256(raw)
    entries = json.loads(
        (Path(startup_hooks.__file__).parent.parent / "data" / "startup_hook_allowlist.json").read_text()
    )["entries"]
    assert {"distutils-precedence.pth", "_virtualenv.pth", "a1_coverage.pth"} <= {e["name"] for e in entries}
    assert all(e["sha256"] and e["source"] for e in entries)


def test_the_npm_entry_without_an_install_script_is_quiet() -> None:
    findings, _ = scan(FIXTURE)
    npm = [f for f in findings if f.rule_id == NPM]
    assert len(npm) == 1
    assert "aak-placeholder-native@1.0.0" in npm[0].evidence
    assert "aak-placeholder-plain" not in npm[0].evidence


def test_sarif_round_trip_places_every_rule_on_a_line() -> None:
    result = run_scan(project_root=FIXTURE)
    mine = ScanResult(findings=[f for f in result.findings if f.rule_id in RULE_IDS])
    sarif = json.loads(format_results(mine, min_severity=Severity.LOW))
    placed = {
        r["ruleId"]: r["locations"][0]["physicalLocation"]["region"]["startLine"]
        for r in sarif["runs"][0]["results"]
    }
    assert set(placed) == set(RULE_IDS)
    assert all(isinstance(line, int) and line >= 1 for line in placed.values())
    rules = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules == set(RULE_IDS)


def test_the_rules_are_registered_at_their_severities() -> None:
    assert RULES[PTH].severity is Severity.HIGH
    assert RULES[CUSTOMIZE].severity is Severity.HIGH
    assert RULES[DOCKERFILE].severity is Severity.MEDIUM
    assert RULES[NPM].severity is Severity.LOW


# ---- where the walk looks ------------------------------------------------------------


@pytest.mark.parametrize("env", [".venv", "venv", "env", ".tox/py312", "vendor"])
def test_site_packages_inside_an_environment_is_read(tmp_path: Path, env: str) -> None:
    site = _site(tmp_path, *env.split("/"), "lib", "python3.12", "site-packages")
    (site / "cook.pth").write_text("import aak_placeholder_noop\n")
    rel = site.relative_to(tmp_path).as_posix()
    assert _found(tmp_path) == {(PTH, f"{rel}/cook.pth", 1)}


def test_debian_dist_packages_and_an_unpacked_image_root_are_read(tmp_path: Path) -> None:
    for site in ("usr/local/lib/python3.12/site-packages", "usr/lib/python3/dist-packages"):
        _site(tmp_path, *site.split("/"))
        (tmp_path / site / "cook.pth").write_text("import aak_placeholder_noop\n")
    assert {path for _, path, _ in _found(tmp_path)} == {
        "usr/local/lib/python3.12/site-packages/cook.pth",
        "usr/lib/python3/dist-packages/cook.pth",
    }


def test_the_scan_root_may_itself_be_site_packages(tmp_path: Path) -> None:
    site = _site(tmp_path, "site-packages")
    (site / "cook.pth").write_text("import aak_placeholder_noop\n")
    assert _found(site) == {(PTH, "cook.pth", 1)}


def test_node_modules_and_git_are_never_walked(tmp_path: Path) -> None:
    for skipped in ("node_modules/pkg/site-packages", ".git/site-packages"):
        site = _site(tmp_path, *skipped.split("/"))
        (site / "cook.pth").write_text("import aak_placeholder_noop\n")
    assert _found(tmp_path) == set()


def test_only_the_top_of_site_packages_is_read(tmp_path: Path) -> None:
    site = _site(tmp_path)
    (site / "pkg").mkdir()
    (site / "pkg" / "cook.pth").write_text("import aak_placeholder_noop\n")
    assert _found(tmp_path) == set()


def test_the_depth_cap_is_where_the_limitation_says(tmp_path: Path) -> None:
    deepest = ["d"] * (MAX_SITE_DEPTH - 1) + ["site-packages"]
    too_deep = ["e"] * MAX_SITE_DEPTH + ["site-packages"]
    for parts in (deepest, too_deep):
        (_site(tmp_path, *parts) / "cook.pth").write_text("import aak_placeholder_noop\n")
    assert {path.split("/")[0] for _, path, _ in _found(tmp_path)} == {"d"}
    assert MAX_SITE_DEPTH == 12  # the limitation names this number
    assert "up to 12 directories" in RULES[PTH].limitations


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_a_symlinked_site_packages_is_not_followed(tmp_path: Path) -> None:
    real = _site(tmp_path, "outside", "site-packages")
    (real / "cook.pth").write_text("import aak_placeholder_noop\n")
    root = tmp_path / "project"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "site-packages").symlink_to(real, target_is_directory=True)
    assert _found(root) == set()


# ---- how a .pth or .start is read ------------------------------------------------------


@pytest.mark.parametrize(
    "content, lines",
    [
        (b"import aak_placeholder_noop\n", [(1, "import aak_placeholder_noop")]),
        (b"import\taak_placeholder_noop\n", [(1, "import\taak_placeholder_noop")]),
        # CPython 3.15 strips the line before the test (PEP 829); 3.9 to 3.14 do not.
        (b"   import aak_placeholder_noop\n", [(1, "import aak_placeholder_noop")]),
        # 3.12 and later decode utf-8-sig, so a BOM does not hide the first line.
        (b"\xef\xbb\xbfimport aak_placeholder_noop\n", [(1, "import aak_placeholder_noop")]),
        # 3.12 and later split with str.splitlines(), which breaks at a form feed.
        (b"/opt/x\x0cimport aak_placeholder_noop\n", [(2, "import aak_placeholder_noop")]),
        (b"# import aak_placeholder_noop\n/opt/x\nimportlib\nimport\n", []),
    ],
)
def test_pth_lines_are_read_as_site_py_reads_them(content: bytes, lines: list[tuple[int, str]]) -> None:
    assert startup_lines(content, ".pth") == lines


def test_a_start_file_reports_its_first_entry_point(tmp_path: Path) -> None:
    site = _site(tmp_path)
    (site / "hook.start").write_text("# a comment\n\naak_placeholder_noop:run\nother:run\n")
    (site / "quiet.start").write_text("# nothing to call\n")
    findings, _ = scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [(PTH, 3)]
    assert "PEP 829" in findings[0].evidence and "1 more line(s)" in findings[0].evidence


def test_a_hidden_pth_is_reported_with_the_version_note(tmp_path: Path) -> None:
    (_site(tmp_path) / ".hidden.pth").write_text("import aak_placeholder_noop\n")
    findings, _ = scan(tmp_path)
    assert len(findings) == 1 and "starts with a dot" in findings[0].evidence


def test_a_long_line_is_cut_to_80_characters_in_the_evidence(tmp_path: Path) -> None:
    (_site(tmp_path) / "long.pth").write_text("import aak_placeholder_noop; " + "x = 1; " * 40 + "\n")
    finding = scan(tmp_path)[0][0]
    shown = finding.evidence.split("line 1, `", 1)[1].split("`", 1)[0]
    assert len(shown) == 81 and shown.endswith("…")


def test_a_startup_file_over_the_cap_is_refused_not_passed(tmp_path: Path) -> None:
    (_site(tmp_path) / "huge.pth").write_bytes(b"import aak_placeholder_noop\n" + b"#" * 1_000_001)
    result = run_scan(project_root=tmp_path)
    assert not [f for f in result.findings if f.rule_id == PTH]
    refused = [f for f in result.findings if f.rule_id == "AAK-INTERNAL-SCANNER-FAIL"]
    assert any("huge.pth" in f.evidence and "startup file larger than" in f.evidence for f in refused)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_a_fifo_named_like_a_pth_is_skipped_without_waiting(tmp_path: Path) -> None:
    os.mkfifo(_site(tmp_path) / "cook.pth")
    assert _found(tmp_path) == set()


# ---- sitecustomize and usercustomize ---------------------------------------------------


def test_every_importable_form_of_sitecustomize_is_reported(tmp_path: Path) -> None:
    site = _site(tmp_path)
    (site / "usercustomize.pyc").write_bytes(b"placeholder")
    (site / "sitecustomize.cpython-312-x86_64-linux-gnu.so").write_bytes(b"placeholder")
    (site / "__pycache__").mkdir()
    (site / "__pycache__" / "sitecustomize.cpython-312.pyc").write_bytes(b"placeholder")
    (site / "__pycache__" / "other.cpython-312.pyc").write_bytes(b"placeholder")
    found = {path.rsplit("/", 1)[-1] for _, path, _ in _found(tmp_path)}
    assert found == {
        "usercustomize.pyc", "sitecustomize.cpython-312-x86_64-linux-gnu.so", "sitecustomize.cpython-312.pyc",
    }


def test_a_sitecustomize_package_is_reported_at_its_init(tmp_path: Path) -> None:
    package = _site(tmp_path) / "sitecustomize"
    package.mkdir()
    (package / "__init__.py").write_text("pass\n")
    assert _found(tmp_path) == {(CUSTOMIZE, ".venv/lib/python3.12/site-packages/sitecustomize/__init__.py", 1)}


def test_a_dockerfile_pythonpath_dir_is_read_in_an_unpacked_image(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nENV PYTHONPATH=/opt/hooks:/srv\n")
    (tmp_path / "opt" / "hooks").mkdir(parents=True)
    (tmp_path / "opt" / "hooks" / "sitecustomize.py").write_text("pass\n")
    findings, _ = scan(tmp_path)
    assert [(f.rule_id, f.file_path) for f in findings] == [(CUSTOMIZE, "opt/hooks/sitecustomize.py")]
    assert "PYTHONPATH" in findings[0].evidence


def test_a_build_context_dir_copied_onto_pythonpath_is_read(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nWORKDIR /app\nCOPY hooks/ ./\nENV PYTHONPATH=/app\n"
    )
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / "sitecustomize.py").write_text("pass\n")
    findings, _ = scan(tmp_path)
    assert [(f.rule_id, f.file_path) for f in findings] == [(CUSTOMIZE, "hooks/sitecustomize.py")]


# ---- Dockerfiles ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "step",
    [
        "COPY cook.pth /usr/local/lib/python3.12/site-packages/",
        'COPY ["cook.pth", "/usr/local/lib/python3.12/site-packages/"]',
        "ADD --chown=app sitecustomize.py /usr/local/lib/python3.12/site-packages/",
        "COPY --from=build /out/hook /usr/local/lib/python3.12/site-packages/aak.pth",
        "RUN echo 'import aak_placeholder_noop' > /usr/local/lib/python3.12/site-packages/aak.pth",
        "RUN printf 'import aak_placeholder_noop\\n' | tee -a /usr/lib/python3/dist-packages/aak.pth",
        "RUN cp /tmp/hook.py /usr/local/lib/python3.12/site-packages/sitecustomize.py",
        "RUN apt-get update \\\n && cat > /usr/local/lib/python3.12/site-packages/aak.pth <<'EOF'\nimport aak_placeholder_noop\nEOF",
    ],
)
def test_a_dockerfile_that_adds_a_startup_file_is_reported(tmp_path: Path, step: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12-slim\n{step}\n")
    assert {(rule, line) for rule, _, line in _found(tmp_path)} == {(DOCKERFILE, 2)}


@pytest.mark.parametrize(
    "step",
    [
        "COPY requirements.txt /app/",
        "RUN echo done > /tmp/notes.txt",
        "RUN pip install --no-cache-dir -r /app/requirements.txt",
        "ENV PYTHONSTARTUP=/app/startup.py",  # no MCP server in this image
    ],
)
def test_ordinary_dockerfile_steps_are_quiet(tmp_path: Path, step: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"FROM python:3.12-slim\n{step}\nCMD [\"python\", \"app.py\"]\n")
    assert _found(tmp_path) == set()


def test_pythonstartup_in_an_mcp_server_image_is_reported(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nENV PYTHONSTARTUP=/app/startup.py\n"
        'CMD ["uvx", "aak-placeholder-mcp-server"]\n'
    )
    findings, _ = scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [(DOCKERFILE, 2)]
    assert "interactive" in findings[0].evidence


# ---- npm lockfiles ----------------------------------------------------------------------------


def _lockfile(root: Path, packages: dict, version: int = 3) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": version, "packages": packages}))


_SCRIPTED = {"": {"name": "x"}, "node_modules/aak-placeholder-native": {"version": "1.0.0", "hasInstallScript": True}}


def test_an_install_script_outside_an_mcp_project_is_quiet(tmp_path: Path) -> None:
    _lockfile(tmp_path, _SCRIPTED)
    assert _found(tmp_path) == set()


def test_an_mcp_json_server_makes_it_an_mcp_project(tmp_path: Path) -> None:
    _lockfile(tmp_path, _SCRIPTED)
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": {"command": "node", "args": ["s.js"]}}}))
    assert {rule for rule, _, _ in _found(tmp_path)} == {NPM}


def test_ignore_scripts_in_npmrc_and_lockfile_v1_are_quiet(tmp_path: Path) -> None:
    sdk = {"node_modules/@modelcontextprotocol/sdk": {"version": "1.0.0"}}
    _lockfile(tmp_path / "a", {**_SCRIPTED, **sdk})
    (tmp_path / "a" / ".npmrc").write_text("ignore-scripts=true\n")
    _lockfile(tmp_path / "b", {**_SCRIPTED, **sdk}, version=1)
    assert _found(tmp_path) == set()


def test_node_modules_lockfiles_are_never_read(tmp_path: Path) -> None:
    sdk = {"node_modules/@modelcontextprotocol/sdk": {"version": "1.0.0"}}
    _lockfile(tmp_path / "node_modules" / "dep", {**_SCRIPTED, **sdk})
    assert _found(tmp_path) == set()


# ---- what lies outside the scanned root -------------------------------------------------


def test_a_pythonpath_outside_the_scan_root_is_not_read(tmp_path: Path) -> None:
    """`ENV PYTHONPATH=/../outside`, or a path through a symlinked directory, named
    the host's own files; the scan read them and then crashed placing the finding."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sitecustomize.py").write_text("import os\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "Dockerfile").write_text("FROM python:3.12\nENV PYTHONPATH=/../outside:/link:/link/../link\n")
    findings, scanned = scan(root)
    assert findings == []
    assert scanned == {"Dockerfile"}


def test_a_symlinked_startup_file_is_read_where_the_image_reads_it(tmp_path: Path) -> None:
    """Debian links `sitecustomize.py` to `/etc/python3.X/`, an absolute target that
    names the image's own file when the tree is an unpacked image; followed on the host
    it named the host's. A link that still leads out of the root is not read."""
    root = tmp_path / "rootfs"
    site = root / "usr" / "lib" / "python3" / "dist-packages"
    site.mkdir(parents=True)
    (root / "etc" / "python3").mkdir(parents=True)
    (root / "etc" / "python3" / "sitecustomize.py").write_text("import os\n")
    (site / "sitecustomize.py").symlink_to("/etc/python3/sitecustomize.py")
    host = tmp_path / "host.pth"
    host.write_text("import host_module\n")
    (site / "absolute-out.pth").symlink_to(host)
    (site / "relative-out.pth").symlink_to(Path("..", "..", "..", "..", "..", "host.pth"))
    (root / "etc" / "python3" / "inside.pth").write_text("import inside_module\n")
    (site / "relative-in.pth").symlink_to(Path("..", "..", "..", "..", "etc", "python3", "inside.pth"))
    findings, _ = scan(root)
    assert sorted((f.rule_id, f.file_path) for f in findings) == [
        ("AAK-STARTUP-HOOK-PTH-001", "usr/lib/python3/dist-packages/relative-in.pth"),
        ("AAK-STARTUP-HOOK-SITECUSTOMIZE-001", "usr/lib/python3/dist-packages/sitecustomize.py"),
    ]

