"""AAK-MALICIOUS-EXTENSION-001: editor extensions of an agent host, checked against the feed.

Cursor's marketplace served tampered builds of `anthropic.claude-code` 2.1.312 and
2.1.313 on 29 Oct 2026. These tests pin where an install is read (a home's
`.<editor>/extensions/` folders and their `extensions.json` index, under the scan
root or, when asked, this user's home), how a folder name parses, which editors an
entry covers, the digest match that tells a tampered build from a real release of
the same number, and that a workspace recommendation, which names no version, is
reported only for an every-version entry. Every fixture is a folder name, a
version string or a few bytes of text; no extension code is used.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from agent_audit_kit import malicious_feed
from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.malicious_extensions import extension_dirs, host_of, scan

FIXTURES = Path(__file__).parent / "fixtures" / "malicious_extensions"
RULE = "AAK-MALICIOUS-EXTENSION-001"
# The SHA-256 Cursor's notice gives for the tampered extension.js of 2.1.312 and 2.1.313.
PAYLOAD_SHA256 = "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15"


def _found(root: Path, **kwargs: object) -> list[tuple[str, int | None]]:
    findings, _ = scan(root, **kwargs)  # type: ignore[arg-type]
    assert all(f.rule_id == RULE and f.severity is Severity.CRITICAL for f in findings)
    return [(f.file_path, f.line_number) for f in findings]


def _extension(home: Path, editor: str, folder: str, **files: str) -> Path:
    path = home / editor / "extensions" / folder
    path.mkdir(parents=True)
    version = folder.split("-")[2] if folder.count("-") >= 2 else "0.0.0"
    (path / "package.json").write_text(
        json.dumps({"name": "claude-code", "publisher": "Anthropic", "version": version}, indent=2))
    for name, text in files.items():
        (path / name.replace("__", ".")).write_text(text)
    return path


def _cached_feed(*extensions: dict) -> None:
    path = malicious_feed.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "generated_at": "2026-11-01T00:00:00Z", "source": "test feed", "entries": [], "oci": [],
        "extensions": list(extensions),
    }))


def _entry(**extra: object) -> dict:
    return {"id": "EXT-TEST", "extension": "anthropic.claude-code", "url": "", "note": "", **extra}


# ---- the fixtures the order names -------------------------------------------------------------


def test_cursor_home_with_2_1_313_is_critical() -> None:
    root = FIXTURES / "cursor-home"
    assert _found(root) == [(".cursor/extensions/anthropic.claude-code-2.1.313/package.json", 4)]
    (finding,), _ = scan(root)
    for part in ("anthropic.claude-code 2.1.313 for cursor", "CURSOR-CLAUDE-CODE-2026-10-29",
                 "Remove the extension", "update to 2.1.314 or later",
                 "svc-telemetry", "authorized_keys", "LaunchAgents", "SysMon", "crontab",
                 "not whether it ran", "bundled copy generated"):
        assert part in finding.evidence, part


def test_the_fixed_release_is_quiet() -> None:
    assert _found(FIXTURES / "cursor-home-fixed") == []


def test_an_entry_for_cursor_alone_leaves_vs_code_alone() -> None:
    _cached_feed(_entry(versions=["2.1.313"], hosts=["cursor"]))
    assert _found(FIXTURES / "vscode-home") == []
    assert _found(FIXTURES / "cursor-home") != []


def test_the_bundled_entry_covers_every_editor() -> None:
    # Anthropic never published a 2.1.313 (absent from npm, the VS Code Marketplace and
    # Open VSX on 2026-11-01), so a 2.1.313 in any editor is the tampered build.
    assert _found(FIXTURES / "vscode-home") == [(".vscode/extensions/anthropic.claude-code-2.1.313/package.json", 4)]


def test_a_platform_suffixed_folder_parses_to_the_same_id_and_version() -> None:
    (finding,), _ = scan(FIXTURES / "cursor-home-platform")
    assert finding.file_path == ".cursor/extensions/anthropic.claude-code-2.1.313-darwin-arm64/package.json"
    assert "anthropic.claude-code 2.1.313 (darwin-arm64) for cursor" in finding.evidence


def test_a_workspace_recommendation_of_a_version_specific_entry_is_quiet() -> None:
    assert _found(FIXTURES / "project-recommends") == []


def test_a_recommendation_of_an_every_version_entry_is_reported() -> None:
    _cached_feed(_entry(extension="evil.fake-claude", all_versions=True))
    assert _found(FIXTURES / "project-recommends") == []  # it recommends anthropic.claude-code only
    _cached_feed(_entry(all_versions=True))
    assert _found(FIXTURES / "project-recommends") == [(".vscode/extensions.json", 3)]


# ---- content, not the version number ----------------------------------------------------------


def test_a_real_2_1_312_is_quiet_and_one_with_the_published_digest_is_not(tmp_path: Path) -> None:
    real = tmp_path / "real"
    _extension(real, ".cursor", "anthropic.claude-code-2.1.312", extension__js="// the publisher's build\n")
    assert _found(real) == []
    body = "// a stand-in whose digest a test feed lists\n"
    _cached_feed(_entry(sha256={"extension.js": [hashlib.sha256(body.encode()).hexdigest()]}))
    tampered = tmp_path / "tampered"
    _extension(tampered, ".vscode", "anthropic.claude-code-2.1.312-win32-x64", extension__js=body)
    (finding,), _ = scan(tampered)
    assert "its extension.js has SHA-256" in finding.evidence and "EXT-TEST" in finding.evidence
    assert _found(real) == []


def test_the_bundled_entry_carries_cursors_published_digest() -> None:
    feed = malicious_feed.parse_feed(json.loads(malicious_feed.BUNDLED_FEED.read_text()), "bundled",
                                     malicious_feed.BUNDLED_FEED)
    (entry,) = feed.extension("Anthropic.Claude-Code")
    assert entry.versions == frozenset({"2.1.313"}) and entry.hosts == frozenset({"*"})
    assert entry.sha256 == (("extension.js", frozenset({PAYLOAD_SHA256})),)
    assert entry.fixed == "2.1.314" and entry.url == "https://cursor.com/blog/claude-code-extension-security-notice"


def test_an_unreadable_or_oversized_file_is_not_hashed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_audit_kit.scanners import malicious_extensions

    body = "x" * 100
    _cached_feed(_entry(sha256={"extension.js": [hashlib.sha256(body.encode()).hexdigest()]}))
    _extension(tmp_path, ".cursor", "anthropic.claude-code-2.1.312", extension__js=body)
    assert len(_found(tmp_path)) == 1
    monkeypatch.setattr(malicious_extensions, "MAX_HASHED_BYTES", 10)
    assert _found(tmp_path) == []


# ---- the index ---------------------------------------------------------------------------------


def _index(home: Path, editor: str, rows: list[tuple[str, str]]) -> Path:
    extensions = home / editor / "extensions"
    extensions.mkdir(parents=True, exist_ok=True)
    index = extensions / "extensions.json"
    index.write_text(json.dumps([
        {"identifier": {"id": ident}, "version": version, "relativeLocation": f"{ident}-{version}",
         "location": {"$mid": 1, "path": f"/home/u/{editor}/extensions/{ident}-{version}", "scheme": "file"}}
        for ident, version in rows
    ]))
    return index


def test_an_index_entry_whose_folder_is_gone_is_reported_once(tmp_path: Path) -> None:
    _index(tmp_path, ".cursor", [("ms-python.python", "2026.10.0"), ("anthropic.claude-code", "2.1.313"),
                                 ("Anthropic.claude-code", "2.1.313")])
    assert _found(tmp_path) == [(".cursor/extensions/extensions.json", 1)]


def test_an_index_entry_with_its_folder_is_judged_by_the_folder(tmp_path: Path) -> None:
    _extension(tmp_path, ".cursor", "anthropic.claude-code-2.1.313")
    _index(tmp_path, ".cursor", [("anthropic.claude-code", "2.1.313")])
    assert _found(tmp_path) == [(".cursor/extensions/anthropic.claude-code-2.1.313/package.json", 4)]
    real = tmp_path / "real"
    _extension(real, ".cursor", "anthropic.claude-code-2.1.312", extension__js="// real\n")
    _index(real, ".cursor", [("anthropic.claude-code", "2.1.312")])
    assert _found(real) == []


# ---- where installs are read --------------------------------------------------------------------


def test_an_image_root_filesystem_reads_each_home(tmp_path: Path) -> None:
    _extension(tmp_path / "home" / "alice", ".cursor-server", "anthropic.claude-code-2.1.313")
    _extension(tmp_path / "root", ".vscode", "anthropic.claude-code-2.1.313")
    _extension(tmp_path / "srv" / "bob", ".cursor", "anthropic.claude-code-2.1.313")  # not a home
    assert sorted(path for path, _ in _found(tmp_path)) == [
        "home/alice/.cursor-server/extensions/anthropic.claude-code-2.1.313/package.json",
        "root/.vscode/extensions/anthropic.claude-code-2.1.313/package.json",
    ]


def test_this_users_home_is_read_only_when_asked(tmp_path: Path) -> None:
    home = Path(os.environ["HOME"])
    folder = _extension(home, ".cursor", "anthropic.claude-code-2.1.313")
    project = tmp_path / "project"
    project.mkdir()
    assert _found(project) == []
    assert _found(project, include_user_config=True) == [((folder / "package.json").as_posix(), 4)]
    result = run_scan(project_root=project, include_user_config=True)
    assert [f.rule_id for f in result.findings if f.rule_id == RULE] == [RULE]


def test_a_symlinked_extension_folder_is_not_followed(tmp_path: Path) -> None:
    elsewhere = _extension(tmp_path / "elsewhere", ".cursor", "anthropic.claude-code-2.1.313")
    home = tmp_path / "home-dir"
    (home / ".cursor" / "extensions").mkdir(parents=True)
    (home / ".cursor" / "extensions" / elsewhere.name).symlink_to(elsewhere, target_is_directory=True)
    assert _found(home) == []


@pytest.mark.parametrize("folder, host", [
    (".cursor", "cursor"), (".vscode", "vscode"), (".vscode-insiders", "vscode-insiders"),
    (".vscode-server", "vscode"), (".cursor-server", "cursor"), (".vscode-oss", "vscode-oss"),
    ("cursor", None), (".", None),
])
def test_an_editor_is_named_by_its_data_folder(folder: str, host: str | None) -> None:
    assert host_of(folder) == host


def test_extension_dirs_skip_dot_folders_without_extensions(tmp_path: Path) -> None:
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    (tmp_path / ".cursor" / "extensions").mkdir(parents=True)
    assert [(h, p.name) for h, p in extension_dirs(tmp_path)] == [("cursor", "extensions")]


# ---- the feed ------------------------------------------------------------------------------------


def test_a_feed_without_extensions_loads_as_before() -> None:
    feed = malicious_feed.parse_feed({"entries": []}, "cached", Path("x"))
    assert feed.extensions == {} and feed.extension("anthropic.claude-code") == ()


@pytest.mark.parametrize("raw", [
    {"extension": "anthropic.claude-code", "versions": ["1.0.0"]},              # no id
    {"id": "X", "extension": "claude-code", "versions": ["1.0.0"]},             # no publisher
    {"id": "X", "extension": "anthropic.claude-code"},                          # nothing to match
    {"id": "X", "extension": "anthropic.claude-code", "sha256": {"a.js": ["nothex"]}},
    {"id": "X", "extension": "anthropic.claude-code", "sha256": {"../a.js": ["0" * 64]}},
    "not an object",
])
def test_an_extension_entry_without_what_it_needs_is_skipped(raw: object) -> None:
    feed = malicious_feed.parse_feed({"entries": [], "extensions": [raw]}, "cached", Path("x"))
    assert feed.extensions == {}


def test_aak_update_keeps_the_bundled_extension_entries() -> None:
    import zipfile
    from io import BytesIO

    def opener(_request: object, timeout: float = 0) -> object:
        del timeout
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w"):
            pass
        buffer.seek(0)
        return _Response(buffer.getvalue())

    done = malicious_feed.refresh(opener=opener)
    data = json.loads(done.path.read_text())
    assert [e["extension"] for e in data["extensions"]] == ["anthropic.claude-code"]
    assert malicious_feed.load_feed().extension("anthropic.claude-code")


class _Response:
    def __init__(self, body: bytes) -> None:
        from io import BytesIO

        self._body = BytesIO(body)
        self.headers: dict[str, str] = {}

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def test_the_rule_is_critical_and_names_no_mcp_risk() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.CRITICAL
    assert rule.owasp_mcp_references == [] and "ASI04" in rule.owasp_agentic_references
