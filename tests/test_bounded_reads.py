"""The shared reader: a regular file of at most a stated size, and nothing else.

A repository can commit a symlink, and a checkout makes it one, so `SKILL.md ->
/dev/zero` or a link to a FIFO reached 31 scanners that compared a size with
their cap and then read, or only read: they waited on the FIFO for a writer, or
would have read /dev/zero until memory ran out. 20 more read a 200 MB file whole
before comparing its length with their cap. `read_text_capped` checks the type
before opening, the size before reading, and never reads past the cap.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from agent_audit_kit.scanners import _helpers
from agent_audit_kit.scanners._helpers import FileNotRead, read_bytes_capped, read_text_capped

ROOT = Path(__file__).resolve().parent.parent

needs_fifo = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")


@pytest.mark.parametrize(("data", "encoding", "errors"), [
    (b"plain text\n", "utf-8", None),
    (b"crlf\r\nline\r\nbreaks\r\n", "utf-8", None),
    (b"lone\rcarriage\rreturns", "utf-8", None),
    (b"\xef\xbb\xbf{\"bom\": 1}", "utf-8-sig", None),
    (b"\xef\xbb\xbf{\"bom kept\": 1}", "utf-8", None),
    (b"bad \xff byte", "utf-8", "replace"),
    (b"bad \xff byte", "utf-8", "ignore"),
    (b"caf\xe9 latin-1", "latin-1", None),
])
def test_text_is_decoded_exactly_as_read_text_decodes_it(
    tmp_path: Path, data: bytes, encoding: str, errors: str | None
) -> None:
    path = tmp_path / "f.txt"
    path.write_bytes(data)
    assert read_text_capped(path, 1_000, encoding, errors) == path.read_text(encoding, errors)


def test_a_decoding_error_raises_as_read_text_raises_it(tmp_path: Path) -> None:
    path = tmp_path / "f.json"
    path.write_bytes(b'{"a": "\xff"}')
    with pytest.raises(UnicodeDecodeError):
        read_text_capped(path, 1_000)


def test_a_file_at_the_cap_is_read_and_one_byte_over_is_not(tmp_path: Path) -> None:
    path = tmp_path / "f.txt"
    path.write_bytes(b"x" * 100)
    assert read_bytes_capped(path, 100) == b"x" * 100
    with pytest.raises(FileNotRead) as exc:
        read_bytes_capped(path, 99)
    assert isinstance(exc.value, OSError)
    assert exc.value.strerror == "larger than 99 bytes"


def test_a_size_the_system_misreports_still_stops_at_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/proc files report a size of 0, and a file can grow between the stat and
    the read: at most cap + 1 bytes are read whatever the size says."""
    path = tmp_path / "f.txt"
    path.write_bytes(b"x" * 10_000)
    real_fstat = os.fstat

    def zero_size(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
                               st.st_gid, 0, st.st_atime, st.st_mtime, st.st_ctime))

    monkeypatch.setattr(_helpers.os, "stat", lambda p: zero_size(os.open(p, os.O_RDONLY)))
    monkeypatch.setattr(_helpers.os, "fstat", zero_size)
    reads: list[int] = []
    real_read = os.read
    monkeypatch.setattr(_helpers.os, "read", lambda fd, n: reads.append(n) or real_read(fd, n))
    with pytest.raises(FileNotRead):
        read_bytes_capped(path, 100)
    assert sum(reads) <= 101


def test_a_file_the_size_fstat_says_is_read_in_one_buffer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read in 1 MB pieces, a 32 MB lockfile held the pieces and their join at
    once, twice the file: the first read asks for the size `fstat` gives and
    one byte more. A file larger than it says is still read whole, up to the
    cap, in further reads."""
    path = tmp_path / "package-lock.json"
    body = b"x" * (3 << 20)
    path.write_bytes(body)
    reads: list[int] = []
    real_read = os.read
    monkeypatch.setattr(_helpers.os, "read", lambda fd, n: reads.append(n) or real_read(fd, n))
    assert read_bytes_capped(path, 32 << 20) == body
    assert reads[0] == len(body) + 1 and len(reads) == 2  # the file, then its end

    real_fstat = os.fstat

    def understated(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
                               st.st_gid, 1_000, st.st_atime, st.st_mtime, st.st_ctime))

    monkeypatch.setattr(_helpers.os, "fstat", understated)
    reads.clear()
    assert read_bytes_capped(path, 32 << 20) == body
    assert reads[0] == 1_001 and len(reads) > 2


def test_a_directory_is_not_read(tmp_path: Path) -> None:
    with pytest.raises(FileNotRead) as exc:
        read_bytes_capped(tmp_path, 1_000)
    assert exc.value.strerror == "not a regular file"


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="no /dev/zero")
def test_a_symlink_to_a_device_is_skipped_before_it_is_opened(tmp_path: Path) -> None:
    link = tmp_path / "SKILL.md"
    link.symlink_to("/dev/zero")
    started = time.perf_counter()
    with pytest.raises(FileNotRead):
        read_text_capped(link, 512_000)
    assert time.perf_counter() - started < 1.0


@needs_fifo
def test_a_symlink_to_a_fifo_is_skipped_without_waiting_for_a_writer(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    link = tmp_path / "requirements.txt"
    link.symlink_to(fifo)
    started = time.perf_counter()
    with pytest.raises(FileNotRead):
        read_text_capped(link, 2_000_000)
    assert time.perf_counter() - started < 1.0


def test_a_missing_file_raises_as_read_text_raises_it(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_text_capped(tmp_path / "absent.json", 1_000)


# The paths the 31 blocking scanners read, from the stall sweep's FIFO run, and
# the configs the 200 MB run caught being read whole. Each becomes a symlink.
_TARGETS = (
    ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".vscode/tasks.json", "mcp.json",
    ".claude/settings.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "Pipfile", "package.json", "server.py", "app/tools.py", "index.ts", "build.gradle",
    "pom.xml", "docker-compose.yml", ".github/workflows/ci.yml", "config.yaml", "crew.yaml",
    "openapi.yaml", "agent.yaml", ".claude/skills/a/SKILL.md", "skills/b/SKILL.md",
    "skills/b/skill.json", "hooks/hooks.json", ".aak/sessions/s.json", "x.session.json",
    "agent-card.json", ".agent-audit-kit.yml", ".aak/composition-boundaries.yaml",
    "flows/f.json", "Cargo.toml", ".claude/routines/r.json", "AGENTS.md", "CLAUDE.md",
    ".agent-audit-kit/tool-pins.json",
)

_SCAN = textwrap.dedent("""
    import json, sys, tempfile, time, tracemalloc
    from pathlib import Path
    from agent_audit_kit.engine import run_scan
    traced = sys.argv[2] == "traced"
    if traced:
        run_scan(Path(tempfile.mkdtemp()))  # import every scanner before tracing
        tracemalloc.start()
    started = time.perf_counter()
    result = run_scan(Path(sys.argv[1]), strict_loading=True)
    seconds = time.perf_counter() - started
    peak = tracemalloc.get_traced_memory()[1] if traced else 0
    print(json.dumps([seconds, peak, [f.evidence for f in result.scanner_failures]]))
""")


def _scan_in_subprocess(project: Path, timeout: float, traced: bool = False) -> tuple[float, int, list[str]]:
    """Run a whole scan in a child, so a scanner that blocks fails the test on
    the timeout instead of hanging the suite. Returns the seconds, the peak of
    what Python allocated during the scan (0 unless `traced`) and the scanner
    failures' evidence.

    The child's peak RSS cannot stand in for what the scan allocated: on Linux a
    child inherits its parent's peak across exec, so on a CI runner one started
    from a pytest worker reported 265 MB, the worker's peak rather than its own.
    tracemalloc counts only the scan's own allocations, and a read of a 200 MB
    file is one of them.
    """
    env = {**os.environ, "PYTHONPATH": str(ROOT), "AAK_TOXIC_FLOW": "1"}
    out = subprocess.run([sys.executable, "-c", _SCAN, str(project), "traced" if traced else "plain"],
                         capture_output=True, text=True, timeout=timeout, env=env, cwd=project)
    assert out.returncode == 0, out.stderr[-2000:]
    seconds, peak, failures = json.loads(out.stdout)
    return float(seconds), int(peak), failures


def _link_everything(project: Path, target: Path) -> None:
    for rel in _TARGETS:
        link = project / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)


@needs_fifo
def test_a_project_of_fifo_symlinks_scans_and_no_scanner_waits(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    project = tmp_path / "proj"
    _link_everything(project, fifo)
    seconds, _peak, failures = _scan_in_subprocess(project, timeout=240)
    assert failures == []
    assert seconds < 60


def test_a_project_of_symlinks_to_a_200_mb_file_reads_none_of_it(tmp_path: Path) -> None:
    """Each scanner that read the file whole spent 200 MB of memory on it (peaks
    of 400 to 590 MB), and two were still reading after 90 s. A sparse file
    costs no disk. The scan's allocations are traced in the child (see
    `_scan_in_subprocess`): about 7 MB at their peak now, while on main one
    AGENTS.md linked to the file took them to 400 MB, the bytes read and the
    text decoded from them."""
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(200_000_000)
    project = tmp_path / "proj"
    _link_everything(project, big)
    seconds, peak, failures = _scan_in_subprocess(project, timeout=240, traced=True)
    # A file over its reader's cap is skipped silently, but the pin file is one
    # the user made to be compared, so the pin-drift check reports it unread.
    assert len(failures) == 1 and "PinFileError" in failures[0] and "larger than 1,000,000 bytes" in failures[0]
    assert peak < 100_000_000, f"the scan allocated {peak / 1e6:.0f} MB at its peak: a scanner read the file"
    assert seconds < 60


# ---------------------------------------------------------------------------
# A reader that skips a file over its cap by a stat holds the cap in the read
# too (#1060)
# ---------------------------------------------------------------------------
#
# These readers decided by `path.stat().st_size` and then read the file whole,
# so a file whose stat understated its size (one that grew after the stat, or a
# filesystem that misreports it) was read past the cap their rules state. Each
# now reads through `read_text_refusing`: the stat still skips a file over the
# cap in silence, as the rules state, and a file the read finds over the cap
# anyway is refused, so `run_scan` reports it as not read.

# (scanner module, file it reads, the cap it states, other files its walk needs)
_STAT_THEN_READ: tuple[tuple[str, str, int, dict[str, str]], ...] = (
    ("agent_trust_surface", ".github/workflows/ci.yml", 1_000_000, {}),
    ("approval_parser_desync", "src/approve.go", 1_000_000, {}),
    ("composition", ".claude/skills/s/run.py", 512_000, {".claude/skills/s/SKILL.md": "---\nname: s\n---\n"}),
    ("india_pii", "notes.md", 512_000, {}),
    ("llm_sql_rce", "server.py", 1_000_000, {}),
    ("mcp_apps_ui", "ui/app.tsx", 1_000_000, {}),
    ("mcp_auth_pathtraversal", "server.py", 1_000_000, {}),
    ("mcp_auth_patterns", "server.go", 512_000, {}),
    ("mcp_cve_pins_2026_07", "requirements.txt", 2_000_000, {}),
    ("mcp_deprecated_features", "server.kt", 1_000_000, {}),
    ("mcp_env_placeholder_exfil", "server.py", 1_000_000, {}),
    ("mcp_http_noauth_server", "server.py", 1_000_000, {}),
    ("mcp_middleware", "server.go", 512_000, {}),
    ("mcp_noauth_default", "server.py", 1_000_000, {}),
    ("mcp_routing_desync", "Server.java", 1_000_000, {}),
    ("mcp_sidecar_http", "server.py", 400_000, {}),
    ("mcp_ssrf_toolarg", "server.py", 1_000_000, {}),
    ("mcp_tasks", "server.py", 512_000, {}),
    ("mcp_toolgate_asymmetry", "server.py", 1_000_000, {}),
    ("mcp_tools_list_unbounded", "server.py", 1_000_000, {}),
    ("mcp_transport_session_unauth", "server.py", 1_000_000, {}),
    ("mcp_tunnel", "mcp-tunnel/key.pem", 100_000, {}),
    ("oauth_misconfig", "oauth.toml", 512_000, {}),
    ("policy_truncation", "server.py", 1_000_000, {}),
    ("quoted_shell_interp", "server.py", 400_000, {}),
    ("rust_pattern_scan", "src/main.rs", 1_000_000, {}),
    ("sandbox_self_disable", "settings.json", 1_000_000, {}),
    ("shared_resource_authz", "manifest.json", 1_000_000, {}),
    ("skill_untrusted_exec_path", "install.sh", 1_000_000, {}),
    ("ssrf_bracketed_host", "fetch.ts", 1_000_000, {}),
    ("ssrf_patterns", "tools.rs", 512_000, {}),
    ("state_privacy", "privacy.md", 512_000, {}),
    ("stdio_injection", "server.mjs", 512_000, {}),
    ("taint_analysis", "server.py", 1_000_000, {}),
    ("typescript_pattern_scan", "server.ts", 1_000_000, {}),
    ("ufo_mobile_mcp", "server.py", 1_000_000, {}),
)

_UNDERSTATED_REASON = "bytes when read, although its size said it was not"


def _padded(size: int) -> bytes:
    """`size` bytes of comment lines, which every reader here reads as nothing."""
    line = b"# " + b"x" * 70 + b"\n"
    body = line * (size // len(line))
    return body + b"#" * (size - len(body) - 1) + b"\n"


def _understate(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make `Path.stat` say `target` is 1,000 bytes. `read_bytes_capped` stats
    and reads through `os` itself, so it still sees what the file holds."""
    real = Path.stat

    def stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        st = real(self, *args, **kwargs)  # type: ignore[arg-type]
        if os.path.abspath(self) != str(target):
            return st
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid,
                               st.st_gid, 1_000, st.st_atime, st.st_mtime, st.st_ctime))

    monkeypatch.setattr(Path, "stat", stat)


def _scan_refusals(module: object, project: Path) -> dict[str, str]:
    with _helpers.collecting_refusals() as refused:
        module.scan(project)  # type: ignore[attr-defined]
    return refused


def _project(tmp_path: Path, rel: str, others: dict[str, str]) -> tuple[Path, Path]:
    project = tmp_path / "proj"
    target = project / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    for other, text in others.items():
        (project / other).parent.mkdir(parents=True, exist_ok=True)
        (project / other).write_text(text, encoding="utf-8")
    return project, target


_IDS = [row[0] for row in _STAT_THEN_READ]


@pytest.mark.parametrize(("name", "rel", "cap", "others"), _STAT_THEN_READ, ids=_IDS)
def test_a_file_whose_stat_understates_its_size_is_refused_not_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, rel: str, cap: int, others: dict[str, str]
) -> None:
    """One byte over the cap with an honest stat, the file is skipped in silence,
    as the rule states. One byte over with a stat that says it is small, it is
    refused, where the stat-then-read read it whole and refused nothing."""
    import importlib

    module = importlib.import_module(f"agent_audit_kit.scanners.{name}")
    project, target = _project(tmp_path, rel, others)
    target.write_bytes(_padded(cap + 1))
    assert _scan_refusals(module, project) == {}
    _understate(monkeypatch, target)
    refused = _scan_refusals(module, project)
    assert refused == {str(target): f"larger than {cap:,} {_UNDERSTATED_REASON}"}


@pytest.mark.parametrize(("name", "rel", "cap", "others"), _STAT_THEN_READ, ids=_IDS)
def test_a_stat_then_read_reader_reads_a_file_at_its_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, rel: str, cap: int, others: dict[str, str]
) -> None:
    """A file of exactly the cap is read, through `read_text_refusing` with the
    cap the rule states, and refused by nothing."""
    import importlib

    module = importlib.import_module(f"agent_audit_kit.scanners.{name}")
    project, target = _project(tmp_path, rel, others)
    reads: list[tuple[str, int, int]] = []
    real_read = module.read_text_refusing

    def spy(path: Path | str, max_bytes: int, *args: object, **kwargs: object) -> str:
        text = real_read(path, max_bytes, *args, **kwargs)
        reads.append((os.path.abspath(path), max_bytes, len(text)))
        return text

    monkeypatch.setattr(module, "read_text_refusing", spy)
    target.write_bytes(_padded(cap))
    assert _scan_refusals(module, project) == {}
    assert (str(target), cap, cap) in reads


def test_a_session_transcript_holds_its_cap_in_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--sessions` reads a transcript of up to 20 MB, decided by a stat; one the
    read finds over the cap is refused, and `aak scan` reports refusals there."""
    from agent_audit_kit.sessions import adapters

    monkeypatch.setattr(adapters, "_MAX_FILE_BYTES", 5_000)
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'{"tool": "a", "args": {}}\n' * 400)
    assert path.stat().st_size > 5_000
    with _helpers.collecting_refusals() as refused:
        assert adapters.normalize_path(path) is None
    assert refused == {}
    _understate(monkeypatch, path)
    with _helpers.collecting_refusals() as refused:
        assert adapters.normalize_path(path) is None
    assert refused == {str(path): f"larger than 5,000 {_UNDERSTATED_REASON}"}


def test_an_extension_file_is_hashed_only_up_to_its_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AAK-MALICIOUS-EXTENSION-001 hashes the file a feed entry names up to
    64 MiB, decided by a stat; the stream now stops at the cap too, and a file
    it finds over the cap is refused rather than hashed whole."""
    import hashlib

    from agent_audit_kit.scanners import malicious_extensions

    monkeypatch.setattr(malicious_extensions, "MAX_HASHED_BYTES", 5_000)
    at_cap = tmp_path / "at.js"
    at_cap.write_bytes(b"x" * 5_000)
    over = tmp_path / "over.js"
    over.write_bytes(b"x" * 5_001)
    with _helpers.collecting_refusals() as refused:
        assert malicious_extensions._sha256(at_cap) == hashlib.sha256(b"x" * 5_000).hexdigest()
        assert malicious_extensions._sha256(over) is None
    assert refused == {}
    _understate(monkeypatch, over)
    with _helpers.collecting_refusals() as refused:
        assert malicious_extensions._sha256(over) is None
    assert refused == {str(over): f"larger than 5,000 {_UNDERSTATED_REASON}"}


def test_read_text_refusing_reads_as_read_text_capped_and_refuses_only_an_oversized_file(
    tmp_path: Path,
) -> None:
    """Text is decoded as `read_text_capped` decodes it; a FIFO or a directory is
    skipped without a refusal, as there."""
    path = tmp_path / "f.txt"
    path.write_bytes(b"crlf\r\nbad \xff byte\n")
    with _helpers.collecting_refusals() as refused:
        assert _helpers.read_text_refusing(path, 100, errors="replace") == path.read_text("utf-8", "replace")
        with pytest.raises(FileNotRead):
            _helpers.read_text_refusing(tmp_path, 100)
        with pytest.raises(FileNotRead):
            _helpers.read_text_refusing(path, 10)
    assert refused == {str(path): f"larger than 10 {_UNDERSTATED_REASON}"}
