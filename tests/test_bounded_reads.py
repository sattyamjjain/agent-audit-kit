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
    import json, resource, sys, time
    from pathlib import Path
    from agent_audit_kit.engine import run_scan
    started = time.perf_counter()
    result = run_scan(Path(sys.argv[1]), strict_loading=True)
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(json.dumps([time.perf_counter() - started, rss, [f.evidence for f in result.scanner_failures]]))
""")


def _scan_in_subprocess(project: Path, timeout: float) -> tuple[float, int, list[str]]:
    """Run a whole scan in a child, so a scanner that blocks fails the test on
    the timeout instead of hanging the suite. Returns the scanner failures'
    evidence."""
    env = {**os.environ, "PYTHONPATH": str(ROOT), "AAK_TOXIC_FLOW": "1"}
    out = subprocess.run([sys.executable, "-c", _SCAN, str(project)], capture_output=True,
                         text=True, timeout=timeout, env=env, cwd=project)
    assert out.returncode == 0, out.stderr[-2000:]
    seconds, rss, failures = json.loads(out.stdout)
    return float(seconds), int(rss), failures


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
    seconds, _rss, failures = _scan_in_subprocess(project, timeout=240)
    assert failures == []
    assert seconds < 60


def test_a_project_of_symlinks_to_a_200_mb_file_reads_none_of_it(tmp_path: Path) -> None:
    """Each scanner that read the file whole spent 200 MB of memory on it (peaks
    of 400 to 590 MB), and two were still reading after 90 s. A sparse file
    costs no disk."""
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(200_000_000)
    project = tmp_path / "proj"
    _link_everything(project, big)
    seconds, rss, failures = _scan_in_subprocess(project, timeout=240)
    rss_mb = rss / (1 << 20) if sys.platform == "darwin" else rss / (1 << 10)
    # A file over its reader's cap is skipped silently, but the pin file is one
    # the user made to be compared, so the pin-drift check reports it unread.
    assert len(failures) == 1 and "PinFileError" in failures[0] and "larger than 1,000,000 bytes" in failures[0]
    assert rss_mb < 200, f"peak RSS {rss_mb:.0f} MB: a scanner read the file"
    assert seconds < 60
