from __future__ import annotations

import datetime
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agent_audit_kit.engine import run_scan
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners._helpers import ZCODE_SERVER_KEY, mcp_server_maps


@dataclass
class FixAction:
    """Represents an auto-fix action applied (or proposed) for a finding.

    Attributes:
        rule_id: The rule ID that triggered the fix.
        file_path: Path to the file that was fixed.
        description: Human-readable description of the fix.
        applied: Whether the fix was actually applied (False in dry-run).
        writes: Whether the fix changes its file: True once written, or in a dry run
            when it would be; False when the recipe refused the file, could not read
            it or had nothing to change, including the value already set that the
            TRUST-004, TRUST-007 and SECRET-006 recipes report as ``applied``. A dry
            run's ``applied`` is False for a fix it would make and a file it refused
            alike, so `suggest --auto-pr`, which plans from one, counted a refused file
            as a fix.
    """

    rule_id: str
    file_path: str
    description: str
    applied: bool = False
    writes: bool = False


def run_fixes(project_root: Path, dry_run: bool = False) -> list[FixAction]:
    """Run auto-fixes for all fixable findings in a project.

    Performs a scan, identifies findings for rules marked as
    ``auto_fixable``, and applies the corresponding fix logic.
    When fixes are actually applied (not dry-run), a log file is
    written to ``.agent-audit-kit/fix-log.json``, or the reason it was
    not is printed on stderr; the fixes stand either way.

    Args:
        project_root: The project root directory to scan and fix.
        dry_run: If True, report what would be fixed without modifying
            any files.

    Returns:
        A list of FixAction objects describing what was (or would be)
        fixed.
    """
    result = run_scan(project_root=project_root)
    fixable_rules = {rid for rid, rule in RULES.items() if rule.auto_fixable}
    fixes: list[FixAction] = []

    for finding in result.findings:
        if finding.rule_id not in fixable_rules:
            continue
        fix = _apply_fix(project_root, finding.rule_id, finding.file_path, dry_run)
        if fix:
            fixes.append(fix)

    if not dry_run and fixes:
        _log_fixes(project_root, fixes)

    return fixes


def _log_fixes(project_root: Path, fixes: list[FixAction]) -> None:
    """Write the fix log, or say on stderr why it was not written.

    The fixes are already on disk by now, so a refused log is reported rather than
    raised: `aak fix` and `suggest --apply-trivial` still list what they changed.
    """
    refused = _write_fix_log(project_root, fixes)
    if isinstance(refused, _PartlyWritten):
        sys.stderr.write(f"fix: {refused}\n")
    elif refused is not None:
        sys.stderr.write(f"fix: the fix log was not written: {refused}\n")


def _write_fix_log(project_root: Path, fixes: list[FixAction]) -> str | None:
    """Write a JSON log of applied fixes to .agent-audit-kit/fix-log.json.

    The log is the tool's own file, but the scanned repository can ship anything
    under `.agent-audit-kit`: `Path.mkdir(exist_ok=True)` accepted a link to a
    directory outside the project and `Path.write_text` followed a link at the log
    itself, so the log was written wherever either pointed, and a regular file or a
    dangling link in the directory's place raised after every fix had been applied.
    The directory now comes from `_make_dir_inside_project` and the log goes through
    `_write_inside_project`, like every recipe's file.

    Args:
        project_root: The project root directory.
        fixes: List of FixAction objects that were applied.

    Returns:
        None when the log was written, otherwise why it was not.
    """
    log_dir = project_root / ".agent-audit-kit"
    log_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "fixes_applied": [
            {
                "rule_id": fix.rule_id,
                "file": fix.file_path,
                "description": fix.description,
            }
            for fix in fixes
            if fix.applied
        ],
    }
    refused = _make_dir_inside_project(log_dir, project_root)
    if refused is not None:
        return refused
    log = _as_written(json.dumps(log_data, indent=2) + "\n")
    return _write_inside_project(log_dir / "fix-log.json", log, project_root)


# ---------------------------------------------------------------------------
# Writing inside the scanned project
#
# `aak fix` writes into the repository it scanned, and that repository decides what sits
# at each path. Through `Path.write_text`, a `.gitignore` linked to a file outside the
# project, such as a shell rc, had the fix's lines appended to that file, a dangling
# link created the file it named, and a FIFO blocked the fix forever, and every other
# recipe wrote its file the same way. Each recipe now asks `_write_refusal` about the
# file it edits before reading it, so it never reads through a link, reads only a
# regular file (`_read_text`, `_read_bytes`), writes through `_write_inside_project`,
# and reports a refusal as "Failed to fix: <reason>", in a dry run too. The fix log and
# `aak pin`'s pin file go into a directory `_make_dir_inside_project` creates or accepts.
# ---------------------------------------------------------------------------


def _is_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _name_in_project(path: Path, project_root: Path) -> str:
    try:
        return str(path.relative_to(project_root))
    except ValueError:
        return str(path)


def _write_refusal(path: Path, project_root: Path) -> str | None:
    """Why ``path`` must not be written, or None when it may be: it must be a regular
    file or missing, and it and its directory must resolve inside ``project_root``.

    The test reads the path itself (`os.lstat`), so a symlink is refused even when it
    points inside the project, and so is a FIFO, a socket, a device or a directory.
    """
    name = _name_in_project(path, project_root)
    root = project_root.resolve()
    if not _is_inside(path.parent.resolve(), root):
        return f"{name} is in a directory outside the project"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        info = None
    except OSError as exc:
        return f"{name} could not be examined ({exc.strerror or exc})"
    if info is not None and stat.S_ISLNK(info.st_mode):
        return f"{name} is a symlink"
    if info is not None and not stat.S_ISREG(info.st_mode):
        return f"{name} is not a regular file"
    if not _is_inside(path.resolve(), root):
        return f"{name} resolves outside the project"
    return None


class _PartlyWritten(str):
    """Why `_write_inside_project` did not finish a write it had started: the open had
    already truncated the file, or appended part of the data, so the file may hold part
    of what was meant. Every other reason it returns left the file as it was. Callers
    that say "was not changed" after a reason check for this first; the text says it
    may be partly written, so one that only shows the reason stays honest.
    """


def _write_inside_project(
    path: Path, data: bytes, project_root: Path, mode: Literal["append", "replace"] = "replace"
) -> str | None:
    """Write ``data`` to ``path`` when `_write_refusal` allows it, appended to the file or
    in place of its content. Returns None once written, or why it refused; a refusal or
    an OS error is reported, never raised. An OS error after the open, which in replace
    mode has already emptied the file, comes back as `_PartlyWritten`.

    The file is opened without following a link (O_NOFOLLOW where the OS has one) and
    without waiting (O_NONBLOCK), and its descriptor must still be a regular file before
    a byte is written, so a link or a FIFO put in its place after the check is refused
    too.

    O_NOFOLLOW guards only the last component of the path. A directory above the file
    swapped for a link between the check and the open is followed, and the write lands
    where that link points. The check runs here, right before the open, even when the
    caller asked `_write_refusal` already, so the window is the time between resolving
    the file's directory in that check and opening the file. Winning it takes a local
    attacker changing the tree while `aak fix` or `aak pin` runs; a repository's
    contents alone cannot. Closing it would take opening each directory relative to
    the last without following a link (`os.open` with ``dir_fd`` and O_NOFOLLOW),
    which would also refuse a link that stays inside the project, as this does not.

    Args:
        path: The file to write.
        data: The bytes to write.
        project_root: The scanned project, which the write must stay inside.
        mode: ``"append"`` adds ``data`` at the end; ``"replace"`` truncates first.

    Returns:
        None when written, otherwise the reason it was not.
    """
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return refused
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "append" else os.O_TRUNC)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o666)
    except OSError as exc:
        return f"{path.name} could not be opened ({exc.strerror or exc})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return f"{path.name} is not a regular file"
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    except OSError as exc:
        return _PartlyWritten(
            f"{path.name} could not be written ({exc.strerror or exc}) and may be partly written"
        )
    finally:
        os.close(fd)
    return None


def _replace_inside_project(path: Path, data: bytes, project_root: Path) -> str | None:
    """Make ``data`` the whole content of ``path``, when `_write_refusal` allows it, by
    writing a new file beside it and moving that over it. Returns None once done, or
    why it refused; a refusal or an OS error is reported, never raised, and leaves
    ``path`` as it was, since a write that fails part way fails on the new file, which
    is removed.

    `_write_inside_project` writes in place, and its open empties the file before a
    byte goes in, so a full disk part way through left part of it. For a file the
    user keeps, such as their pre-commit config, that is the wrong failure. The new
    file is created with O_CREAT, O_EXCL and O_NOFOLLOW in ``path``'s directory, so
    nothing already there, a link included, can stand in for it; it takes the
    original's permission bits and is synced before the move; and `_write_refusal`
    is asked about ``path`` again just before `os.replace`, which renames over a
    link rather than writing through it in any case. As a new file it no longer
    shares its contents with another hard link to the old one, and it belongs to
    whoever runs the command.
    """
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return refused
    try:
        mode: int | None = stat.S_IMODE(os.lstat(path).st_mode)
    except FileNotFoundError:
        mode = None
    except OSError as exc:
        return f"{path.name} could not be examined ({exc.strerror or exc})"
    if mode is not None:
        # A rename needs only the directory to be writable, so a file the user made
        # read-only would be replaced all the same; it is opened for writing first,
        # without truncating it, and refused as an in-place write refuses it.
        flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            os.close(os.open(path, flags))
        except OSError as exc:
            return f"{path.name} could not be opened ({exc.strerror or exc})"
    temp = path.with_name(f".{path.name}.aak-{os.getpid()}-{os.urandom(4).hex()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(temp, flags, 0o666)
    except OSError as exc:
        return f"{path.name} could not be written ({exc.strerror or exc})"
    moved = False
    try:
        try:
            if mode is not None and hasattr(os, "fchmod"):
                os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        refused = _write_refusal(path, project_root)
        if refused is not None:
            return refused
        os.replace(temp, path)
        moved = True
    except OSError as exc:
        return f"{path.name} could not be written ({exc.strerror or exc})"
    finally:
        if not moved:
            try:
                os.unlink(temp)
            except OSError:
                pass
    return None


def _make_dir_inside_project(path: Path, project_root: Path) -> str | None:
    """Create the directory ``path`` when nothing is there and its parent resolves inside
    ``project_root``. Returns None when ``path`` is a directory inside the project, or
    why it is not; a refusal or an OS error is reported, never raised.

    `os.mkdir` never follows a link at ``path``, so a dangling one creates nothing and
    is refused, as is a regular file, a FIFO or anything else that is not a directory.
    A link to a directory is followed like any directory above a file `_write_refusal`
    allows: it may lead elsewhere inside the project, never out of it. A link loop
    reads as not a directory before anything resolves it, since `Path.resolve` raises
    on one before Python 3.13.
    """
    name = _name_in_project(path, project_root)
    root = project_root.resolve()
    if not _is_inside(path.parent.resolve(), root):
        return f"{name} is in a directory outside the project"
    try:
        os.mkdir(path)
    except FileExistsError:
        if not path.is_dir():
            return f"{name} is not a directory"
        if not _is_inside(path.resolve(), root):
            return f"{name} resolves outside the project"
    except OSError as exc:
        return f"{name} could not be created ({exc.strerror or exc})"
    return None


_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
)


def _open_regular(path: Path) -> int:
    """A descriptor to read ``path`` from, opened as `_write_inside_project` opens one to
    write: without following a link or waiting on a FIFO, and only when it is a regular
    file. Anything else raises OSError, as a missing file does.

    A recipe asks `_write_refusal` before it reads, which refuses a link, a FIFO or a
    directory by name; this refuses one put in the file's place after that look, so a
    recipe never reads through a link or waits on a FIFO.
    """
    fd = os.open(path, _READ_FLAGS)
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except OSError:
        os.close(fd)
        raise
    if not regular:
        os.close(fd)
        raise OSError(f"{path.name} is not a regular file")
    return fd


def _read_text(path: Path, encoding: str | None = None) -> str:
    """``path``'s text as `Path.read_text` decodes it, with ``encoding`` (the locale's
    when None) and universal newlines, read through `_open_regular`. The recipes read
    with `Path.read_text` before, and decode the same way still, so a CRLF file comes
    out with LF line ends as it did."""
    with open(_open_regular(path), encoding=encoding) as handle:
        return handle.read()


def _read_bytes(path: Path) -> bytes:
    """``path``'s bytes, read through `_open_regular`."""
    with open(_open_regular(path), "rb") as handle:
        return handle.read()


def _as_written(text: str) -> bytes:
    """The bytes `Path.write_text` wrote for ``text``: each newline as `os.linesep`, in
    UTF-8. The recipes that wrote through it write the same bytes through
    `_write_inside_project`. Those that passed no encoding wrote JSON, which
    `json.dumps` keeps to ASCII, so the locale's encoding gave these bytes too."""
    return text.replace("\n", os.linesep).encode("utf-8")


def _write_json(path: Path, data: object, project_root: Path) -> str | None:
    """Write ``data`` to ``path`` as the JSON recipes always have, indented by two with
    a final newline, through `_write_inside_project`."""
    return _write_inside_project(path, _as_written(json.dumps(data, indent=2) + "\n"), project_root)


def _apply_fix(
    project_root: Path,
    rule_id: str,
    file_path: str,
    dry_run: bool,
) -> FixAction | None:
    """Dispatch to the appropriate fix function for a given rule.

    Args:
        project_root: The project root directory.
        rule_id: The rule ID to fix.
        file_path: Relative path to the file containing the finding.
        dry_run: If True, do not modify files.

    Returns:
        A FixAction if a fix was attempted, or None if not applicable.
    """
    full_path = project_root / file_path
    if not full_path.is_file():
        return None

    if rule_id == "AAK-TRUST-001":
        return _fix_enable_all_mcp(full_path, project_root, dry_run)
    elif rule_id == "AAK-TRUST-004":
        return _fix_missing_deny(full_path, project_root, dry_run)
    elif rule_id == "AAK-TRUST-007":
        return _fix_missing_allowlist(full_path, project_root, dry_run)
    elif rule_id == "AAK-SECRET-006":
        return _fix_env_gitignore(project_root, dry_run)
    elif rule_id == "AAK-SECRET-007":
        return _fix_secret_env_ref(full_path, project_root, dry_run)
    elif rule_id in _RAISED_PIN_RULES:
        return _fix_raised_pin(full_path, rule_id, project_root, dry_run)
    elif rule_id == "AAK-LITELLM-CVE-2026-30623-PIN-001":
        return _fix_litellm_version(full_path, project_root, dry_run)
    elif rule_id in _DEPENDENCY_FLOORS:
        return _fix_dependency_floor(full_path, rule_id, project_root, dry_run)
    elif rule_id == "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001":
        return _fix_langgraph_toolnode(full_path, project_root, dry_run)
    return None


# ---------------------------------------------------------------------------
# CVE auto-remediations (--cve flag)
# ---------------------------------------------------------------------------

_CVE_FIXABLE_RULES: frozenset[str] = frozenset({
    "AAK-LANGCHAIN-001",  # CVE-2026-34070 — bump langchain-core >=1.2.22
    "AAK-LANGCHAIN-003",  # CVE-2025-68664 — bump langchain-core >=0.3.14
    "AAK-LITELLM-CVE-2026-30623-PIN-001",  # CVE-2026-30623 — bump litellm >=1.83.7
})

# A requirement line's optional operator, with the blanks after it. The pin
# patterns below start at `^[^\S\n]*`, not `^\s*`: with MULTILINE, `^\s*` started
# at every line of a run of blank lines and read to its end, and the two `\s*`
# around an optional operator split a run of blanks every way, so either shape
# took the square of its length. A blank line before a pin is no longer part of
# the match, and the replacement wrote it back anyway, so the text comes out the
# same.
_PIN_OPERATOR = r"(?:(?:==|>=|<=|<|>|~=|!=)\s*)?"


# The version pins `aak fix` raises through their rule's own reader, so a fix
# rewrites every declaration the rule reports and nothing it does not.
_RAISED_PIN_RULES = frozenset({"AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003", "AAK-NEO4J-001"})


def run_cve_fixes(project_root: Path, dry_run: bool = True) -> list[FixAction]:
    """Apply the `--cve` subset of auto-fixes.

    Scope is deliberately narrow: only rules where the remediation is
    mechanical (version bump in a lockfile or manifest). Any rule that
    needs a code change — auth-bypass handlers, SSRF hardening, OAuth
    scope reshuffles — is refused here, because false confidence kills
    scanners (ROADMAP §5).

    Args:
        project_root: project to fix.
        dry_run: if True, report proposed fixes without modifying files.
    """
    result = run_scan(project_root=project_root)
    fixes: list[FixAction] = []
    for finding in result.findings:
        if finding.rule_id not in _CVE_FIXABLE_RULES:
            continue
        fix = _apply_fix(project_root, finding.rule_id, finding.file_path, dry_run)
        if fix:
            fixes.append(fix)
    if not dry_run and fixes:
        _log_fixes(project_root, fixes)
    return fixes


def _fix_raised_pin(path: Path, rule_id: str, project_root: Path, dry_run: bool) -> FixAction:
    """Raise a pinned package to its fix wherever the rule reads it.

    The bumps for these rules matched `name op version` at the start of a
    requirement line and judged the first number, as the rules did before they
    moved onto `_dependency_pins`. So `aak fix` answered "No langchain-core pin
    below the fix" for `langchain-core<1.2.22`, which the rule reports, could
    not see a pin with extras, and refused pyproject.toml, where the rules read
    PEP 621 and Poetry tables. `raise_to_fix` reads the file as the rule does,
    rewrites every declaration that admits an affected release, and checks the
    result against the rule before anything is written. AAK-LANGCHAIN-001 and
    -003 both raise langchain-core, and whichever runs second finds nothing
    below its floor, so a pin is never lowered.

    The file is read and written without newline translation, so a CRLF
    manifest stays CRLF. A pyproject.toml change needs a re-lock to take effect,
    and the action says so. The manifest must be a regular file inside the
    project (`_write_refusal`): a link, which the rule reads through, would have
    the fix rewrite whatever it names, and a FIFO would block the read or the
    write forever. One is refused before it is read, and reported in a dry run
    too; the read takes only a regular file, and the write goes through
    `_write_inside_project`, so one put in the manifest's place in between is
    refused as well.
    """
    from agent_audit_kit.scanners import langchain_vuln, neo4j_cve
    from agent_audit_kit.scanners._dependency_pins import _regular_bytes, raise_to_fix
    from agent_audit_kit.scanners._manifest_deps import MAX_MANIFEST_BYTES

    pin, label = {
        "AAK-LANGCHAIN-001": (langchain_vuln._PATH_TRAVERSAL, "langchain-core"),
        "AAK-LANGCHAIN-003": (langchain_vuln._DESERIALIZE, "langchain-core"),
        "AAK-NEO4J-001": (neo4j_cve._PIN, "mcp-neo4j-cypher"),
    }[rule_id]
    floor = ".".join(str(n) for n in pin.fixed)
    name = path.name.lower()
    if not (name.endswith(".txt") or name == "pyproject.toml"):
        return FixAction(rule_id, str(path), f"{path.name} is not a manifest the {label} pin reads", False)
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return FixAction(rule_id, str(path), f"{path.name} is over 2 MB, which the rule does not read", False)
        raw = _regular_bytes(path, MAX_MANIFEST_BYTES)
        text = raw.decode("utf-8") if raw is not None else None
    except (OSError, UnicodeDecodeError):
        text = None
    if text is None:
        return FixAction(rule_id, str(path), "Unable to read file", False)
    result = raise_to_fix(path, text, pin)
    if result.refused:
        left = "; ".join(f"line {line} {why}" if line else why for line, why in result.refused)
        return FixAction(rule_id, str(path), f"Left {path.name} as it is: {left}", False)
    if not result.raised:
        return FixAction(rule_id, str(path), f"No {label} declaration admits a release below {floor}", False)
    if not dry_run:
        refused = _write_inside_project(path, result.text.encode("utf-8"), project_root, mode="replace")
        if refused is not None:
            return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
    relock = "; re-lock the project to install it" if name == "pyproject.toml" else ""
    return FixAction(
        rule_id,
        str(path),
        f"Raised {result.raised} {label} declaration(s) to >={floor}{relock}",
        not dry_run,
        writes=True,
    )


def _fix_litellm_version(path: Path, project_root: Path, dry_run: bool) -> FixAction:
    """Bump a vulnerable litellm pin to 1.83.7 (CVE-2026-30623).

    Rewrite line-based requirements*.txt manifests in place; refuse to
    touch lockfiles or pyproject.toml because their locking semantics make
    a naive text bump unsafe. The manifest is read and written only as
    `_write_refusal` allows (see "Writing inside the scanned project").
    """
    import re as _re

    rule_id = "AAK-LITELLM-CVE-2026-30623-PIN-001"
    min_version = "1.83.7"
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
    try:
        text = _read_text(path, encoding="utf-8")
    except OSError:
        return FixAction(rule_id, str(path), "Unable to read file", False)

    if path.name.endswith(".txt"):
        pin_re = _re.compile(
            r"^([^\S\n]*)(litellm)\s*" + _PIN_OPERATOR + r"[0-9][0-9a-zA-Z.\-_]*",
            _re.MULTILINE | _re.IGNORECASE,
        )
        new_text, count = pin_re.subn(rf"\1\2>={min_version}", text)
        if count == 0:
            return FixAction(rule_id, str(path), "No matching litellm pin", False)
        if new_text == text:
            # Every pin it matched already reads >=1.83.7, and the one the rule reports
            # is a form it does not match (`litellm[proxy]==1.50.0`): no change to write.
            return FixAction(rule_id, str(path), f"Nothing in {path.name} this recipe can rewrite", False)
        if not dry_run:
            refused = _write_inside_project(path, _as_written(new_text), project_root)
            if refused is not None:
                return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
        return FixAction(
            rule_id,
            str(path),
            f"Bumped {count} litellm pin(s) to >={min_version}",
            not dry_run,
            writes=True,
        )

    return FixAction(
        rule_id,
        str(path),
        f"{path.name} is not a supported manifest for auto-bump "
        "(only requirements*.txt is line-safe to rewrite)",
        False,
    )


# A dependency floor bump that had an AUTO_PR_ALLOWLIST entry but no recipe, so
# `aak fix` silently did nothing and `suggest --auto-pr` could never reach it
# (run_fixes -> _apply_fix returned None, so it never entered `pending`).
# AAK-NEO4J-001 was the other entry; it reads through `_fix_raised_pin` now.
# rule_id -> (package-name regex, minimum version, label used in the FixAction)
_DEPENDENCY_FLOORS: dict[str, tuple[str, str, str]] = {
    # Pin floor is the highest fixed version, matching _FLOWISE_PATCHED_VERSION in
    # scanners/stdio_injection.py, so 3.1.0/3.1.1/3.1.2 stay flagged for the CVEs
    # they remain exposed to.
    "AAK-FLOWISE-001": (r"flowise(?:-components)?", "3.1.3", "flowise"),
}


def _fix_dependency_floor(path: Path, rule_id: str, project_root: Path, dry_run: bool) -> FixAction:
    """Raise a vulnerable dependency to its vendor-published fixed version.

    Same posture as ``_fix_litellm_version``: rewrite line-based
    ``requirements*.txt`` and the ``package.json`` dependency maps, and refuse
    lockfiles or poetry's ``pyproject.toml``, whose locking semantics make a naive
    text bump unsafe, and read and write the manifest only as `_write_refusal`
    allows.
    """
    name_pattern, min_version, label = _DEPENDENCY_FLOORS[rule_id]
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
    try:
        text = _read_text(path, encoding="utf-8")
    except OSError:
        return FixAction(rule_id, str(path), "Unable to read file", False)

    if path.name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return FixAction(rule_id, str(path), "package.json is not valid JSON", False)
        bumped = 0
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name in list(deps):
                if re.fullmatch(name_pattern, dep_name):
                    deps[dep_name] = f">={min_version}"
                    bumped += 1
        if bumped == 0:
            return FixAction(rule_id, str(path), f"No matching {label} dep found", False)
        if not dry_run:
            refused = _write_json(path, data, project_root)
            if refused is not None:
                return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
        return FixAction(
            rule_id,
            str(path),
            f"Bumped {bumped} {label} dep(s) to >={min_version} (package.json)",
            not dry_run,
            writes=True,
        )

    if path.name.endswith(".txt"):
        pin_re = re.compile(
            rf"^([^\S\n]*)({name_pattern})\s*{_PIN_OPERATOR}[0-9][0-9a-zA-Z.\-_]*",
            re.MULTILINE | re.IGNORECASE,
        )
        new_text, count = pin_re.subn(rf"\1\2>={min_version}", text)
        if count == 0:
            return FixAction(rule_id, str(path), f"No matching {label} pin", False)
        if new_text == text:
            return FixAction(rule_id, str(path), f"Nothing in {path.name} this recipe can rewrite", False)
        if not dry_run:
            refused = _write_inside_project(path, _as_written(new_text), project_root)
            if refused is not None:
                return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
        return FixAction(
            rule_id,
            str(path),
            f"Bumped {count} {label} pin(s) to >={min_version}",
            not dry_run,
            writes=True,
        )

    return FixAction(
        rule_id,
        str(path),
        f"{path.name} is not a supported manifest for auto-bump "
        "(only requirements*.txt and package.json are safe to rewrite)",
        False,
    )


def _fix_langgraph_toolnode(path: Path, project_root: Path, dry_run: bool) -> FixAction | None:
    """Apply the ``ToolNode([...]) -> ToolNode(tools=[...])`` codemod.

    The codemod itself already lived in ``autofix/langgraph_toolnode.py`` but was
    only reachable from ``suggest --apply-trivial``, so the rule's
    ``AUTO_PR_ALLOWLIST`` entry was dead: ``run_fixes`` never produced an action for
    it. Wiring it here makes the existing claim true.

    Returns None when the codemod is a no-op, so an unchanged file never reports as
    a fix (the rewrite is idempotent, so re-running is safe). A source file
    `_write_refusal` refuses is reported before it is read, so a link is refused
    whether or not the codemod would have changed what it names.
    """
    from agent_audit_kit.autofix.langgraph_toolnode import fix as _toolnode_fix

    rule_id = "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001"
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
    try:
        text = _read_text(path, encoding="utf-8")
    except OSError:
        return FixAction(rule_id, str(path), "Unable to read file", False)

    new_text = _toolnode_fix(text)
    if new_text == text:
        return None
    if not dry_run:
        refused = _write_inside_project(path, _as_written(new_text), project_root)
        if refused is not None:
            return FixAction(rule_id, str(path), f"Failed to fix: {refused}", False)
    return FixAction(
        rule_id,
        str(path),
        "Rewrote ToolNode(positional list) to ToolNode(tools=[...])",
        not dry_run,
        writes=True,
    )


def _fix_enable_all_mcp(path: Path, project_root: Path, dry_run: bool) -> FixAction:
    """Set enableAllProjectMcpServers to false.

    The settings file is read and written only as `_write_refusal` allows: the rule
    reads a link, so a settings file linked out of the project reached this recipe,
    which wrote the JSON over whatever the link named.
    """
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction("AAK-TRUST-001", str(path), f"Failed to fix: {refused}", False)
    try:
        data = json.loads(_read_text(path))
        data["enableAllProjectMcpServers"] = False
        if not dry_run:
            refused = _write_json(path, data, project_root)
            if refused is not None:
                return FixAction("AAK-TRUST-001", str(path), f"Failed to fix: {refused}", False)
        return FixAction(
            "AAK-TRUST-001",
            str(path),
            "Set enableAllProjectMcpServers to false",
            not dry_run,
            writes=True,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-001", str(path), "Failed to fix", False)


def _fix_missing_deny(path: Path, project_root: Path, dry_run: bool) -> FixAction:
    """Add default deny rules to the permissions block, reading and writing the
    settings file only as `_write_refusal` allows."""
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction("AAK-TRUST-004", str(path), f"Failed to fix: {refused}", False)
    try:
        data = json.loads(_read_text(path))
        perms = data.setdefault("permissions", {})
        writes = not perms.get("deny")
        if writes:
            perms["deny"] = [
                "Bash(rm -rf *)",
                "Bash(curl *)",
                "Bash(wget *)",
            ]
            if not dry_run:
                refused = _write_json(path, data, project_root)
                if refused is not None:
                    return FixAction("AAK-TRUST-004", str(path), f"Failed to fix: {refused}", False)
        return FixAction(
            "AAK-TRUST-004",
            str(path),
            "Added default deny rules",
            not dry_run,
            writes=writes,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-004", str(path), "Failed to fix", False)


def _fix_missing_allowlist(path: Path, project_root: Path, dry_run: bool) -> FixAction:
    """Add an empty enabledMcpjsonServers allowlist, reading and writing the settings
    file only as `_write_refusal` allows."""
    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction("AAK-TRUST-007", str(path), f"Failed to fix: {refused}", False)
    try:
        data = json.loads(_read_text(path))
        writes = "enabledMcpjsonServers" not in data
        if writes:
            data["enabledMcpjsonServers"] = []
            if not dry_run:
                refused = _write_json(path, data, project_root)
                if refused is not None:
                    return FixAction("AAK-TRUST-007", str(path), f"Failed to fix: {refused}", False)
        return FixAction(
            "AAK-TRUST-007",
            str(path),
            "Added empty enabledMcpjsonServers allowlist",
            not dry_run,
            writes=writes,
        )
    except (json.JSONDecodeError, OSError):
        return FixAction("AAK-TRUST-007", str(path), "Failed to fix", False)


def _fix_secret_env_ref(path: Path, project_root: Path, dry_run: bool) -> FixAction | None:
    """Replace a literal secret in an MCP server ``env`` block with ``${KEY}``, or
    with ``${env:KEY}`` in VS Code's ``servers`` map, the form each client expands.

    Mechanical by this project's own bar (see ``autopr.AUTO_PR_ALLOWLIST``): the edit
    has exactly one correct form, because the variable name is already present as the
    JSON key, and a reviewer confirms it from the diff without reading the program.

    The substitution is the exact inverse of the detection predicate in
    ``scanners/secret_exposure.py`` — same ``MCP_ENV_SECRET_KEYS`` pattern, imported
    rather than restated so the fix cannot drift from what fires. That matters: the
    rule stops firing because the literal is genuinely gone, not because a key the
    client ignores was added. Adding an ignored key is the v0.3.78 defect
    (``deny_stdio_transport``), and this is deliberately the opposite shape.

    The ``${VAR}`` form is attested, not invented: 158 env values across the 748
    public configs in ``benchmarks/data`` already use it, overwhelmingly as
    ``KEY = ${KEY}``.

    Deliberately NOT in ``AUTO_PR_ALLOWLIST``: the server stops working until the
    operator exports the variable, and whether that is a fix or an outage is a
    deployment fact AAK cannot see — the same reason the bind-address swap is listed
    in ``autopr.NON_MECHANICAL``. It is a recipe ``aak fix`` will apply on request,
    not something AAK pushes.

    Returns None when nothing matched, so a no-op never reports as a fix. A config
    `_write_refusal` refuses is reported before it is read, matched or not.
    """
    # Imported here rather than at module scope to keep fix.py free of a hard
    # dependency on any individual scanner module.
    from agent_audit_kit.scanners.secret_exposure import MCP_ENV_SECRET_KEYS

    refused = _write_refusal(path, project_root)
    if refused is not None:
        return FixAction("AAK-SECRET-007", str(path), f"Failed to fix: {refused}", False)
    # Plain JSON only. A JSONC config (VS Code's `.vscode/mcp.json` allows comments
    # and trailing commas) is left alone: writing it back through `json.dumps`
    # would delete its comments.
    try:
        data = json.loads(_read_text(path))
    except (json.JSONDecodeError, OSError):
        return None

    rewritten: list[str] = []
    # Both server maps, as the rule reads them. Each server object is the one
    # inside `data`, so the edit lands in the map the server came from, and the
    # dump below writes that map back under its own key. The reference takes the
    # form that map's client expands: VS Code reads `servers` and substitutes
    # `${env:KEY}`, and would pass a bare `${KEY}` to the server as written.
    # ZCode expands no reference in a config-file server at all, so its map is
    # left as it is rather than rewritten into a literal the server cannot use.
    for map_key, servers in mcp_server_maps(data, path):
        if map_key == ZCODE_SERVER_KEY:
            continue
        form = "${env:%s}" if map_key == "servers" else "${%s}"
        for server_cfg in servers.values():
            if not isinstance(server_cfg, dict):
                continue
            env = server_cfg.get("env")
            if not isinstance(env, dict):
                continue
            for key, value in list(env.items()):
                if not isinstance(value, str) or not value:
                    continue
                if not MCP_ENV_SECRET_KEYS.search(key):
                    continue
                if re.match(r"^\$\{.+\}$", value):
                    continue  # already a reference
                env[key] = form % key
                rewritten.append(key)

    if not rewritten:
        return None

    if not dry_run:
        refused = _write_json(path, data, project_root)
        if refused is not None:
            return FixAction("AAK-SECRET-007", str(path), f"Failed to fix: {refused}", False)

    names = ", ".join(sorted(set(rewritten)))
    return FixAction(
        "AAK-SECRET-007",
        str(path),
        f"Replaced literal secret with an environment reference for: {names} "
        "(export the variable before starting the server, and rotate the exposed value)",
        not dry_run,
        writes=True,
    )


def _fix_env_gitignore(project_root: Path, dry_run: bool) -> FixAction:
    """Add .env patterns to .gitignore, unless it already ignores every root env file.

    Coverage is judged as AAK-SECRET-006 judges it (`_gitignore_rules`). A substring
    test here, `".env" in content`, read `!.env.example`, `# .env` or `.envrc` as
    covering `.env`, so the fix reported the finding fixed and wrote nothing. The
    patterns go at the end, where the last match decides, so a template the file took
    back with `!` (`!.env.example`) is taken back again after them.

    The decision uses the rule's read; the write appends to the file through
    `_write_inside_project`, leaving every byte already there as it was. Rewritten from
    that read, bounded to 1,000,000 bytes and decoded with replacement, a longer file lost
    its tail, and `rstrip()` turned a last line `secret\\ ` into `secret\\`, which git
    reads differently. A `.gitignore` that is a link, a FIFO or anything but a regular
    file is refused, and so reported in a dry run too, and the read takes only a regular
    file (`_read_bytes`), so one put in its place after that look is not read through
    or waited on either.
    """
    from agent_audit_kit.scanners.secret_exposure import (
        _ENV_TEMPLATE_SUFFIXES,
        _gitignore_ignores,
        _gitignore_rules,
        _read_gitignore,
        _root_env_files,
    )

    gitignore = project_root / ".gitignore"
    try:
        names = [path.name for path in _root_env_files(project_root)] or [".env"]
        rules = _gitignore_rules(_read_gitignore(project_root) or "")
        writes = not all(_gitignore_ignores(rules, name) for name in names)
        if writes:
            refused = _write_refusal(gitignore, project_root)
            if refused is not None:
                return FixAction("AAK-SECRET-006", ".gitignore", f"Failed to fix: {refused}", False)
            try:
                raw = _read_bytes(gitignore)
            except FileNotFoundError:
                raw = b""
            templates = tuple(suffix.encode() for suffix in _ENV_TEMPLATE_SUFFIXES)
            kept = [
                line.strip() for line in raw.splitlines()
                if line.strip().startswith(b"!") and line.strip().lower().endswith(templates)
            ]
            block = b"" if not raw else b"\n" if raw.endswith(b"\n") else b"\n\n"
            block += b"# Environment files\n.env\n.env.*\n" + b"".join(line + b"\n" for line in kept)
            if not dry_run:
                refused = _write_inside_project(gitignore, block, project_root, mode="append")
                if refused is not None:
                    return FixAction("AAK-SECRET-006", ".gitignore", f"Failed to fix: {refused}", False)
        return FixAction(
            "AAK-SECRET-006",
            ".gitignore",
            "Added .env patterns to .gitignore",
            not dry_run,
            writes=writes,
        )
    except OSError:
        return FixAction("AAK-SECRET-006", ".gitignore", "Failed to fix", False)
