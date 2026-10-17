"""India DPDP PII detection scanner.

Fires AAK-INDIA-PII-001..006 — Aadhaar, PAN, UPI, IFSC, Indian phone
numbers, and Indian vehicle registration. Paired with the
`--framework india-dpdp` compliance report to give Indian customers
DPDP Act 2023 §8(4) "reasonable security safeguards" evidence.

Patterns use the canonical structures; false-positive risk is low because
each identifier has specific length + checksum / prefix semantics that
random strings rarely satisfy.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, in_skip_dir, placed


_SCAN_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs",
    ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".md",
    ".cfg", ".ini", ".conf",
    ".go", ".rs", ".java", ".rb",
}
_MAX_FILE_BYTES = 512_000


def _is_env_file(name: str) -> bool:
    """`.env`, `.env.local`, `.env.production`, `prod.env`: what the secret walker reads.

    The extension test alone never opened `.env` itself, whose suffix is empty, nor
    `.env.local`, whose suffix is `.local`.
    """
    return name.startswith(".env") or name.endswith(".env")

# Aadhaar: 12 digits formatted as XXXX XXXX XXXX or XXXX-XXXX-XXXX or bare
# First digit cannot be 0 or 1 (UIDAI spec).
_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b")

# A *bare* 12-digit run (no XXXX XXXX XXXX grouping) that merely passes the
# Verhoeff checksum is a weak signal — ~1 in 10 random 12-digit numbers
# (timestamps, DB ids, counters) pass Verhoeff. Require an Aadhaar/UID cue
# nearby for the unformatted form; the grouped form stays a strong signal on
# its own.
_AADHAAR_CONTEXT_RE = re.compile(r"aadhaar|aadhar|uidai|\buid\b|आधार", re.IGNORECASE)

# PAN: 5 letters + 4 digits + 1 letter, 10 chars total.
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

# UPI ID: <handle>@<psp>  where psp is oksbi, okhdfcbank, paytm, upi, ybl, axl, ...
_UPI_PSP = r"@(?:oksbi|okhdfcbank|okicici|okaxis|paytm|ybl|axl|ibl|apl|upi|hdfcbank|axisbank|icici|sbi|fbl)\b"
_UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}" + _UPI_PSP, re.IGNORECASE)
_UPI_HANDLE_RUN_RE = re.compile(r"[a-zA-Z0-9.\-_]+", re.IGNORECASE)
_UPI_PSP_RE = re.compile(_UPI_PSP, re.IGNORECASE)


def _upi_matches(text: str) -> Iterator[re.Match[str]]:
    """`_UPI_RE.finditer(text)`, reading each run of handle characters once.

    No handle character is `@`, so a match can only start in a run of them that
    ends right at an `@`. `finditer` tried the pattern from every word boundary
    of every run and read the run to its end each time before failing, so a
    long dotted run with no `@` (`a.b.a.b...`) cost the square of its length:
    60 KB took 14 seconds. Here the pattern is tried only in a run followed by
    `@<psp>`, from where `finditer` would have resumed, and no further than the
    character after the `<psp>` that its trailing `\\b` reads, so it returns the
    same matches.
    """
    resume = 0
    for run in _UPI_HANDLE_RUN_RE.finditer(text):
        psp = _UPI_PSP_RE.match(text, run.end())
        if psp is None:
            continue
        match = _UPI_RE.search(text, max(run.start(), resume), psp.end() + 1)
        if match is not None:
            resume = match.end()
            yield match


# IFSC: 4 letters + 0 + 6 alnum (bank code + reserved 0 + branch).
_IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

# Indian phone: +91 followed by 10 digits starting with 6/7/8/9
_PHONE_RE = re.compile(r"\+91[ -]?[6-9]\d{9}\b")

# Vehicle registration: state (2 letters) + district (2 digits) + series (1-3 letters) + number (4 digits)
_VEHICLE_RE = re.compile(r"\b(?:AP|AR|AS|BR|CG|CH|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|OR|PB|PY|RJ|SK|TN|TR|TS|UK|UP|WB)[ -]?\d{2}[ -]?[A-Z]{1,3}[ -]?\d{4}\b")


def _verhoeff_check(digits: str) -> bool:
    """Validate Aadhaar checksum (Verhoeff algorithm).

    Drop-in helper to reduce false positives. Returns True if the
    12-digit string passes the checksum.
    """
    d_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    p_table = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    c = 0
    for i, ch in enumerate(reversed(digits)):
        if not ch.isdigit():
            return False
        c = d_table[c][p_table[i % 8][int(ch)]]
    return c == 0


def _iter_source(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file() or not (path.suffix.lower() in _SCAN_EXTS or _is_env_file(path.name)):
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(path)
    return out


def _masked(value: str) -> str:
    """The first three characters and the last of a matched identifier, the rest masked.

    The IFSC and vehicle-registration evidence used to quote the whole match. Since env
    files are read, a match there can be a credential in the same shape (an 11-character
    upper-case key with a 0 in the fifth place reads as an IFSC code), so every one of
    these identifiers is shown the way PAN always was.
    """
    return f"{value[:3]}****{value[-1]}"


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    unplaced: list[tuple[Finding, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(path.relative_to(project_root))

    for m in _AADHAAR_RE.finditer(text):
        digits_only = re.sub(r"[ -]", "", m.group(0))
        if not _verhoeff_check(digits_only):
            continue
        # Grouped form (with space/hyphen separators) is self-evidently an
        # Aadhaar; a bare 12-digit run needs an Aadhaar/UID cue in the vicinity
        # so we don't flag coincidental numeric ids.
        has_separator = " " in m.group(0) or "-" in m.group(0)
        if not has_separator:
            window = text[max(0, m.start() - 64) : m.end() + 24]
            if not _AADHAAR_CONTEXT_RE.search(window):
                continue
        masked = f"{digits_only[:4]}****{digits_only[-4:]}"
        unplaced.append((
            make_finding(
                "AAK-INDIA-PII-001",
                rel,
                f"Aadhaar number (Verhoeff-valid): {masked}",
            ),
            m.group(0),
        ))

    for m in _PAN_RE.finditer(text):
        unplaced.append((
            make_finding(
                "AAK-INDIA-PII-002",
                rel,
                f"PAN detected: {_masked(m.group(0))}",
            ),
            m.group(0),
        ))

    for m in _upi_matches(text):
        unplaced.append((
            make_finding(
                "AAK-INDIA-PII-003",
                rel,
                f"UPI ID detected: {m.group(0).split('@')[0][:3]}***@{m.group(0).split('@')[1]}",
            ),
            m.group(0),
        ))

    for m in _IFSC_RE.finditer(text):
        unplaced.append((
            make_finding(
                "AAK-INDIA-PII-004",
                rel,
                f"IFSC code detected: {_masked(m.group(0))}",
            ),
            m.group(0),
        ))

    for m in _PHONE_RE.finditer(text):
        raw = m.group(0)
        unplaced.append((
            make_finding(
                "AAK-INDIA-PII-005",
                rel,
                f"Indian mobile number: +91 {raw[-4:]}",
            ),
            raw,
        ))

    for m in _VEHICLE_RE.finditer(text):
        unplaced.append((
            make_finding(
                "AAK-INDIA-PII-006",
                rel,
                f"Indian vehicle registration: {_masked(m.group(0))}",
            ),
            m.group(0),
        ))

    # Every finding's line in one pass over the file, not one search of it per match.
    return placed(text, unplaced)


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
