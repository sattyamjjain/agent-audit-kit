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

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_SCAN_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs",
    ".json", ".yaml", ".yml", ".toml", ".env", ".txt", ".md",
    ".go", ".rs", ".java", ".rb",
}
_MAX_FILE_BYTES = 512_000

# Aadhaar: 12 digits formatted as XXXX XXXX XXXX or XXXX-XXXX-XXXX or bare
# First digit cannot be 0 or 1 (UIDAI spec).
_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b")

# PAN: 5 letters + 4 digits + 1 letter, 10 chars total.
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

# UPI ID: <handle>@<psp>  where psp is oksbi, okhdfcbank, paytm, upi, ybl, axl, ...
_UPI_RE = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,}@(?:oksbi|okhdfcbank|okicici|okaxis|paytm|ybl|axl|ibl|apl|upi|hdfcbank|axisbank|icici|sbi|fbl)\b",
    re.IGNORECASE,
)

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
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(path)
    return out


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    rel = str(path.relative_to(project_root))

    for m in _AADHAAR_RE.finditer(text):
        digits_only = re.sub(r"[ -]", "", m.group(0))
        if not _verhoeff_check(digits_only):
            continue
        masked = f"{digits_only[:4]}****{digits_only[-4:]}"
        findings.append(
            make_finding(
                "AAK-INDIA-PII-001",
                rel,
                f"Aadhaar number (Verhoeff-valid): {masked}",
                line_number=find_line_number(text, m.group(0)),
            )
        )

    for m in _PAN_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-INDIA-PII-002",
                rel,
                f"PAN detected: {m.group(0)[:3]}****{m.group(0)[-1]}",
                line_number=find_line_number(text, m.group(0)),
            )
        )

    for m in _UPI_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-INDIA-PII-003",
                rel,
                f"UPI ID detected: {m.group(0).split('@')[0][:3]}***@{m.group(0).split('@')[1]}",
                line_number=find_line_number(text, m.group(0)),
            )
        )

    for m in _IFSC_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-INDIA-PII-004",
                rel,
                f"IFSC code detected: {m.group(0)}",
                line_number=find_line_number(text, m.group(0)),
            )
        )

    for m in _PHONE_RE.finditer(text):
        raw = m.group(0)
        findings.append(
            make_finding(
                "AAK-INDIA-PII-005",
                rel,
                f"Indian mobile number: +91 {raw[-4:]}",
                line_number=find_line_number(text, raw),
            )
        )

    for m in _VEHICLE_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-INDIA-PII-006",
                rel,
                f"Indian vehicle registration: {m.group(0)}",
                line_number=find_line_number(text, m.group(0)),
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
