"""Scoring package — penalty-based AAK score + AIVSS v0.8 annotator.

`compute_score` and `generate_badge` are the original AAK score
(0–100, letter grade) used by `aak score <path>` (legacy).
`aivss.score_finding` and `aivss.annotate_sarif` are the v0.3.10
AIVSS v0.8 layer used by `aak score <sarif-in> --aivss`.
"""
from __future__ import annotations

from agent_audit_kit.models import ScanResult, Severity


def compute_score(result: ScanResult) -> None:
    """Mutates result.score and result.grade in place.

    Penalty-based: CRITICAL -20, HIGH -10, MEDIUM -5, LOW -2.
    Score is clamped to [0, 100] and mapped to a letter grade.
    """
    score = 100
    for f in result.findings:
        if f.severity == Severity.CRITICAL:
            score -= 20
        elif f.severity == Severity.HIGH:
            score -= 10
        elif f.severity == Severity.MEDIUM:
            score -= 5
        elif f.severity == Severity.LOW:
            score -= 2
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    result.score = score
    result.grade = grade


def generate_badge(score: int, grade: str) -> str:
    """Generate an SVG badge string for the audit score."""
    colors = {
        "A": "#4c1",
        "B": "#97CA00",
        "C": "#dfb317",
        "D": "#fe7d37",
        "F": "#e05d44",
    }
    color = colors.get(grade, "#9f9f9f")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20">\n'
        f'  <linearGradient id="b" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>\n'
        f'  <mask id="a"><rect width="160" height="20" rx="3" fill="#fff"/></mask>\n'
        f'  <g mask="url(#a)">'
        f'<rect width="100" height="20" fill="#555"/>'
        f'<rect x="100" width="60" height="20" fill="{color}"/>'
        f'<rect width="160" height="20" fill="url(#b)"/></g>\n'
        f'  <g fill="#fff" text-anchor="middle" '
        f'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">\n'
        f'    <text x="50" y="15" fill="#010101" fill-opacity=".3">agent-audit</text>'
        f'<text x="50" y="14">agent-audit</text>\n'
        f'    <text x="130" y="15" fill="#010101" fill-opacity=".3">'
        f'{grade} {score}/100</text>'
        f'<text x="130" y="14">{grade} {score}/100</text>\n'
        f"  </g>\n"
        f"</svg>"
    )


__all__ = ["compute_score", "generate_badge"]
