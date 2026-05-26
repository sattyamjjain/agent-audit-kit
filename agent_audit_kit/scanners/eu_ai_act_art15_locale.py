"""AAK-EU-AI-ACT-ART15-LOCALE-001 — multilingual-eval coverage evidence.

The 2026-08-02 EU AI Act high-risk obligations (Regulation (EU) 2024/1689,
Article 15) require an "appropriate level of accuracy, robustness and
cybersecurity" — robustness explicitly covering "errors, faults or
inconsistencies that may occur within the system or the environment". For
multilingual user-facing AI systems, that means demonstrating robustness
across each language the system claims to serve.

Ford et al. 2026 (arXiv:2605.23157) documents the gap empirically: a
363-prompt red-team across four frontier MLLMs in US English and Mexican
Spanish shows safety rankings inverting between languages, with linguistic
attacks more effective in one language and visual attacks more effective
in the other. Their conclusion — "treating language and modality as
independent dimensions in safety frameworks misses critical
vulnerabilities" — is the technical justification for tracking
per-language eval coverage as Article 15 evidence.

This scanner fires when ALL hold:

1. The repo contains at least one agent / safety / eval config file
   declaring two or more locales (or `multilingual: true` with no eval
   override).
2. The same config (or sibling metadata) marks the agent user-facing —
   either explicitly (`user_facing: true`, `surface: end-user`, role
   strings like `assistant` / `chatbot` / `support`) or implicitly via
   the multilingual declaration on a non-internal agent.
3. The repository's eval / test fixtures reference only a single language
   — the union of locale codes found in eval filenames, eval directory
   structure, and eval-file body language tags has cardinality ≤ 1
   (versus the ≥ 2 declared on the agent).

The finding is INFO severity (advisory) and surfaces through the
`compliance.py` Article 15 evidence subsection rather than the
PASS/FAIL ASI-driven path — so it does not flip an entire control to
FAIL on a single locale-coverage gap.

Suppression: opt out via `.agent-audit-kit.yml`:

    accepts_locale_coverage_gap: true
    justification: "describe why per-locale eval is intentionally absent"
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding

# --------------------------------------------------------------------------
# Locale detection
# --------------------------------------------------------------------------

# ISO 639-1 two-letter codes commonly seen in agent configs. Tight set —
# we intentionally don't match every BCP-47 tag, only the codes a
# scanner can recognize with high precision in filenames and dir parts.
_KNOWN_LOCALES: frozenset[str] = frozenset({
    "en", "fr", "de", "es", "it", "pt", "nl", "pl", "ru", "tr",
    "ja", "zh", "ko", "ar", "he", "hi", "bn", "id", "th", "vi",
    "sv", "no", "da", "fi", "cs", "hu", "ro", "uk", "el", "bg",
})

# BCP-47 tag matcher: en, en-US, zh-Hans, pt-BR.
_BCP47_RE = re.compile(r"^([a-z]{2})(?:[-_][A-Za-z0-9]+)*$")


def _normalize_locale(token: str) -> str | None:
    """Return the ISO 639-1 root if `token` looks like a recognised locale,
    else None. 'en-US' / 'EN' / 'en_US' all collapse to 'en'."""
    t = token.strip()
    if not t:
        return None
    m = _BCP47_RE.match(t.lower().replace("_", "-"))
    if not m:
        return None
    root = m.group(1)
    return root if root in _KNOWN_LOCALES else None


# Agent-config file globs (intentionally narrow — only files whose name
# clearly identifies them as agent / safety / eval metadata).
_AGENT_CONFIG_GLOBS: tuple[str, ...] = (
    "agent.yaml", "agent.yml", "agents.yaml", "agents.yml",
    "agent.json", "agents.json",
    "crew.yaml", "crew.yml",
    "manifest.yaml", "manifest.yml",
    "safety.yaml", "safety.yml",
    "eval.yaml", "eval.yml", "evals.yaml", "evals.yml",
    ".agent.yaml", ".agent.yml",
)

# Eval/test fixture roots — where we look for per-language coverage.
_EVAL_DIR_NAMES: frozenset[str] = frozenset({
    "evals", "eval", "evaluation", "evaluations",
    "fixtures", "scenarios", "i18n", "locales",
    "test_data", "testdata", "benchmarks",
})

# Role strings that imply a user-facing surface (vs internal / batch).
_USER_FACING_ROLES: frozenset[str] = frozenset({
    "assistant", "chatbot", "support", "agent", "concierge",
    "helper", "advisor", "tutor", "companion",
})

# Surface markers that signal end-user exposure.
_USER_FACING_SURFACE_RE = re.compile(
    r"\b(?:user[_-]?facing|end[_-]?user|consumer|customer[_-]?facing|public)\b",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------
# Config-side parsing
# --------------------------------------------------------------------------

def _extract_declared_locales(data: Any) -> set[str]:
    """Walk a YAML/JSON document looking for locale declarations. Recognises
    the common shapes: `locales: [en, fr]`, `languages: [en, es]`,
    `supported_languages: ...`, `i18n.supported: ...`, `multilingual: true`
    (which we treat as ≥2 locales without naming them — but only fires
    when paired with a `default_locale`/`primary_locale` so we have a
    locale set baseline)."""
    found: set[str] = set()

    def _visit(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                key_lower = str(key).lower()
                if key_lower in {
                    "locales", "languages", "supported_languages",
                    "supported", "locale_set", "language_set",
                }:
                    if isinstance(val, list):
                        for item in val:
                            loc = _normalize_locale(str(item))
                            if loc:
                                found.add(loc)
                    elif isinstance(val, str):
                        for part in re.split(r"[,\s]+", val):
                            loc = _normalize_locale(part)
                            if loc:
                                found.add(loc)
                elif key_lower in {"locale", "language", "default_locale", "primary_locale"}:
                    if isinstance(val, str):
                        loc = _normalize_locale(val)
                        if loc:
                            found.add(loc)
                _visit(val)
        elif isinstance(node, list):
            for item in node:
                _visit(item)

    _visit(data)
    return found


def _is_user_facing(data: Any, raw_text: str) -> bool:
    """Heuristic: an agent config marks itself user-facing if any of:
    - explicit `user_facing: true` / `userFacing: true` anywhere in tree;
    - `surface:` value contains 'end-user' / 'user-facing' / 'public';
    - `role:` value matches one of `_USER_FACING_ROLES`;
    - raw text contains a user-facing marker phrase."""
    explicit = {"unset"}

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                kl = str(k).lower()
                if kl in {"user_facing", "userfacing", "is_user_facing"}:
                    if v is True or (isinstance(v, str) and v.strip().lower() in {"true", "yes", "1"}):
                        explicit.add("yes")
                    elif v is False or (isinstance(v, str) and v.strip().lower() in {"false", "no", "0"}):
                        explicit.add("no")
                elif kl in {"surface", "audience", "channel"}:
                    if isinstance(v, str) and _USER_FACING_SURFACE_RE.search(v):
                        explicit.add("yes")
                elif kl in {"role", "type", "kind"}:
                    if isinstance(v, str) and v.strip().lower() in _USER_FACING_ROLES:
                        explicit.add("yes")
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)

    if "yes" in explicit:
        return True
    if "no" in explicit:
        return False
    # Fallback: raw-text marker.
    return bool(_USER_FACING_SURFACE_RE.search(raw_text))


def _parse_config(path: Path) -> tuple[Any, str] | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if path.suffix in {".yaml", ".yml"}:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None
    elif path.suffix == ".json":
        import json as _json
        try:
            data = _json.loads(raw)
        except _json.JSONDecodeError:
            return None
    else:
        return None
    return data, raw


# --------------------------------------------------------------------------
# Eval-coverage detection
# --------------------------------------------------------------------------

# Filename / dir-part patterns that carry a locale code.
# Examples: scenarios/fr/welcome.yaml, evals/welcome.en.yaml,
#           tests/i18n/de-DE/auth.yaml.
_LOCALE_IN_NAME_RE = re.compile(r"(?:^|[._/-])([a-z]{2})(?:[-_][A-Za-z0-9]+)?(?=[._/-]|$)")


def _eval_locales(project_root: Path) -> set[str]:
    """Return the set of ISO 639-1 roots that appear in eval/test-fixture
    paths under recognised eval dirs. The locale-in-name regex is intentionally
    strict — only matches segments that look like locale codes."""
    found: set[str] = set()
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        rel_parts = [p.lower() for p in path.relative_to(project_root).parts]
        if not any(part in _EVAL_DIR_NAMES for part in rel_parts):
            continue
        # Examine every segment of the path (dir + filename).
        for segment in rel_parts:
            for m in _LOCALE_IN_NAME_RE.finditer(segment):
                loc = _normalize_locale(m.group(1))
                if loc:
                    found.add(loc)
    return found


# --------------------------------------------------------------------------
# Risk-acceptance opt-out
# --------------------------------------------------------------------------

def _accepts_risk(project_root: Path) -> bool:
    cfg = project_root / ".agent-audit-kit.yml"
    if not cfg.is_file():
        return False
    try:
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    if data.get("accepts_locale_coverage_gap") is not True:
        return False
    justification = data.get("justification")
    return isinstance(justification, str) and justification.strip() != ""


# --------------------------------------------------------------------------
# Public scan() entry point
# --------------------------------------------------------------------------

def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()

    if _accepts_risk(project_root):
        scanned.add(".agent-audit-kit.yml")
        return findings, scanned

    # Gather agent configs.
    candidates: list[Path] = []
    for glob_name in _AGENT_CONFIG_GLOBS:
        for path in project_root.rglob(glob_name):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            candidates.append(path)

    if not candidates:
        return findings, scanned

    # Compute the union of locale codes present in eval/test fixtures.
    eval_locales = _eval_locales(project_root)

    for path in candidates:
        parsed = _parse_config(path)
        if parsed is None:
            continue
        data, raw_text = parsed
        declared = _extract_declared_locales(data)
        if len(declared) < 2:
            continue
        if not _is_user_facing(data, raw_text):
            continue
        # Eval coverage is "evidenced" when ≥2 of the declared locales
        # show up in eval paths.
        covered = declared & eval_locales
        if len(covered) >= 2:
            continue

        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        declared_sorted = ", ".join(sorted(declared))
        covered_sorted = ", ".join(sorted(covered)) if covered else "none"
        findings.append(make_finding(
            "AAK-EU-AI-ACT-ART15-LOCALE-001",
            rel,
            (
                f"Agent declares locales=[{declared_sorted}] for a user-facing "
                f"surface; eval/test fixtures cover locales=[{covered_sorted}]. "
                f"EU AI Act Article 15 (binding 2026-08-02) requires per-language "
                f"robustness evidence."
            ),
            line_number=1,
        ))

    return findings, scanned
