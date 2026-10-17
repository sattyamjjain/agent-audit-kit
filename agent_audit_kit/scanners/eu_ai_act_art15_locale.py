"""AAK-EU-AI-ACT-ART15-LOCALE-001 — multilingual-eval coverage evidence.

The EU AI Act high-risk obligations (Regulation (EU) 2024/1689, Article 15,
as amended by the AI Omnibus Regulation, OJ L_202601744, in force July 2026)
require an "appropriate level of accuracy, robustness and cybersecurity" —
robustness explicitly covering "errors, faults or inconsistencies that may
occur within the system or the environment". Under the AI Omnibus these
obligations are binding for Annex III high-risk use cases on 2027-12-02 and
for Annex I product-embedded high-risk systems on 2028-08-02; the original
2 August 2026 application date was superseded by that regulation change (not
removed by us). For multilingual user-facing AI systems, that means
demonstrating robustness across each language the system claims to serve.

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
   declaring two or more locales, or `multilingual: true`.
2. The same config marks the agent user-facing (`user_facing: true`,
   `surface: end-user`, role strings like `assistant` / `chatbot` /
   `support`, or a user-facing marker phrase in its text).
3. The repository's eval / test fixtures cover fewer than two of the
   declared locales: the locale codes found in the paths of files under
   eval directories. For `multilingual: true` beside fewer than two named
   locales, the declared set is unknown, so any two eval languages count.

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
from typing import Any, Iterator

import yaml

from agent_audit_kit.models import Finding

from ._helpers import CONFIG_MAX_BYTES, in_skip_dir, load_yaml, loads_json, make_finding, read_text_capped

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

# A list item has no key; its pair is walked into but never yielded.
_NO_KEY = object()


def _pairs_depth_first(data: Any) -> Iterator[tuple[Any, Any]]:
    """Every `(key, value)` of every mapping in a YAML/JSON document, in the
    order the two walks below met them when they recursed: a pair, then
    everything inside its value, then the next pair. Lists are entered at any
    depth.

    One frame per level took a config nested past the recursion limit, which
    JSON's parser reads on Python 3.12 and later (about 10,000 levels), down
    with the whole scanner. The walk keeps a stack of iterators instead.
    """
    stack: list[Iterator[tuple[Any, Any]]] = [_children(data)]
    while stack:
        pair = next(stack[-1], None)
        if pair is None:
            stack.pop()
            continue
        key, value = pair
        if key is not _NO_KEY:
            yield key, value
        if isinstance(value, (dict, list)):
            stack.append(_children(value))


def _children(node: Any) -> Iterator[tuple[Any, Any]]:
    if isinstance(node, dict):
        return iter(node.items())
    if isinstance(node, list):
        return ((_NO_KEY, item) for item in node)
    return iter(())


def _extract_declared_locales(data: Any) -> set[str]:
    """Walk a YAML/JSON document looking for locale declarations. Recognises
    the common shapes: `locales: [en, fr]`, `languages: [en, es]`,
    `supported_languages: ...`, `i18n.supported: ...`, and a single
    `locale` / `language` / `default_locale` / `primary_locale`.
    `multilingual: true`, which names no locale, is read by
    `_declares_multilingual`."""
    found: set[str] = set()
    for key, val in _pairs_depth_first(data):
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
    return found


# Keys that make a mapping the agent's own: the role and audience keys
# `_is_user_facing` reads, and the locale-list keys. `locale` and `language`
# are left out, since a tool may carry them (`language: python`).
_AGENT_KEYS: frozenset[str] = frozenset({
    "role", "user_facing", "userfacing", "is_user_facing", "surface", "audience",
    "locales", "default_locale", "primary_locale", "supported_languages",
})


def _declares_multilingual(data: Any) -> bool:
    """A `multilingual: true` that describes the agent: at the top of the
    document, or in a mapping that also carries one of `_AGENT_KEYS` (a CrewAI
    entry beside its `role`). The rule text and this module's docstring
    promised the key, but it was never read, and a config naming fewer than two
    locales was skipped, so `multilingual: true` with `default_locale: en` never
    fired. Read anywhere, a tool's own `multilingual: true` counted as the
    agent's."""

    def _true(val: Any) -> bool:
        return val is True or (isinstance(val, str) and val.strip().lower() in {"true", "yes", "1"})

    # A stack, not a frame a level, as in `_pairs_depth_first`: recursing, with
    # a generator frame for each `any`, took 3.9 past its recursion limit at
    # 333 levels, inside the 500 a JSON file may nest.
    stack: list[tuple[Any, bool]] = [(data, True)]
    while stack:
        node, top = stack.pop()
        if isinstance(node, dict):
            keys = {str(k).lower(): v for k, v in node.items()}
            if "multilingual" in keys and (top or keys.keys() & _AGENT_KEYS) and _true(keys["multilingual"]):
                return True
            stack.extend((v, False) for v in reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend((item, False) for item in reversed(node))
    return False


def _is_user_facing(data: Any, raw_text: str) -> bool:
    """Heuristic: an agent config marks itself user-facing if any of:
    - explicit `user_facing: true` / `userFacing: true` anywhere in tree;
    - `surface:` value contains 'end-user' / 'user-facing' / 'public';
    - `role:` value matches one of `_USER_FACING_ROLES`;
    - raw text contains a user-facing marker phrase."""
    explicit = {"unset"}
    for k, v in _pairs_depth_first(data):
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

    if "yes" in explicit:
        return True
    if "no" in explicit:
        return False
    # Fallback: raw-text marker.
    return bool(_USER_FACING_SURFACE_RE.search(raw_text))


def _parse_config(path: Path) -> tuple[Any, str] | None:
    try:
        raw = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
    except OSError:
        return None
    if path.suffix in {".yaml", ".yml"}:
        try:
            data = load_yaml(raw, path)
        except yaml.YAMLError:
            return None
    elif path.suffix == ".json":
        import json as _json
        try:
            data = loads_json(raw, path)
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
        if in_skip_dir(path, project_root):
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
        data = load_yaml(read_text_capped(cfg, CONFIG_MAX_BYTES, errors="replace"), cfg) or {}
    except (yaml.YAMLError, OSError):
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
            if in_skip_dir(path, project_root):
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
        # Two or more named locales are judged against that set, flag or no
        # flag. `multilingual: true` beside fewer names declares a set it does
        # not name, so any two languages the evals cover evidence it.
        multilingual = len(declared) < 2 and _declares_multilingual(data)
        if len(declared) < 2 and not multilingual:
            continue
        if not _is_user_facing(data, raw_text):
            continue
        # Eval coverage is "evidenced" when ≥2 of the declared locales
        # show up in eval paths.
        covered = set(eval_locales) if multilingual else declared & eval_locales
        if len(covered) >= 2:
            continue

        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        declared_sorted = ", ".join(sorted(declared))
        covered_sorted = ", ".join(sorted(covered)) if covered else "none"
        # compliance.py reads the first `locales=[...]` as the declared set.
        claim = (
            f"multilingual: true (named locales=[{declared_sorted}])"
            if multilingual else f"locales=[{declared_sorted}]"
        )
        findings.append(make_finding(
            "AAK-EU-AI-ACT-ART15-LOCALE-001",
            rel,
            (
                f"Agent declares {claim} for a user-facing "
                f"surface; eval/test fixtures cover locales=[{covered_sorted}]. "
                f"EU AI Act Article 15 (Annex III high-risk: binding 2027-12-02; Annex I: 2028-08-02) requires per-language "
                f"robustness evidence."
            ),
            line_number=1,
        ))

    return findings, scanned
