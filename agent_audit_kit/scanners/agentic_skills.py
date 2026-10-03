"""OWASP Agentic Skills Top 10 (AST10) — the statically decidable subset.

AST10 v1 (OWASP incubator project, `www-project-agentic-skills-top-10`) names ten
risks in agent *skills*: the behaviour layer between the model and the tools.
Most of them are not a static question. This module ships the three where a check
over a skill bundle gives a deterministic answer, and the README states plainly
which seven it does not cover rather than implying ten.

Three of the ten were already covered before this module existed, which is why
they are not re-implemented here:

  * AST01 Malicious Skills and the *semantic* half of AST04 -- brand-impersonating
    names, hidden instructions, exfiltration primitives -- are `AAK-SKILL-001`
    through `AAK-SKILL-005` and `AAK-POISON-001` through `AAK-POISON-006`.
  * AST03 Over-Privileged Skills, in its "declare `network: false`, then call
    `curl`" form, is `AAK-COMPOSE-003`, which compares a manifest against the
    capability its own body exercises.

Writing those again would report one defect twice, which is the failure the
composition pass was built to avoid.

What this module adds
---------------------
`AAK-AST02-001` (AST02 Supply Chain Compromise, and the pinning half of AST07)
    A skill bundle that pulls an external resource with nothing pinning it: a
    branch instead of a commit, `releases/latest`, a bare domain, an unpinned
    package. AST02's own evidence is that this is the common case rather than an
    edge one -- Air Security's *Circus of Skills* found 17,822 of 142,836 live
    skills (~12.4%, 6.7M installs) resting on at least one untrusted external
    resource, and *SkillJacking* showed 925 of them sitting on sources that could
    be taken over outright. The check is deterministic because it reads what the
    bundle declares, not what the resource currently serves.

`AAK-AST04-001` (AST04 Insecure Metadata, parsing layer)
    A language-specific deserialization tag in skill frontmatter --
    `!!python/object/apply`, `!ruby/object`, and friends. AST04 names this
    directly: "`SKILL.md` frontmatter contains
    `!!python/object/apply:os.system [...]` -- executes on parse". This is the
    parsing half of AST04, distinct from the semantic half `AAK-SKILL-005`
    already covers: that rule reads frontmatter *values* for injection triggers,
    while a deserialization tag executes before any value is read.

`AAK-AST10-001` (AST10 Cross-Platform Reuse)
    A skill bundle carrying more than one platform manifest -- `SKILL.md` YAML,
    `skill.json`, `manifest.json`, `package.json` -- where a security-relevant
    field present in one is missing from another, or declares something weaker.
    AST10's first attack scenario is exactly this: "a skill with `risk_tier: L3`
    is ported to a platform that doesn't support `risk_tier`; the warning is
    silently dropped". Like the composition pass, this is a cross-artifact
    question: no single manifest is wrong on its own, and the defect exists only
    in the disagreement between them.

Extraction is reused rather than rebuilt: frontmatter parsing comes from
`skill_composition._parse_frontmatter`, so this module does not carry a second
copy of the SKILL.md format.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, find_line_number, make_finding
from agent_audit_kit.scanners.skill_composition import _parse_frontmatter

_RULE_PROVENANCE = "AAK-AST02-001"
_RULE_METADATA = "AAK-AST04-001"
_RULE_CROSS_PLATFORM = "AAK-AST10-001"

RULE_IDS = frozenset({_RULE_PROVENANCE, _RULE_METADATA, _RULE_CROSS_PLATFORM})

# AST10 category ids this module decides statically. The README states the other
# seven as not covered; `tests/test_agentic_skills.py` holds that list against
# the ten the OWASP repo actually publishes, so a category cannot quietly move
# from "not covered" to unmentioned.
COVERED_AST_CATEGORIES = ("AST02", "AST04", "AST07", "AST10")

_MAX_FILE_BYTES = 512_000

# The four platform manifests AST10 names, in the project's own words: "OpenClaw
# (SKILL.md YAML), Claude Code (skill.json), Cursor/Codex (manifest.json), and
# VS Code (package.json)".
_PLATFORM_MANIFESTS: tuple[tuple[str, str], ...] = (
    ("SKILL.md", "OpenClaw / SKILL.md frontmatter"),
    ("skill.json", "Claude Code"),
    ("manifest.json", "Cursor / Codex"),
    ("package.json", "VS Code"),
)

# Security-relevant metadata whose loss in translation is the AST10 defect.
# Deliberately not "every field": a description differing between manifests is
# editorial, while a dropped permission scope is a control that stopped existing.
_SECURITY_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("risk tier", ("risk_tier", "risk-tier", "riskTier", "risk")),
    ("permissions", ("permissions", "allowed-tools", "allowed_tools", "allowedTools")),
    ("signature", ("signature", "integrity", "sha256", "sigstore", "publicKey")),
    ("egress allow-list", ("egress", "network", "destinations", "allowed_hosts")),
    ("capabilities", ("capabilities", "capability")),
)

# Deserialization tags that execute during parse, before any value is read.
# Anchored on the tag punctuation so ordinary prose cannot match: a bare word
# like "python" or "object" appears in half of all skill descriptions.
_DESERIALIZATION_TAG_RE = re.compile(
    r"!!(?:python|ruby|java|js)/[\w.]+"
    r"|(?<![\w!])!(?:ruby|python)/[\w.]+"
    r"|!!(?:map|seq|str):[\w.]+"
    r"|(?<![\w!])!<tag:[^>]+>",
    re.IGNORECASE,
)

# An external resource with nothing pinning it. Each arm is a shape AST02 or
# AST07 names: a floating git ref, a "latest" redirect, a bare install command.
_UNPINNED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("a git ref that moves", re.compile(
        r"(?:github\.com|gitlab\.com)/[\w.-]+/[\w.-]+"
        r"(?:/(?:blob|raw|archive|tree))?/(?:main|master|HEAD|latest|develop)(?![\w-])",
        re.IGNORECASE)),
    ("a `releases/latest` redirect", re.compile(
        r"releases/latest(?:/download)?", re.IGNORECASE)),
    ("a pipe-to-shell install", re.compile(
        r"curl[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh|wget[^\n|]{0,200}\|\s*(?:ba)?sh",
        re.IGNORECASE)),
    ("an unpinned package install", re.compile(
        r"(?:npm\s+(?:i|install)|pipx?\s+install|uvx?\s+(?:tool\s+)?install|"
        r"cargo\s+install|go\s+install)\s+(?:-{1,2}[\w-]+\s+)*"
        r"(?!.*(?:==|@\d|#egg=|--version))[@\w./-]+(?:\s|$)",
        re.IGNORECASE)),
)

# A pinned reference anywhere in the bundle clears the "nothing pins it" claim
# for that resource shape. Kept separate so a bundle that pins *some* things and
# floats others is still reported for the ones it floats.
_PINNED_RE = re.compile(
    r"sha256[:=-]|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b|integrity\s*[:=]|@\d+\.\d+\.\d+",
    re.IGNORECASE,
)


@dataclass
class _Bundle:
    """One skill directory and every platform manifest it ships."""

    root: Path
    rel: str
    manifests: dict[str, tuple[Path, dict[str, Any]]] = field(default_factory=dict)
    skill_md: Path | None = None
    body: str = ""


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _bundles(project_root: Path) -> list[_Bundle]:
    """Every directory holding a `SKILL.md`, with its sibling platform manifests.

    A skill bundle is defined by the presence of `SKILL.md`, so a repository that
    merely contains a `package.json` is not treated as a skill -- this module has
    no opinion about ordinary projects.
    """
    out: list[_Bundle] = []
    for skill_md in sorted(project_root.rglob("SKILL.md")):
        if any(part in SKIP_DIRS for part in skill_md.parts):
            continue
        directory = skill_md.parent
        try:
            rel = directory.relative_to(project_root).as_posix() or "."
        except ValueError:
            continue
        raw = _read(skill_md)
        bundle = _Bundle(
            root=directory,
            rel=rel,
            skill_md=skill_md,
            body=raw,
        )
        frontmatter = _parse_frontmatter(raw)
        if frontmatter:
            bundle.manifests["SKILL.md"] = (skill_md, frontmatter)
        for name, _platform in _PLATFORM_MANIFESTS:
            if name == "SKILL.md":
                continue
            candidate = directory / name
            if not candidate.is_file():
                continue
            data = _load_json(candidate)
            if data is not None:
                bundle.manifests[name] = (candidate, data)
        out.append(bundle)
    return out


def _declared(data: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    """The first of ``keys`` the manifest declares, searching one level in.

    `package.json` nests skill metadata under a platform key, so a top-level miss
    is not proof of absence.
    """
    for key in keys:
        if key in data:
            return data[key]
    for nested_key in ("skill", "agent", "contributes", "mcp", "metadata"):
        nested = data.get(nested_key)
        if isinstance(nested, dict):
            for key in keys:
                if key in nested:
                    return nested[key]
    return None


def _is_weaker(source: Any, target: Any) -> bool:
    """True when ``target`` states a weaker control than ``source``.

    Only the unambiguous direction: an allow-list replaced by a blanket `true`,
    or a non-empty declaration replaced by an empty one. Anything requiring a
    judgement about which of two lists is safer is left alone, because a rule
    that guesses there would be exactly the padding this family avoids.
    """
    if target is True and isinstance(source, (list, tuple, str)) and source:
        return True
    if isinstance(target, (list, tuple)) and not target and source:
        return True
    return False


def _provenance_findings(bundle: _Bundle) -> list[Finding]:
    """AST02 / AST07: an external resource the bundle does not pin."""
    findings: list[Finding] = []
    text = bundle.body
    for _name, (path, _data) in sorted(bundle.manifests.items()):
        if path != bundle.skill_md:
            text += "\n" + _read(path)
    if not text.strip():
        return findings

    hits: list[str] = []
    for label, pattern in _UNPINNED_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append(f"{label} (`{match.group(0).strip()[:70]}`)")
    if not hits:
        return findings
    if _PINNED_RE.search(text):
        # The bundle pins something. Report only when nothing is pinned at all,
        # so a bundle that pins its dependencies and links a docs URL stays quiet.
        return findings

    findings.append(make_finding(
        _RULE_PROVENANCE,
        f"{bundle.rel}/SKILL.md",
        f"Skill bundle `{bundle.rel}` pulls an external resource with nothing "
        f"pinning it: {'; '.join(hits)}. No content hash, commit SHA, integrity "
        "field or exact version appears anywhere in the bundle, so what this skill "
        "runs is whatever the source serves at the time it is used.",
        1,
    ))
    return findings


def _metadata_findings(bundle: _Bundle) -> list[Finding]:
    """AST04 parsing layer: a deserialization tag that executes on parse."""
    findings: list[Finding] = []
    if bundle.skill_md is None:
        return findings
    raw = bundle.body
    if not raw.startswith("---"):
        return findings
    try:
        _, frontmatter, _ = raw.split("---", 2)
    except ValueError:
        frontmatter = raw
    match = _DESERIALIZATION_TAG_RE.search(frontmatter)
    if match is None:
        return findings
    tag = match.group(0)
    findings.append(make_finding(
        _RULE_METADATA,
        f"{bundle.rel}/SKILL.md",
        f"Frontmatter carries the deserialization tag `{tag}`. A loader using its "
        "language's unsafe default constructs the named object while parsing, so "
        "this runs before any field of the skill is read and before the skill is "
        "ever invoked.",
        find_line_number(raw, tag) or 1,
    ))
    return findings


def _cross_platform_findings(bundle: _Bundle) -> list[Finding]:
    """AST10: a security property present in one manifest and lost in another."""
    findings: list[Finding] = []
    if len(bundle.manifests) < 2:
        return findings

    platform_of = dict(_PLATFORM_MANIFESTS)
    losses: list[str] = []
    for label, keys in _SECURITY_FIELDS:
        declared: dict[str, Any] = {}
        for name, (_path, data) in bundle.manifests.items():
            value = _declared(data, keys)
            if value is not None:
                declared[name] = value
        if not declared:
            continue
        missing = [n for n in bundle.manifests if n not in declared]
        for name in sorted(missing):
            source = sorted(declared)[0]
            losses.append(
                f"{label} declared in {source} ({platform_of.get(source, source)}) "
                f"but absent from {name} ({platform_of.get(name, name)})"
            )
        for name, value in sorted(declared.items()):
            for other, other_value in sorted(declared.items()):
                if other <= name:
                    continue
                if _is_weaker(value, other_value):
                    losses.append(
                        f"{label} is weaker in {other} ({other_value!r}) than in "
                        f"{name} ({value!r})"
                    )
                elif _is_weaker(other_value, value):
                    losses.append(
                        f"{label} is weaker in {name} ({value!r}) than in "
                        f"{other} ({other_value!r})"
                    )

    if not losses:
        return findings

    anchor = sorted(bundle.manifests)[0]
    findings.append(make_finding(
        _RULE_CROSS_PLATFORM,
        f"{bundle.rel}/{anchor}",
        f"Skill bundle `{bundle.rel}` ships {len(bundle.manifests)} platform "
        f"manifests ({', '.join(sorted(bundle.manifests))}) whose security "
        f"metadata disagrees: {'; '.join(losses)}. Whichever platform loads the "
        "weaker manifest runs the skill without the control the other declares.",
        1,
        related_locations=[
            {
                "file_path": f"{bundle.rel}/{name}",
                "line_number": 1,
                "message": f"{name} ({platform_of.get(name, name)})",
            }
            for name in sorted(bundle.manifests)
        ],
    ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan skill bundles for the statically decidable AST10 risks.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    for bundle in _bundles(project_root):
        found = (
            _provenance_findings(bundle)
            + _metadata_findings(bundle)
            + _cross_platform_findings(bundle)
        )
        if found:
            findings.extend(found)
            scanned.update(f"{bundle.rel}/{name}" for name in bundle.manifests)

    return findings, scanned
