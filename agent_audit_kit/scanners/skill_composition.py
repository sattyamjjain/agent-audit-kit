"""Composition-aware capability-union check (AAK-AGENT-COMPOSE-001).

The `AAK-AGENT-TRUST-*` and `AAK-SKILL-*` rules inspect ONE artifact at a time.
That is a pre-screen, not a boundary control: it cannot see intent split across
several individually-benign skills that load into the same agent context. This
is the ColluSkill shape (arXiv:2608.09732): benign skills whose *composed*
capability is an attack, reported at a 96.0% average success rate across six
per-skill scanners.

This scanner operates on the SET, not the artifact. For each container of skills
that would load together (all `SKILL.md` under a common parent such as
`.claude/skills/`), it:

  1. Reads each skill's declared capability — from `allowed-tools` frontmatter
     (tool -> capability), an explicit `capabilities:` list, and an `egress:`
     list of network destinations.
  2. Computes the UNION across the set, remembering which skill contributed
     which capability (and which egress destination).
  3. Trips a configured boundary when the union spans both sides of it AND no
     single skill in the set holds both sides — i.e. the risk exists only
     because the skills were composed.

Default boundary (see `data/composition_boundaries.yaml`, overridable per-project
via `.aak/composition-boundaries.yaml`, documented in
`docs/rules/skill-composition.md`):

    {filesystem_read OR credential_access} + {network egress to a
     non-allowlisted destination} = exfiltration path, HIGH.

The finding names which skill contributed which capability, and emits every
contributing skill as a SARIF related location so it is navigable in a
code-scanning UI. This is a heuristic on *declared* capability; a skill that
under-declares is out of scope for this rule (the per-skill scanners and taint
analysis cover in-body behaviour).
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, make_finding

_RULE_ID = "AAK-AGENT-COMPOSE-001"

_CAPABILITIES = frozenset({
    "filesystem_read",
    "filesystem_write",
    "network_egress",
    "shell_execution",
    "credential_access",
    "memory_write",
})

# Standard agent/skill tool names -> the capability they grant.
_TOOL_CAPABILITY: dict[str, str] = {
    "read": "filesystem_read", "glob": "filesystem_read", "grep": "filesystem_read",
    "ls": "filesystem_read", "cat": "filesystem_read", "notebookread": "filesystem_read",
    "view": "filesystem_read",
    "write": "filesystem_write", "edit": "filesystem_write", "multiedit": "filesystem_write",
    "notebookedit": "filesystem_write", "applypatch": "filesystem_write",
    "bash": "shell_execution", "shell": "shell_execution", "execute": "shell_execution",
    "run": "shell_execution", "terminal": "shell_execution",
    "webfetch": "network_egress", "websearch": "network_egress", "fetch": "network_egress",
    "curl": "network_egress", "http": "network_egress", "browser": "network_egress",
    "memory": "memory_write", "memorywrite": "memory_write", "remember": "memory_write",
    "credentials": "credential_access", "secrets": "credential_access", "keychain": "credential_access",
}

_DEFAULT_BOUNDARIES = Path(__file__).resolve().parent.parent / "data" / "composition_boundaries.yaml"
_PROJECT_OVERRIDE = ".aak/composition-boundaries.yaml"
_MAX_FILE_BYTES = 512_000


def _parse_frontmatter(text: str) -> dict:
    """Parse the YAML frontmatter block of a SKILL.md, tolerant of no block."""
    if not text.startswith("---"):
        return {}
    try:
        _, fm, _ = text.split("---", 2)
    except ValueError:
        return {}
    try:
        data = yaml.safe_load(fm)
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.replace(",", " ").split() if v.strip()]
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for v in value:
            out.extend(_as_list(v))
        return out
    return [str(value).strip()]


def _host(dest: str) -> str:
    """Normalise a declared egress destination to a bare host for allowlisting."""
    dest = dest.strip()
    if "://" in dest:
        return (urlparse(dest).hostname or dest).lower()
    return dest.split("/")[0].lower()


class _Skill:
    __slots__ = ("path", "rel", "line", "caps", "egress")

    def __init__(self, path: Path, rel: str, line: int) -> None:
        self.path = path
        self.rel = rel
        self.line = line
        self.caps: set[str] = set()
        self.egress: set[str] = set()  # declared destination hosts


def _extract_skill(path: Path, project_root: Path) -> _Skill | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    fm = _parse_frontmatter(raw)
    rel = path.relative_to(project_root).as_posix()
    skill = _Skill(path, rel, 1)

    tools = _as_list(fm.get("allowed-tools") or fm.get("allowed_tools") or fm.get("tools"))
    for tool in tools:
        cap = _TOOL_CAPABILITY.get(tool.split("(")[0].strip().lower())
        if cap:
            skill.caps.add(cap)

    for cap in _as_list(fm.get("capabilities")):
        c = cap.strip().lower()
        if c in _CAPABILITIES:
            skill.caps.add(c)

    egress = _as_list(fm.get("egress") or fm.get("network") or fm.get("destinations"))
    if egress:
        skill.caps.add("network_egress")
        skill.egress = {_host(d) for d in egress}
    return skill


def _load_boundaries(project_root: Path) -> tuple[list[dict], set[str]]:
    override = project_root / _PROJECT_OVERRIDE
    src = override if override.is_file() else _DEFAULT_BOUNDARIES
    try:
        data = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return [], set()
    boundaries = data.get("boundaries", []) if isinstance(data, dict) else []
    allowlist = {h.lower() for h in _as_list(data.get("egress_allowlist"))}
    return [b for b in boundaries if isinstance(b, dict)], allowlist


def _skill_sets(project_root: Path) -> dict[Path, list[_Skill]]:
    """Group SKILL.md files by their container (the parent that holds several
    skill subdirs). Skills in the same container load into one context."""
    sets: dict[Path, list[_Skill]] = {}
    for path in project_root.rglob("SKILL.md"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        skill = _extract_skill(path, project_root)
        if skill is None:
            continue
        container = path.parent.parent  # <container>/<skill-name>/SKILL.md
        sets.setdefault(container, []).append(skill)
    return sets


def _egress_contributors(skills: list[_Skill], allowlist: set[str]) -> list[_Skill]:
    """Skills whose egress goes to a non-allowlisted (or unspecified) destination."""
    out = []
    for s in skills:
        if "network_egress" not in s.caps:
            continue
        # Unspecified destination (network tool, no declared host) cannot be
        # verified safe -> treated as non-allowlisted. Otherwise flag if ANY
        # declared destination is off the allowlist.
        if not s.egress or any(h not in allowlist for h in s.egress):
            out.append(s)
    return out


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan skill sets for capability-union boundary violations (AAK-AGENT-COMPOSE-001)."""
    findings: list[Finding] = []
    evaluated = {_RULE_ID}

    boundaries, allowlist = _load_boundaries(project_root)
    if not boundaries:
        return findings, evaluated

    for container, skills in _skill_sets(project_root).items():
        if len(skills) < 2:
            continue  # composition needs at least two artifacts
        for boundary in boundaries:
            left = {c.lower() for c in boundary.get("left", [])}
            right = {c.lower() for c in boundary.get("right", [])}
            dest_side = boundary.get("destination_checked_side", "")

            # Contributors of each side. If the right side is destination-checked
            # (network_egress), only non-allowlisted egress skills count.
            left_skills = [s for s in skills if s.caps & left]
            if dest_side == "right" and right == {"network_egress"}:
                right_skills = _egress_contributors(skills, allowlist)
            else:
                right_skills = [s for s in skills if s.caps & right]

            if not left_skills or not right_skills:
                continue
            # Composition-only: skip if a single skill already holds both sides
            # (the per-skill rules own that case; this rule is about the union).
            if any((s.caps & left) and (s in right_skills) for s in skills):
                continue

            findings.append(_compose_finding(
                project_root, container, skills, left_skills, right_skills, boundary, left,
            ))

    return findings, evaluated


def _compose_finding(
    project_root: Path,
    container: Path,
    skills: list[_Skill],
    left_skills: list[_Skill],
    right_skills: list[_Skill],
    boundary: dict,
    left: set[str],
) -> Finding:
    left_names = {s.rel for s in left_skills}
    right_names = {s.rel for s in right_skills}
    anchor = left_skills[0]

    def _caps_of(s: _Skill, side: set[str]) -> str:
        return ", ".join(sorted(s.caps & side)) or "network_egress"

    related: list[dict] = []
    for s in left_skills:
        related.append({
            "file_path": s.rel, "line_number": s.line,
            "message": f"contributes {_caps_of(s, left)}",
        })
    for s in right_skills:
        dests = ", ".join(sorted(s.egress)) if s.egress else "unspecified destination"
        related.append({
            "file_path": s.rel, "line_number": s.line,
            "message": f"contributes network egress ({dests})",
        })
    # De-dupe related locations by (file, message).
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for r in related:
        key = (r["file_path"], r["message"])
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    related = deduped

    container_rel = container.relative_to(project_root).as_posix() if container != project_root else "."
    all_dests = sorted({d for s in right_skills for d in (s.egress or {"unspecified"})})
    evidence = (
        f"Skill set under `{container_rel}` ({len(skills)} skills): the union of "
        f"declared capability crosses the '{boundary.get('name', 'boundary')}' boundary "
        f"that no single skill in the set requested. "
        f"Read/credential side: {', '.join(sorted(left_names))}. "
        f"Egress side: {', '.join(sorted(right_names))} -> {', '.join(all_dests)}. "
        f"Each skill is individually clean; composed, they are an exfiltration path."
    )
    return make_finding(_RULE_ID, anchor.rel, evidence, anchor.line, related_locations=related)
