"""Container image tag pins: self-hosted MCP platforms that ship only as images.

Some MCP platforms are not packages. Obot is a Go server published as
`ghcr.io/obot-platform/obot` and a Helm chart; npm's `obot` is an empty 2018
placeholder and PyPI's `obot` an unrelated bot library. MetaMCP's root
`package.json` is `private: true`, its compose file pulls
`ghcr.io/metatool-ai/metamcp:latest`, and npm's `@metamcp/mcp-server-metamcp` is
a separate client proxy from another repository. heym is on neither registry and
ships as `ghcr.io/heymrun/heym`. Nothing `mcp_cve_pins_2026_07` reads carries
their version, and a pin on a look-alike package name would report somebody
else's project. The image tag is the only place a deployment states which
release it runs, so this module reads image references and nothing else.

Where a reference is read
-------------------------
  * YAML (compose files, Kubernetes manifests, MCP configs): `image: REPO:TAG`,
    or the reference anywhere else on a line, such as a `docker run` argument
  * Helm values: a mapping with `repository: REPO` (or `registry` + `repository`)
    and `tag: TAG`, read through the YAML node tree so `tag: 2.10` stays the
    string it was written as instead of the float 2.1
  * Dockerfile / Containerfile: `FROM REPO:TAG`
  * MCP configs (`*mcp*.json`, `claude_desktop_config.json`) that start the
    server with `docker run ... REPO:TAG`

What a tag means
----------------
A tag is a version when it starts with `v?N.N.N`; a suffix after the numbers
(`-test`, `-amd64`) is ignored. A two-part tag such as `2.4` floats to the newest
patch of that line, so it is reported only when the whole line is below the
floor. Everything else states no version this module can trust:

  * No tag, or `latest`: the floating tag. Reported only for a pin whose
    `latest` resolves inside the affected range (`floating_affected`). MetaMCP's
    does: on 2026-10-03 `latest`, `2`, `2.4` and `2.4.22` were one digest. Obot's
    `latest` was v0.26.2 and heym's 0.0.123, both fixed, so they stay quiet.
    A floating reference also has to sit where an image goes (an `image:` value,
    a `FROM` line, or a whole quoted string such as a JSON `args` element), so a
    sentence that merely names the image is not read as a deployment.
  * A tag that is not a version (`main`, `main-20250617`, `dev`), a digest with
    no tag, or an interpolated tag (`:${OBOT_VERSION}`, `:{{ .Values.tag }}`).
  * A Helm `tag` that is empty or missing: the chart's appVersion decides, which
    the values file does not state, and it is not `latest` either.

The image name must match exactly. `ghcr.io/obot-platform/obot-enterprise` is a
different image whose tags were not checked, and a mirror under another registry
is not recognised. Commented-out YAML and Dockerfile lines are skipped.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding

_Ver = tuple[int, int, int]


@dataclass(frozen=True)
class _ImagePin:
    rule_id: str
    display: str
    image: str                      # repository with registry, lowercase
    floor: _Ver                     # first version outside the affected range
    range_label: str                # the affected range, for the evidence line
    fix_label: str
    cves: tuple[str, ...]
    floating_affected: bool = False  # `latest` resolves inside the range today


_PINS: tuple[_ImagePin, ...] = (
    # CVE-2026-101084 (< v0.21.1), CVE-2026-101062 and CVE-2026-101064 (< v0.23.0),
    # CVE-2026-103758 (0.21.1 to 0.24.1, no patched version named). v0.25.0 is the
    # first tag carrying obot-platform/obot#7375 (190356202d), which made `checkUI`
    # authorize only the UI's own "/" route. v0.24.2 was cut from the 0.24 branch
    # after that, with one unrelated commit, and still has the 0.24.1 deny list.
    _ImagePin(
        "AAK-MCP-OBOT-CVE-2026-101084-001", "Obot", "ghcr.io/obot-platform/obot",
        (0, 25, 0), "below v0.25.0", "Fixed in v0.25.0.",
        ("CVE-2026-101084", "CVE-2026-101062", "CVE-2026-103758", "CVE-2026-101064"),
    ),
    # NVD scopes both "up to and including 2.4.22". There is no fixed release, and
    # 2.4.22 is the newest image tag, so the floor is the next patch number.
    _ImagePin(
        "AAK-MCP-METAMCP-CVE-2026-79538-001", "MetaMCP", "ghcr.io/metatool-ai/metamcp",
        (2, 4, 23), "up to and including 2.4.22", "No fixed release yet.",
        ("CVE-2026-79538", "CVE-2026-79537"),
        floating_affected=True,
    ),
    # NVD: "before 0.0.109"; GHSA-39j3-6x3x-8rcr names 0.0.109 as patched.
    _ImagePin(
        "AAK-MCP-HEYM-CVE-2026-100858-001", "heym", "ghcr.io/heymrun/heym",
        (0, 0, 109), "below 0.0.109", "Fixed in 0.0.109.", ("CVE-2026-100858",),
    ),
)

_MAX_FILE_BYTES = 2_000_000
# The Docker tag grammar: one word character, then up to 127 of [\w.-].
_TAG_RE = re.compile(r":([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})")
_VER_RE = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?(?!\d)")
_IMAGE_KEY_RE = re.compile(r"""\bimage\s*:\s*["']?$""", re.I)
# A `repository:` value belongs to the Helm mapping reader, which knows its tag.
_REPOSITORY_KEY_RE = re.compile(r"""\brepository\s*:\s*["']?$""", re.I)
_COMMENT_RE = re.compile(r"(?:^|\s)#")


def _ref_re(image: str) -> re.Pattern[str]:
    """The image name with a boundary on both sides, so `.../obot` stays off
    `.../obot-enterprise` and `myghcr.io/...`."""
    return re.compile(r"(?<![\w./-])" + re.escape(image) + r"(?![\w./-])", re.I)


_REF_RES = {pin.image: _ref_re(pin.image) for pin in _PINS}


def _in_image_slot(prefix: str) -> bool:
    """Is a reference after this line prefix where an image goes: the value of
    `image:`, or the image of a FROM line after any `--platform=...` flags?"""
    if _IMAGE_KEY_RE.search(prefix):
        return True
    words = prefix.split()
    return bool(words) and words[0].upper() == "FROM" and all(w.startswith("--") for w in words[1:])


def _affected(tag: str | None, pin: _ImagePin) -> bool:
    """Does this tag name a release inside the pin's range? None means untagged."""
    if tag is None or tag.lower() == "latest":
        return pin.floating_affected
    m = _VER_RE.match(tag)
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    if m.group(3) is None:
        return (major, minor) < pin.floor[:2]
    return (major, minor, int(m.group(3))) < pin.floor


def _kind(name: str) -> str | None:
    low = name.lower()
    if low.endswith((".yml", ".yaml")):
        return "yaml"
    if (
        low in ("dockerfile", "containerfile")
        or low.startswith(("dockerfile.", "containerfile."))
        or low.endswith(".dockerfile")
    ):
        return "dockerfile"
    if low.endswith(".json") and ("mcp" in low or low == "claude_desktop_config.json"):
        return "json"
    return None


def _candidates(project_root: Path) -> Iterator[tuple[Path, str]]:
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            kind = _kind(name)
            if kind is not None:
                yield Path(dirpath) / name, kind


def _inline_hit(text: str, kind: str, pin: _ImagePin) -> tuple[str, int] | None:
    """(reference as written, line) for the first affected inline reference."""
    for m in _REF_RES[pin.image].finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[line_start:m.start()]
        if kind != "json" and _COMMENT_RE.search(prefix):
            continue
        if kind == "yaml" and _REPOSITORY_KEY_RE.search(prefix):
            continue
        nxt = text[m.end():m.end() + 1]
        if nxt == ":":
            tag_m = _TAG_RE.match(text, m.end())
            if tag_m is None:
                continue  # `:${VAR}` / `:{{ ... }}`: the file states no version
            tag: str | None = tag_m.group(1)
            end = tag_m.end()
        elif nxt == "@":
            continue  # digest only
        else:
            tag, end = None, m.end()
            before = text[m.start() - 1:m.start()]
            whole_string = before in ("'", '"') and nxt == before
            if not (whole_string or _in_image_slot(prefix)):
                continue
        if _affected(tag, pin):
            return text[m.start():end], text.count("\n", 0, m.start()) + 1
    return None


def _helm_refs(text: str) -> Iterator[tuple[str, str, int]]:
    """(repository, tag, line) for every mapping that pairs the two, as Helm
    values do. Composed, not loaded: node values are the strings as written."""
    try:
        roots = [n for n in yaml.compose_all(text, Loader=yaml.SafeLoader) if n is not None]
    except yaml.YAMLError:
        return
    seen: set[int] = set()
    stack: list[yaml.Node] = roots
    while stack:
        node = stack.pop()
        if id(node) in seen:  # an alias can point back at its own ancestor
            continue
        seen.add(id(node))
        if isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
            continue
        if not isinstance(node, yaml.MappingNode):
            continue
        fields: dict[str, yaml.ScalarNode] = {}
        for key, value in node.value:
            stack.append(value)
            if isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode):
                fields[key.value] = value
        repo, tag = fields.get("repository"), fields.get("tag")
        if repo is None or tag is None or not tag.value:
            continue
        name = repo.value
        registry = fields.get("registry")
        if registry is not None and registry.value:
            name = f"{registry.value.rstrip('/')}/{name}"
        yield name.lower(), tag.value, repo.start_mark.line + 1


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report image references whose tag falls inside a pinned CVE range.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path, kind in _candidates(project_root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        lowered = text.lower()
        # Filter on the path without the registry: Helm values may split
        # `registry: ghcr.io` from `repository: obot-platform/obot`.
        pins = [pin for pin in _PINS if pin.image.split("/", 1)[1] in lowered]
        if not pins:
            continue
        helm = list(_helm_refs(text)) if kind == "yaml" else []
        for pin in pins:
            hit = _inline_hit(text, kind, pin)
            if hit is None:
                hit = next(
                    (
                        (f"{name}:{tag}", line)
                        for name, tag, line in helm
                        if name == pin.image and _affected(tag, pin)
                    ),
                    None,
                )
            if hit is None:
                continue
            shown, line = hit
            if ":" not in shown[len(pin.image):]:
                shown += " (untagged, so latest)"
            findings.append(make_finding(
                pin.rule_id,
                rel,
                f"`{shown}` in {path.name}: {pin.display} {pin.range_label} "
                f"({', '.join(pin.cves)}). {pin.fix_label}",
                line,
            ))
    return findings, scanned
