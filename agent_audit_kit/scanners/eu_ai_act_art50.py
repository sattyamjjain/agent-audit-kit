"""EU AI Act Article 50 transparency evidence (AAK-AIACT50-001..003).

Regulation (EU) 2024/1689, Article 50, "Transparency obligations for providers
and deployers of certain AI systems". **These obligations have applied since
2 August 2026** — they are live, not forthcoming, which is the opposite of the
Article 15 high-risk duties this repository already maps (Annex III binding
2027-12-02, Annex I 2028-08-02 after the AI Omnibus deferral).

The paragraphs this scanner produces evidence toward, read from the
consolidated article on 2026-09-12 (https://artificialintelligenceact.eu/article/50/):

  50(1)  PROVIDER. AI systems intended to interact directly with natural
         persons are designed so those persons are informed they are
         interacting with an AI system. Exempt where obvious to a reasonably
         informed person, and for certain law-enforcement systems.
  50(2)  PROVIDER. Outputs that are synthetic audio, image, video or text are
         marked in a machine-readable format and detectable as artificially
         generated or manipulated, effectively and interoperably so far as
         technically feasible. Exempt for assistive editing that does not
         substantially alter the input data.
  50(4)  DEPLOYER. Deep-fake image, audio or video content is disclosed as
         artificially generated or manipulated, and so is text published to
         inform the public on matters of public interest. Exempt for artistic,
         creative, satirical or fictional works, and where the text had human
         editorial review and someone holds editorial responsibility.

50(5) requires the information to be given clearly and distinguishably at the
latest at the time of the first interaction or exposure.

WHAT THIS SCANNER DOES NOT DO
-----------------------------
It does not determine that Article 50 applies to anyone, and it does not
determine that a duty has been discharged. Whether a system is "intended to
interact directly with natural persons", whether disclosure is "obvious from
context", and whether an exemption is engaged are all facts about a deployed
product that a static read of a repository cannot reach. Findings are evidence
toward a duty.

50(3) — the deployer's duty to notify people exposed to emotion-recognition or
biometric-categorisation systems — is deliberately **not** given a rule. This
scanner has no honest signal for "biometric data is being processed to infer
emotion", and a rule that guessed would accuse a project of a duty under a
different Chapter of the Act. The framework arm says so in place of citing a
paragraph it cannot evidence.

Detection reuses `healthcare_ai`'s conversational-surface and AI-disclosure
patterns rather than restating them: 50(1) is the general case of the duty that
`AAK-HEALTHCARE-AI-004` already checks in clinical text, so the two must agree
on what a conversational surface is.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS
from agent_audit_kit.scanners.admt_documentation import (
    _mcp_descriptions,
    _tool_declarations,
)
from agent_audit_kit.scanners.healthcare_ai import (
    _AGENT_SURFACE_RE,
    _AI_DISCLOSURE_RE,
)

_TEXT_EXTS = {".md", ".txt", ".json", ".yaml", ".yml", ".py", ".ts", ".js"}
_MAX_FILE_BYTES = 512_000

# An agent surface is a specific artifact, not any file that uses the word
# "assistant". The first draft of this scanner read every text file and gated
# 50(1) on `_AGENT_SURFACE_RE` alone; swept over this repository it produced 83
# findings, because a security scanner's rule catalogue, tests and launch notes
# discuss personas and system prompts constantly. Describing an agent surface is
# not being one -- the same trap the Colorado ADMT scanner hit, and the same fix:
# read declarations only from places a developer declares product intent.
_SURFACE_FILENAME_RE = re.compile(
    r"^(?:skill|agent|agents|persona|system[-_]?prompt|prompt|"
    r"agent[-_]card|agent_card|character|instructions)\."
    r"(?:md|txt|json|yaml|yml)$",
    re.IGNORECASE,
)

# 50(2): a declared capability to produce synthetic media or text. Generation is
# the trigger; the marking duty attaches to the output.
_SYNTHETIC_OUTPUT_RE = re.compile(
    r"(?<![\w-])(?:text[-_ ]?to[-_ ]?(?:image|speech|video|audio)|image[-_ ]?gener\w*|"
    r"video[-_ ]?gener\w*|audio[-_ ]?gener\w*|speech[-_ ]?synth\w*|voice[-_ ]?clon\w*|"
    r"face[-_ ]?swap|synthetic[-_ ]?(?:media|audio|image|video|voice)|"
    r"generate[-_ ]?(?:image|video|audio|speech)|dall[-_ ]?e|stable[-_ ]?diffusion|"
    r"midjourney|elevenlabs)\b",
    re.IGNORECASE,
)

# 50(2): the machine-readable marking the paragraph asks for. C2PA / Content
# Credentials is the interoperable standard the Commission's code of practice
# points at; SynthID and a generic watermark/provenance marker also count as
# evidence that the question was considered.
_PROVENANCE_MARKING_RE = re.compile(
    r"(?<![\w-])(?:c2pa|content[-_ ]?credential\w*|synthid|watermark\w*|"
    r"provenance[-_ ]?(?:manifest|metadata|signature)|xmp[-_ ]?metadata|"
    r"iptc[-_ ]?digital[-_ ]?source|digital[-_ ]?source[-_ ]?type)\b",
    re.IGNORECASE,
)

# 50(4): deep-fake generation or manipulation of a real person's likeness, and
# text published to inform the public.
_DEEPFAKE_RE = re.compile(
    r"(?<![\w-])(?:deep[-_ ]?fake\w*|face[-_ ]?swap|lip[-_ ]?sync|"
    r"voice[-_ ]?clon\w*|likeness|impersonat\w*|"
    r"synthetic[-_ ]?(?:anchor|presenter|spokesperson))\b",
    re.IGNORECASE,
)
_PUBLIC_INTEREST_TEXT_RE = re.compile(
    r"(?<![\w-])(?:news[-_ ]?(?:article|story|wire|desk)|press[-_ ]?release|"
    r"publish[-_ ]?(?:article|post|story)|editorial|newsroom|journalis\w*|"
    r"public[-_ ]?interest)\b",
    re.IGNORECASE,
)
_DISCLOSURE_RE = re.compile(
    r"(?<![\w-])(?:artificially[-_ ]generated|AI[-_ ]generated|"
    r"generated[-_ ]by[-_ ]AI|synthetic[-_ ]content[-_ ]disclosure|"
    r"this[-_ ](?:image|video|audio|text)[-_ ]was[-_ ](?:generated|created)|"
    r"AI[-_ ]disclosure|clearly[-_ ]labell?ed[-_ ]as[-_ ]AI)\b",
    re.IGNORECASE,
)

# 50(2) and 50(4) both carve out work where a human stays in charge of the
# output, and 50(4) exempts artistic, creative, satirical and fictional works.
_EXEMPT_RE = re.compile(
    r"(?<![\w-])(?:assistive[-_ ]editing|spell[-_ ]?check\w*|grammar[-_ ]?check\w*|"
    r"autocorrect|satir\w*|parody|fiction\w*|creative[-_ ]writing|"
    r"editorial[-_ ]review|human[-_ ]editorial|artistic[-_ ]work)\b",
    re.IGNORECASE,
)


def _iter_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _TEXT_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Evidence toward Article 50, never a determination that it applies.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    # (relative path, declaration text). Three sources, all of them places a
    # developer states what a capability is for: an agent-surface artifact, an
    # MCP server or tool description, and a tool-decorated function.
    declarations: list[tuple[str, str]] = []
    for rel, blob in _mcp_descriptions(project_root):
        declarations.append((rel, blob))
    for path in _iter_files(project_root):
        rel = str(path.relative_to(project_root))
        if _SURFACE_FILENAME_RE.match(path.name):
            text = _read(path)
            if text:
                declarations.append((rel, text))
        elif path.suffix.lower() == ".py":
            for blob in _tool_declarations(path):
                declarations.append((rel, blob))

    for rel, text in declarations:
        if not text:
            continue
        if _EXEMPT_RE.search(text):
            # 50(2) and 50(4) both carve out assistive editing, and 50(4) carves
            # out artistic, satirical and fictional work and text under human
            # editorial responsibility. Say nothing rather than accuse.
            continue

        fired = False

        # 50(1) — provider: tell people they are talking to an AI.
        if _AGENT_SURFACE_RE.search(text) and not _AI_DISCLOSURE_RE.search(text):
            findings.append(make_finding(
                "AAK-AIACT50-001",
                rel,
                "Conversational agent surface with no string telling the user "
                "they are interacting with an AI. Art. 50(1) has applied since "
                "2026-08-02 where the system is intended to interact directly "
                "with natural persons and the fact is not obvious from context.",
            ))
            fired = True

        # 50(2) — provider: mark synthetic output machine-readably.
        if _SYNTHETIC_OUTPUT_RE.search(text) and not _PROVENANCE_MARKING_RE.search(text):
            findings.append(make_finding(
                "AAK-AIACT50-002",
                rel,
                "Declares generation of synthetic audio, image, video or text "
                "with no machine-readable provenance marking (C2PA / Content "
                "Credentials, SynthID, or an equivalent watermark). Art. 50(2).",
            ))
            fired = True

        # 50(4) — deployer: disclose deep fakes and public-interest text.
        deepfake = _DEEPFAKE_RE.search(text)
        public_text = _PUBLIC_INTEREST_TEXT_RE.search(text)
        if (deepfake or public_text) and not _DISCLOSURE_RE.search(text):
            what = "deep-fake image, audio or video" if deepfake else (
                "text published to inform the public"
            )
            findings.append(make_finding(
                "AAK-AIACT50-003",
                rel,
                f"Declares {what} with no disclosure that the content is "
                "artificially generated or manipulated. Art. 50(4), which the "
                "deployer owes at the latest at first exposure (50(5)).",
            ))
            fired = True

        if fired:
            scanned.add(rel)

    return findings, scanned
