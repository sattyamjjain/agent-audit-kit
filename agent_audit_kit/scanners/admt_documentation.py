"""Colorado SB 26-189 developer-documentation evidence (AAK-ADMT-001..004).

Colorado SB 26-189, "Automated Decision-Making Technology", signed 2026-05-14
(Chapter 131, Session Laws of 2026). SECTION 5 of the act: "Except as otherwise
provided in subsection (2) of this section, this act takes effect January 1,
2027", and "(3) This act applies to consequential decisions made on or after
January 1, 2027."

The duty this scanner produces evidence toward is C.R.S. 6-1-1702, "Developer
responsibilities - documentation". Subsection (1) requires a developer to make
available to each deployer of a covered ADMT, in a form reasonably understandable
and protecting trade secrets:

  (1)(a) intended uses and known harmful or inappropriate uses
  (1)(b) categories of data, including personal data, used to train it
  (1)(c) known limitations, including risks and circumstances of non-use
  (1)(d) instructions for appropriate use, monitoring, and meaningful human review
  (1)(e) information the deployer needs to satisfy 6-1-1704

with 6-1-1702(2)(a) adding notice of material updates and 6-1-1702(4) a
three-year retention duty over the resulting records.

WHAT THIS SCANNER DOES NOT DO
-----------------------------
It does not determine that 6-1-1702 applies to anyone. That determination turns
on facts a static read of a repository cannot reach: whether the operator does
business in Colorado, whether the technology materially influences a
consequential decision, and whether any of the 6-1-1701(3)(b) carve-outs apply.
Findings here are evidence toward a duty, never a holding that the duty attaches.

The trigger is therefore deliberately narrow, and it is narrow in the shape the
statute itself uses. 6-1-1702(3) limits the duty to an ADMT "MARKETED,
ADVERTISED, CONFIGURED, CONTRACTED, SOLD, OR LICENSED TO BE USED TO MATERIALLY
INFLUENCE A CONSEQUENTIAL DECISION", and 6-1-1702(5) attaches it when a developer
creates one "INTENDED, DOCUMENTED, MARKETED, ADVERTISED, CONFIGURED, OR
CONTRACTED" for consequential decisions. Both are tests on what the developer
*declared*, not on what the code turns out to do. So this scanner fires only
where the project's own tool names, docstrings or MCP server descriptions declare
both an inference verb and a 6-1-1701(6) covered domain. Where nothing declares
it, nothing is emitted: a false positive here reads as an accusation of breaking
a consumer-protection statute, which is a worse failure than a miss.

Covered domains are taken from 6-1-1701(6) verbatim, not from a summary: an
education enrollment or opportunity; employment creating an employer-employee
relationship; the lease or purchase of residential real estate in Colorado; a
financial or lending service; insurance; health-care services; and essential
government services and public benefits. Legal services are NOT a covered domain
under this act.

The negative vocabulary comes from the 6-1-1701(3)(b) exclusions, which remove
low-stakes and routine processes, "ROUTINE SCHEDULING, CLASSROOM
PERSONALIZATION, ADMINISTRATIVE ROUTING, CUSTOMER SERVICE TRIAGE, COMMUNICATION
OF DECISIONS, OR WORKFLOW MANAGEMENT", advertising, marketing, differentiated
product recommendations, search and content moderation.

Primary source (read 2026-09-12): the signed act,
https://leg.colorado.gov/bill_files/116489/download
Bill page: https://leg.colorado.gov/bills/sb26-189
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Iterable, Optional

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

_DECL_EXTS = {".py"}
_DOC_EXTS = {".md", ".txt", ".rst", ".html"}
_MAX_FILE_BYTES = 512_000

_MCP_CONFIG_NAMES = (
    ".mcp.json", "mcp.json", "claude_desktop_config.json",
    ".cursor/mcp.json", ".vscode/mcp.json", ".windsurf/mcp.json",
)

# An inference that materially influences an outcome. 6-1-1701(3)(b)(IV) carves
# out systems that summarise or present information for human review and do NOT
# "PRODUCE A SCORE, RANKING, RECOMMENDATION, CLASSIFICATION, PREDICTION, OR OTHER
# INFERENCE THAT MATERIALLY INFLUENCES AN OUTCOME OR A DECISION", so those verbs
# are the ones worth matching.
_INFERENCE_RE = re.compile(
    r"(?<![\w-])(?:score|scoring|rank|ranking|classif\w*|predict\w*|assess\w*|evaluat\w*|"
    r"screen\w*|shortlist\w*|adjudicat\w*|underwrit\w*|approve|approval|deny|denial|"
    r"reject\w*|eligib\w*|creditworth\w*|risk[-_ ]?scor\w*|decision\w*|"
    r"determinat\w*|triage)\b",
    re.IGNORECASE,
)

# Both alternations use a `(?<![\w-])` lookbehind rather than a bare `\b`, the
# same bounding the CVE pin table uses on package names. Without it "hire"
# matches inside "acqui-hire" and "qualif" inside "qualified inbound", which is
# how a self-scan of this repository picked KILL-CRITERIA.md as a declared
# lending surface. `qualif\w*` is gone entirely: "qualify" is sales and hiring
# vocabulary far more often than it is the statute's, and 6-1-1701 reaches the
# same concept through "eligib\w*".

# C.R.S. 6-1-1701(6) covered domains, one group per statutory paragraph.
_COVERED_DOMAIN_RE = re.compile(
    r"(?<![\w-])(?:"
    # (a) education enrollment or opportunity
    # "admission" is dropped on purpose: "admission control" is a networking term
    # and matched this repository's own README. 6-1-1701(6)(a) is still reached
    # through enrolment, student, transcript, scholarship and applicant, and an
    # education-admissions system names at least one of those.
    r"enrol\w*|student\w*|applicant\w*|transcript\w*|scholarship\w*|"
    # (b) employment / employment opportunity
    r"hiring|hire\w*|recruit\w*|candidate\w*|r[eé]sum[eé]\w*|resume\w*|cv[-_ ]?screen\w*|"
    r"employment|job[-_ ]?application\w*|promotion\w*|termination\w*|payroll|"
    # (c) lease or purchase of residential real estate
    r"tenan\w*|renta\w*|lease|leasing|landlord|housing|mortgage\w*|"
    # (d) financial or lending service
    r"loan\w*|lending|lender\w*|credit[-_ ]?(?:limit|line|applicat\w*|decision\w*|score)|"
    r"creditworth\w*|borrower\w*|"
    # (e) insurance
    # "premium" is dropped on purpose: it is product-marketing vocabulary far
    # more often than insurance vocabulary, and it matched "premium brandable
    # domains" in a cached research page during the self-scan.
    r"insuran\w*|underwrit\w*|policyholder\w*|claim[-_ ]?(?:adjudicat|decision|denial)\w*|"
    # (f) health-care services
    r"patient\w*|diagnos\w*|clinical|health[-_ ]?care|healthcare|prior[-_ ]?authoriz\w*|"
    r"medical[-_ ]?(?:necessity|record)\w*|"
    # (g) essential government services and public benefits
    r"public[-_ ]?benefit\w*|welfare|medicaid|snap[-_ ]?benefit\w*|"
    r"benefit[-_ ]?(?:eligib|determinat|renewal)\w*"
    r")\b",
    re.IGNORECASE,
)

# 6-1-1701(3)(b) exclusions. A declaration that reads as one of these is not a
# consequential decision even when the other two signals are present.
_EXCLUDED_RE = re.compile(
    r"\b(?:routine\s+scheduling|classroom\s+personaliz\w*|administrative\s+routing|"
    r"customer[-_ ]service\s+triage|workflow\s+management|content\s+moderation|"
    r"advertis\w*|marketing|product\s+recommendation\w*|search\s+ranking)\b",
    re.IGNORECASE,
)

# Files that plausibly ARE the developer documentation 6-1-1702(1) calls for.
_DOC_NAME_HINTS = (
    "model_card", "model-card", "modelcard",
    "system_card", "system-card", "systemcard",
    "admt", "ai_disclosure", "ai-disclosure", "transparency",
)

# 6-1-1702(1)(a) intended uses.
_INTENDED_USE_RE = re.compile(
    r"\b(?:intended\s+use\w*|intended\s+purpose\w*|appropriate\s+use\w*|"
    r"out[-_ ]of[-_ ]scope\s+use\w*|known\s+(?:harmful|inappropriate)\s+use\w*)\b",
    re.IGNORECASE,
)
# 6-1-1702(1)(b) categories of training data.
_TRAINING_DATA_RE = re.compile(
    r"\b(?:training\s+data|training\s+(?:set|corpus|dataset)\w*|data\s+used\s+to\s+train|"
    r"categories\s+of\s+data|trained\s+on)\b",
    re.IGNORECASE,
)
# 6-1-1702(1)(c) known limitations.
_LIMITATIONS_RE = re.compile(
    r"\b(?:known\s+limitation\w*|limitations?\b|known\s+risk\w*|should\s+not\s+be\s+used|"
    r"out[-_ ]of[-_ ]scope|failure\s+mode\w*)\b",
    re.IGNORECASE,
)
# 6-1-1702(1)(d) instructions for appropriate use, monitoring and meaningful
# human review. The statute is at its most specific here.
_HUMAN_REVIEW_RE = re.compile(
    r"\b(?:human\s+review|human[-_ ]in[-_ ]the[-_ ]loop|meaningful\s+human\s+\w+|"
    r"human\s+oversight|manual\s+review|reviewed\s+by\s+a\s+(?:human|person|clinician|underwriter))\b",
    re.IGNORECASE,
)


def _iter_files(project_root: Path, exts: set[str]) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in exts:
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


def _declares_consequential_decision(text: str) -> bool:
    """Both an inference verb and a covered domain, and no carve-out signal."""
    if _EXCLUDED_RE.search(text):
        return False
    return bool(_INFERENCE_RE.search(text) and _COVERED_DOMAIN_RE.search(text))


def _mcp_config_paths(project_root: Path) -> list[Path]:
    """Every MCP config in the tree, not only the ones at the root.

    Tool declarations are read recursively, because `_iter_files` uses rglob.
    Reading MCP configs only at the project root made the same project answer
    differently depending on which surface carried the declaration: a repository
    whose ADMT service sits in a subdirectory was invisible, while the identical
    declaration in a tool docstring was found. Caught by the 0.5.0 smoke test,
    which scanned `examples/vulnerable-configs` and saw nothing because the
    declaration was one directory down.
    """
    seen: set[Path] = set()
    out: list[Path] = []
    for name in _MCP_CONFIG_NAMES:
        path = project_root / name
        if path.is_file() and path not in seen:
            seen.add(path)
            out.append(path)
    basenames = {Path(name).name for name in _MCP_CONFIG_NAMES}
    for path in sorted(project_root.rglob("*")):
        if path in seen or not path.is_file() or path.name not in basenames:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        seen.add(path)
        out.append(path)
    return out


def _mcp_descriptions(project_root: Path) -> list[tuple[str, str]]:
    """(relative path, declaration text) for MCP server names + descriptions."""
    out: list[tuple[str, str]] = []
    for path in _mcp_config_paths(project_root):
        name = str(path.relative_to(project_root))
        try:
            data = json.loads(_read(path))
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            continue
        parts: list[str] = []
        for server_name, cfg in servers.items():
            parts.append(str(server_name))
            if isinstance(cfg, dict):
                for key in ("description", "displayName", "title", "instructions"):
                    value = cfg.get(key)
                    if isinstance(value, str):
                        parts.append(value)
                tools = cfg.get("tools")
                if isinstance(tools, list):
                    for tool in tools:
                        if isinstance(tool, dict):
                            for key in ("name", "description"):
                                value = tool.get(key)
                                if isinstance(value, str):
                                    parts.append(value)
        if parts:
            out.append((name, "\n".join(parts)))
    return out


_TOOL_DECORATOR_RE = re.compile(r"\btool\b", re.IGNORECASE)


def _decorator_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for dec in getattr(node, "decorator_list", []) or []:
        target = dec.func if isinstance(dec, ast.Call) else dec
        parts: list[str] = []
        while isinstance(target, ast.Attribute):
            parts.append(target.attr)
            target = target.value
        if isinstance(target, ast.Name):
            parts.append(target.id)
        names.append(".".join(reversed(parts)))
    return names


def _tool_declarations(path: Path) -> Iterable[str]:
    """Name + docstring of every tool-decorated function in a Python file.

    Restricted to decorated functions on purpose. An earlier draft read whole
    files, and a sweep of this repository showed what that costs: a security
    scanner's own rule catalog describes prior-authorization denials and
    insurance coverage decisions in prose, and every one of those lines read as
    a declared covered-domain surface. Describing a decision system is not
    declaring one. `@tool` (or `@mcp.tool`, `@server.tool`, ...) is where a
    developer states what a capability is for, which is the surface
    6-1-1702(3) and (5) actually test.
    """
    try:
        tree = ast.parse(_read(path))
    except (SyntaxError, ValueError, RecursionError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_TOOL_DECORATOR_RE.search(name) for name in _decorator_names(node)):
            continue
        doc = ast.get_docstring(node) or ""
        yield f"{node.name}\n{doc}"


def _find_declaration(project_root: Path) -> Optional[tuple[str, str]]:
    """First declaration of a covered-domain consequential decision, or None.

    Returns (relative path, the matching text) so the finding can quote the
    project's own words rather than assert a conclusion about it.
    """
    for rel, blob in _mcp_descriptions(project_root):
        if _declares_consequential_decision(blob):
            for line in blob.splitlines():
                if _declares_consequential_decision(line):
                    return rel, line.strip()
            return rel, blob.splitlines()[0].strip()

    for path in _iter_files(project_root, _DECL_EXTS):
        rel = str(path.relative_to(project_root))
        for blob in _tool_declarations(path):
            if not _declares_consequential_decision(blob):
                continue
            for line in blob.splitlines():
                if _declares_consequential_decision(line):
                    return rel, line.strip()[:200]
            return rel, blob.splitlines()[0].strip()[:200]
    return None


def _find_documentation(project_root: Path) -> Optional[tuple[str, str]]:
    """The developer-documentation file, by name hint or by content."""
    by_content: Optional[tuple[str, str]] = None
    for path in _iter_files(project_root, _DOC_EXTS):
        rel = str(path.relative_to(project_root))
        text = _read(path)
        if not text:
            continue
        stem = path.name.lower()
        if any(hint in stem for hint in _DOC_NAME_HINTS):
            return rel, text
        if by_content is None and _INTENDED_USE_RE.search(text):
            by_content = (rel, text)
    return by_content


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Evidence toward C.R.S. 6-1-1702, never a determination that it applies.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    declaration = _find_declaration(project_root)
    if declaration is None:
        # Nothing in the project declares a covered-domain consequential
        # decision, so there is no evidence that 6-1-1702 is even in play.
        return [], set()

    decl_path, decl_line = declaration
    scanned: set[str] = {decl_path}
    findings: list[Finding] = []

    documentation = _find_documentation(project_root)
    if documentation is None:
        findings.append(make_finding(
            "AAK-ADMT-001",
            decl_path,
            f"Declares a covered-domain decision surface ({decl_line!r}) and the "
            "repository carries no developer documentation (no model card, system "
            "card or page naming intended uses). C.R.S. 6-1-1702(1) requires that "
            "documentation from 2027-01-01 where the technology is one the statute "
            "covers.",
        ))
        return findings, scanned

    doc_path, doc_text = documentation
    scanned.add(doc_path)

    if not _TRAINING_DATA_RE.search(doc_text):
        findings.append(make_finding(
            "AAK-ADMT-002",
            doc_path,
            "Developer documentation does not name the categories of data used to "
            f"train the system. Decision surface declared in {decl_path}. "
            "C.R.S. 6-1-1702(1)(b).",
        ))
    if not _LIMITATIONS_RE.search(doc_text):
        findings.append(make_finding(
            "AAK-ADMT-003",
            doc_path,
            "Developer documentation names no known limitations, risks or "
            f"circumstances in which the system should not be used. Decision "
            f"surface declared in {decl_path}. C.R.S. 6-1-1702(1)(c).",
        ))
    if not _HUMAN_REVIEW_RE.search(doc_text):
        findings.append(make_finding(
            "AAK-ADMT-004",
            doc_path,
            "Developer documentation gives no instruction for meaningful human "
            f"review of the system's output. Decision surface declared in "
            f"{decl_path}. C.R.S. 6-1-1702(1)(d).",
        ))
    return findings, scanned
