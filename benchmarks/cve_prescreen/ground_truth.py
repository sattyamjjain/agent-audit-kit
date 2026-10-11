"""Ground truth for the backtest: what the maintainer actually decided.

Two sources, both written by the maintainer at triage time:

1. **`CHANGELOG.cves.md` table rows** in sections dated `SINCE` or later. The
   ledger has used two table shapes in that window: `| CVE | Reference | AAK
   rule / disposition | Triaged |` until 2026-09-09, and `| CVE | CVSS | Package
   | What changed | Issue |` from 2026-09-12. Both are parsed.
2. **Closed `cve-response` issues** created `SINCE` or later, read through `gh`
   REST: the last disposition statement in the comments (`## Disposition: ...`
   and the older bold forms), then the close reason. This is what covers CVEs
   the ledger records only in prose, such as the Apache Storm advisories.

Why 2026-08-11: every record from then on was published after the June 2026
knowledge cutoff of the models under test, so none of them can have been
memorised.

The ledger wins when both speak, and within the ledger the newest row wins: a
disposition is sometimes revised (heym was out of scope at 11:44Z on
2026-10-03 and pinned five hours later once an image-tag reader existed), and
the backtest asks what the right answer turned out to be.

Labels. The classes are `version-pin`, `new-detection`, `out-of-scope` and
`needs-human` (a deferral that never resolved). The fine-grained `detail` says
which kind of each (`new-pin`, `existing-pin`, `floor-change`, `new-rule`,
`new-arm`, `existing-detection`, `non-pinnable`, ...). A row whose disposition
did two things (a pin *and* pattern rules) accepts either class.

`is_noise` is not parsed. It is the hand-adjudicated `NOISE` table below: the
records the maintainer closed because the product is not AI-agent, MCP or LLM
tooling at all, each with the maintainer's reason. A product with a real MCP
surface whose bug sits elsewhere (BetterLinks) or that AAK cannot see (every
WordPress MCP plugin) is out of scope, but it is not noise.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from benchmarks.cve_prescreen import DISPOSITIONS

SINCE = "2026-08-11"
DEFAULT_REPO = "sattyamjjain/agent-audit-kit"

_SECTION_RE = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})(.*)$")
_HEADER_V1 = "| CVE | Reference | AAK rule / disposition | Triaged |"
_HEADER_V2 = "| CVE | CVSS | Package | What changed | Issue |"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
#: `CVE-2026-79743 … CVE-2026-79750`: the ledger's spelling of a run of ids.
_CVE_RUN_RE = re.compile(r"CVE-(\d{4})-(\d{4,7})\s*(?:…|\.\.\.)\s*CVE-(\d{4})-(\d{4,7})")
_ISSUE_RE = re.compile(r"#(\d{3,5})")
_ISSUE_RUN_RE = re.compile(r"#(\d{3,5})\s*[–-]\s*#(\d{3,5})")
_RULE_RE = re.compile(r"\bAAK-[A-Z0-9]+(?:-[A-Z0-9]+)*\b")
_BOLD_LEAD_RE = re.compile(r"^\*\*([^*]{1,160})\*\*")

#: Records whose product is not AI-agent, MCP or LLM tooling: the keyword
#: watcher's false positives. Hand-adjudicated from the maintainer's own close
#: reason (issue comment or ledger prose); the reason is quoted or paraphrased
#: so each entry can be checked against its source.
NOISE: dict[str, str] = {
    "CVE-2026-68456": "Linux kernel ueagle-atm USB driver; the description never says mcp (#598, "
                      "scripts/cve_watcher.py)",
    "CVE-2026-89622": "Linux kernel HID mcp2221 driver: 'The acronym collides with Model Context "
                      "Protocol' (#714)",
    "CVE-2026-82427": "Apache Storm; matched 'Claude agents' in an acknowledgement line (#735)",
    "CVE-2026-82428": "Apache Storm; matched 'Claude agents' in an acknowledgement line (#734)",
    "CVE-2026-82429": "Apache Storm; matched 'Claude agents' in an acknowledgement line (#736)",
    "CVE-2026-82439": "Apache Storm; matched 'Claude agents' in an acknowledgement line (#733)",
}

#: Rows whose automatic reading was wrong or ambiguous, settled by hand. Each
#: maps a CVE to `(class, detail, reason)`. Kept small and explicit so the
#: parser's own accuracy is visible: everything not listed here was labelled
#: by the rules below.
OVERRIDES: dict[str, tuple[str, str, str]] = {
    "CVE-2026-68456": (
        "out-of-scope", "out-of-scope",
        "#598 closed with no comment; scripts/cve_watcher.py records it as a ueagle-atm "
        "USB driver race whose description never says mcp, the case is_relevant() was written for",
    ),
    "CVE-2026-73497": (
        "version-pin", "existing-pin",
        "ledger 2026-09-16: 'No new rule ... Same 0.22.0 fix release', the mcp-atlassian "
        "pin's floor, with no pin wording the rules can read",
    ),
    "CVE-2026-81102": (
        "new-detection", "new-arm",
        "#660 deferred, then closed by #685 (253207b14), which widened AAK-DNS-REBIND-001 "
        "to Python FastMCP",
    ),
    "CVE-2026-37006": (
        "new-detection", "new-arm",
        "#662 deferred, then closed by #685 alongside #660, which widened the transport "
        "rules to WebSocket",
    ),
}


@dataclass(frozen=True)
class LedgerRow:
    cves: tuple[str, ...]
    section_date: str
    section_heading: str
    line: int
    shape: str
    package: str
    subject: str
    disposition: str
    issues: tuple[int, ...]


@dataclass
class Truth:
    cve: str
    disposition: str
    acceptable: list[str]
    detail: str
    is_noise: bool
    package: str
    issue: int | None
    section_date: str
    source: str
    evidence: str
    rules_cited: list[str] = field(default_factory=list)
    notes: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Ledger parsing
# ---------------------------------------------------------------------------


def split_cells(line: str) -> list[str]:
    """Table cells, honouring `\\|` escapes inside a cell."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", body)]


def _depth_zero(text: str) -> str:
    """The text outside every parenthesis: a v1 cell's subject, not its description."""
    out = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def subject_cves(cell: str) -> tuple[str, ...]:
    """The CVE ids a row is about, not the ones it mentions for context.

    A v1 cell reads `CVE-A (desc...)`, `CVE-A / CVE-B (desc...)`, `CVE-A (7.6),
    CVE-B (6.9) — desc` or `CVE-A … CVE-H (desc)`. The ids that matter sit
    outside the parentheses and before the first dash that opens a
    description; a run written with an ellipsis is expanded.
    """
    outer = _depth_zero(cell)
    for dash in (" — ", " – ", " - "):
        if dash in outer:
            outer = outer.split(dash, 1)[0]
    found: list[str] = []
    for run in _CVE_RUN_RE.finditer(outer):
        y1, a, y2, b = run.groups()
        lo, hi = int(a), int(b)
        if y1 == y2 and 0 < hi - lo <= 50:
            found.extend(f"CVE-{y1}-{n}" for n in range(lo, hi + 1))
    found.extend(_CVE_RE.findall(outer))
    return tuple(dict.fromkeys(found))


def _issues_in(text: str) -> tuple[int, ...]:
    nums: list[int] = []
    for run in _ISSUE_RUN_RE.finditer(text):
        lo, hi = int(run.group(1)), int(run.group(2))
        if 0 < hi - lo <= 50:
            nums.extend(range(lo, hi + 1))
    nums.extend(int(n) for n in _ISSUE_RE.findall(text))
    return tuple(dict.fromkeys(nums))


_FLOOR_PACKAGE_RE = re.compile(
    r"(?:floor|pins?)\s+(?:npm\s+|pip\s+|PyPI\s+)?`(@?[A-Za-z0-9][A-Za-z0-9._/@:-]{0,79})\s*(?:>=|<=|<|>)"
)
_VERSIONED_TICK_RE = re.compile(r"`(@?[A-Za-z0-9][A-Za-z0-9._/@:-]{0,79})`\s*(?:<=|>=|<|>|≤|\d)")
_PRODUCT_END_RE = re.compile(r"\s(?:<=|>=|<|>|≤|through|before|up to)\s|\s\d|,|\s[-—–]\s")


def package_from_disposition(text: str) -> str:
    """The registry name a v1 disposition pins: "floor `pkg >= 1.2.3`"."""
    match = _FLOOR_PACKAGE_RE.search(text)
    return match.group(1) if match else ""


def _v1_package(subject: str, disposition: str) -> str:
    """Best-effort package for a v1 row; a secondary metric only.

    The pinned registry name when the disposition states a floor, else the
    backticked name the description puts a version next to, else the product
    phrase that opens the first parenthetical.
    """
    pinned = package_from_disposition(disposition)
    if pinned:
        return pinned
    ticked = _VERSIONED_TICK_RE.search(subject)
    if ticked:
        return ticked.group(1)
    start = subject.find("(")
    if start == -1:
        return ""
    inner = subject[start + 1:start + 200]
    end = _PRODUCT_END_RE.search(inner)
    phrase = (inner[:end.start()] if end else inner).strip(" `")
    if not phrase or phrase.upper().startswith(("CVSS", "CWE")):
        return ""
    return phrase[:60]


def parse_ledger(text: str, since: str = SINCE) -> list[LedgerRow]:
    rows: list[LedgerRow] = []
    date = ""
    heading = ""
    shape = ""
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.startswith("## Older"):
            break
        section = _SECTION_RE.match(line)
        if section:
            date, heading = section.group(1), section.group(2).strip(" :—-")
            shape = ""
            continue
        stripped = line.strip()
        if stripped == _HEADER_V1:
            shape = "v1"
            continue
        if stripped == _HEADER_V2:
            shape = "v2"
            continue
        if not stripped.startswith("| CVE-") or not date or date < since or not shape:
            continue
        cells = split_cells(stripped)
        if shape == "v2" and len(cells) >= 5:
            cves = tuple(dict.fromkeys(_CVE_RE.findall(cells[0])))
            rows.append(LedgerRow(
                cves=cves, section_date=date, section_heading=heading, line=lineno,
                shape="v2", package=cells[2], subject=cells[0],
                disposition=" | ".join(cells[3:-1]), issues=_issues_in(cells[-1]),
            ))
        elif shape == "v1" and len(cells) >= 4:
            disposition = " | ".join(cells[2:-1])
            rows.append(LedgerRow(
                cves=subject_cves(cells[0]), section_date=date, section_heading=heading,
                line=lineno, shape="v1", package=_v1_package(cells[0], disposition),
                subject=cells[0], disposition=disposition, issues=_issues_in(disposition),
            ))
    return rows


# ---------------------------------------------------------------------------
# Disposition text -> class
# ---------------------------------------------------------------------------

#: Negations stripped before looking for cues: "no new pin", "non-pinnable",
#: "no new rule", "no detector change". Without this, the most common
#: existing-coverage row in the ledger ("No new rule, no new pin. ...") reads
#: as a new rule.
_NEGATION = re.compile(
    r"\b(?:no (?:new |version )?pins?|non-pinnable|not pinnable|not pinned|no pinnable"
    r"|nothing (?:to|for a) pin|a pin would|a pin on|pin row"
    r"|no new (?:detection )?rules?|no (?:rule|detector) change)\b",
    re.I,
)
_PIN_CUE = re.compile(
    r"\bnew (?:image )?pins?\b|\bpinned\b|\bsame pin\b|\bpins? on the existing\b"
    r"|\bfloors?\b|\bpresence-only\b|\brange widened\b|\bcovered by (?:the|a new) pin\b"
    r"|\brecorded against the (?:same )?pin\b|\bthe pin's\b|\bexisting pin\b|\bon the pin\b",
    re.I,
)
_DETECTION_HEADLINE = re.compile(
    r"\barm (?:added|extended)\b|\bnew (?:arm|hop)\b|\bpattern rules?\b"
    r"|\bdetection rule\b|\brule widened\b",
    re.I,
)
_OUT_HEADLINE = re.compile(r"\bout[- ]of[- ]scope\b|\bunreachable\b|\bnot an mcp defect\b", re.I)
_DEFER_HEADLINE = re.compile(r"\bdeferred\b", re.I)
#: A disposition that recorded the CVE on a pin AND on a detection rule.
_ALSO_RECORDED = re.compile(r"\brecorded (?:against|there)\b|\balso recorded\b", re.I)


def headline(text: str) -> str:
    """The lead phrase a disposition opens with: its bold lead, else its first sentence."""
    stripped = text.strip()
    bold = _BOLD_LEAD_RE.match(stripped)
    if bold:
        return bold.group(1).strip()
    first = re.split(r"(?<=[.:;])\s", stripped, maxsplit=1)[0]
    return first[:200]


def _core(head: str) -> str:
    """The headline without parentheticals or negations: what it asserts.

    "new pin (was out of scope)" asserts a pin; "detection rule (not pinned)"
    asserts a detection rule; "No new rule, no new pin." asserts nothing.
    """
    return _NEGATION.sub(" ", re.sub(r"\([^)]*\)", " ", head))


def classify_text(
    text: str, is_pin_rule: Callable[[str], bool], head: str | None = None
) -> tuple[str, str, list[str], str]:
    """`(class, detail, rules cited, evidence)` for one disposition text.

    `head` overrides the headline (an issue's `## Disposition:` line, whose
    body below it is `text`). Ordered: an out-of-scope or deferred headline
    decides outright; then detection and pin cues in the headline; then the
    rule the headline names, looked up in the pin tables; then cues anywhere
    in the text. Negations are stripped first throughout. Returns class ""
    when nothing decides, for the caller to fall back on.
    """
    explicit_head = head is not None
    head = headline(text) if head is None else head
    core = _core(head)
    # An issue heading can name the rule itself: "rule shipped (`AAK-MCP-SSRF-001`)".
    rules = list(dict.fromkeys(_RULE_RE.findall(f"{head}\n{text}" if explicit_head else text)))
    unnegated = _NEGATION.sub(" ", text)
    if _OUT_HEADLINE.search(core):
        if re.search(r"already covered as a class", core, re.I):
            return "out-of-scope", "out-of-scope-class-covered", rules, head
        return "out-of-scope", "out-of-scope", rules, head
    if _DEFER_HEADLINE.search(core):
        return "needs-human", "deferred", rules, head
    if re.search(r"\bpinned \+ pattern rules\b", core, re.I):
        return "version-pin", "pin-and-detection", rules, head
    if _DETECTION_HEADLINE.search(core):
        return "new-detection", _detection_detail(core, text), rules, head
    if _PIN_CUE.search(core):
        return "version-pin", _pin_detail(core), rules, head
    lead_rule = rules[0] if rules else ""
    if re.search(r"\b(?:new rule|rule shipped|added to|already covered|covered)\b", core, re.I) and lead_rule:
        # "already covered by AAK-FLOWISE-001 ... whose detector already floors
        # Flowise at 3.1.3": a version floor outside the pin tables is a pin.
        if is_pin_rule(lead_rule) or re.search(r"\balready floors \S+ at\b", unnegated, re.I):
            return "version-pin", _pin_detail(core), rules, head
        return "new-detection", _detection_detail(core, text), rules, head
    pinned = bool(_PIN_CUE.search(unnegated)) or any(is_pin_rule(r) for r in rules)
    detected = [r for r in rules if not is_pin_rule(r)]
    if pinned:
        if detected and _ALSO_RECORDED.search(unnegated):
            return "version-pin", "pin-and-detection", rules, head
        return "version-pin", "existing-pin", rules, head
    if rules:
        return "new-detection", _detection_detail(core, text), rules, head
    return "", "", rules, head


def _pin_detail(core: str) -> str:
    low = core.lower()
    if "floor" in low or "range widened" in low:
        return "floor-change"
    if any(k in low for k in ("new pin", "new image pin", "pinned", "new rule", "rule shipped", "two new pins")):
        return "new-pin"
    return "existing-pin"


def _detection_detail(core: str, text: str) -> str:
    low = core.lower()
    if "arm" in low or "widened" in low or "gained" in text.lower():
        return "new-arm"
    if re.search(r"\bno new rule\b", text, re.I):
        return "existing-detection"
    if any(k in low for k in ("new rule", "rule shipped", "pattern rule", "detection rule")):
        return "new-rule"
    return "existing-detection"


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------

def _bold_after(body: str, start: int) -> str:
    """The text up to the next `**` after `start`, or "" when the span never closes."""
    end = body.find("**", start)
    return body[start:end].strip() if end != -1 else ""


def comment_statement(body: str) -> str:
    """The disposition a comment states, in the forms the tracker has used.

    `## Disposition: X` (every triage since 2026-08-25), `**Disposition: X**`,
    `Triaged ...: **X**`, `Closing as **X**` and `Adjudicated IN SCOPE ...`.
    Plain string scanning, not a regex: comment bodies are remote text, and the
    natural patterns here (`\\s*:?\\s*(.+)`) backtrack polynomially on a long
    run of whitespace.
    """
    lines = body.splitlines()
    for line in lines:
        text = line.strip()
        if text.startswith("##"):
            rest = text.lstrip("#").strip()
            if rest[:11].lower() == "disposition":
                statement = rest[11:].lstrip(" \t:").strip()
                if statement:
                    return statement
    low = body.lower()
    at = low.find("**disposition:")
    if at != -1:
        statement = _bold_after(body, at + len("**disposition:"))
        if statement.startswith("(") and ")" in statement[:4]:
            statement = statement[statement.index(")") + 1:].strip()
        if statement:
            return statement
    for line in lines:
        if line.lower().startswith("triaged"):
            colon = line.find(":", 0, 60)
            after = line[colon + 1:].lstrip() if colon != -1 else ""
            if after.startswith("**"):
                statement = _bold_after(after, 2)
                if statement:
                    return statement
    at = low.find("closing as **")
    if at != -1:
        statement = _bold_after(body, at + len("closing as **"))
        if statement:
            return statement
    for phrase in ("adjudicated in scope", "adjudicated out of scope"):
        at = low.find(phrase)
        if at != -1:
            start = at + len("adjudicated ")
            stops = [i for i in (body.find(".", start), body.find("\n", start)) if i != -1]
            return body[start:min(stops) if stops else len(body)].strip()
    return ""


def issue_disposition(issue: dict[str, Any]) -> tuple[str, str]:
    """`(statement, the comment body it came from)` from the last comment that states one."""
    for comment in reversed(issue.get("comments") or []):
        body = str(comment.get("body") or "")
        statement = comment_statement(body)
        if statement:
            return statement, body
    comments = issue.get("comments") or []
    if comments:
        body = str(comments[-1].get("body") or "")
        return body.strip().split("\n", 1)[0][:200], body
    return "", ""


def gh_api_list(api_path: str, timeout: float = 120.0) -> list[Any]:
    """`gh api --paginate` (REST) for an endpoint that returns a JSON array."""
    proc = subprocess.run(
        ["gh", "api", "--paginate", api_path],
        capture_output=True, text=True, timeout=timeout, check=True,
    )
    raw = proc.stdout.strip()
    decoder = json.JSONDecoder()
    items: list[Any] = []
    i = 0
    while i < len(raw):
        obj, end = decoder.raw_decode(raw, i)
        if isinstance(obj, list):
            items.extend(obj)
        i = end
        while i < len(raw) and raw[i].isspace():
            i += 1
    return items


def fetch_issue_snapshot(
    repo: str = DEFAULT_REPO,
    since: str = SINCE,
    list_api: Callable[[str], list[Any]] = gh_api_list,
) -> list[dict[str, Any]]:
    """Every `cve-response` issue created on or after `since`, with its comments."""
    issues = list_api(f"/repos/{repo}/issues?state=all&labels=cve-response&per_page=100")
    out = []
    for issue in issues:
        if "pull_request" in issue or str(issue.get("created_at", "")) < since:
            continue
        comments = list_api(f"/repos/{repo}/issues/{issue['number']}/comments?per_page=100")
        out.append({
            "number": issue["number"],
            "title": issue.get("title") or "",
            "state": issue.get("state"),
            "state_reason": issue.get("state_reason"),
            "labels": sorted(lbl["name"] for lbl in issue.get("labels") or []),
            "created_at": issue.get("created_at"),
            "closed_at": issue.get("closed_at"),
            "comments": [
                {"created_at": c.get("created_at"), "body": c.get("body") or ""}
                for c in comments
            ],
        })
    return sorted(out, key=lambda i: int(i["number"]))


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def default_is_pin_rule() -> Callable[[str], bool]:
    """Pin rules, from the pin scanners' own tables plus the pin-shaped ids.

    Read from the live registry, not a copied list, so a renamed pin cannot
    leave the ground truth calling it a detection rule.
    """
    from agent_audit_kit.scanners import container_image_pins, mcp_cve_pins_2026_07

    table = {p.rule_id for p in mcp_cve_pins_2026_07._PINS}
    table |= {p.rule_id for p in container_image_pins._PINS}
    # The JVM SDK pin and the `-PIN-001` family live outside those two tables.
    table.add("AAK-MCP-STDIO-UNBOUNDED-BUFFER-001")

    def is_pin(rule_id: str) -> bool:
        return rule_id in table or rule_id.endswith("-PIN-001")

    return is_pin


def _issue_cve(issue: dict[str, Any]) -> str:
    found = _CVE_RE.findall(str(issue.get("title") or ""))
    return found[0] if found else ""


def build(
    ledger_text: str,
    issues: list[dict[str, Any]],
    since: str = SINCE,
    is_pin_rule: Callable[[str], bool] | None = None,
) -> tuple[list[Truth], dict[str, Any]]:
    """Ground truth for every closed issue and ledger row in the window.

    Returns `(records, report)`. The report lists what was excluded and why, and
    every record the parser could not label, so nothing drops silently.
    """
    pin = is_pin_rule or default_is_pin_rule()
    rows = parse_ledger(ledger_text, since)
    by_cve: dict[str, list[LedgerRow]] = {}
    for row in rows:
        for cve in row.cves:
            by_cve.setdefault(cve, []).append(row)

    issue_by_cve: dict[str, dict[str, Any]] = {}
    open_cves: set[str] = set()
    for item in issues:
        cve = _issue_cve(item)
        if not cve or str(item.get("created_at") or "")[:10] < since:
            continue
        if item.get("state") != "closed":
            open_cves.add(cve)
            continue
        issue_by_cve[cve] = item

    report: dict[str, Any] = {
        "since": since,
        "ledger_rows": len(rows),
        "issues_in_window": len(issues),
        "open_issues_excluded": sorted(open_cves),
        "unlabelled": [],
        "ledger_issue_disagreements": [],
    }
    out: list[Truth] = []
    for cve in sorted(set(by_cve) | set(issue_by_cve)):
        if cve in open_cves and cve not in by_cve:
            continue
        issue = issue_by_cve.get(cve)
        record = _truth_for(cve, by_cve.get(cve, []), issue, pin)
        if record is None:
            report["unlabelled"].append(cve)
            continue
        if issue is not None and record.source == "ledger":
            statement, body = issue_disposition(issue)
            issue_class = classify_text(body, pin, head=statement)[0] if statement else ""
            if not issue_class and issue.get("state_reason") == "not_planned":
                issue_class = "out-of-scope"
            if issue_class and issue_class not in record.acceptable:
                report["ledger_issue_disagreements"].append(
                    {"cve": cve, "ledger": record.disposition, "issue": issue_class, "statement": statement[:160]}
                )
        out.append(record)
    return out, report


def _acceptable(klass: str, detail: str) -> list[str]:
    """The classes a prediction may name and still match what was decided."""
    if detail == "pin-and-detection":
        return [klass, "new-detection" if klass == "version-pin" else "version-pin"]
    if detail == "out-of-scope-class-covered":
        return ["out-of-scope", "new-detection"]
    return [klass]


def _truth_for(
    cve: str,
    rows: list[LedgerRow],
    issue: dict[str, Any] | None,
    pin: Callable[[str], bool],
) -> Truth | None:
    issue_no = int(issue["number"]) if issue else None
    if cve in OVERRIDES:
        klass, detail, reason = OVERRIDES[cve]
        row = sorted(rows, key=lambda r: (r.section_date, -r.line), reverse=True)[0] if rows else None
        return Truth(
            cve=cve, disposition=klass, acceptable=_acceptable(klass, detail), detail=detail,
            is_noise=cve in NOISE, package=row.package if row else "",
            issue=issue_no or (row.issues[0] if row and row.issues else None),
            section_date=row.section_date if row else str((issue or {}).get("closed_at", ""))[:10],
            source="override", evidence=reason, notes=NOISE.get(cve, ""),
        )
    if rows:
        # Newest section first; within a date the ledger runs newest-first too.
        row = sorted(rows, key=lambda r: (r.section_date, -r.line), reverse=True)[0]
        klass, detail, rules, evidence = classify_text(row.disposition, pin)
        if klass:
            return Truth(
                cve=cve, disposition=klass, acceptable=_acceptable(klass, detail), detail=detail,
                is_noise=cve in NOISE, package=row.package,
                issue=issue_no or (row.issues[0] if row.issues else None),
                section_date=row.section_date, source="ledger", evidence=evidence,
                rules_cited=rules, notes=NOISE.get(cve, ""),
            )
    if issue is None:
        return None
    statement, body = issue_disposition(issue)
    klass, detail, rules, evidence = (
        classify_text(body, pin, head=statement) if statement else ("", "", [], "")
    )
    if not klass and issue.get("state_reason") == "not_planned":
        klass, detail, evidence = "out-of-scope", "closed-not-planned", statement or "closed as not planned"
    if not klass:
        return None
    return Truth(
        cve=cve, disposition=klass, acceptable=_acceptable(klass, detail), detail=detail,
        is_noise=cve in NOISE, package="", issue=issue_no,
        section_date=str(issue.get("closed_at") or "")[:10], source="issue",
        evidence=evidence, rules_cited=rules, notes=NOISE.get(cve, ""),
    )


def summary(records: list[Truth]) -> dict[str, Any]:
    counts = {d: 0 for d in DISPOSITIONS}
    for rec in records:
        counts[rec.disposition] = counts.get(rec.disposition, 0) + 1
    return {
        "records": len(records),
        "by_class": counts,
        "noise": sum(1 for r in records if r.is_noise),
        "multi_label": sum(1 for r in records if len(r.acceptable) > 1),
        "by_source": {
            s: sum(1 for r in records if r.source == s) for s in ("ledger", "issue", "override")
        },
    }


def write(path: Path, records: list[Truth], report: dict[str, Any]) -> None:
    payload = {
        "schema": "aak-cve-prescreen-ground-truth/1",
        "since": report["since"],
        "summary": summary(records),
        "report": report,
        "records": [r.to_json() for r in records],
    }
    path.write_text(json.dumps(payload, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def load(path: Path) -> list[Truth]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [Truth(**rec) for rec in payload["records"]]
