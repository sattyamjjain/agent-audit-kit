from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from agent_audit_kit.redaction import redact_evidence, redact_related_locations


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def numeric(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric() >= other.numeric()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric() > other.numeric()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric() <= other.numeric()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.numeric() < other.numeric()


class Category(Enum):
    MCP_CONFIG = "mcp-config"
    HOOK_INJECTION = "hook-injection"
    TRUST_BOUNDARY = "trust-boundary"
    SECRET_EXPOSURE = "secret-exposure"
    SUPPLY_CHAIN = "supply-chain"
    AGENT_CONFIG = "agent-config"
    TOOL_POISONING = "tool-poisoning"
    TAINT_ANALYSIS = "taint-analysis"
    TRANSPORT_SECURITY = "transport-security"
    A2A_PROTOCOL = "a2a-protocol"
    LEGAL_COMPLIANCE = "legal-compliance"
    MCP_SERVER_CARD = "mcp-server-card"
    COMPOSITION = "composition"
    AGENTIC_SKILL = "agentic-skill"


# Schema versioning — bump when new reference fields land on Finding /
# RuleDefinition. Consumers (SARIF, rules.json, PR-summary) read this so
# they can gracefully ignore unknown fields from newer scanners.
#
# 2: added `incident_references` + `aicm_references` (v0.3.2). The CSA
# MCP Security Baseline v0.1 RC is expected to drop this week — when
# it does, we'll tag rules with `csa_mcp_baseline_references` as a v3
# addition. Track at:
#   https://cloudsecurityalliance.org/blog/2025/08/20/securing-the-agentic-ai-control-plane-announcing-the-mcp-security-resource-center
#   https://cloudsecurityalliance.org/artifacts/ai-controls-matrix
SCHEMA_VERSION = 3


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str
    line_number: int | None = None
    evidence: str = ""
    remediation: str = ""
    cve_references: list[str] = field(default_factory=list)
    owasp_mcp_references: list[str] = field(default_factory=list)
    owasp_agentic_references: list[str] = field(default_factory=list)
    adversa_references: list[str] = field(default_factory=list)
    # v0.3.2 additions (SCHEMA_VERSION 2):
    # Reference incidents that drove the rule. Use stable IDs of the
    # form `<VENDOR>-<DATE>` (e.g. `VERCEL-2026-04-19`, `OX-MCP-2026-04-15`).
    # Distinct from CVEs — covers disclosed incidents that never got a CVE.
    incident_references: list[str] = field(default_factory=list)
    # Control IDs from the CSA AI Controls Matrix (AICM) — used by the
    # `agent-audit-kit report --compliance aicm` output to group findings
    # by control. Empty for rules with no AICM mapping yet.
    aicm_references: list[str] = field(default_factory=list)
    # v0.3.85 (SCHEMA_VERSION 3): OWASP Agentic Skills Top 10 (AST01-AST10) ids.
    # Its own list rather than a reuse of owasp_agentic_references, because AST10
    # is a different taxonomy over a different layer -- MCP is how the model talks
    # to tools, AST10 is what those tools do -- and folding them together would
    # make both coverage numbers wrong.
    owasp_ast_references: list[str] = field(default_factory=list)
    # v0.3.73 additions (SCHEMA_VERSION 3): other artifacts that, together with
    # file_path, constitute the finding — e.g. the individual skills whose
    # capability union AAK-AGENT-COMPOSE-001 flags. Each entry is
    # {"file_path": str, "line_number": int | None, "message": str}. Emitted as
    # SARIF `relatedLocations` so a code-scanning UI can navigate to each
    # contributing artifact.
    related_locations: list[dict] = field(default_factory=list)

    def __setattr__(self, name: str, value: object) -> None:
        """Redact credentials from evidence whenever it is set.

        Every formatter repeats ``evidence`` and each related location's
        ``message``: console, JSON, SARIF (so GitHub code-scanning alerts),
        PR summaries, notification webhooks and private advisories. Scanners
        quote what they matched, and what they matched can hold a token, so
        the value is redacted here, the one place every finding passes
        through, including findings built outside ``make_finding`` and
        evidence edited after the fact (``scan --verify-secrets`` appends to
        it). See :mod:`agent_audit_kit.redaction` for what is masked.
        """
        if name == "evidence" and isinstance(value, str):
            value = redact_evidence(value)
        elif name == "related_locations" and isinstance(value, list):
            value = redact_related_locations(value)
        object.__setattr__(self, name, value)


# The engine files this rule when a scanner raises. It is referenced by the
# engine, the models, every formatter and the CLI exit path, so it lives here
# rather than being spelled out as a literal in five places.
SCANNER_FAIL_RULE_ID = "AAK-INTERNAL-SCANNER-FAIL"

# `scan --llm-scan` files this for every tool it was asked to analyze and did
# not: no credential, a failed request, a refusal, a reply cut off before the
# verdict. It answers the same question as a crashed scanner (did the run cover
# what it was asked to cover?), so it is exempt from the same floors and makes
# the run INCOMPLETE the same way.
LLM_INCOMPLETE_RULE_ID = "AAK-LLM-002"
INCOMPLETE_RULE_IDS: frozenset[str] = frozenset({SCANNER_FAIL_RULE_ID, LLM_INCOMPLETE_RULE_ID})


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_evaluated: int = 0
    scan_duration_ms: float = 0.0
    score: int | None = None
    grade: str | None = None
    # Which offline data feed each feed-reading rule used, and when it was built
    # (`engine._data_feeds`): {"maliciousReleases": {"generatedAt", "source", "origin"}}.
    data_feeds: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.numeric()).severity

    def exceeds_threshold(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)

    def findings_at_or_above(self, min_severity: Severity) -> list[Finding]:
        """Findings at or above ``min_severity``, plus any scanner failure.

        ``AAK-INTERNAL-SCANNER-FAIL`` is exempt from the floor. It is filed at
        INFO, which sits below the default floor of LOW, so a run in which four
        scanners died rendered an empty findings array, a 100/100 A and a SARIF
        file with zero results -- indistinguishable from a clean project
        (issue #743). The engine already exempts it from the active-rules
        filter; this is the same exemption for the reporting floor, and it is
        done here rather than by re-grading the rule so the severity keeps
        meaning "how bad is the finding" rather than "how loudly is it shown".
        AAK-LLM-002, a tool ``--llm-scan`` was asked to analyze and did not, is
        exempt for the same reason.
        """
        return [
            f for f in self.findings
            if f.severity >= min_severity or f.rule_id in INCOMPLETE_RULE_IDS
        ]

    @property
    def scanner_failures(self) -> list[Finding]:
        """Findings recording a scanner that did not finish every file: one that
        raised, or one file it refused (each refused file is a finding of its own)."""
        return [f for f in self.findings if f.rule_id == SCANNER_FAIL_RULE_ID]

    @property
    def failed_scanners(self) -> list[str]:
        """Each scanner behind `scanner_failures` once, in the order they failed.

        A scanner that refuses three files has three failures, so a count of
        failures is not a count of scanners. The name is read back from the
        evidence, which the engine starts `scanner='<name>' error=`.
        """
        names: dict[str, None] = {}
        for f in self.scanner_failures:
            evidence = f.evidence or ""
            if evidence.startswith("scanner=") and " error=" in evidence:
                names.setdefault(evidence[len("scanner="):evidence.index(" error=")].strip("'\""), None)
            else:
                names.setdefault("unknown", None)
        return list(names)

    @property
    def llm_gaps(self) -> list[Finding]:
        """Findings recording a tool that ``--llm-scan`` was asked to analyze and did not."""
        return [f for f in self.findings if f.rule_id == LLM_INCOMPLETE_RULE_ID]

    @property
    def incomplete(self) -> bool:
        """True when something this run was asked to evaluate was not evaluated."""
        return any(f.rule_id in INCOMPLETE_RULE_IDS for f in self.findings)
