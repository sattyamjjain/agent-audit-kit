from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str
    line_number: Optional[int] = None
    evidence: str = ""
    remediation: str = ""
    cve_references: list[str] = field(default_factory=list)
    owasp_mcp_references: list[str] = field(default_factory=list)
    owasp_agentic_references: list[str] = field(default_factory=list)
    adversa_references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    rules_evaluated: int = 0
    scan_duration_seconds: float = 0.0
    score: Optional[int] = None
    grade: Optional[str] = None

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

    def findings_at_or_above(self, min_severity: Severity) -> list[Finding]:
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        threshold_idx = severity_order.index(min_severity)
        allowed = set(severity_order[: threshold_idx + 1])
        return [f for f in self.findings if f.severity in allowed]
