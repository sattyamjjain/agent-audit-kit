from __future__ import annotations

from agent_audit_kit.models import ScanResult
from agent_audit_kit.rules.builtin import RULES

# OWASP Agentic Top 10 (ASI01-ASI10)
OWASP_AGENTIC = {
    "ASI01": "Agent Goal Hijacking",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# OWASP MCP Top 10
OWASP_MCP = {
    "MCP01:2025": "Token & Credential Mismanagement",
    "MCP02:2025": "Context Over-Sharing / Tool Sprawl",
    "MCP03:2025": "Supply Chain Attacks",
    "MCP04:2025": "Command Injection",
    "MCP05:2025": "Tool Poisoning / Trust Boundary",
    "MCP06:2025": "Privilege Escalation",
    "MCP07:2025": "Insufficient Authentication",
    "MCP08:2025": "Audit Logging Gaps",
    "MCP09:2025": "SSRF / Network Boundary",
    "MCP10:2025": "Dependency & Package Risks",
}

# Adversa AI MCP Security Top 25 (representative subset mapped to our rules)
ADVERSA_TOP_25 = {
    "ADV-AUTH-01": "Missing Authentication",
    "ADV-INJECT-01": "Shell Injection via MCP",
    "ADV-INJECT-02": "Path Manipulation",
    "ADV-INJECT-03": "Header Injection",
    "ADV-INJECT-04": "Tool Param Shell Injection",
    "ADV-INJECT-05": "Tool Param Code Injection",
    "ADV-INJECT-06": "Tool Param Path Traversal",
    "ADV-INJECT-07": "Tool Param SQL Injection",
    "ADV-INJECT-08": "Unsafe Deserialization",
    "ADV-TOKEN-01": "Hardcoded MCP Secrets",
    "ADV-TOKEN-02": "Hook Credential Theft",
    "ADV-TOKEN-03": "Anthropic Key Exposure",
    "ADV-TOKEN-04": "OpenAI Key Exposure",
    "ADV-TOKEN-05": "AWS Credential Exposure",
    "ADV-TOKEN-06": "Generic Secret Exposure",
    "ADV-TOKEN-07": "Private Key Exposure",
    "ADV-TOKEN-08": "Env File Leak",
    "ADV-TOKEN-09": "MCP Env Secret",
    "ADV-TOKEN-10": "Git Token Exposure",
    "ADV-TOKEN-11": "GCP Key Exposure",
    "ADV-TOKEN-12": "Token in URL",
    "ADV-SUPPLY-01": "Runtime Package Fetch",
    "ADV-SUPPLY-02": "Unpinned Package",
    "ADV-SUPPLY-03": "Unpinned MCP Package",
    "ADV-SUPPLY-04": "Known Vulnerable Dep",
    "ADV-SUPPLY-05": "Dangerous Install Script",
    "ADV-SUPPLY-06": "Missing Lockfile",
    "ADV-SUPPLY-07": "Excessive Dependencies",
    "ADV-SUPPLY-08": "MCP-Specific Vuln",
    "ADV-SCOPE-01": "Excessive Server Count",
    "ADV-SCOPE-02": "Filesystem Root Access",
    "ADV-SCOPE-03": "Excessive Hooks",
    "ADV-SCOPE-04": "Wildcard Permissions",
    "ADV-SCOPE-05": "Excessive Dangerous Sinks",
    "ADV-SSRF-01": "Internal Network MCP",
    "ADV-SSRF-02": "Tool Param SSRF",
    "ADV-EXFIL-01": "Network Hook Exfiltration",
    "ADV-EXFIL-02": "Source File Exfiltration",
    "ADV-ESCAPE-01": "Hook Boundary Escape",
    "ADV-HOOK-01": "Sensitive Lifecycle Hook",
    "ADV-OBFUSC-01": "Base64 Obfuscation",
    "ADV-OBFUSC-02": "Obfuscated Hook Payload",
    "ADV-PRIV-01": "Hook Privilege Escalation",
    "ADV-TRUST-01": "Auto-Enable All Servers",
    "ADV-TRUST-02": "Missing Deny Rules",
    "ADV-TRUST-03": "User Deny Override",
    "ADV-TRUST-04": "No Server Allowlist",
    "ADV-REDIRECT-01": "Anthropic URL Redirect",
    "ADV-REDIRECT-02": "API URL Redirect",
    "ADV-HIJACK-01": "Agent Shell Directives",
    "ADV-HIJACK-02": "Agent External URLs",
    "ADV-HIJACK-03": "Agent Security Override",
    "ADV-HIJACK-04": "Agent Credential Ref",
    "ADV-HIJACK-05": "Agent Hidden Content",
    "ADV-POISON-01": "Invisible Unicode",
    "ADV-POISON-02": "Prompt Injection",
    "ADV-POISON-03": "Cross-Tool Reference",
    "ADV-POISON-04": "Encoded Description",
    "ADV-POISON-05": "Excessive Description",
    "ADV-POISON-06": "URL in Description",
    "ADV-VALID-01": "Missing Input Validation",
    "ADV-TRANSPORT-01": "HTTP Not HTTPS",
    "ADV-TRANSPORT-02": "TLS Disabled",
    "ADV-TRANSPORT-03": "Deprecated SSE",
    "ADV-RUGPULL-01": "Tool Definition Changed",
    "ADV-RUGPULL-02": "New Tool Added",
    "ADV-RUGPULL-03": "Tool Removed",
    "ADV-A2A-01": "A2A Internal Capabilities",
    "ADV-A2A-02": "A2A No Auth",
    "ADV-A2A-03": "A2A No Input Schema",
    "ADV-A2A-04": "A2A HTTP Endpoint",
}


def _build_coverage_map(framework: dict[str, str], ref_field: str) -> dict[str, list[str]]:
    coverage: dict[str, list[str]] = {code: [] for code in framework}
    for rule_id, rule in RULES.items():
        refs = getattr(rule, ref_field, [])
        for ref in refs:
            if ref in coverage:
                coverage[ref].append(rule_id)
    return coverage


def format_results(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("\n\u2501\u2501\u2501 OWASP Coverage Report \u2501\u2501\u2501\n")

    # OWASP Agentic Top 10
    lines.append("OWASP Agentic Top 10 (ASI01-ASI10):")
    lines.append("-" * 60)
    agentic_map = _build_coverage_map(OWASP_AGENTIC, "owasp_agentic_references")
    agentic_covered = sum(1 for rules in agentic_map.values() if rules)
    for code, desc in OWASP_AGENTIC.items():
        rules = agentic_map.get(code, [])
        status = f"\u2705 {len(rules)} rule(s)" if rules else "\u274c Not covered"
        lines.append(f"  {code} {desc}: {status}")
        if rules:
            lines.append(f"         Rules: {', '.join(rules[:5])}")
    lines.append(f"\n  Coverage: {agentic_covered}/{len(OWASP_AGENTIC)} ({100*agentic_covered//len(OWASP_AGENTIC)}%)\n")

    # OWASP MCP Top 10
    lines.append("OWASP MCP Top 10:")
    lines.append("-" * 60)
    mcp_map = _build_coverage_map(OWASP_MCP, "owasp_mcp_references")
    mcp_covered = sum(1 for rules in mcp_map.values() if rules)
    for code, desc in OWASP_MCP.items():
        rules = mcp_map.get(code, [])
        status = f"\u2705 {len(rules)} rule(s)" if rules else "\u274c Not covered"
        lines.append(f"  {code} {desc}: {status}")
        if rules:
            lines.append(f"         Rules: {', '.join(rules[:5])}")
    lines.append(f"\n  Coverage: {mcp_covered}/{len(OWASP_MCP)} ({100*mcp_covered//len(OWASP_MCP)}%)\n")

    # Adversa Top 25 summary
    lines.append("Adversa AI MCP Security Top 25:")
    lines.append("-" * 60)
    adversa_map = _build_coverage_map(ADVERSA_TOP_25, "adversa_references")
    adversa_covered = sum(1 for rules in adversa_map.values() if rules)
    lines.append(f"  Coverage: {adversa_covered}/{len(ADVERSA_TOP_25)} categories mapped")

    # Score info
    if result.score is not None:
        lines.append(f"\nSecurity Score: {result.score}/100  Grade: {result.grade}")

    lines.append(f"\nTotal rules evaluated: {result.rules_evaluated}")
    lines.append(f"Total findings: {len(result.findings)}\n")

    return "\n".join(lines)
