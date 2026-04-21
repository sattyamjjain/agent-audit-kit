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
    "Flowise < 3.1.0 MCP adapter authenticated RCE",
    "Package manifest depends on `flowise` or `flowise-components` at "
    "version < 3.1.0, and/or a Flowise flow config (`.flowise/*.json`, "
    "`flows/*.json`) declares an MCP adapter node with `customFunction` "
    "or `runCode` sinks. CVE-2026-40933 (GHSA-c9gw-hvqq-f33r, CVSS 10.0) "
    "lets an authenticated attacker combine allowlisted commands like "
    "`npx` with execution flags such as `-c` to achieve arbitrary OS "
    "command execution. Same architectural class as Ox's original STDIO "
    "disclosure (see AAK-STDIO-001).",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade flowise and flowise-components to 3.1.0 or later. Audit "
    "every MCP adapter node in your flow configs; remove "
    "`customFunction`/`runCode` sinks unless they're validated against "
    "a strict argv allowlist. See also AAK-STDIO-001 for the "
    "architectural-class detector.",
    sarif_name="FlowiseMcpAdapterRce",
    cve_references=["CVE-2026-40933"],
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
    "tool call reach into arbitrary reads/writes. Fixed in 0.6.1.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `apache-doris-mcp-server` to 0.6.1 or newer. Audit every "
    "tool the adapter exposes to confirm arguments flow through a "
    "parameterized query builder, never string concatenation.",
    sarif_name="DorisMcpSqlInjection",
    cve_references=["CVE-2025-66335"],
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
