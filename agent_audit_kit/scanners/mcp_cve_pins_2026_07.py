"""MCP/agent CVE version-pins — 2026-07 disclosure wave (table-driven).

Twenty-six dependency version-pin rules for MCP/agent CVEs disclosed 2026-07-08..22
that have both a vendor-fixed version and a pinnable PyPI / npm artifact. Each
pin fires when a project references the affected package below its fix floor (or
unpinned) across dependency manifests, lockfiles, and MCP config files — the same
shape as the Kong / gateway-registry / Serena pins in `supply_chain`.

Packages + fix floors were verified against PyPI / npm (and NVD CPE ranges where
available) before shipping:

  - litellm                        >= 1.84.0  (CVE-2026-59822, CVE-2026-59820)
  - cline                          >= 3.0.30  (CVE-2026-59723)
  - mcp-text-editor                >  1.0.2   (CVE-2026-15138; NVD "up to 1.0.2")
  - n8n                            >= 2.27.4  (CVE-2026-59207; also 2.28.1 line)
  - ruflo                          >= 3.16.3  (CVE-2026-59726)
  - @arikusi/deepseek-mcp-server   >= 1.8.0   (CVE-2026-55604, CVE-2026-55605)
  - mcp-server-kubernetes          >= 3.9.0   (CVE-2026-61459)
  - astrbot                        >  4.25.2  (CVE-2026-15501; NVD "up to 4.25.2")
  - awslabs.healthlake-mcp-server  >= 0.0.14  (CVE-2026-15643)
  - praisonai                      >= 4.6.78  (CVE-2026-61427)
  - appium-mcp                     >= 1.85.10 (CVE-2026-58500)
  - @penpot/mcp                    >= 2.15.0  (CVE-2026-45805)
  - openclaw                       >= 2026.6.6 (CVE-2026-62195; NVD 2026.5.20..<2026.6.6)
  - repomix                        >= 1.14.1  (CVE-2026-49988)
  - better-auth / @better-auth/oauth-provider >= 1.6.13 (CVE-2026-53512, CVE-2026-53518, CVE-2026-67333, CVE-2026-67336)
  - mcp (MCP Python SDK)            >= 1.28.1  (CVE-2026-52869, CVE-2026-52870, CVE-2026-59950)
  - 9router                        >= 0.5.2   (CVE-2026-46339, CVE-2026-49353, CVE-2026-62312, CVE-2026-63732)
  - awslabs.aws-api-mcp-server     >= 1.3.47  (CVE-2026-16584; affected 0.2.13–1.3.46)
  - n8n-mcp                        >= 2.57.4  (CVE-2026-54052, CVE-2026-55608)
  - dbt-mcp                        >= 1.17.1  (CVE-2026-44968, CVE-2026-44970, CVE-2026-44969)
  - @apify/actors-mcp-server       >= 0.9.21  (CVE-2026-46341)
  - agentic-flow                   >= 2.0.14  (CVE-2026-58195)
  - awslabs.aws-healthomics-mcp-server >= 0.0.36 (CVE-2026-15415)
  - awslabs.amazon-mq-mcp-server    >= 2.0.24  (CVE-2026-18655)
  - @langchain/langgraph-checkpoint-mongodb >= 1.3.1 (CVE-2026-48121)
  - awslabs.documentdb-mcp-server   >= 1.0.12  (CVE-2026-18954)
  - frontmcp                        >= 1.5.7   (CVE-2026-67531)
  - langgraph-checkpoint-postgres/sqlite >= 3.1.1 (CVE-2026-71433)
  - meta-ads-mcp                    >= 1.0.109 (CVE-2026-48039)
  - whatsapp-mcp                   >= 0.2.1   (CVE-2026-46555)
  - @agenticmail/{claudecode,codex,core,openclaw} (CVE-2026-57495; fix floors
    0.2.39 / 0.1.33 / 0.9.43 / 0.5.71 respectively — one rule, four pins)
  - stata-mcp                      >= 1.19.0  (CVE-2026-47708, CVE-2026-55071 —
    the PyPI name is `stata-mcp`; the GHSA title "MCP-for-Stata" is the project
    name, and `mcp-for-stata` does not exist on PyPI)
  - @adenot/mcp-google-search      <= 0.3.1   (CVE-2026-19337; SSRF, no fixed release yet)
  - mcp-florence2                  <= 0.3.13  (CVE-2026-19984; get_images SSRF — upstream
    ships no code fix and points at an SSRF-safe egress proxy, so there is no fix
    floor to wait for and presence-only is the permanent state, not a placeholder)
  - mcp-grafana                    >= 1.1.0   (CVE-2026-19516; SSRF via X-Grafana-URL destination)
  - n8n (MCP Client node)          >= 2.32.1  (CVE-2026-72768; SSRF-protection bypass)
  - claude-code-templates          >= 1.29.4  (CVE-2026-73222; --studio unauth 0.0.0.0 RCE)
  - mcp-atlassian                  >= 0.22.0  (CVE-2026-73498; confluence_upload_attachment
    arbitrary file read via unvalidated file_path)
  - @jshookmcp/jshook              >= 0.3.2   (CVE-2026-49856; ICMP/traceroute skip the
    SSRF authorization policy)
  - auth-fetch-mcp                 >= 3.0.2   (CVE-2026-49857; IPv4-mapped IPv6 loopback
    bypasses the private-address guard — floor is 3.0.2 per GHSA, not the 3.0.1 in NVD prose)
  - mcp-memory-service             >= 10.67.1 (CVE-2026-50027; /api/documents/* unauthenticated)
  - neuro-cortex-memory            >= 3.18.0  (CVE-2026-49986; CLAUDE_PROJECT_DIR exec — floor
    is 3.18.0 per GHSA, not the 3.17.1 in NVD prose, which was never published)
  - @aborruso/ckan-mcp-server      >= 0.4.112 (CVE-2026-73846/73845/73844; cache-key collision,
    prefix-only host check, verbose errors — one fix version, three CVEs)
  - @apify/actors-mcp-server       >= 0.10.11 (CVE-2026-50143 moved this floor up from
    the 0.9.21 of CVE-2026-46341 — same package and rule, higher floor)
  - codewhale                      >= 0.8.64  (CVE-2026-75858, CVE-2026-75857; rlm_eval and
    exec_shell_interact return ApprovalRequirement::Auto and skip the approval policy.
    `deepseek-tui` is the pre-rename name, deprecated, pinned at its own 0.8.41 boundary.
    The crates.io twin `codewhale-tui` has the same defect but Cargo manifests are not in
    _CANDIDATE_NAMES, so it is out of this detector's reach)

CVEs without a pinnable PyPI/npm artifact (aerostack-mcp SSRF, MaxKB stdio
command-injection, mastergo-magic-mcp path-traversal/SSRF with no vendor fix,
Grafana MCP on Go, Apache SkyWalking MCP on Go, ArcadeDB on Maven, Context7 whose
defect is in the hosted service rather than any published client version,
mcp-gitlab with no NVD version data yet) or a tractable version
scheme (langchain4j's four parallel beta fix-lines) are handled outside this
module — see CHANGELOG.cves.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS
from agent_audit_kit.scanners.supply_chain import (
    _LOCKFILES,
    _resolve_lockfile_version,
    _semver3,
)

_Ver = tuple[int, int, int]


def _mk_re(name: str) -> re.Pattern[str]:
    """Match ``name`` optionally followed by a version, across requirements /
    pyproject / npm (``"name": "^1.2.3"``) / MCP-config forms."""
    return re.compile(
        re.escape(name)
        + r'\s*(?:==|>=|~=|<=|<|>|@|:|"\s*:\s*"[\^~><=v ]*|"?\s*version"?\s*[:=])?'
        r"\s*v?([0-9][\w.\-]*)?",
        re.IGNORECASE,
    )


# Precise token regexes for names that are substrings of *other* packages —
# `_mk_re` has no left boundary, so a bare "mcp" would match "fastmcp",
# "mcp-text-editor", "n8n-mcp", etc. These require a real dependency token.
_VER_REQ = (
    r'(?:==|>=|~=|!=|<=|<|>|@|"\s*:\s*"[\^~><=v ]*|"?\s*version"?\s*[:=])'
    r'\s*v?([0-9][\w.\-]*)'
)
_VER_OPT = (
    r'(?:\s*(?:==|>=|~=|!=|<=|<|>|@|"\s*:\s*"[\^~><=v ]*|"?\s*version"?\s*[:=])'
    r'\s*v?([0-9][\w.\-]*))?'
)
# Bare `mcp` (the MCP Python SDK on PyPI). Requires a version so an ambiguous
# lone "mcp" token can't fire; the negative lookbehind/`[` handling keeps it off
# fastmcp / mcp-text-editor / n8n-mcp / awslabs.*-mcp-server.
_MCP_SDK_RE = re.compile(r"(?<![\w./-])mcp(?:\[[\w,\s-]+\])?\s*" + _VER_REQ, re.IGNORECASE)
_N8N_MCP_RE = re.compile(r"(?<![\w./-])n8n-mcp(?![\w])" + _VER_OPT, re.IGNORECASE)
# `letta` (the agent server, formerly MemGPT). The right boundary excludes the
# hyphen so this stays off `letta-client`, a separate client SDK on its own
# version line; the lookbehind keeps it off `pyletta`.
_LETTA_RE = re.compile(r"(?<![\w./-])letta(?![\w-])" + _VER_OPT, re.IGNORECASE)
# `codewhale` (npm) and its pre-rename name `deepseek-tui`. Both exclude a trailing
# hyphen so `codewhale` stays off the crates.io twin `codewhale-tui`, which carries the
# same defect but lives in an ecosystem this detector does not read (no Cargo.toml in
# _CANDIDATE_NAMES) — firing on it from a JS manifest would be a claim we cannot make.
# The lookbehind is what the 0.3.82 `cline` fix taught: an unbounded name matches prose.
_CODEWHALE_RE = re.compile(r"(?<![\w./-])codewhale(?![\w-])" + _VER_OPT, re.IGNORECASE)
_DEEPSEEK_TUI_RE = re.compile(
    r"(?<![\w./-])deepseek-tui(?![\w-])" + _VER_OPT, re.IGNORECASE
)
# `cline` needs the same treatment, and for a blunter reason: unbounded, `_mk_re`
# matches the substring in ordinary English. "declined", "inclined", "recline" and
# "declines" all fired, so any prose file that happened to contain one reported a
# CVE pin for a package the project does not depend on. Found while writing the
# mcp-florence2 fixtures, whose comment used the word "declined".
_CLINE_RE = re.compile(r"(?<![\w./-])cline(?![\w-])" + _VER_OPT, re.IGNORECASE)
# `n8n` fixed to exclude the distinct `n8n-mcp` package (right boundary).
_N8N_RE = re.compile(r"(?<![\w./-])n8n(?![\w-])" + _VER_OPT, re.IGNORECASE)


@dataclass(frozen=True)
class _Pin:
    rule_id: str
    display: str
    names: tuple[str, ...]
    floor: _Ver | None          # None => presence-only (fire on any match)
    introduced: _Ver | None = None   # fire only if version >= introduced
    fix_label: str = ""
    regexes: tuple[re.Pattern[str], ...] = field(default=(), compare=False)

    def compiled(self) -> tuple[re.Pattern[str], ...]:
        return self.regexes or tuple(_mk_re(n) for n in self.names)


_PINS: tuple[_Pin, ...] = (
    _Pin("AAK-MCP-LITELLM-CVE-2026-59822-001", "litellm", ("litellm",), (1, 84, 0),
         fix_label="1.84.0"),
    # Bounded regex, not the default `_mk_re`: see `_CLINE_RE` above — unbounded,
    # this matched "cline" inside ordinary words like "declined".
    _Pin("AAK-MCP-CLINE-CVE-2026-59723-001", "cline", ("cline",), (3, 0, 30),
         fix_label="3.0.30", regexes=(_CLINE_RE,)),
    _Pin("AAK-MCP-TEXTEDITOR-CVE-2026-15138-001", "mcp-text-editor", ("mcp-text-editor",),
         (1, 0, 3), fix_label="1.0.3 (affected up to 1.0.2)"),
    _Pin("AAK-MCP-N8N-CVE-2026-59207-001", "n8n", ("n8n",), (2, 27, 4),
         fix_label="2.27.4 / 2.28.1", regexes=(_N8N_RE,)),
    _Pin("AAK-MCP-RUFLO-CVE-2026-59726-001", "ruflo", ("ruflo",), (3, 16, 3),
         fix_label="3.16.3"),
    _Pin("AAK-MCP-DEEPSEEK-CVE-2026-55604-001", "@arikusi/deepseek-mcp-server",
         ("@arikusi/deepseek-mcp-server",), (1, 8, 0), introduced=(1, 4, 2),
         fix_label="1.8.0"),
    _Pin("AAK-MCP-K8S-CVE-2026-61459-001", "mcp-server-kubernetes", ("mcp-server-kubernetes",),
         (3, 9, 0), fix_label="3.9.0"),
    _Pin("AAK-MCP-ASTRBOT-CVE-2026-15501-001", "astrbot", ("astrbot",), (4, 25, 3),
         fix_label="4.25.3 (affected up to 4.25.2)"),
    # --- 2026-07-13..15 wave ---
    _Pin("AAK-MCP-HEALTHLAKE-CVE-2026-15643-001", "awslabs.healthlake-mcp-server",
         ("awslabs.healthlake-mcp-server",), (0, 0, 14), fix_label="0.0.14"),
    _Pin("AAK-MCP-PRAISONAI-CVE-2026-61427-001", "praisonai", ("praisonai",), (4, 6, 78),
         fix_label="4.6.78"),
    _Pin("AAK-MCP-APPIUM-CVE-2026-58500-001", "appium-mcp", ("appium-mcp",), (1, 85, 10),
         fix_label="1.85.10"),
    _Pin("AAK-MCP-PENPOT-CVE-2026-45805-001", "@penpot/mcp", ("@penpot/mcp",), (2, 15, 0),
         fix_label="2.15.0"),
    _Pin("AAK-MCP-OPENCLAW-CVE-2026-62195-001", "openclaw", ("openclaw",), (2026, 6, 6),
         introduced=(2026, 5, 20), fix_label="2026.6.6 (affected 2026.5.20–2026.6.5)"),
    _Pin("AAK-MCP-REPOMIX-CVE-2026-49988-001", "repomix", ("repomix",), (1, 14, 1),
         fix_label="1.14.1"),
    # Floor raised 1.6.11 -> 1.6.13 for CVE-2026-67333 (redirect_uri scheme not
    # validated; fixed 1.6.13), which 1.6.11/1.6.12 are still exposed to. Also cites
    # CVE-2026-67336 (weak crypto defaults, fixed 1.6.11 — already ⊆ this floor).
    _Pin("AAK-MCP-BETTERAUTH-CVE-2026-53512-001", "better-auth",
         ("better-auth", "@better-auth/oauth-provider"), (1, 6, 13), fix_label="1.6.13"),
    # --- 2026-07-15..17 wave ---
    _Pin("AAK-MCP-SDK-CVE-2026-52869-001", "mcp (MCP Python SDK)", ("mcp",), (1, 28, 1),
         fix_label="1.28.1", regexes=(_MCP_SDK_RE,)),
    _Pin("AAK-MCP-9ROUTER-CVE-2026-46339-001", "9router", ("9router",), (0, 5, 2),
         fix_label="0.5.2"),
    _Pin("AAK-MCP-N8NMCP-CVE-2026-54052-001", "n8n-mcp", ("n8n-mcp",), (2, 57, 4),
         fix_label="2.57.4", regexes=(_N8N_MCP_RE,)),
    _Pin("AAK-MCP-DBTMCP-CVE-2026-44968-001", "dbt-mcp", ("dbt-mcp",), (1, 17, 1),
         fix_label="1.17.1"),
    # Floor moved 0.9.21 -> 0.10.11 for CVE-2026-50143 (Actor path-authority token
    # leak). Same package, same rule: a second pin on the same name would report the
    # one dependency twice, and the higher floor already covers the lower one.
    _Pin("AAK-MCP-APIFY-CVE-2026-46341-001", "@apify/actors-mcp-server",
         ("@apify/actors-mcp-server",), (0, 10, 11), fix_label="0.10.11"),
    _Pin("AAK-MCP-AGENTICFLOW-CVE-2026-58195-001", "agentic-flow", ("agentic-flow",),
         (2, 0, 14), fix_label="2.0.14"),
    _Pin("AAK-MCP-HEALTHOMICS-CVE-2026-15415-001", "awslabs.aws-healthomics-mcp-server",
         ("awslabs.aws-healthomics-mcp-server",), (0, 0, 36), fix_label="0.0.36"),
    # --- 2026-07-19..20 wave ---
    _Pin("AAK-MCP-WHATSAPP-CVE-2026-46555-001", "whatsapp-mcp", ("whatsapp-mcp",),
         (0, 2, 1), fix_label="0.2.1"),
    # AgenticMail ships four npm packages, each with its own fix floor for the same
    # CVE — one rule_id, four pins (whichever @agenticmail/* the project depends on
    # fires below its own floor). `@agenticmail/openclaw` is distinct from the bare
    # `openclaw` pin above.
    _Pin("AAK-MCP-AGENTICMAIL-CVE-2026-57495-001", "@agenticmail/claudecode",
         ("@agenticmail/claudecode",), (0, 2, 39), fix_label="0.2.39"),
    _Pin("AAK-MCP-AGENTICMAIL-CVE-2026-57495-001", "@agenticmail/codex",
         ("@agenticmail/codex",), (0, 1, 33), fix_label="0.1.33"),
    _Pin("AAK-MCP-AGENTICMAIL-CVE-2026-57495-001", "@agenticmail/core",
         ("@agenticmail/core",), (0, 9, 43), fix_label="0.9.43"),
    _Pin("AAK-MCP-AGENTICMAIL-CVE-2026-57495-001", "@agenticmail/openclaw",
         ("@agenticmail/openclaw",), (0, 5, 71), fix_label="0.5.71"),
    # --- 2026-07-21 wave ---
    # The GHSA titles read "MCP-for-Stata", but the PyPI artifact is `stata-mcp`
    # — `mcp-for-stata` is a 404 and never matched a real manifest. Floor moves
    # 1.17.3 -> 1.19.0 for CVE-2026-55071 (GHSA-49m4-vp58-wgc9, CVSS 3.1 8.4):
    # `ado_package_install` concatenates an unsanitized `package` into a Stata
    # command, and Stata's shell escape turns newline injection into OS RCE.
    _Pin("AAK-MCP-STATA-CVE-2026-47708-001", "stata-mcp", ("stata-mcp",),
         (1, 19, 0), fix_label="1.19.0"),
    # --- 2026-07-22 wave ---
    # n8n CVE-2026-65594 is fixed on two branches (2.29.8 mainline, 2.30.1 on the
    # 2.30.x line) and affects only from 2.27.0 — two pin arms, one rule_id, each
    # bounded by `introduced` so patched releases on either branch clear.
    _Pin("AAK-MCP-N8N-CVE-2026-65594-001", "n8n", ("n8n",), (2, 29, 8),
         introduced=(2, 27, 0), fix_label="2.29.8", regexes=(_N8N_RE,)),
    _Pin("AAK-MCP-N8N-CVE-2026-65594-001", "n8n", ("n8n",), (2, 30, 1),
         introduced=(2, 30, 0), fix_label="2.30.1", regexes=(_N8N_RE,)),
    # --- 2026-07-23..24 wave ---
    # AWS API MCP Server: security-policy enforcement is skipped for the process
    # lifetime if policy-data init fails at startup — affected 0.2.13–1.3.46,
    # fixed 1.3.47 (introduced-bounded so pre-0.2.13 and patched releases clear).
    _Pin("AAK-MCP-AWSAPIMCP-CVE-2026-16584-001", "awslabs.aws-api-mcp-server",
         ("awslabs.aws-api-mcp-server",), (1, 3, 47), introduced=(0, 2, 13),
         fix_label="1.3.47 (affected 0.2.13–1.3.46)"),
    # --- 2026-07-29..30 wave ---
    # Flyto2 Core (`flyto-core`, PyPI) < 2.26.6: `llm.chat` reads provider keys
    # (OPENAI_API_KEY / ANTHROPIC_API_KEY) from the environment and forwards them in
    # the Authorization: Bearer header to a caller-controlled `base_url` that clears
    # the SSRF guard → operator provider-key exfiltration. Fixed 2.26.6 (all prior
    # versions affected, so no `introduced` bound).
    _Pin("AAK-MCP-FLYTO-CVE-2026-67425-001", "flyto-core", ("flyto-core",),
         (2, 26, 6), fix_label="2.26.6"),
    # --- 2026-07-30..31 wave ---
    # IBM Langflow OSS (`langflow`, PyPI) 1.0.0–1.10.1: the MCP stdio launcher's
    # DANGEROUS_ENV_VARS blocklist (`src/lfx/base/mcp/util.py`) omits SHELLOPTS /
    # BASHOPTS / PS4 → unauthenticated env-var-injection RCE (CVE-2026-12940,
    # CRITICAL 9.8). Fixed 1.11.0 (the first release after the affected 1.10.1;
    # introduced-bounded at 1.0.0 so pre-MCP 0.x releases clear).
    _Pin("AAK-MCP-LANGFLOW-CVE-2026-12940-001", "langflow", ("langflow",),
         (1, 11, 0), introduced=(1, 0, 0),
         fix_label="1.11.0 (affected 1.0.0–1.10.1)"),
    # --- 2026-08-01 wave ---
    # gemini-bridge (PyPI) 1.0.0–1.3.0: `consult_gemini_with_files` inline mode reads
    # any file path in the `files` argument without confining it to the working
    # directory, then forwards the contents to the Gemini CLI → path-traversal file
    # exfiltration (CVE-2026-54785, MEDIUM 6.2). Fixed 1.3.1. The npm `gemini-bridge`
    # (0.1.x) is an unrelated package below the affected range; the PyPI artifact is
    # the one the CVE versions (1.0.0–1.3.1) match, so this pins the PyPI package.
    _Pin("AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001", "gemini-bridge", ("gemini-bridge",),
         (1, 3, 1), introduced=(1, 0, 0),
         fix_label="1.3.1 (affected 1.0.0–1.3.0)"),
    # --- 2026-08-04 wave ---
    # awslabs.amazon-mq-mcp-server (PyPI) < 2.0.24: the RabbitMQ broker-connection
    # tools do not restrict the broker hostname, so a prompt-injection actor can
    # steer broker credentials / OAuth tokens to a crafted attacker endpoint
    # (CVE-2026-18655). Fourth awslabs.*-mcp-server pin in this family. Fixed 2.0.24.
    _Pin("AAK-MCP-AMAZONMQ-CVE-2026-18655-001", "awslabs.amazon-mq-mcp-server",
         ("awslabs.amazon-mq-mcp-server",), (2, 0, 24), fix_label="2.0.24"),
    # --- 2026-08-05 wave ---
    # @langchain/langgraph-checkpoint-mongodb (npm) <= 1.3.0: checkpoint identifiers
    # (thread_id / checkpoint_ns / checkpoint_id) from config.configurable flow into
    # MongoDBSaver.getTuple() find() queries without type enforcement, so an object
    # payload with operators ($gt/$ne) is read as a query operator, bypassing thread
    # scoping and leaking checkpoints across tenants (CVE-2026-48121). Fixed 1.3.1.
    _Pin("AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001",
         "@langchain/langgraph-checkpoint-mongodb",
         ("@langchain/langgraph-checkpoint-mongodb",), (1, 3, 1), fix_label="1.3.1"),
    # --- 2026-08-06 wave ---
    # awslabs.documentdb-mcp-server (PyPI) < 1.0.12: write-capable aggregation
    # pipeline stages bypass read-only-mode enforcement → unauthorized writes
    # (CVE-2026-18954). Fifth pin in the awslabs.*-mcp-server family. Fixed 1.0.12.
    _Pin("AAK-MCP-DOCUMENTDB-CVE-2026-18954-001",
         "awslabs.documentdb-mcp-server",
         ("awslabs.documentdb-mcp-server",), (1, 0, 12), fix_label="1.0.12"),
    # frontmcp (npm) < 1.5.7: the sandboxed codecall:execute tool reaches the host
    # Zod schema's Function constructor and runs arbitrary code as the server user;
    # default public auth mode serves it unauthenticated (CVE-2026-67531). Fixed 1.5.7.
    _Pin("AAK-MCP-FRONTMCP-CVE-2026-67531-001",
         "frontmcp", ("frontmcp",), (1, 5, 7), fix_label="1.5.7"),
    # --- 2026-08-08 wave ---
    # langgraph-checkpoint-postgres / -sqlite (PyPI) < 3.1.1: namespaces stored as a
    # dot-joined string and read by simple prefix match → a scoped read spills into a
    # sibling namespace, cross-tenant checkpoint leak (CVE-2026-71433). Fixed 3.1.1.
    _Pin("AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001",
         "langgraph-checkpoint-postgres/sqlite",
         ("langgraph-checkpoint-postgres", "langgraph-checkpoint-sqlite"),
         (3, 1, 1), fix_label="3.1.1"),
    # meta-ads-mcp (PyPI) < 1.0.109: AuthInjectionMiddleware forwards unauthenticated
    # requests without a 401, and a failed Graph API call serialises the request URL
    # (with the access_token) into the response → unauth tool invocation + token leak
    # (CVE-2026-48039, CVSS 9.1). Fixed 1.0.109.
    _Pin("AAK-METAADS-CVE-2026-48039-001",
         "meta-ads-mcp", ("meta-ads-mcp",), (1, 0, 109), fix_label="1.0.109"),
    # --- 2026-08-09 wave ---
    # @adenot/mcp-google-search (npm) <= 0.3.1: the `read_webpage` tool
    # (`src/index.ts`) fetches the caller-supplied `url` argument with no host or
    # scheme validation → server-side request forgery to internal endpoints
    # (CVE-2026-19337, CVSS 5.3). Same SSRF-via-tool-argument shape as the astrbot
    # MCP-test-endpoint pin. No fixed release exists yet: the upstream patch (commit
    # f071d491) is unreleased, so every published version (0.1.0–0.3.1) is exposed —
    # floor=None (presence-only, fire on any match). The unscoped `mcp-google-search`
    # (latest 1.0.0) is an unrelated package by a different author and is NOT pinned:
    # `_mk_re` escapes the full scoped name so it cannot match the bare package. Set
    # the floor to the fix version once upstream publishes a patched release.
    _Pin("AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001", "@adenot/mcp-google-search",
         ("@adenot/mcp-google-search",), None,
         fix_label="no fixed release yet (upstream patch f071d491 unreleased) — "
                   "remove or replace until a patched version ships"),
    # --- 2026-08-11 wave ---
    # mcp-grafana (PyPI; a Go server with a resolvable uvx / PyPI wrapper) < 1.1.0: a
    # caller-supplied X-Grafana-URL header controls the destination of the server's
    # outbound requests, and grafana_api_request lets the caller pick method / path /
    # body, so the destination is not restricted to the configured Grafana instance ->
    # SSRF to internal / loopback / metadata endpoints (CVE-2026-19516, CVSS 9.1). The
    # incomplete-fix follow-up to CVE-2026-15583 (which stopped the token leak but not
    # the destination). Fixed 1.1.0, which restricts destinations. Supersedes the
    # archived "unpinnable Go module" note for CVE-2026-15583: a PyPI wrapper exists.
    _Pin("AAK-MCP-GRAFANA-CVE-2026-19516-001", "mcp-grafana", ("mcp-grafana",),
         (1, 1, 0),
         fix_label="1.1.0 (affected <= 1.0.0; completes the incomplete fix of CVE-2026-15583)"),
    # --- 2026-08-11..12 wave ---
    # n8n (npm) < 2.32.1: the MCP Client node lets an authenticated workflow author send
    # requests to internal / blocked hosts without routing through n8n's SSRF protection,
    # exposing internal services and reading the responses back (CVE-2026-72768). A third
    # distinct n8n arm — separate from the 59207 credential-domain bypass and the 65594
    # two-branch OAuth fix. NVD says "before 2.32.1", so all prior versions are affected
    # (floor 2.32.1, no `introduced`). Uses `_N8N_RE` so it never trips the distinct
    # `n8n-mcp` package.
    _Pin("AAK-MCP-N8N-CVE-2026-72768-001", "n8n", ("n8n",), (2, 32, 1),
         fix_label="2.32.1", regexes=(_N8N_RE,)),
    # claude-code-templates (npm) < 1.29.4: the `--studio` option launches the Claude Code
    # Studio server (`cli-tool/src/sandbox-server.js`) bound to 0.0.0.0:3444 with CORS open
    # and no authentication. `POST /api/execute` (the `prompt` body field) and
    # `POST /api/install-agent` (the `agentName` field), plus the agent path reachable from
    # `/api/execute` via `checkAndInstallAgent()`, reach `child_process.spawn()` with shell
    # execution enabled, so shell metacharacters in those values run as OS commands with the
    # developer's privileges. Reachable directly by anyone who can hit the port, or via a
    # malicious site a developer visits while Studio runs (CVE-2026-73222, CVSS 8.8). Fixed
    # 1.29.4; the version before it is 1.29.2 (no 1.29.3 was published), so treat < 1.29.4
    # and unpinned as exposed.
    _Pin("AAK-MCP-CCTEMPLATES-CVE-2026-73222-001", "claude-code-templates",
         ("claude-code-templates",), (1, 29, 4), fix_label="1.29.4"),
    # mcp-atlassian < 0.22.0 passes the client-supplied `file_path` of
    # `confluence_upload_attachment` straight into `open(file_path, "rb")` inside
    # `_upload_attachment_direct()` without calling `validate_safe_path`, so an
    # authenticated MCP client reads any file the server process can reach and
    # exfiltrates it to Confluence as an attachment — including whatever holds
    # CONFLUENCE_API_TOKEN (CVE-2026-73498, CVSS 7.7). Fixed 0.22.0; resolves on
    # PyPI (0.22.0 published, 0.23.0 latest).
    _Pin("AAK-MCP-ATLASSIAN-CVE-2026-73498-001", "mcp-atlassian",
         ("mcp-atlassian",), (0, 22, 0), fix_label="0.22.0"),
    # @jshookmcp/jshook 0.3.1 gates its SSRF authorization policy on the raw
    # HTTP/TCP/TLS tools only; the ICMP probe and traceroute tools call the
    # native sink directly, so an MCP client can map internal reachability with
    # private-network access disabled (CVE-2026-49856, CVSS 4.3). Fixed 0.3.2;
    # GHSA-c5r6-m4mr-8q5j lists 0.3.1 as the only affected release.
    _Pin("AAK-MCP-JSHOOK-CVE-2026-49856-001", "@jshookmcp/jshook",
         ("@jshookmcp/jshook",), (0, 3, 2), fix_label="0.3.2"),
    # auth-fetch-mcp <= 3.0.1: isPrivateV6() misses IPv4-mapped IPv6 loopback in
    # hex-normalised form, so http://[::ffff:127.0.0.1]/ normalises to
    # [::ffff:7f00:1], net.isIPv4('7f00:1') is false, and the guard passes the
    # URL through to loopback (CVE-2026-49857, CVSS 7.4). The fix floor is 3.0.2
    # per GHSA-pvrj-8cg3-j5f8 — NOT 3.0.1 as the NVD prose states; 3.0.1 is
    # inside the affected range.
    _Pin("AAK-MCP-AUTHFETCH-CVE-2026-49857-001", "auth-fetch-mcp",
         ("auth-fetch-mcp",), (3, 0, 2), fix_label="3.0.2"),
    # mcp-memory-service < 10.67.1 serves every /api/documents/* route with no
    # auth dependency even when MCP_API_KEY or OAuth is configured, so an
    # unauthenticated caller can write, read and delete other users' memories.
    # The sibling /api/memories routes DO enforce auth, which is what makes it an
    # inconsistent boundary rather than an obviously-open server
    # (CVE-2026-50027, CVSS 9.8). GHSA-84hp-mqvj-3p8h: affected < 10.67.1.
    _Pin("AAK-MCP-MEMSERVICE-CVE-2026-50027-001", "mcp-memory-service",
         ("mcp-memory-service",), (10, 67, 1), fix_label="10.67.1"),
    # Cortex (neuro-cortex-memory) <= 3.17.0 treats CLAUDE_PROJECT_DIR — set by
    # Claude Code to the open project — as a candidate source root, validated
    # only by the presence of mcp_server/ and ui/unified-viz.html, then executes
    # mcp_server/server/visualize_bootstrap.py from it (CVE-2026-49986, HIGH).
    # Floor is 3.18.0, NOT the 3.17.1 the NVD prose names: GHSA-gvpp-v77h-5w8g
    # records <= 3.17.0 affected with 3.18.0 first patched, and no 3.17.1 was
    # ever published to PyPI. The successor distribution `hypermnesia-mcp`
    # starts at 3.24.0, always above this floor, so it needs no pin of its own.
    _Pin("AAK-MCP-CORTEX-CVE-2026-49986-001", "neuro-cortex-memory",
         ("neuro-cortex-memory",), (3, 18, 0), fix_label="3.18.0"),
    # @aborruso/ckan-mcp-server < 0.4.112: cache-key collision via unescaped
    # &/=/| in canonicalizeParams (CVE-2026-73846), prefix-only dati.gov.it host
    # check in isValidMqaServer (CVE-2026-73845), and verbatim upstream/exception
    # text in error paths (CVE-2026-73844). One pin, one fix version, three CVEs.
    _Pin("AAK-MCP-CKAN-CVE-2026-73846-001", "@aborruso/ckan-mcp-server",
         ("@aborruso/ckan-mcp-server",), (0, 4, 112), fix_label="0.4.112"),
    # letta (formerly MemGPT) carries four disclosed CVEs across its 0.4–0.16
    # line with no fixed release named in any of them: CVE-2025-51482 (RCE via
    # /v1/tools/run, 0.7.12), CVE-2026-4964 (file-URL handler, 0.16.4),
    # CVE-2026-4965 (ast_parsers, 0.16.4, an incomplete fix for CVE-2025-6101)
    # and CVE-2025-6101 (interface.py, up to 0.4.1).
    #
    # Floor 0.16.5 is the first release after the highest affected version, not
    # a vendor fix — every CPE names an exact version with no
    # versionEndExcluding and all four GHSA records are `unreviewed` with no
    # curated range. PyPI `letta` only: the vulnerable code is in letta/…
    # module paths, while letta-client and @letta-ai/letta-client are separate
    # client SDKs and npm @letta-ai/letta is a 0.0.1 placeholder.
    #
    # Uses the bounded `_LETTA_RE` rather than the default `_mk_re`, which
    # anchors on neither side: `_mk_re("letta")` matches `letta-client` (a real,
    # separate client SDK) and `pyletta` too — the same class of collision the
    # `mcp` / `n8n` pins above already carry explicit regexes for.
    _Pin("AAK-MCP-LETTA-CVE-2025-51482-001", "letta",
         ("letta",), (0, 16, 5),
         fix_label="0.16.5 (first release past every affected version)",
         regexes=(_LETTA_RE,)),
    # --- 2026-08-17 wave ---
    # mcp-florence2 (PyPI, jkawamoto) <= 0.3.13: `get_images`
    # (`src/mcp_florence2/__init__.py`) fetches the caller-supplied `src` argument
    # with no host or scheme validation → SSRF to internal endpoints
    # (CVE-2026-19984, CVSS 3.1 6.3, public exploit).
    #
    # floor=None (presence-only) — and unlike the @adenot pin above, this is not a
    # placeholder awaiting a release. The vendor has ruled out a source change and
    # states the mitigation is routing HTTP(S) through an SSRF-safe proxy "without
    # requiring changes to the mcp-florence2 source code". So there is no fix version
    # to re-pin to later, and a newer release must still fire: the remediation is
    # deployment-side egress control, not an upgrade. Do NOT convert this to a version
    # floor unless upstream actually ships a validating fix.
    _Pin("AAK-MCP-FLORENCE2-CVE-2026-19984-001", "mcp-florence2",
         ("mcp-florence2",), None,
         fix_label="no fixed release, by vendor decision — mitigate with an "
                   "SSRF-safe egress proxy / allow-list rather than an upgrade"),
    # --- 2026-08-18 wave ---
    #
    # CodeWhale: two CVEs, one package, one fix version, so one rule with two pins —
    # the CKAN precedent. CVE-2026-75858 (rlm_eval) and CVE-2026-75857
    # (exec_shell_interact) are the same defect class in two tools: both return
    # ApprovalRequirement::Auto, which the engine reads as "never prompt", so the
    # user's --approval-policy is bypassed. GHSA-wrj3-vj8c-784f and GHSA-g29h-pfmp-qp9r
    # both list >= 0.8.41, < 0.8.64 patched at 0.8.64.
    #
    # `deepseek-tui` is the same project before it was renamed: npm marks it deprecated
    # ("use codewhale instead") and both advisories carry it as a separate affected row
    # patched at 0.8.41 — which is where the codewhale line begins, so the rename is
    # the boundary rather than a real fix. A pre-0.8.41 deepseek-tui is exposed and has
    # no fixed release of its own; the upgrade path is the renamed package.
    _Pin("AAK-MCP-CODEWHALE-CVE-2026-75858-001", "codewhale", ("codewhale",),
         (0, 8, 64), fix_label="0.8.64", regexes=(_CODEWHALE_RE,)),
    _Pin("AAK-MCP-CODEWHALE-CVE-2026-75858-001", "deepseek-tui", ("deepseek-tui",),
         (0, 8, 41), fix_label="0.8.41 (deprecated — migrate to codewhale >= 0.8.64)",
         regexes=(_DEEPSEEK_TUI_RE,)),
)

_CANDIDATE_NAMES = (
    "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    ".mcp.json", "mcp.json", "claude_desktop_config.json",
)
_CANDIDATE_GLOBS = ("requirements*.txt", "*.mcp.yaml", "*.mcp.yml")
_MAX_FILE_BYTES = 2_000_000


def _fires(pin: _Pin, version: _Ver | None) -> bool:
    if pin.floor is None:
        return True
    if version is None:
        return True
    if version >= pin.floor:
        return False
    if pin.introduced is not None and version < pin.introduced:
        return False
    return True


def _candidate_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for name in _CANDIDATE_NAMES:
        p = project_root / name
        if p.is_file():
            out.append(p)
            seen.add(p)
    for pattern in _CANDIDATE_GLOBS:
        for p in project_root.rglob(pattern):
            if p.is_file() and p not in seen and not any(part in SKIP_DIRS for part in p.parts):
                out.append(p)
                seen.add(p)
    return out


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for the 2026-07 MCP/agent CVE dependency pins.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    for path in _candidate_files(project_root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        is_lockfile = path.name.lower() in _LOCKFILES
        matched_here = False
        for pin in _PINS:
            if is_lockfile:
                # Resolve the actual locked version; fire ONLY when it is below
                # the fix floor. Absent / unparseable → no finding, so a correct
                # upgrade + re-lock clears the rule instead of forcing suppression.
                resolved = _resolve_lockfile_version(text, path.name.lower(), pin.names)
                if resolved is not None and _fires(pin, resolved):
                    shown = ".".join(str(x) for x in resolved)
                    findings.append(make_finding(
                        pin.rule_id,
                        rel,
                        f"{pin.display} resolves to {shown} in {path.name} — fixed "
                        f"in {pin.fix_label}; upgrade and re-lock.",
                    ))
                    matched_here = True
                continue
            for rx in pin.compiled():
                m = rx.search(text)
                if not m:
                    continue
                raw = m.group(1)
                version = _semver3(raw) if raw else None
                if _fires(pin, version):
                    shown = f"{raw!r}" if raw else "unpinned"
                    findings.append(make_finding(
                        pin.rule_id,
                        rel,
                        f"{pin.display} referenced at {shown} — fixed in "
                        f"{pin.fix_label}; pin the patched release.",
                    ))
                    matched_here = True
                break  # one finding per pin per file
        if matched_here:
            scanned.add(rel)

    return findings, scanned
