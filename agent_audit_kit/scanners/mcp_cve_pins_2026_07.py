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
  - n8n                            >= 2.41.4, and 2.42.0  (CVE-2026-59207, and since
    2026-10-16 CVE-2026-110852, a webhook lookup that ignores the webhook's id; was
    2.27.4, with a 2.28.1 line)
  - ruflo                          >= 3.16.3  (CVE-2026-59726)
  - @arikusi/deepseek-mcp-server   >= 1.8.0   (CVE-2026-55604, CVE-2026-55605)
  - mcp-server-kubernetes          >= 3.9.0   (CVE-2026-61459)
  - astrbot                        >  4.25.2  (CVE-2026-15501; NVD "up to 4.25.2")
  - awslabs.healthlake-mcp-server  >= 0.0.14  (CVE-2026-15643)
  - praisonai                      >= 4.6.78  (CVE-2026-61427)
  - appium-mcp                     >= 1.85.10 (CVE-2026-58500)
  - @penpot/mcp                    >= 2.15.0  (CVE-2026-45805)
  - openclaw                       >= 2026.7.1 (CVE-2026-62195 was 2026.5.20..<2026.6.6;
    CVE-2026-100585 raised the floor to 2026.7.1 and has no lower bound;
    CVE-2026-100587 and CVE-2026-100596 sit at the same floor)
  - repomix                        >= 1.14.1  (CVE-2026-49988)
  - better-auth / @better-auth/oauth-provider >= 1.6.13 (CVE-2026-53512, CVE-2026-53518, CVE-2026-67333, CVE-2026-67336)
  - mcp (MCP Python SDK)            >= 1.29.1, and 2.0.x below 2.1.0  (CVE-2026-52869,
    CVE-2026-52870, CVE-2026-59950; CVE-2026-109527 raised the floor from 1.28.1 and
    added the 2.0 line. ecosystem="py": npm's `mcp` is another package)
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
  - langgraph-checkpoint-postgres >= 3.1.3, langgraph-checkpoint-sqlite >= 3.1.2
    (CVE-2026-71433, CVE-2026-115883; one rule, a row per package)
  - meta-ads-mcp                    >= 1.0.109 (CVE-2026-48039)
  - verygoodplugins/whatsapp-mcp   >= 0.2.1   (CVE-2026-46555; read from a reference to
    the GitHub repository that names a release, `_REPO_PINS`. npm's and PyPI's
    `whatsapp-mcp` are other projects and out of scope)
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
  - n8n (MCP Client node)          >= 2.41.4, and 2.42.0  (CVE-2026-72768; SSRF-protection
    bypass. The floor rose for CVE-2026-77068, -77073, -85166 and, on 2026-10-16,
    CVE-2026-110842, the MCP workflow-validation tool's prototype pollution)
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
  - tooluniverse                    >= 1.3.0   (CVE-2026-81096; affected up to 1.2.6)
  - mcp-contextforge-gateway        >= 1.0.9   (CVE-2026-77822, CVE-2026-18905,
    CVE-2026-18486, CVE-2026-18489 — one floor, four CVEs, four issues; 1.0.9 is
    from IBM's bulletin, which is the only source that carries the range)
  - postgres-mcp                    <= 0.3.0   (CVE-2026-85620; no fixed release —
    upstream issue #178 open, v0.3.0 still the newest tag)
  - awslabs.postgres-mcp-server     >= 1.1.7   (CVE-2026-85787)
  - knowns                          presence-only (CVE-2026-86439 fixed in 0.30.0,
    but CVE-2026-88938 is scoped "through 0.33.0" and its advisory names no
    patched version; npm's 0.34.0 and 0.34.1 are not confirmed fixed, so there
    is no floor to pin to)
  - langflow                        >= 1.12.0  (CVE-2026-9186 raised the 1.11.0
    floor of CVE-2026-12940; CVE-2026-85025 / CVE-2026-78575 / CVE-2026-81941,
    all scoped 1.0.0–1.11.5, then raised it again, and CVE-2026-101861, eval() on
    Tool-Mode input options up to 1.11.6, raised it to 1.12.0 — same package, same rule.
    CVE-2026-105697 / -105740 / -105741 sit under that floor. The same rule reads
    `langflow-base` and `lfx` at 1.12.0, the release all three reached together)
  - awslabs.postgres-mcp-server     >= 1.1.7   (CVE-2026-85787 + CVE-2026-87911;
    the second is OS command injection through a crafted COPY-to-PROGRAM
    statement, CRITICAL 9.6, and the floor was already correct — only the rule's
    threat description moved. Written without the literal SQL here on purpose:
    `AAK-LLM-SQL-RCE-001` matches that syntax, and this repo scans itself, so
    the exact clause in prose fails the self-scan on a finding that is a
    docstring)
  - mcp-contextforge-gateway        >= 1.0.9   (+ CVE-2026-78573 default
    credentials, 1.0.0–1.0.7; already under the existing floor. CVE-2026-53709,
    a published default JWT key below 1.0.2, CVE-2026-53711, an Admin UI
    stored XSS below 0.3.1, and CVE-2026-8355, an OAuth token-URL SSRF below
    1.0.6, joined it the same way)
  - awslabs.security-agent-mcp-server >= 0.2.0   (CVE-2026-87913; unverified S3
    bucket ownership for scan output)
  - mysql-mcp-server               >= 0.4.2   (CVE-2026-59971; SSE transport with no
    security_settings and a 0.0.0.0 default reaches execute_sql unauthenticated)
  - praisonai (npm, TypeScript)    >= 1.7.2   (CVE-2026-57139 — a DIFFERENT project
    from the 4.6.x PyPI `praisonai` above. Same name, two registries, two version
    lines, which is why `_Pin.ecosystem` exists)
  - @zereight/mcp-gitlab           >= 2.1.30  (CVE-2026-61560, CVE-2026-61559 fixed
    2.1.27; CVE-2026-61568 fixed 2.1.30 — one pin at the highest floor)
  - flowise                        >= 3.1.4   (CVE-2026-91931, CVE-2026-91932; npx
    package names and an unvalidated cwd in the Custom MCP node)
  - mcp-from-openapi               >= 2.5.0   (CVE-2026-59973; external-$ref SSRF on
    its own 2.x line — `frontmcp`/`@frontmcp/adapters` carry the same defect but
    were fixed at 1.5.0, already under that pin's 1.5.7 floor)
  - @contentful/mcp-server         >= 1.7.19  (CVE-2026-53957; one rule, two pins —
    @contentful/mcp-tools >= 0.4.5 carries the same defect on its own 0.x line)
  - mcp-searxng                    >= 1.7.1   (CVE-2026-58483; a missing Content-Length
    bypasses the read cap and the whole body is consumed)
  - atomic-agents-stack            >= 1.1.0   (CVE-2026-91988; cleartext registry
    catalog -> injected argv spawned by MCPClientPool)
  - netlicensing-mcp               >= 0.1.8   (CVE-2026-54446; unauthenticated /mcp
    falls back to the operator's API key. CVE-2026-57496 raised the floor from 0.1.6
    and the rule to CRITICAL: a product number with `../` reads the token endpoint
    unredacted. `container_image_pins` reads the GHCR and Docker Hub images)
  - mcp-remote                     0.1.16–0.1.38 (CVE-2026-51994 and CVE-2026-51995,
    OAuth discovery SSRF from 0.1.32; CVE-2026-51997, internal URLs reach the
    browser launch from 0.1.16; CVE-2026-51996, MD5-derived token-file names,
    0.1.16-0.1.38 per NVD; CVE-2026-52001, the SSE fetch wrapper adds the bearer
    token with no origin check of its own, 0.1.18-0.1.38 per NVD. Upstream names
    no fix, so the pin is the union of
    the advisories' ranges, and it needs a stated version: an unpinned
    `npx mcp-remote` resolves to 0.14.x)
  - @moonshot-ai/kimi-code         >= 0.31.1  (CVE-2026-95660; an untrusted workspace's
    `.mcp.json` servers spawned before the trust prompt)
  - @zosmaai/pi-llm-wiki           >= 0.11.8  (CVE-2026-102911; the wiki_capture_source MCP
    tool's `url` reaches `sh -c`. A stated version is required, as for mcp-remote)
  - fast-mcp-telegram              >= 0.30.1  (CVE-2026-55096; the attachment SSRF guard
    checks the literal hostname and never resolves it. NVD prints the fix as "30.1")
  - office-powerpoint-mcp-server   presence-only (CVE-2025-71427; save_presentation,
    open_presentation and manage_image take any path. No fixed release: 2.0.7 is the
    newest and the fix, upstream PR #33, is unmerged)
  - @penpot/mcp                    >= 2.18.0  (CVE-2026-100868; the plugin WebSocket
    bridge listens on every interface. Its own MEDIUM rule beside the CRITICAL 2.15.0
    REPL pin above. The fix is in Penpot's 2.18.0 tag, whose mcp/package.json reads
    2.17.0, and no npm build has been published from it, so every published release
    is reported)
  - voice-mode                     >= 8.10.2  (CVE-2026-79535; update_config writes the
    caller's value into a sourced env file, double-quoted at best)
  - @0xshariq/github-mcp-server    presence-only (CVE-2026-102906; git tools run
    interpolated strings through child_process.exec. Every release, 2.0.0 to 2.5.0,
    has it, and upstream has not answered)
  - openclaw                       2026.7.2 <= v < 2026.9.4  (CVE-2026-102807; an
    operator.read token runs operator.write MCP App tools through a standalone
    ticket. Its own MEDIUM rule beside the HIGH 2026.7.1 pin above; the feature is
    absent before 2026.7.2)
  - zscaler-mcp                    0.7.0 <= v < 0.7.2  (CVE-2026-59563; 31 delete tools
    signed an empty parameter set into the HMAC confirmation token, so one token
    confirmed the delete of any resource of that type)
  - utcp-mcp                       >= 1.1.3   (CVE-2026-101057; a call template's
    plain-HTTP, non-loopback MCP server URLs are dialed as configured)
  - @toolbox-sdk/server            1.2.0 <= v < 1.10.0  (CVE-2026-102242; Google MCP
    Toolbox's local-path checks never resolve symlinks. The npm launcher runs the
    toolbox binary of its own version)
  - next                           16.0.0 <= v < 16.3.8  (CVE-2026-94486; the `next dev`
    server's MCP endpoint answers cross-site requests. Dev server only, LOW, and only
    a `"next": "<version>"` entry or a lockfile is read)
  - @anthropic-ai/claude-code      2.0.68 <= v < 2.1.260  (CVE-2026-103012; a stored API
    key was preferred over the Enterprise or Team sign-in for managed settings. LOW,
    a stated version is required, and its own rule beside the HIGH folder-trust pin
    in `supply_chain`, whose floor is 2.1.179)
  - @anthropic-ai/claude-code      < 1.0.111  (CVE-2025-59536; project code ran before
    the startup trust dialog. AAK-HOOK-RCE-003, which read settings.local.json
    commands until 2026-10-17. A stated version is required)
  - langgraph-sdk                  0.1.45 <= v < 0.4.4  (CVE-2026-104873; the
    resource-scoped auth decorators register a handler for every action whatever
    `actions` says. Only a deployment that passes `actions` is exposed)
  - @modelcontextprotocol/sdk      1.12.0 <= v < 1.31.0, and
    @modelcontextprotocol/client   < 2.2.0  (CVE-2026-104850; the OAuth client sends
    stored or configured credentials to the authorization server the MCP server
    names. One rule, two pins. Servers and stdio clients are not affected)
  - @payloadcms/plugin-mcp         3.61.0 <= v < 3.88.0  (CVE-2026-105806; the API-keys
    collection has no access rules, so a user can manage another account's keys)
  - @langchain/redis               >= 1.1.1   (CVE-2026-105799; RediSearch filter values
    are not escaped. LOW)
  - @langchain/mongodb             >= 1.3.1   (CVE-2026-106119; MongoDBChatMessageHistory
    takes an object session id as a query condition)
  - obsidian-tc                    1.0.0 <= v < 1.3.1  (CVE-2026-77366, CVE-2026-77363,
    CVE-2026-77364, CVE-2026-77361, CVE-2026-77362; the HTTP transport's vault
    binding and Origin checks, and three read-ACL gaps. One fix release, one rule,
    a stated version required. `container_image_pins` reads the GHCR image)
  - @jetbrains/junie, and
    @jetbrains/junie-cli           888.0.0 <= v < 2548.5.0  (CVE-2026-111091; Junie CLI
    before 26.8.3 runs an untrusted project's MCP server configuration. The npm
    version is the Junie build, and 2548.5 is 26.8.3. A stated version is required)
  - mcp (MCP Python SDK)            1.8.0 <= v < 1.30.0, and 2.0.x/2.1.x below 2.2.0
    (CVE-2026-59951; stateful Streamable HTTP sessions never expire. MEDIUM, its own
    rule beside the HIGH pin on the same name)
  - network-ai                     5.14.0 <= v < 5.15.2  (CVE-2026-109331 and
    CVE-2026-73614; ClaudeHookBridge matches deny patterns against one truncated
    field. A stated version is required)
  - mcp-remote                     >= 0.8.0, launched with --device-code
    (CVE-2026-108716; the device-code grant posts the client secret to http
    endpoints. No fixed release, so an unpinned launch is reported, and a launch
    without the flag, a dependency entry and a lockfile are not)
  - open-computer-use, open-computer-use-mcp and
    open-codex-computer-use-mcp    any version  (CVE-2026-108721; the macOS
    password-manager denylist is case-sensitive. No fixed release)
  - odoo-mcp                       >= 1.0.0  (CVE-2026-108861; `execute_method` skips
    the field policy. No fixed release; PyPI only)
  - network-ai                     4.0.0 <= v < 5.15.2  (CVE-2026-109332; the MCP SSE
    transport answers other origins. LOW, its own rule beside the HIGH pin, and a
    stated version is required)
  - claude-agent-sdk               >= 0.2.121, and
    @anthropic-ai/claude-agent-sdk >= 0.3.208  (CVE-2026-96620; `resume` reaches the
    Claude CLI as its own argv token, so a session id starting with `-` injects a
    flag such as --mcp-config. The CVE names the Python SDK, and its fix commit says
    the TypeScript SDK shipped the same fix in 0.3.208. One rule, two pins, a stated
    version required)
  - langchain-chatchat             presence-only  (CVE-2026-75128; `POST /tools/call`
    runs the always-registered shell tool for an unauthenticated caller, in every
    release from 0.3.0 to 0.3.1.3, the newest; the images are image-pin rows)
  - @modelcontextprotocol/sdk      1.24.0 <= v < 1.32.0  (CVE-2026-111767; the
    experimental tasks feature kept every task of one InMemoryTaskStore in one pool,
    so a client with a session of its own could list, read and cancel another
    session's tasks. Its own HIGH rule beside the 1.31.0 OAuth pin above, since
    1.31.0 is fixed for that bug and affected by this one. A stated version is
    required, and only a server that configures the SDK's task store is exposed)
  - mcp-ripgrep                    presence-only  (CVE-2026-113378; the advanced-search
    and list-files tools append `-t ${fileType}` unescaped to a command line run
    through a shell. Every release, 0.1.0 to 0.4.0, the newest, has it, and there
    is no fixed release)
  - d365fo-mcp                     < 1.11.0  (CVE-2026-114123; the documented Azure
    one-click deployment left the apiKey parameter empty, the middleware passed
    every request through with API_KEY empty, and the HTTP listener bound 0.0.0.0,
    so a public App Service answered unauthenticated tools/call on /mcp. 1.11.0
    requires the key and refuses a keyless listener off loopback. A stated version
    is required; the deployment template and the App Service setting are not read)
  - litellm                        1.87.0 <= v < 1.100.4, and 1.101.0-1.101.2,
    1.102.0-1.102.1 and 1.103.0  (CVE-2026-114612; session tokens were sealed with
    the at-rest secrets helper, and the key API seals a key's callback_vars with it,
    so an internal user could have an administrator session minted and replay it.
    Its own CRITICAL rule above the 1.84.0 row; PyPI only, a stated version
    required; 1.104.0rc1 reads as 1.104.0, which is fixed)
  - @zenalexa/unicli               0.208.0 <= v < 0.225.2  (CVE-2026-58497; the legacy
    JSON-RPC-over-HTTP MCP transport took a web page's cross-origin POST to loopback
    /mcp with no Origin check. 0.207.1 has no HTTP transport; a stated version is
    required)
  - obsidian-tc                    1.0.1 <= v < 1.31.4  (CVE-2026-115477, CVE-2026-115478;
    a declined human-in-the-loop confirmation could still complete over HTTP, and the
    memory tools overwrote notes they did not own. Its own HIGH rule beside the
    CRITICAL 1.3.1 row, with an image row in container_image_pins)
  - mcp-from-openapi               2.2.0 <= v < 2.9.0  (CVE-2026-115750, CVE-2026-115751;
    spec fetches carried Authorization and Cookie across a cross-origin redirect, and
    a trailing dot slipped past ssrf.blockedHosts. Its own LOW rule beside the 2.5.0
    row)
  - langgraph-cli                  0.4.15 <= v < 0.4.32  (CVE-2026-115885; `langgraph
    deploy --verbose` printed the registry push token it hands to docker login)

CVEs without a pinnable PyPI/npm artifact (aerostack-mcp SSRF, MaxKB stdio
command-injection, mastergo-magic-mcp path-traversal/SSRF with no vendor fix,
Grafana MCP on Go, Apache SkyWalking MCP on Go, ArcadeDB on Maven, Context7 whose
defect is in the hosted service rather than any published client version,
mcp-gitlab with no NVD version data yet) or a tractable version
scheme (langchain4j's four parallel beta fix-lines) are handled outside this
module — see CHANGELOG.cves.md.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import in_skip_dir, loads_toml, make_finding, strip_jsonc
from agent_audit_kit.scanners._manifest_deps import (
    MAX_LOCKFILE_BYTES,
    MAX_MANIFEST_BYTES,
    Declaration,
    _json_key,
    _toml_positions,
    declaration_lines,
    declarations,
)
from agent_audit_kit.scanners._versions import TOP, ZERO, Spans, admits, intersect, intersect_all, parse_range
from agent_audit_kit.scanners.supply_chain import (
    _LOCKFILES,
    _PNPM_ENTRY_RE,
    _lockfile_canon,
    _lockfile_index,
    _lockfile_lookup,
    _semver3,
)

_Ver = tuple[int, int, int]

# How a pin finds its package.
#
# Every candidate file is parsed into the dependency declarations it makes
# (`_manifest_deps`): requirement lines, pyproject and Pipfile tables, the
# package.json dependency maps and overrides, and the packages a launcher fetches
# in an MCP config or a package.json script (`_launchers`). A pin matches a
# declaration on its whole name only, compared as the registry compares names:
# case-insensitively, and for PyPI as PEP 503 normalises them. Comments,
# descriptions, server names, paths, image names and URLs are never
# declarations, so none of them can stand in for the package or hide it.
#
# That retired the per-pin regexes this table carried. Each one bounded a name
# that the old unbounded pattern matched inside other text, and the reasons are
# kept here because they are facts about the registries, not about regexes:
#
#   - A name inside other text: `cline` in English words ("declined",
#     "inclined"); `n8n` in `n8n-mcp`; `letta` in `letta-client`; `langflow` in
#     `langflow-base`; `codewhale` in its crates.io twin `codewhale-tui`, which
#     this detector cannot see because no Cargo manifest is a candidate; `marimo`
#     in `marimo-team/marimo`; bare `mcp` (the MCP Python SDK) in `fastmcp`,
#     `mcp-text-editor` and every `awslabs.*-mcp-server`; and `frontmcp` and
#     `better-auth` in their scoped siblings `@frontmcp/adapters` and
#     `@better-auth/oauth-provider`, where the bare match also shadowed the
#     scoped pin that would have read the version.
#   - The same name for a different project on the other registry: npm `marimo`
#     (a test runner), npm `omnigent`, npm `praisonai` (the TypeScript framework,
#     pinned on its own), npm `langflow` (a React frontend for another product),
#     npm `lfx` (an empty placeholder), PyPI `browse-mcp` (a paper-search server
#     whose line never reaches the npm fix), PyPI `mcphub` (Cognitive-Stack's
#     library, which is why the MCPHub pin names `@samanhappy/mcphub`), PyPI
#     `knowns` (a stub whose only release, 0.1.0, the pin's `introduced` excludes)
#     and npm `postgres-mcp` (a 1.x server the 0.4.0 floor keeps off). A pin's
#     `ecosystem` keeps a manifest from the other registry off it, and the
#     launcher decides the registry of an MCP config entry (`npx` reads npm,
#     `uvx` reads PyPI).
#   - Lookalikes that are other packages: `@langchain/langgraph-sdk` is not
#     PyPI's `langgraph-sdk`, `@utcp/mcp` is not `utcp-mcp`, `zscaler-mcp-server`
#     (the README's uvx name, not on PyPI) is not `zscaler-mcp`, the
#     `@toolbox-sdk/server-<os>-<arch>` binaries are not the launcher, and
#     `postgres-mcp-server`, `awslabs.postgres-mcp-server` and `postgres-mcp-pro`
#     are not `postgres-mcp`, `argocd-mcp-server` and `mcp-argocd` (other npm
#     projects) and any `@scope/argocd-mcp` are not `argocd-mcp`, the unscoped
#     npm `1mcp` (buremba/1mcp, its own 0.1.x line) is not `@1mcp/agent`, and the
#     scoped `@the-40-thieves/obsidian-tc` (a 0.0.1 placeholder) and the monorepo's
#     `@the-40-thieves/obsidian-tc-*` parts are not the `obsidian-tc` server.
#   * `@jetbrains/junie-cli` 1.0.0 (2025-08-04) is an empty package.json, published
#     before the 0.1.x launchers; the Junie pin's 888.0.0 start keeps it quiet.
#
# `requires_version` marks the pins that report only a stated version, because
# an unpinned reference resolves to a release the advisory does not cover:
# mcp-remote (`npx mcp-remote` installs 0.14.x, and it sits in a large share of
# all MCP configs), the MCP TypeScript SDKs, Payload's plugin, the two
# LangChain.js integrations, obsidian-tc, Junie CLI, both Claude Agent SDKs,
# d365fo-mcp and LiteLLM's CVE-2026-114612 row (`latest` resolved to a fixed
# release for each),
# Claude Code (the CLI updates itself), pi-llm-wiki (upstream registers it by a
# node_modules path, which states none), bare `mcp` (a lone `mcp` names too much
# to report unversioned), and `next`, where only a declared version says which
# dev server runs.


@dataclass(frozen=True)
class _Pin:
    rule_id: str
    display: str
    names: tuple[str, ...]
    floor: _Ver | None          # None => presence-only (fire on any match)
    introduced: _Ver | None = None   # fire only if version >= introduced
    fix_label: str = ""
    # Report only a declaration that states a version; see the note above.
    requires_version: bool = False
    # Which package registry this pin's version line belongs to: "py", "js", or
    # None for "do not care". Names are not unique across registries, and a pin
    # is a claim about ONE project's version line, so matching a same-named
    # package from the other registry compares two unrelated numbering schemes.
    # `praisonai` is the case that forced this: PyPI's line is 4.6.x and npm's
    # is 1.7.x, so the 4.6.78 floor reported a fully-patched npm praisonai@1.7.4
    # as vulnerable and told the reader to upgrade to a version npm has never
    # published. Only set this where a real twin exists; None matches both
    # registries. An MCP config entry takes its registry from the launcher
    # (`npx` is npm, `uvx` is PyPI); a program run by name has none and still
    # matches every pin.
    ecosystem: str | None = None
    # Further affected [introduced, fixed) ranges on a release line the main range
    # does not reach. `mcp` 2.0.0a1 to 2.0.1 is affected by CVE-2026-109527 although
    # 2.0.0 sits above the 1.29.1 floor; a second row for the same name would
    # report one declaration twice.
    also: tuple[tuple[_Ver, _Ver], ...] = ()
    # Report only a launch that passes this option. mcp-remote's device-code grant
    # runs only with `--device-code`, so a dependency or a launch without the flag
    # never reaches the flaw, and a lockfile, which records no arguments, is not
    # judged at all.
    requires_arg: str | None = None


_PINS: tuple[_Pin, ...] = (
    _Pin("AAK-MCP-LITELLM-CVE-2026-59822-001", "litellm", ("litellm",), (1, 84, 0),
         fix_label="1.84.0"),
    # Matched on the whole name: unbounded, this matched "cline" inside ordinary
    # words like "declined" (see the matching note above).
    _Pin("AAK-MCP-CLINE-CVE-2026-59723-001", "cline", ("cline",), (3, 0, 30),
         fix_label="3.0.30"),
    _Pin("AAK-MCP-TEXTEDITOR-CVE-2026-15138-001", "mcp-text-editor", ("mcp-text-editor",),
         (1, 0, 3), fix_label="1.0.3 (affected up to 1.0.2)"),
    # Floor moved 2.27.4 -> 2.41.4 for CVE-2026-110852 (MEDIUM, CVSS 4.0 6.3,
    # GHSA-4c7j-qff5-r9cx): the static webhook lookup returned a dynamic-path row
    # on its path alone, so a request that left out the webhook's id ran another
    # project's workflow under that project's credentials. `WebhookService` does a
    # bare `findOneBy({ webhookPath: path, method })` at 2.0.0, 2.27.4, 2.41.3 and
    # 2.42.0, and 2.41.4 and 2.42.1 reject a dynamic row. 2.42.0 sorts above the
    # floor and is still affected, so it is an `also` range on this row rather
    # than a second row, which would report an unversioned n8n twice.
    _Pin("AAK-MCP-N8N-CVE-2026-59207-001", "n8n", ("n8n",), (2, 41, 4),
         also=(((2, 42, 0), (2, 42, 1)),), fix_label="2.41.4 / 2.42.1"),
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
    # ecosystem="py": npm publishes an unrelated `praisonai` (the TypeScript
    # agent framework, 1.x line) whose CVE and floor are the separate pin below.
    # Without the scope, npm praisonai@1.7.4 -- the newest release there -- was
    # reported vulnerable against this 4.6.78 PyPI floor.
    _Pin("AAK-MCP-PRAISONAI-CVE-2026-61427-001", "praisonai", ("praisonai",), (4, 6, 78),
         ecosystem="py",
         fix_label="4.6.78"),
    _Pin("AAK-MCP-APPIUM-CVE-2026-58500-001", "appium-mcp", ("appium-mcp",), (1, 85, 10),
         fix_label="1.85.10"),
    _Pin("AAK-MCP-PENPOT-CVE-2026-45805-001", "@penpot/mcp", ("@penpot/mcp",), (2, 15, 0),
         fix_label="2.15.0"),
    # Floor raised 2026.6.6 -> 2026.7.1 and the 2026.5.20 lower bound dropped for
    # CVE-2026-100585 (owner-only Claude permission replies over the MCP channel
    # bridge), which GHSA-p5g8-m35v-7m82 scopes `< 2026.7.1` with no lower bound.
    # CVE-2026-100587 (Codex computer-use install) and CVE-2026-100596 (`/mcp set`
    # persisting a stdio command) are `< 2026.7.1` too, so the floor holds.
    # npm only. Each openclaw/openclaw advisory (GHSA-52xj-c9p8-78cv,
    # GHSA-p5g8-m35v-7m82, GHSA-pjjr-5qhr-5w6r, GHSA-wwx7-573h-pqwc) names the npm
    # package `openclaw` and nothing else, and NVD's CPE for CVE-2026-62195 is
    # `openclaw:openclaw` on node.js. The PyPI project `openclaw` (2.0.1 and 2.0.2,
    # 2026-08-13) is an installer for the cmdop CLI that says it is not affiliated
    # with OpenClaw; unscoped, `openclaw==2.0.2` read as an OpenClaw below the floor.
    _Pin("AAK-MCP-OPENCLAW-CVE-2026-62195-001", "openclaw", ("openclaw",), (2026, 7, 1),
         fix_label="2026.7.1 (CVE-2026-100585, CVE-2026-100587, CVE-2026-100596; "
                   "CVE-2026-62195 alone was fixed in 2026.6.6)",
         ecosystem="js"),
    _Pin("AAK-MCP-REPOMIX-CVE-2026-49988-001", "repomix", ("repomix",), (1, 14, 1),
         fix_label="1.14.1"),
    # Floor raised 1.6.11 -> 1.6.13 for CVE-2026-67333 (redirect_uri scheme not
    # validated; fixed 1.6.13), which 1.6.11/1.6.12 are still exposed to. Also cites
    # CVE-2026-67336 (weak crypto defaults, fixed 1.6.11 — already ⊆ this floor).
    _Pin("AAK-MCP-BETTERAUTH-CVE-2026-53512-001", "better-auth",
         ("better-auth", "@better-auth/oauth-provider"), (1, 6, 13),
         fix_label="1.6.13"),
    # --- 2026-07-15..17 wave ---
    # Floor raised 1.28.1 -> 1.29.1 for CVE-2026-109527 (HIGH, as the session CVEs
    # are): the SSE, Streamable HTTP and OAuth endpoints buffer a request body of
    # any size before 1.29.1, and on the 2.0 line (2.0.0a1 to 2.0.1) before 2.1.0.
    # ecosystem="py": npm's `mcp` (1.4.2) is another package.
    _Pin("AAK-MCP-SDK-CVE-2026-52869-001", "mcp (MCP Python SDK)", ("mcp",), (1, 29, 1),
         also=(((2, 0, 0), (2, 1, 0)),),
         fix_label="1.29.1, or 2.1.0 on the 2.x line (the session CVEs were fixed in 1.28.1)",
         requires_version=True, ecosystem="py"),
    _Pin("AAK-MCP-9ROUTER-CVE-2026-46339-001", "9router", ("9router",), (0, 5, 2),
         fix_label="0.5.2"),
    _Pin("AAK-MCP-N8NMCP-CVE-2026-54052-001", "n8n-mcp", ("n8n-mcp",), (2, 57, 4),
         fix_label="2.57.4"),
    # Floor raised 1.17.1 -> 1.20.0 on 2026-09-16 for CVE-2026-55837: the local
    # OAuth helper serves GET /dbt_platform_context unauthenticated with no Host
    # validation, handing out access and refresh tokens. 1.17.1 through 1.19.x
    # were vulnerable and, at the old floor, silent.
    _Pin("AAK-MCP-DBTMCP-CVE-2026-44968-001", "dbt-mcp", ("dbt-mcp",), (1, 20, 0),
         fix_label="1.20.0"),
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
    # AAK-MCP-WHATSAPP-CVE-2026-46555-001 was a row here on the name `whatsapp-mcp`,
    # and it is a `_RepoPin` below since 2026-10-17: npm's and PyPI's packages of
    # that name are other projects, so no upgrade of either could clear it.
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
    # 2.30.x line) and affects only from 2.27.0. One row: the mainline range is
    # bounded by `introduced`, and 2.30.0, which sorts above the 2.29.8 floor, is an
    # `also` range, so patched releases on either branch clear. It was two rows, one
    # per branch, until 2026-10-16, and an unversioned n8n was reported twice.
    _Pin("AAK-MCP-N8N-CVE-2026-65594-001", "n8n", ("n8n",), (2, 29, 8),
         introduced=(2, 27, 0), also=(((2, 30, 0), (2, 30, 1)),),
         fix_label="2.29.8 / 2.30.1"),
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
    # versions affected, so no `introduced` bound). CVE-2026-55786 (the HTTP MCP
    # route runs `execute_module` unauthenticated, 2.26.2 to 2.26.3, fixed 2.26.4)
    # sits under the same floor and joined the rule with no row change.
    _Pin("AAK-MCP-FLYTO-CVE-2026-67425-001", "flyto-core", ("flyto-core",),
         (2, 26, 6), fix_label="2.26.6"),
    # --- 2026-07-30..31 wave ---
    # IBM Langflow OSS (`langflow`, PyPI) 1.0.0–1.10.1: the MCP stdio launcher's
    # DANGEROUS_ENV_VARS blocklist (`src/lfx/base/mcp/util.py`) omits SHELLOPTS /
    # BASHOPTS / PS4 → unauthenticated env-var-injection RCE (CVE-2026-12940,
    # CRITICAL 9.8). Fixed 1.11.0 (the first release after the affected 1.10.1;
    # introduced-bounded at 1.0.0 so pre-MCP 0.x releases clear).
    # Floor raised 1.11.0 -> 1.11.3 for CVE-2026-9186 (HIGH 6.5): Langflow OSS
    # 1.0.0-1.11.2 trusts a spoofed `X-Forwarded-For: 127.0.0.1` to satisfy its
    # localhost-only guard on MCP-config installation, so a remote authenticated
    # caller writes arbitrary IDE config files (`~/.cursor/mcp.json` and friends).
    # 1.11.0 through 1.11.2 are exposed to it, so the old floor would have marked
    # three vulnerable releases patched. Same package, same rule, higher floor --
    # the `@apify` shape; a second pin on the name would report one dependency
    # twice. CVE-2026-85025 / -78575 / -81941 (1.0.0-1.11.5) then took it to
    # 1.11.6, and CVE-2026-101861 (CVSS 4.1) takes it to 1.12.0: an authenticated
    # caller's Tool-Mode input options reach `eval()` in schema.py when a component
    # becomes a LangChain tool, 1.0.16-1.11.6 per GHSA-33p4-w7j3-33mw. 1.11.6 is the
    # only release the new floor adds, and it is reported at this rule's CRITICAL.
    # CVE-2026-105697, -105740, -105741 and -105699 (2026-10-06) are fixed in
    # 1.10.3 and 1.9.x, under the floor, so they join the rule with no floor change.
    # 105697 names `langflow-base` 0.10.3 and `lfx` 1.10.3 too, and
    # GHSA-33p4-w7j3-33mw scopes both below 1.12.0, the version all three reached
    # together on 2026-09-01. So the rule reads them at 1.12.0 as well: one rule,
    # three pins, the @agenticmail shape.
    _Pin("AAK-MCP-LANGFLOW-CVE-2026-12940-001", "langflow", ("langflow",),
         (1, 12, 0), introduced=(1, 0, 0),
         fix_label="1.12.0 (affected 1.0.0–1.11.6)",
         ecosystem="py"),
    _Pin("AAK-MCP-LANGFLOW-CVE-2026-12940-001", "langflow-base", ("langflow-base",),
         (1, 12, 0), fix_label="1.12.0 (its 0.x line, up to 0.11.6, is affected)",
         ecosystem="py"),
    _Pin("AAK-MCP-LANGFLOW-CVE-2026-12940-001", "lfx", ("lfx",),
         (1, 12, 0), fix_label="1.12.0 (affected below 1.12.0)",
         ecosystem="py"),
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
    # CVE-2026-55253 (HIGH 7.7) is the same defect in the *PyPI* distributions,
    # which the npm pin above does not see: MongoDBSaver.list/alist and
    # MongoDBStore.search fold caller-controlled filter dicts into the query
    # without recursively rejecting `$`-prefixed keys, so `$regex` / `$where`
    # defeat the equality filter a multi-tenant deployment relies on. Two
    # packages, two fix releases, so two pins rather than one.
    _Pin("AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001",
         "langgraph-checkpoint-mongodb",
         ("langgraph-checkpoint-mongodb",), (0, 3, 0), fix_label="0.3.0"),
    _Pin("AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001",
         "langgraph-store-mongodb",
         ("langgraph-store-mongodb",), (0, 4, 0), fix_label="0.4.0"),
    # langgraph-api < 0.10.0: a relative webhook target delivered over the
    # in-process loopback transport skips the external auth context, so an
    # authenticated user can create or modify a run on another user's thread.
    _Pin("AAK-MCP-LANGGRAPH-API-CVE-2026-55235-001", "langgraph-api",
         ("langgraph-api",), (0, 10, 0), fix_label="0.10.0"),
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
    # `@frontmcp/adapters` added 2026-09-19 for CVE-2026-59973: the OpenAPI
    # adapter's external-$ref guard checks hostname strings without resolving,
    # pinning or revalidating addresses. It ships from the same repo on the same
    # version line and was fixed in 1.5.0 -- at or below this 1.5.7 floor, so no
    # floor move is needed, only the name the pin was missing.
    _Pin("AAK-MCP-FRONTMCP-CVE-2026-67531-001",
         "frontmcp", ("frontmcp", "@frontmcp/adapters"), (1, 5, 7),
         fix_label="1.5.7", ecosystem="js"),
    # --- 2026-08-08 wave ---
    # langgraph-checkpoint-postgres / -sqlite (PyPI) < 3.1.1: namespaces stored as a
    # dot-joined string and read by simple prefix match → a scoped read spills into a
    # sibling namespace, cross-tenant checkpoint leak (CVE-2026-71433). Fixed 3.1.1.
    # Floors raised 2026-10-24 (#1091) for CVE-2026-115883, the same flattening: the
    # stores join namespace labels with "." and validated labels only on put and
    # aput, so a dotted label passed to get, search, delete or list_namespaces
    # reached another tenant's namespace (CVSS 4.0 6.0, GHSA-6hmw-9432-67qq). Checked
    # in the sdists: postgres 3.1.2 and sqlite 3.1.1 never call
    # `validate_op_namespace`; postgres 3.1.3 and sqlite 3.1.2 do (bfcfea55). The two
    # packages are fixed at different releases, so the row splits in two on the one
    # rule, one name each.
    _Pin("AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001",
         "langgraph-checkpoint-postgres", ("langgraph-checkpoint-postgres",),
         (3, 1, 3), fix_label="3.1.3"),
    _Pin("AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001",
         "langgraph-checkpoint-sqlite", ("langgraph-checkpoint-sqlite",),
         (3, 1, 2), fix_label="3.1.2"),
    # meta-ads-mcp (PyPI) < 1.0.109: AuthInjectionMiddleware forwards unauthenticated
    # requests without a 401, and a failed Graph API call serialises the request URL
    # (with the access_token) into the response → unauth tool invocation + token leak
    # (CVE-2026-48039, CVSS 9.1). Fixed 1.0.109.
    # Floor raised 1.0.109 -> 1.0.115 on 2026-09-19 for CVE-2026-54549:
    # upload_ad_image hands an attacker-controlled image_url to
    # try_multiple_download_methods(), where httpx.AsyncClient runs with
    # follow_redirects=True and validates neither scheme, host nor resolved IP,
    # and Meta credential validation happens only AFTER the download. 1.0.109
    # through 1.0.114 were vulnerable and, at the old floor, silent.
    _Pin("AAK-METAADS-CVE-2026-48039-001",
         "meta-ads-mcp", ("meta-ads-mcp",), (1, 0, 115), fix_label="1.0.115",
         ecosystem="py"),
    # --- 2026-08-09 wave ---
    # @adenot/mcp-google-search (npm) <= 0.3.1: the `read_webpage` tool
    # (`src/index.ts`) fetches the caller-supplied `url` argument with no host or
    # scheme validation → server-side request forgery to internal endpoints
    # (CVE-2026-19337, CVSS 5.3). Same SSRF-via-tool-argument shape as the astrbot
    # MCP-test-endpoint pin. No fixed release exists yet: the upstream patch (commit
    # f071d491) is unreleased, so every published version (0.1.0–0.3.1) is exposed —
    # floor=None (presence-only, fire on any match). The unscoped `mcp-google-search`
    # (latest 1.0.0) is an unrelated package by a different author and is NOT pinned:
    # the pin names the scoped package, and names match whole. Set the floor to the
    # fix version once upstream publishes a patched release.
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
    # (floor 2.32.1, no `introduced`). Names match whole, so the distinct `n8n-mcp`
    # package never reads as `n8n`.
    # Floor moved 2.32.1 -> 2.34.1 for CVE-2026-77068 (node-schema loader path
    # traversal -> RCE) and CVE-2026-77073 (cross-project credential reference).
    # This is already the highest of AAK's three n8n floors, so raising it here
    # keeps one authoritative floor instead of adding a fifth pin to a package that
    # would then report the same dependency five times. CVE-2026-77068 names two
    # lines ("before 2.33.4 and 2.34.x before 2.34.1"); a single 2.34.1 floor covers
    # both, and CVE-2026-77073 is "before 2.34.1" outright.
    # Floor moved again, 2.34.1 -> 2.35.4, for CVE-2026-85166: inline sub-workflow
    # JSON (the Workflow Tool node) is persisted without validating that the caller
    # owns the credentials it references, and MCP is one of the named write paths,
    # so a shared-workflow editor plants a node that resolves someone else's secret
    # when the workflow next runs under an identity holding it.
    #
    # Two arms, not one, and the second is the whole point. NVD reads "before
    # 2.35.4 and 2.36.x before 2.36.2" -- a lone 2.35.4 floor clears 2.36.0 and
    # 2.36.1, which are *vulnerable*, because they sort above it. That was the shape
    # then used for CVE-2026-65594 above: same rule_id, one arm per fix line, the
    # second bounded by `introduced` so 2.36.2+ clears and nothing below 2.36.0
    # ever reaches it. Both fix versions are published on npm (latest 2.37.10).
    #
    # Floor moved again, 2.35.4 -> 2.41.4, for CVE-2026-110842 (HIGH, CVSS 4.0 7.7,
    # GHSA-5jr4-xmvf-frmj): the MCP server's workflow-validation tool, present at
    # 2.30.0, 2.35.4, 2.36.2 and 2.41.3, runs an AST interpreter that gains its
    # built-in prototype guards in 2.41.4 and, on the 2.42.x line, in 2.42.1. The
    # 2.36.x line now sits below the floor, so the branch range is 2.42.0, which
    # sorts above it. It is an `also` range on one row: the two rows reported an
    # unversioned n8n twice.
    _Pin("AAK-MCP-N8N-CVE-2026-72768-001", "n8n", ("n8n",), (2, 41, 4),
         also=(((2, 42, 0), (2, 42, 1)),), fix_label="2.41.4 / 2.42.1"),
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
    # Names match whole, so `letta-client` (a real, separate client SDK) and
    # `pyletta` are not read as `letta`; the old unbounded pattern matched both.
    _Pin("AAK-MCP-LETTA-CVE-2025-51482-001", "letta",
         ("letta",), (0, 16, 5),
         fix_label="0.16.5 (first release past every affected version)"),
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
         (0, 8, 64), fix_label="0.8.64"),
    _Pin("AAK-MCP-CODEWHALE-CVE-2026-75858-001", "deepseek-tui", ("deepseek-tui",),
         (0, 8, 41), fix_label="0.8.41 (deprecated — migrate to codewhale >= 0.8.64)"),
    # --- 2026-08-19 wave ---
    #
    # marimo: a notebook's own MCP server entry carries an attacker-controlled
    # `command` that marimo launches as a subprocess when the notebook is opened in
    # edit mode -- before any cell runs and with no authentication. This is AAK's own
    # stdio-launcher shape arriving through a notebook file rather than an MCP config.
    #
    # No `introduced` bound, deliberately. NVD says "before 0.23.15" with no lower
    # bound, and the advisory database independently carries two other pip-ecosystem
    # marimo CVEs at `< 0.23.0` (GHSA-2679-6mx9-h9xc, pre-auth RCE) and `< 0.23.9`
    # (GHSA-8m59-7xv8-735h, reflected XSS), so "any marimo below 0.23.15 is exposed"
    # is a true statement about the package rather than an over-reach on this one CVE.
    # ecosystem="py": npm carries an unrelated `marimo` test runner (lawrips/marimo,
    # 0.0.1 to 1.6.1 with no 0.23.x at all). An old-npm-marimo hit was once "the
    # accepted cost" of covering three real pip CVEs on the same name; scoping the
    # pin to PyPI means there is no longer a cost to accept.
    _Pin("AAK-MCP-MARIMO-CVE-2026-75149-001", "marimo", ("marimo",),
         (0, 23, 15), fix_label="0.23.15", ecosystem="py"),
    # --- 2026-08-21 wave ---
    #
    # omnigent: PUT /sessions/{id}/agent checks LEVEL_EDIT on the session but does
    # not reject a bound shared/template agent whose agent.session_id is None, so
    # an editor swaps the shared bundle, adds a stdio MCP server, and every later
    # session using that shared agent launches an attacker-chosen command.
    # GHSA-jrrm-9hc7-2v3h: pip `omnigent` < 0.3.0, patched 0.3.0.
    # ecosystem="py": npm carries an unrelated `omnigent` agent platform whose
    # only release is 2.0.0, well above this floor either way.
    _Pin("AAK-MCP-OMNIGENT-CVE-2026-62674-001", "omnigent", ("omnigent",),
         (0, 3, 0), fix_label="0.3.0", ecosystem="py"),
    # --- 2026-08-20 wave ---
    #
    # neo.mjs: command injection in the file-system MCP server (checkSyntax /
    # runPlaywrightTest interpolate a caller-controlled absolutePath into a shell
    # command). floor=None, and the reason is checked rather than assumed: the fix
    # is commit 88c77fc dated 2026-08-11, and npm's own publish timeline shows no
    # neo.mjs release after 2026-07-03 (13.1.0 is latest on both npm and GitHub
    # releases). The fix exists in git and has never shipped, so there is no version
    # to pin to and every published release is affected. Convert to a floor the day
    # a release containing 88c77fc appears -- this is a placeholder, unlike the
    # mcp-florence2 pin below whose vendor has ruled a source fix out entirely.
    _Pin("AAK-MCP-NEOMJS-CVE-2026-18482-001", "neo.mjs", ("neo.mjs",), None,
         fix_label="no released fix yet — the fix commit (88c77fc, 2026-08-11) "
                   "postdates the newest published release (13.1.0)"),
    # LangBot: any authenticated user can set an STDIO MCP server `command`, which
    # StdioServerParameters starts as a subprocess on the LangBot host. floor=None
    # because there is no fix: GHSA-3pvh-63gf-j9mw records `patched: null`, NVD
    # states no fixed version is available, and 4.10.8 (published 31 minutes after
    # the CVE) is a WeCom media-delivery patch whose notes claim no security fix.
    # The remediation is therefore an authorization control, not an upgrade.
    _Pin("AAK-MCP-LANGBOT-CVE-2026-54449-001", "langbot", ("langbot",), None,
         fix_label="no fixed release — restrict who may configure STDIO MCP servers "
                   "rather than waiting for a version bump"),
    # --- 2026-08-26 wave ---
    # Five of thirteen watcher-filed CVEs that resolve to a real artifact on a
    # registry this detector reads. The other eight are recorded out of scope or
    # already covered in CHANGELOG.cves.md; the deciding question was never
    # severity, it was whether the vulnerable thing is published where we look.
    _Pin("AAK-MCP-QWED-CVE-2026-55546-001", "qwed-mcp", ("qwed-mcp",), (0, 2, 1),
         fix_label="0.2.1"),
    _Pin("AAK-MCP-NEXTCLOUD-CVE-2026-55640-001", "nextcloud-mcp-server",
         ("nextcloud-mcp-server",), (0, 117, 2), fix_label="0.117.2"),
    _Pin("AAK-MCP-BROWSEMCP-CVE-2026-55557-001", "browse-mcp", ("browse-mcp",),
         (0, 8, 2), fix_label="0.8.2"),
    _Pin("AAK-MCP-GENIEACS-CVE-2026-55637-001", "genieacs-mcp", ("genieacs-mcp",),
         (0, 3, 2), fix_label="0.3.2"),
    # One CVE, two npm packages, different floors — the @agenticmail shape.
    _Pin("AAK-MCP-SUBLINEAR-CVE-2026-55609-001", "sublinear-time-solver",
         ("sublinear-time-solver",), (1, 6, 0), fix_label="1.6.0"),
    _Pin("AAK-MCP-SUBLINEAR-CVE-2026-55609-001", "consciousness-explorer",
         ("consciousness-explorer",), (1, 1, 2), fix_label="1.1.2"),
    # --- 2026-08-27..31 wave (deferred 2026-09-03, shipped 2026-09-04) ---
    # Two pins closing nine watcher-filed issues. Both were held under
    # `cve-deferred` with a dated target rather than shipped blind, and both were
    # released by a registry lookup rather than by the clock.
    #
    # MCPHub: eight advisories against one product (CVE-2026-79743..79750), fixed
    # across 0.12.13, 0.12.15, 1.0.29, 1.0.30, 1.0.31 and 1.0.32. One floor at the
    # highest of those covers all eight, which is why this is one pin and not
    # eight: reporting a single dependency eight times is noise, not coverage.
    _Pin("AAK-MCP-MCPHUB-CVE-2026-79748-001", "@samanhappy/mcphub",
         ("@samanhappy/mcphub",), (1, 0, 32), fix_label="1.0.32"),
    _Pin("AAK-MCP-SEQTHINKING-CVE-2026-81845-001", "mcp-sequential-thinking",
         ("mcp-sequential-thinking",), (0, 6, 0), fix_label="0.6.0"),
    # --- 2026-09-04..07 wave (deferred 2026-09-06, shipped 2026-09-08) ---
    # Seven watcher-filed issues close on these five pins plus the langflow floor
    # raise above. Every one was held under `cve-deferred` on the reading that a
    # bug inside a third-party server's own binary has no consumer-side signal --
    # true of the *defect*, and false of the *dependency*, which is the thing this
    # module pins. Registry lookups changed two of the five outcomes.
    #
    # ToolUniverse (PyPI `tooluniverse`) through 1.2.6: `python_code_executor`
    # deny-lists attribute names while leaving the attribute-lookup builtins
    # reachable, so a caller walks from a literal's class to its base and
    # enumerates subclasses to reach `subprocess`; the HTTP and MCP servers bind
    # every interface with debugging on and no authentication, so reaching the
    # port is enough. 1.3.0 adds bearer-token auth, defaults the bind to loopback,
    # and hardens the attribute checks. The *generic* deny-list-sandbox detector
    # is a separate rule to design and is tracked on its own issue; this pin is
    # the part that is true today for anyone who depends on the package.
    _Pin("AAK-MCP-TOOLUNIVERSE-CVE-2026-81096-001", "tooluniverse", ("tooluniverse",),
         (1, 3, 0), fix_label="1.3.0 (affected up to 1.2.6)"),
    # IBM ContextForge MCP Gateway (PyPI `mcp-contextforge-gateway`) <= 1.0.8.
    # One floor, four CVEs, four issues: CVE-2026-18905 (DNS rebinding during tool
    # invocation, <= 1.0.6), CVE-2026-18486 (improper jq filter validation leaking
    # credentials, <= 1.0.7), CVE-2026-18489 (Translate utility exposing data to
    # the wrong session, <= 1.0.8) and CVE-2026-77822 (DNS rebinding via the A2A
    # invoke endpoint, <= 1.0.8).
    #
    # 1.0.9 came from IBM's own bulletin, and it had to: NVD carries no CPE range
    # for CVE-2026-77822 at all, and the project's GitHub advisory list stops at a
    # v1.0.8 patched-version. A floor inferred from either source alone would have
    # shipped one release short and called four vulnerable installs patched.
    #
    # Five more have since joined below the floor, no row change: CVE-2026-53710
    # (1.0.2), CVE-2026-78573 (1.0.8), CVE-2026-53709 (a published default JWT key
    # and the platform-admin bootstrap, fixed 1.0.2), CVE-2026-53711 (an Admin UI
    # stored XSS, fixed 0.3.1) and CVE-2026-8355 (OAuth gateway registration posts
    # to a caller's token URL, fixed 1.0.6). No `introduced`, so every one of them
    # fires. The image the README runs has a row in `container_image_pins`.
    _Pin("AAK-MCP-CONTEXTFORGE-CVE-2026-77822-001", "mcp-contextforge-gateway",
         ("mcp-contextforge-gateway",), (1, 0, 9),
         fix_label="1.0.9 (affected <= 1.0.8)"),
    # Postgres MCP Pro (PyPI `postgres-mcp`) 0.3.0: restricted ("read-only") mode
    # applies function-name validation to plain function calls but not to
    # RangeFunction nodes, so `pg_read_file` reached through FROM-clause syntax
    # reads arbitrary files despite the restriction.
    #
    # There is no fixed release. Upstream's newest tag is v0.3.0 (2025-05-16) and
    # crystaldba/postgres-mcp#178 -- the security issue itself -- is still open, so
    # every published version of this distribution is affected. The separate PyPI
    # name `postgres-mcp-pro` (0.4.0-0.4.2) carries the product's marketing name
    # and the same summary string but declares no repository and is not referenced
    # by the upstream project, so it is deliberately NOT offered as the upgrade
    # target: pointing users at an unverified same-named package is the failure
    # mode this detector exists to catch, not one to commit.
    #
    # The floor is 0.4.0 rather than `None` (presence-only) for one reason: npm
    # carries an unrelated `postgres-mcp` -- a type-safe multi-database MCP server
    # on the 1.0.x line -- and a presence-only pin would flag every dependent of
    # that project, permanently, for someone else's CVE. That is the MCPHub trap.
    # A 0.4.0 floor separates the two by version line: every release of the
    # vulnerable 0.x distribution fires, and the npm project's 1.0.x never does.
    _Pin("AAK-MCP-POSTGRESMCP-CVE-2026-85620-001", "postgres-mcp", ("postgres-mcp",),
         (0, 4, 0),
         fix_label="no fixed release — upstream issue #178 is open and v0.3.0 is "
                   "still the newest tag; stop treating restricted mode as a "
                   "security boundary and use a least-privilege database role"),
    # Amazon awslabs postgres-mcp-server (PyPI) before 1.1.7: the SQL validation
    # component's disallowed-input list is incomplete, so crafted SQL reaching it
    # through content an authenticated user interacts with writes beyond the
    # read-only scope. Vendor fix is 1.1.7.
    _Pin("AAK-MCP-AWSPOSTGRES-CVE-2026-85787-001", "awslabs.postgres-mcp-server",
         ("awslabs.postgres-mcp-server",), (1, 1, 7), fix_label="1.1.7"),
    # knowns (npm, knowns-dev) before 0.30.0: the MCP doc and memory tools take a
    # filesystem path straight from tool arguments without confining it to the
    # project directory, so traversal sequences read, create, overwrite and delete
    # files anywhere the server process can reach. Fixed in v0.30.0.
    #
    # `introduced=(0, 1, 1)` is not a range statement -- every release before
    # 0.30.0 is affected -- it resolves a name collision. PyPI carries an unrelated
    # `knowns` whose only release is 0.1.0 ("Add your description here"), and npm's
    # own history also starts at 0.1.0, so the two overlap at exactly one version.
    # Bounding at 0.1.1 keeps the pin off the PyPI stub at the cost of npm's single
    # 0.1.0 release -- the cheaper of the two errors, since 86 of the real
    # project's 87 published versions still fire.
    # CVE-2026-88938 (2026-09-10) reopened the same class on the `code.find` tool
    # and is scoped "through 0.33.0", then the newest release (npm, 2026-09-05).
    # Its advisory, GHSA-5cj9-fcqq-g2h7, names no patched version. npm published
    # 0.34.0 and 0.34.1 on 2026-09-22 and 2026-09-28, and neither the advisory nor
    # NVD says whether they fix it, so the floor stays None and the pin stays
    # presence-only until a fixed release is named, the same as `postgres-mcp` and
    # `mcp-florence2` above. The label names the advisory's range, not a newest
    # release, which goes stale with every publish (it read "0.33.0 is newest"
    # for three weeks after 0.34.0). The 0.1.1 `introduced` bound still matters
    # and is still honoured -- see the ordering note in `_fires`.
    _Pin("AAK-MCP-KNOWNS-CVE-2026-86439-001", "knowns", ("knowns",), None,
         introduced=(0, 1, 1),
         fix_label="no release yet: GHSA-5cj9-fcqq-g2h7 names no patched version, "
                   "and CVE-2026-88938 covers every release through 0.33.0"),
    # --- 2026-09-10..11 wave ---
    # AWS Security Agent MCP server (PyPI) before 0.2.0 writes scan output to an S3
    # bucket it never verifies the ownership of, and the bucket name derives from a
    # publicly known account id. Vendor fix is 0.2.0; latest is 0.2.1.
    _Pin("AAK-MCP-AWSSECAGENT-CVE-2026-87913-001", "awslabs.security-agent-mcp-server",
         ("awslabs.security-agent-mcp-server",), (0, 2, 0), fix_label="0.2.0"),
    # --- 2026-09-15..16 wave (dispositioned 2026-09-19) ---
    #
    # mysql-mcp-server (PyPI) < 0.4.2: with MCP_TRANSPORT=sse, server.py builds
    # SseServerTransport with neither security_settings nor
    # enable_dns_rebinding_protection, the Starlette routes /, /sse and
    # /messages/ carry no authentication, and the service binds 0.0.0.0 by
    # default. execute_sql is then reachable directly from the network, or via
    # DNS rebinding through a victim's browser. With FILE privileges on the
    # MySQL account the same access reads and writes server files. The default
    # stdio transport is unaffected (CVE-2026-59971, CVSS 10.0).
    _Pin("AAK-MCP-MYSQLMCP-CVE-2026-59971-001", "mysql-mcp-server",
         ("mysql-mcp-server", "mysql_mcp_server"), (0, 4, 2), fix_label="0.4.2",
         ecosystem="py"),
    # praisonai (npm) < 1.7.2 -- the TypeScript framework, NOT the 4.6.x PyPI
    # package of the same name pinned above. MCPServer.startHttp() in
    # src/praisonai-ts/src/mcp/server.ts binds with no host restriction and
    # forwards every POST to handleRequest() with no authentication, so any
    # network client reaches tools/call, resources/read and prompts/get with
    # server-side credentials (CVE-2026-57139, CVSS 9.8). NVD gives the range as
    # 1.5.0 until 1.7.2 and calls 1.7.2 an initial remediation, so the floor is
    # 1.7.2 and not a later release.
    _Pin("AAK-MCP-PRAISONAI-TS-CVE-2026-57139-001", "praisonai (npm, TypeScript)",
         ("praisonai",), (1, 7, 2), fix_label="1.7.2", ecosystem="js"),
    # @zereight/mcp-gitlab: three CVEs, one pin at the highest floor. 2.1.27
    # fixes CVE-2026-61560 (SSE=true exposes every tool unauthenticated, and
    # upload_markdown reads any local file via an unsanitised file_path, so
    # /proc/self/environ yields GITLAB_PERSONAL_ACCESS_TOKEN -- the default for
    # Docker deployments) and CVE-2026-61559 (ENABLE_DYNAMIC_API_URL=true makes
    # the server trust the X-GitLab-API-URL request header as the outbound base
    # URL with no allowlist, attaching the victim's Private-Token to a request
    # aimed at an attacker's host). 2.1.30 fixes CVE-2026-61568 (Streamable HTTP
    # with no effective Host/Origin allowlist, so DNS rebinding reaches the MCP
    # init path). 2.1.30 is the higher, and a second pin on the same name would
    # report one dependency twice.
    _Pin("AAK-MCP-GITLAB-ZEREIGHT-CVE-2026-61560-001", "@zereight/mcp-gitlab",
         ("@zereight/mcp-gitlab",), (2, 1, 30), fix_label="2.1.30",
         ecosystem="js"),
    # flowise (npm) < 3.1.4: two authenticated-RCE paths through the Custom MCP
    # node, both fixed in the same release. CVE-2026-91931 takes npx package
    # names from mcpServerConfig and invokes npx on attacker-chosen npm
    # packages; CVE-2026-91932 bypasses the path validation with a clean
    # filename in args while controlling cwd. One floor, two CVEs.
    _Pin("AAK-MCP-FLOWISE-CVE-2026-91931-001", "flowise", ("flowise",),
         (3, 1, 4), fix_label="3.1.4", ecosystem="js"),
    # mcp-from-openapi (npm) < 2.5.0: the same external-$ref SSRF as
    # CVE-2026-59973's frontmcp half, but on its own 2.x version line, so the
    # frontmcp pin's 1.5.7 floor cannot express it. loadOpenAPISpec() forwards
    # untrusted url/spec and refResolution into OpenAPIToolGenerator, whose
    # guard compares hostname strings without resolving addresses, pinning the
    # validated address, revalidating redirect targets, or normalising
    # IPv4-mapped IPv6 -- so DNS-to-loopback, redirect-to-loopback and ::ffff:
    # forms all reach internal services from the backend origin.
    _Pin("AAK-MCP-FROMOPENAPI-CVE-2026-59973-001", "mcp-from-openapi",
         ("mcp-from-openapi",), (2, 5, 0), fix_label="2.5.0", ecosystem="js"),
    # --- 2026-09-15..18 wave (dispositioned 2026-09-24) ---
    #
    # Contentful ships the defect in two packages on two different version
    # lines, so one rule_id carries two pins — the AgenticMail shape above.
    # export_space/import_space expose host, proxy, rawProxy and insecure to
    # LLM-controlled tool arguments and combine them with the server's
    # CONTENTFUL_MANAGEMENT_TOKEN, so a direct call or prompt injection through
    # attacker-controlled Contentful content redirects the Management API
    # request, and its Authorization header, to a host of the attacker's
    # choosing. The regular tools pin the host from server config and are
    # unaffected (CVE-2026-53957, CVSS 7.7, CWE-918).
    _Pin("AAK-MCP-CONTENTFUL-CVE-2026-53957-001", "@contentful/mcp-server",
         ("@contentful/mcp-server",), (1, 7, 19), fix_label="1.7.19",
         ecosystem="js"),
    _Pin("AAK-MCP-CONTENTFUL-CVE-2026-53957-001", "@contentful/mcp-tools",
         ("@contentful/mcp-tools",), (0, 4, 5), fix_label="0.4.5",
         ecosystem="js"),
    # mcp-searxng < 1.7.1: checkContentLength() treats a missing Content-Length
    # header as an inconclusive preflight, and both the normal and the error
    # path then consume the whole body with response.text(). A server that omits
    # the header bypasses URL_READ_MAX_CONTENT_LENGTH_BYTES entirely; the string
    # is then fed to NodeHtmlMarkdown.translate(), so an unauthenticated caller
    # reaches unbounded memory and CPU (CVE-2026-58483, CVSS 7.5, CWE-400).
    _Pin("AAK-MCP-SEARXNG-CVE-2026-58483-001", "mcp-searxng", ("mcp-searxng",),
         (1, 7, 1), fix_label="1.7.1", ecosystem="js"),
    # atomic-agents-stack < 1.1.0: the HTTP MCP server-registry backend factory
    # accepts cleartext http:// schemes, so a network attacker rewrites the
    # catalog response and injects command and argv values that MCPClientPool
    # spawns as local subprocesses (CVE-2026-91988, CVSS 8.1, CWE-319). The same
    # distribution appears in the 2026-08-16 section for an unrelated dashboard
    # path traversal that never received a CVE id.
    _Pin("AAK-MCP-ATOMICAGENTS-CVE-2026-91988-001", "atomic-agents-stack",
         ("atomic-agents-stack",), (1, 1, 0), fix_label="1.1.0", ecosystem="py"),
    # netlicensing-mcp < 0.1.6: a /mcp request omitting x-netlicensing-api-key,
    # Authorization: Bearer and the apikey query parameter passes straight
    # through ApiKeyMiddleware, and api_key_ctx then falls back to the
    # operator's NETLICENSING_API_KEY — so an unauthenticated caller drives
    # every licensing tool, including the destructive ones, as the operator
    # (CVE-2026-54446, CVSS 8.1, CWE-306).
    # Floor raised 0.1.6 -> 0.1.8, and the rule to CRITICAL, for CVE-2026-57496
    # (CVSS 9.6): netlicensing_get_product puts the caller's product_number into
    # the REST path unchecked, so `../token` reaches the token endpoint and returns
    # API keys and shop URLs in plaintext. Every release before 0.1.8 has the
    # unchecked path; 0.1.8 (b8fd0ea) validates each segment. The ghcr.io and
    # Docker Hub images are rows in `container_image_pins`. `latest` is 0.1.10 and
    # the README runs an unpinned `uvx netlicensing-mcp`, so a stated version is now
    # required.
    _Pin("AAK-MCP-NETLICENSING-CVE-2026-54446-001", "netlicensing-mcp",
         ("netlicensing-mcp",), (0, 1, 8),
         fix_label="0.1.8 (CVE-2026-57496; CVE-2026-54446 was fixed in 0.1.6)",
         requires_version=True, ecosystem="py"),
    # --- 2026-09-26 wave ---
    # mcp-remote 0.1.32-0.1.38 fetches the `resource_metadata` URL a remote
    # server puts in its WWW-Authenticate header with no destination policy
    # (CVE-2026-51994, CVSS 9.1, CWE-918), and in the same range fetches an
    # authorization server's well-known metadata from an unvalidated origin
    # (CVE-2026-51995). From 0.1.16, the release that added a URL check for
    # CVE-2025-6514, that check lets loopback, private and metadata addresses
    # through to the browser launch (CVE-2026-51997), so `introduced` is 0.1.16:
    # the union of the advisory ranges. CVE-2026-51996 (MD5-derived names for the
    # per-server OAuth state files, `getServerUrlHash`) is scoped 0.1.16-0.1.38
    # by NVD, inside that union, so it moved nothing, and neither did
    # CVE-2026-52001 (#921: the SSE transport's `eventSourceInit` fetch wrapper
    # adds the bearer token with no origin check of its own), scoped 0.1.18-0.1.38.
    # `requires_version` keeps unpinned references out.
    _Pin("AAK-MCP-REMOTE-CVE-2026-51994-001", "mcp-remote", ("mcp-remote",), (0, 1, 39),
         introduced=(0, 1, 16),
         fix_label="a release outside 0.1.16–0.1.38 (upstream names no fix)",
         requires_version=True, ecosystem="js"),
    # Kimi Code <= 0.31.0 spawns a workspace's `.mcp.json` servers before asking
    # whether the workspace is trusted (CVE-2026-95660, CVSS 6.3, CWE-77/78).
    _Pin("AAK-MCP-KIMICODE-CVE-2026-95660-001", "@moonshot-ai/kimi-code",
         ("@moonshot-ai/kimi-code",), (0, 31, 1), fix_label="0.31.1", ecosystem="js"),
    # --- 2026-10-02 wave ---
    # pi-llm-wiki's wiki_capture_source MCP tool hands its `url` argument to
    # `sh -c "uvx ... markitdown \"${source}\""` (CVE-2026-102911, CVSS 9.9,
    # CWE-77/78). 0.11.8 calls markitdown with an argv list instead (fix
    # 36086703). NVD says "up to 0.11.7" with no lower bound, and the shell call
    # is in the upstream source from 2026-05-11, so there is no `introduced`.
    _Pin("AAK-MCP-PILLMWIKI-CVE-2026-102911-001", "@zosmaai/pi-llm-wiki",
         ("@zosmaai/pi-llm-wiki",), (0, 11, 8), fix_label="0.11.8",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-03 wave ---
    # fast-mcp-telegram's attachment download checks the URL's literal hostname
    # in `_validate_url_security` and never resolves it, then httpx resolves the
    # name itself (CVE-2026-55096, CVSS 7.1, CWE-918). 0.30.1 resolves first (fix
    # e6b3032c). NVD and the advisory print the fix as "30.1"; PyPI and the
    # GitHub tag say 0.30.1. No npm package of that name exists.
    _Pin("AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001", "fast-mcp-telegram",
         ("fast-mcp-telegram",), (0, 30, 1), fix_label="0.30.1",
         ecosystem="py"),
    # --- 2026-10-03 wave, second batch (#863-#867) ---
    # Office-PowerPoint-MCP-Server's save_presentation / open_presentation /
    # manage_image tools take any path (CVE-2025-71427, CVSS 6.8, CWE-22, "through
    # 2.0.7"). No fixed release: 2.0.7 (2025-12-31) is the newest on PyPI and the
    # fix, upstream PR #33, is unmerged, so floor=None (presence-only). npm has no
    # package of that name. Give the pin a floor once a fixed release ships.
    _Pin("AAK-MCP-OFFICEPPT-CVE-2025-71427-001", "office-powerpoint-mcp-server",
         ("office-powerpoint-mcp-server",), None,
         fix_label="no fixed release (upstream PR #33 is unmerged and 2.0.7 is the "
                   "newest); confine the server to a scratch directory meanwhile",
         ecosystem="py"),
    # @penpot/mcp's plugin WebSocket bridge is `new WebSocketServer({ port })` with
    # no host, so it listens on every interface, unauthenticated in single-user
    # mode (CVE-2026-100868, CVSS 6.3, GHSA-ch2q-6x56-qg5r). The fix, b5274a44
    # (2026-09-22), is in Penpot's 2.18.0 tag, but that tag's mcp/package.json still
    # reads 2.17.0 (penpot/penpot#12007) and npm has no build from it. npm's own
    # 2.17.0 (2026-07-08) predates the fix, and `latest` is 2.15.4: both affected,
    # re-checked from the tarball on 2026-10-04. A fixed npm build numbered below
    # 2.18.0 would be reported until this floor follows it (#872). A rule of its
    # own, not a raised floor on the 45805 pin above: that one is a CRITICAL RCE
    # fixed in 2.15.0, and raising its floor would report 2.15.0-2.17.x as critical.
    _Pin("AAK-MCP-PENPOT-CVE-2026-100868-001", "@penpot/mcp", ("@penpot/mcp",),
         (2, 18, 0),
         fix_label="Penpot 2.18.0, but no npm build has been published from that "
                   "tag yet (its mcp/package.json reads 2.17.0, penpot/penpot#12007, "
                   "and npm's 2.17.0 predates the fix); meanwhile firewall the plugin "
                   "WebSocket port, 4402 by default"),
    # --- 2026-10-03 wave, third batch (#879-#883) ---
    # VoiceMode's update_config MCP tool writes the caller's value into
    # ~/.voicemode/voicemode.env, which the service scripts `source`; before 8.10.2
    # a value was at best double-quoted, which does not stop `$(...)`
    # (CVE-2026-79535, CVSS 6.3, CWE-78, GHSA-h97v-r3jw-cf6f). Checked in the
    # wheels: 8.10.2's `_format_env_value` single-quotes anything not shell-inert.
    _Pin("AAK-MCP-VOICEMODE-CVE-2026-79535-001", "voice-mode", ("voice-mode",),
         (8, 10, 2), fix_label="8.10.2", ecosystem="py"),
    # @0xshariq/github-mcp-server builds git commands as strings and runs them with
    # child_process.exec: `gitRemove(file)` is `git reset HEAD "${file}"`
    # (CVE-2026-102906, CVSS 6.3, CWE-77/78). Checked in the npm tarballs: 2.0.0 and
    # 2.5.0 (the newest) both have it. Upstream has not answered issue #2 and there
    # is no fixed release, so floor=None (presence-only).
    _Pin("AAK-MCP-SHARIQ-GITHUB-CVE-2026-102906-001", "@0xshariq/github-mcp-server",
         ("@0xshariq/github-mcp-server",), None,
         fix_label="no fixed release (2.5.0 is the newest and upstream has not "
                   "answered); keep it away from agents that read untrusted text",
         ecosystem="js"),
    # OpenClaw's mcp.app.view issued standalone tickets that did not carry the
    # issuer's tool authority, so an operator.read token ran operator.write tools
    # (CVE-2026-102807, CVSS 5.3, CWE-863, GHSA-3xrq-g42v-gh57). The standalone host
    # (`src/gateway/mcp-app-standalone.ts`) is absent at v2026.7.1 and tools through
    # it arrived in 7c070d6 (first in 2026.7.2-beta.4, first stable 2026.8.1); the
    # fix, 3bd8ec2b, is in 2026.9.4 and not in extended-stable 2026.8.35. MEDIUM, so
    # its own rule beside the HIGH pin above rather than a raised floor.
    # npm only, as the pin above: the PyPI `openclaw` is another project.
    _Pin("AAK-MCP-OPENCLAW-CVE-2026-102807-001", "openclaw", ("openclaw",),
         (2026, 9, 4), introduced=(2026, 7, 2),
         fix_label="2026.9.4 (the 2026.8.x extended-stable line has no fix yet)",
         ecosystem="js"),
    # --- 2026-10-05 wave (#887-#896) ---
    # Zscaler MCP Server signs an HMAC confirmation token over a write tool's name
    # and arguments. From 0.7.0, 31 delete tools across ZIA, ZPA and ZTW passed an
    # empty parameter set to `check_confirmation()`, so a token issued for one
    # resource confirmed the delete of another of the same type (CVE-2026-59563,
    # CVSS 4.6, CWE-305). Checked in the wheels: 0.6.2 binds the arguments on every
    # call, 0.7.0 and 0.7.1 have the 31 empty calls, and 0.7.2
    # (zscaler/zscaler-mcp-server#41) passes each resource id.
    _Pin("AAK-MCP-ZSCALER-CVE-2026-59563-001", "zscaler-mcp", ("zscaler-mcp",),
         (0, 7, 2), introduced=(0, 7, 0),
         fix_label="0.7.2 (affected 0.7.0 and 0.7.1)",
         ecosystem="py"),
    # utcp-mcp dialed the HTTP and WebSocket MCP server URLs in a call template's
    # mcpServers as configured, so a plain-HTTP, non-loopback server got a
    # cleartext MCP handshake (CVE-2026-101057, CVSS 3.1, CWE-319). Checked in the
    # wheels: 1.1.3 adds `_ensure_secure_mcp_url` (HTTPS/WSS, or HTTP/WS to a
    # literal loopback address) before any connection, and 1.1.2 has no check.
    # AAK-TRANSPORT-001 does not see the template: it reads a top-level
    # mcpServers, and utcp nests it under the template's `config`.
    _Pin("AAK-MCP-UTCP-CVE-2026-101057-001", "utcp-mcp", ("utcp-mcp",),
         (1, 1, 3), fix_label="1.1.3", ecosystem="py"),
    # Google MCP Toolbox's Cloud Storage tools check local paths lexically
    # (`filepath.Clean`, later `filepath.Rel`) and never resolve symlinks, so a
    # link inside an allowed root reaches files outside it (CVE-2026-102242,
    # CVSS 4.0 8.6, CWE-22/59). `ValidateLocalPath` is in v1.2.0, and the fix,
    # googleapis/mcp-toolbox#3810 (`ResolveSymlinks`), is in v1.10.0 and not v1.9.0.
    # The server is a Go binary, but the docs register it with an MCP client as
    # the npm `@toolbox-sdk/server`, which runs the binary of its own version.
    _Pin("AAK-MCP-TOOLBOX-CVE-2026-102242-001", "@toolbox-sdk/server",
         ("@toolbox-sdk/server",), (1, 10, 0), introduced=(1, 2, 0),
         fix_label="1.10.0 (affected 1.2.0–1.9.0)",
         ecosystem="js"),
    # Next.js 16's `next dev` server serves an MCP endpoint that does not reliably
    # check where a request comes from, so a page the developer visits can read
    # the project's path on disk, source snippets from error reports, the route
    # inventory and the dev logs (CVE-2026-94486, CVSS 4.0 2.3, CWE-346,
    # GHSA-39w2-rjm5-chcv). Dev server only: production does not serve it. The MCP
    # middleware is absent at v15.5.7 and present from v16.0.0, and the fix,
    # 2d9f50a ("Fix MCP middleware DNS rebinding"), is in 16.3.8.
    _Pin("AAK-MCP-NEXTJS-CVE-2026-94486-001", "next", ("next",),
         (16, 3, 8), introduced=(16, 0, 0),
         fix_label="16.3.8 (dev server only; production builds do not serve the endpoint)",
         requires_version=True, ecosystem="js"),
    # Claude Code fetched the organization's server-managed settings with a stored
    # API key ahead of the session's Enterprise or Team sign-in, and when that key
    # was rejected the session ran without the org policy, or on a stale cached
    # copy (CVE-2026-103012, CVSS 4.0 2.0, CWE-696, GHSA-gfvf-j8jh-jxxw). Local
    # access only, and auto-update has delivered the fix. LOW, so its own rule
    # beside the HIGH folder-trust pin in `supply_chain` (below 2.1.83 then, below
    # 2.1.129 once CVE-2026-103435 joined it, below 2.1.179 since CVE-2026-86063).
    _Pin("AAK-MCP-CLAUDECODE-CVE-2026-103012-001", "@anthropic-ai/claude-code",
         ("@anthropic-ai/claude-code",), (2, 1, 260), introduced=(2, 0, 68),
         fix_label="2.1.260 (affected from 2.0.68)",
         requires_version=True, ecosystem="js"),
    # Claude Code before 1.0.111 could run code a project carried before the user
    # accepted the startup trust dialog (CVE-2025-59536, CVSS 4.0 8.7, CWE-94,
    # GHSA-4fgq-fpq9-mr3g; NVD's CPE range is `versionEndExcluding: 1.0.111`, and
    # 1.0.111 reached npm on 2025-09-10). The rule id is the one that fired on any
    # command in a committed settings.local.json, which cannot say whether a hook
    # runs before trust: the release decides that. Re-aimed here on 2026-10-17.
    _Pin("AAK-HOOK-RCE-003", "@anthropic-ai/claude-code",
         ("@anthropic-ai/claude-code",), (1, 0, 111),
         fix_label="1.0.111",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-05 wave, second batch (#900-#901) ---
    # langgraph-sdk's resource-scoped auth decorators (`@auth.on.threads`,
    # `.assistants`, `.crons`) took an `actions` argument and registered the
    # handler for every action anyway, so a narrow handler shadowed the broader
    # fallbacks and one authenticated user could read, update or delete another's
    # resource (CVE-2026-104873, CVSS 4.0 7.6, GHSA-fvww-7h3r-vfhp). Checked in the
    # wheels: `langgraph_sdk.auth` first ships in 0.1.45, 0.4.3's `_ResourceOn`
    # registers under "*" whatever `actions` says, and 0.4.4 registers each action.
    _Pin("AAK-MCP-LANGGRAPHSDK-CVE-2026-104873-001", "langgraph-sdk", ("langgraph-sdk",),
         (0, 4, 4), introduced=(0, 1, 45),
         fix_label="0.4.4 (affected from 0.1.45)",
         ecosystem="py"),
    # --- 2026-10-07 batch (#911-#915) ---
    # The MCP TypeScript SDK's OAuth client let the MCP server it connected to name
    # the authorization server that received the client's refresh token, client
    # secret or signed assertion (CVE-2026-104850, CVSS 3.1 7.5, CWE-345/522,
    # GHSA-6qxp-vccf-f47h). Checked in the tarballs: 1.11.5's client has no
    # protected-resource-metadata discovery, 1.12.0 adds it and reads the server's
    # `authorization_servers`, and 1.31.0 adds `expectedIssuer`, `issuersMatch` and
    # `discardIfIssuerMismatch`, which 1.30.1 lacks. On 2.x the client is its own
    # package, fixed in 2.2.0, which also pins `@modelcontextprotocol/core` 2.2.0.
    # One rule, two pins, like `@agenticmail`. Servers built on the SDK and stdio
    # clients are not affected, and the version cannot tell them apart.
    _Pin("AAK-MCP-TSSDK-CVE-2026-104850-001", "@modelcontextprotocol/sdk",
         ("@modelcontextprotocol/sdk",), (1, 31, 0), introduced=(1, 12, 0),
         fix_label="1.31.0 (affected from 1.12.0)",
         requires_version=True, ecosystem="js"),
    _Pin("AAK-MCP-TSSDK-CVE-2026-104850-001", "@modelcontextprotocol/client",
         ("@modelcontextprotocol/client",), (2, 2, 0),
         fix_label="2.2.0 (every 2.x release before it)",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-08 batch (#916-#921) ---
    # Payload's MCP plugin created its API-keys collection with no access rules,
    # so any authenticated user could manage keys outside their own account and
    # take another one over (CVE-2026-105806, CVSS 4.0 8.6, CWE-862,
    # GHSA-2q76-m6w6-qgc6). The plugin's first release is 3.61.0; 3.87.0's
    # `createApiKeysCollection` still declares no `access`, and 3.88.0 adds
    # user-scoped access rules (payloadcms/payload#17751).
    _Pin("AAK-MCP-PAYLOAD-CVE-2026-105806-001", "@payloadcms/plugin-mcp",
         ("@payloadcms/plugin-mcp",), (3, 88, 0), introduced=(3, 61, 0),
         fix_label="3.88.0 (affected from 3.61.0)",
         requires_version=True, ecosystem="js"),
    # LangChain.js's Redis vector store put filter values into RediSearch queries
    # without escaping them, so an attacker-influenced filter used as a tenant or
    # document boundary could widen the search (CVE-2026-105799, CVSS 4.0 2.3,
    # CWE-943, GHSA-5x6v-p487-7qh2). Checked in the tarballs: `buildCustomQuery`
    # interpolates TAG and TEXT values raw from 0.1.4, the structured `filters`
    # module ships in 1.1.0, and 1.1.1 (langchainjs#10701) also replaces the
    # partial `escapeSpecialChars` of the string-array path every release has.
    _Pin("AAK-MCP-LANGCHAIN-REDIS-CVE-2026-105799-001", "@langchain/redis",
         ("@langchain/redis",), (1, 1, 1),
         fix_label="1.1.1",
         requires_version=True, ecosystem="js"),
    # LangChain.js's MongoDBChatMessageHistory put the session id into
    # `findOne`/`updateOne`/`deleteOne` filters as given, so an object id became a
    # query condition and reached another user's conversation (CVE-2026-106119,
    # CVSS 4.0 6.0, CWE-943, GHSA-m6rx-h84q-8r95). Every release through 1.3.0
    # does this; 1.3.1 (langchainjs#11672) rejects a non-string id and wraps it in
    # `$eq`. The same shape as the checkpointer pin for CVE-2026-48121 above.
    _Pin("AAK-MCP-LANGCHAIN-MONGO-CVE-2026-106119-001", "@langchain/mongodb",
         ("@langchain/mongodb",), (1, 3, 1),
         fix_label="1.3.1",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-11 batch (#953-#959) ---
    # argocd-mcp puts `applicationName` into Argo CD API paths unencoded and resolves
    # them with `new URL`, so `../repositories/<repo>` turns delete_application into a
    # DELETE on another resource (CVE-2026-108585, CVSS 5.4, CWE-22). Checked in the
    # npm tarballs: 0.0.1 (the first release) and 0.9.0 (the newest, 2026-08-11)
    # both build `/api/v1/applications/${applicationName}`; 0.4.0 was published
    # without its dist/. No commit since 0.9.0, so floor=None (presence-only).
    _Pin("AAK-MCP-ARGOCD-CVE-2026-108585-001", "argocd-mcp", ("argocd-mcp",), None,
         fix_label="no fixed release (0.9.0 is the newest); set MCP_READ_ONLY=true "
                   "or use an Argo CD token that cannot delete",
         ecosystem="js"),
    # 1MCP Agent's scope check validates only the tags an advanced `tag-filter`
    # expression names, so `not <granted-tag>` passes and selects every other
    # backend (CVE-2026-108586, CVSS 5.4, CWE-863). Checked in the npm tarballs:
    # 0.19.0 has no `tag-filter`, 0.20.0 adds it with `extractTagsFromExpression`
    # as the check, and 0.39.0 (the newest, 2026-10-09) still has it. No fixed
    # release, so presence-only from 0.20.0.
    _Pin("AAK-MCP-1MCP-CVE-2026-108586-001", "@1mcp/agent", ("@1mcp/agent",), None,
         introduced=(0, 20, 0),
         fix_label="no fixed release (0.39.0 is the newest; affected from 0.20.0); "
                   "do not rely on tag scopes to keep backends apart",
         ecosystem="js"),
    # --- 2026-10-13 batch (#963, #973-#977) ---
    # The elvix MCP server built every tool's request URL as
    # `new URL(args.path ?? tool._meta.path, baseUrl)`, so an absolute URL in `path`
    # replaced the base and the request went out with the Bearer `ELVIX_API_KEY`
    # (CVE-2026-108542, CVSS 6.3, CWE-918). Checked in the npm tarballs: 0.1.0 and
    # 0.10.1 build it that way; 0.10.2 (ed0c622, 2026-08-30) binds the tool to its
    # manifest path and refuses another origin. 0.0.0 is an empty placeholder.
    _Pin("AAK-MCP-ELVIX-CVE-2026-108542-001", "@elvix.is/sdk", ("@elvix.is/sdk",),
         (0, 10, 2), introduced=(0, 1, 0),
         fix_label="0.10.2; rotate any elvix API key used with the MCP server",
         ecosystem="js"),
    # --- 2026-10-15 batch (#982-#986) ---
    # obsidian-tc's HTTP transport let any token reach every configured vault
    # (CVE-2026-77366, CVSS 9.9) and answered cross-origin requests on loopback
    # (CVE-2026-77363, CVSS 8.8), and three read-ACL gaps ride the same fix
    # (CVE-2026-77364, CVE-2026-77361, CVE-2026-77362). Checked in the npm
    # tarballs: 1.0.1, 1.0.2 and 1.2.1 resolve each tool's `vault` argument against
    # every vault and carry no Host or Origin check; 1.3.1 (38b4992, 6428bfe) has
    # both guards. There is no 1.3.0. 0.0.1 is a placeholder with no server, so the
    # pin starts at 1.0.0, and `latest` (1.33.1) is fixed, so a stated version is
    # required: the README's own config is an unpinned `npx -y obsidian-tc`.
    _Pin("AAK-MCP-OBSIDIANTC-CVE-2026-77366-001", "obsidian-tc", ("obsidian-tc",),
         (1, 3, 1), introduced=(1, 0, 0),
         fix_label="1.3.1 (affected 1.0.1 to 1.2.1)",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-15 second batch (#995-#999) ---
    # Junie CLI before 26.8.3 ran an untrusted project's MCP server configuration
    # (CVE-2026-111091, CVSS 7.8, CWE-829). The npm package is a launcher whose
    # version is the Junie build it installs (`junieVersion`), and 26.8.3 is build
    # 2548.5 (npm 2548.5.0, 2026-08-03). Checked in the builds: 888.112 and 2470.4
    # read `<project>/.junie/mcp/mcp.json`, and 2548.5 adds the trust prompt that
    # previews it. `@jetbrains/junie-cli` is the earlier name: below 888 it installed
    # the EAP builds of August 2025 to February 2026, which were not checked, and its
    # 1.0.0 is an empty placeholder, so the pin starts at 888.0.0. `latest` is
    # 3110.7.0, fixed, so a stated version is required.
    _Pin("AAK-MCP-JUNIE-CVE-2026-111091-001", "Junie CLI",
         ("@jetbrains/junie", "@jetbrains/junie-cli"), (2548, 5, 0),
         introduced=(888, 0, 0),
         fix_label="2548.5.0, which is Junie 26.8.3 (affected from 888.0.0)",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-16 batch (#1001-#1005) ---
    # The MCP Python SDK's stateful Streamable HTTP session manager keeps every
    # session with no idle expiry or count limit (CVE-2026-59951, CVSS 4.0 6.9). The
    # manager arrives in 1.8.0; 1.30.0 and 2.2.0 add a 30-minute default idle timeout
    # and a 10,000-session cap. MEDIUM, so its own rule beside the HIGH pin above.
    _Pin("AAK-MCP-SDK-CVE-2026-59951-001", "mcp (MCP Python SDK)", ("mcp",), (1, 30, 0),
         introduced=(1, 8, 0), also=(((2, 0, 0), (2, 2, 0)),),
         fix_label="1.30.0, or 2.2.0 on the 2.x line (affected from 1.8.0)",
         requires_version=True, ecosystem="py"),
    # Network-AI's ClaudeHookBridge, a Claude Code PreToolUse hook, matches deny
    # patterns against the first candidate field only (CVE-2026-109331), and before
    # 5.15.1 against its first 500 characters only (CVE-2026-73614). The bridge first
    # ships in 5.14.0; 5.15.1 drops the truncation and 5.15.2 checks every field.
    # `latest` (5.15.4) is fixed and the README launches it unpinned.
    _Pin("AAK-MCP-NETWORKAI-CVE-2026-109331-001", "network-ai", ("network-ai",), (5, 15, 2),
         introduced=(5, 14, 0), fix_label="5.15.2 (affected from 5.14.0)",
         requires_version=True, ecosystem="js"),
    # mcp-remote's device-code sign-in (`--device-code`, from 0.8.0) sends the client
    # secret to, and takes tokens from, whatever device-authorization and token
    # endpoints the server's metadata names, http included (CVE-2026-108716). It
    # runs only with the flag, so only a launch that passes it is judged. Unchanged
    # through 0.15.1, the newest release: no fixed release, so an unpinned launch
    # is reported too.
    _Pin("AAK-MCP-REMOTE-CVE-2026-108716-001", "mcp-remote", ("mcp-remote",), None,
         introduced=(0, 8, 0),
         fix_label="no fixed release (0.15.1 is the newest); sign in without --device-code "
                   "or check that the server's OAuth endpoints are https",
         requires_arg="--device-code", ecosystem="js"),
    # --- 2026-10-16 second batch (records the watcher had not filed) ---
    # Open Computer Use's macOS backend checks a requested bundle identifier against
    # its lowercase password-manager denylist with an exact `contains`, while the
    # app lookup ignores case, so `com.1Password.1Password` passes (CVE-2026-108721).
    # The denylist ships in 0.1.2, the first npm release, and the check is unchanged
    # at 1.1.1, the newest, and on `main`, although the record says "through 1.0.0":
    # no fixed release. The project publishes the same build under three names.
    _Pin("AAK-MCP-OPENCOMPUTERUSE-CVE-2026-108721-001", "Open Computer Use",
         ("open-computer-use", "open-computer-use-mcp", "open-codex-computer-use-mcp"),
         None, fix_label="no fixed release (1.1.1 is the newest); lock password "
                         "managers while an agent drives the desktop"),
    # Odoo MCP's `execute_method` tool returns `read` and `search_read` results
    # without the field policy its read tools apply (CVE-2026-108861). The policy
    # (`field_policy.py`) arrives in 1.0.0; PyPI's newest release, 1.3.0, and the
    # newest tag, v1.3.2, still skip it. npm's `odoo-mcp` is another project.
    _Pin("AAK-MCP-ODOOMCP-CVE-2026-108861-001", "odoo-mcp", ("odoo-mcp",), None,
         introduced=(1, 0, 0),
         fix_label="no fixed release (1.3.0 is the newest on PyPI); enforce hidden "
                   "fields with Odoo's own access rules",
         ecosystem="py"),
    # Network-AI's MCP SSE transport answers other origins (CVE-2026-109332, LOW):
    # `Access-Control-Allow-Origin: *` from 4.0.0, where `lib/mcp-transport-sse`
    # first ships, to at least 5.1.0, then a reflected localhost Origin whatever the
    # bind address; 5.15.2 reflects only on a loopback bind. LOW, so its own rule
    # beside the HIGH pin above, and like it a stated version is required.
    _Pin("AAK-MCP-NETWORKAI-CVE-2026-109332-001", "network-ai", ("network-ai",), (5, 15, 2),
         introduced=(4, 0, 0), fix_label="5.15.2 (affected from 4.0.0)",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-16 (#1026) ---
    # The Claude Agent SDK passed `resume` to the Claude CLI as two argv tokens,
    # `["--resume", value]`. The CLI declares `--resume` with an optional value, so a
    # value starting with `-` is read as a flag of its own, and an injected
    # `--mcp-config` defines a stdio MCP server whose command the CLI starts
    # (CVE-2026-96620, CVSS 4.0 9.2, GHSA-h4mw-j7qp-8mwm). Checked in the sdists:
    # 0.0.23, the first release, 0.1.0 and 0.2.120 build the two tokens, and 0.2.121
    # (347a1cb) and 0.2.168, the newest, pass `--resume=<value>`. The fix commit says
    # the TypeScript SDK shipped the same fix in 0.3.208, and the npm tarballs agree:
    # 0.0.4, 0.2.120 and 0.3.207 push two tokens, 0.3.208 and 0.3.302 one. `latest`
    # is fixed on both registries, so a stated version is required. npm's unscoped
    # `claude-agent-sdk` is a 0.0.1 name reservation by another publisher, so the
    # PyPI row reads PyPI only; npm's own 0.2.121 is not the PyPI fix.
    _Pin("AAK-MCP-CLAUDEAGENTSDK-CVE-2026-96620-001", "Claude Agent SDK for Python",
         ("claude-agent-sdk",), (0, 2, 121), fix_label="0.2.121",
         requires_version=True, ecosystem="py"),
    _Pin("AAK-MCP-CLAUDEAGENTSDK-CVE-2026-96620-001", "Claude Agent SDK for TypeScript",
         ("@anthropic-ai/claude-agent-sdk",), (0, 3, 208),
         fix_label="0.3.208 (the TypeScript SDK's fix; the CVE record names only the "
                   "Python SDK)",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-20 (#1055) ---
    # Langchain-Chatchat's API runs any registered tool, the always-registered
    # `shell` tool included, from an unauthenticated `POST /tools/call`
    # (CVE-2026-75128, CVSS 3.1 9.8). PyPI carries 0.3.0 (2024-05-06) to 0.3.1.3
    # (2024-07-23), and the wheels at both ends mount the route and register the
    # tool. Nothing has been published since, and `master` serves the route
    # unchanged, so the pin is presence-only: an unpinned reference installs an
    # affected release as well. npm has no package by the name, and PyPI's
    # `chatchat` is another project. The images are rows in `container_image_pins`.
    _Pin("AAK-CHATCHAT-CVE-2026-75128-001", "langchain-chatchat",
         ("langchain-chatchat",), None,
         fix_label="no fixed release (0.3.1.3 is the newest); keep the API port, "
                   "7861, off networks you do not trust"),
    # --- 2026-10-21 (#1059, #1065) ---
    # The MCP TypeScript SDK's experimental tasks feature kept every task of one
    # InMemoryTaskStore in one pool: each of the store's methods took the caller's
    # session id and ignored it, so a client with a session of its own could list,
    # read and cancel another session's tasks (CVE-2026-111767, CVSS 3.1 8.6,
    # CWE-639/CWE-862, GHSA-22jm-h49p-29qw). Checked in the tarballs: 1.23.1
    # (published after 1.24.0) ships no task store; 1.24.0 and 1.31.0 give every
    # store method a `_sessionId` they never read; 1.32.0 records the session on
    # createTask and answers another session's lookup as a task not found
    # (727075b5, typescript-sdk#2925). The OAuth pin above has a 1.31.0 floor and
    # 1.31.0 is affected here, so this is its own rule rather than a raised floor.
    # Only a server that configures the SDK's task store is exposed, which the
    # version cannot tell; the 2.x packages are not affected. `latest` is 1.32.1, so a
    # stated version is required.
    _Pin("AAK-MCP-TSSDK-CVE-2026-111767-001", "@modelcontextprotocol/sdk",
         ("@modelcontextprotocol/sdk",), (1, 32, 0), introduced=(1, 24, 0),
         fix_label="1.32.0 (affected from 1.24.0)",
         requires_version=True, ecosystem="js"),
    # mcp-ripgrep builds its rg command line as a string and runs it through
    # `spawn(program, args, {shell: true})`. The advanced-search and list-files
    # tools append ` -t ${fileType}` as given, where every pattern, path and glob
    # goes through escapeShellArg, so a fileType holding `;` or `$(...)` runs a
    # command as the server's user (CVE-2026-113378, CVSS 3.1 5.3, CWE-77/CWE-78,
    # GHSA-qq9r-r4m4-c72m). Checked in the npm tarballs: 0.1.0, the first release,
    # and 0.4.0, the newest (2025-04-29), both have it in dist/index.js. Nothing
    # has been pushed since, the maintainer points at the README's warning, and
    # there is no fixed release, so floor=None (presence-only). PyPI has no
    # `mcp-ripgrep`, and npm's `ripgrep-mcp` is another server.
    _Pin("AAK-MCP-RIPGREP-CVE-2026-113378-001", "mcp-ripgrep", ("mcp-ripgrep",), None,
         fix_label="no fixed release (0.4.0 is the newest and the maintainer cites the "
                   "README's warning); keep it away from agents that read untrusted text",
         ecosystem="js"),
    # --- 2026-10-22 (#1071) ---
    # d365fo-mcp (dynamics365ninja/d365fo-mcp-server), the D365 F&O MCP Server,
    # ships an HTTP mode for Azure App Service. Before 1.11.0 its documented
    # one-click deployment (infrastructure/azuredeploy.json, main.bicep) defaulted
    # the apiKey parameter to "" and passed it to the App Service's API_KEY
    # setting; with API_KEY empty the middleware passed every request through,
    # and index.js bound `HOST || '0.0.0.0'`, so a deployer who left the optional
    # key blank got a public App Service answering unauthenticated tools/call on
    # /mcp, read-only mode included (CVE-2026-114123, CVSS 3.1 7.5, CWE-306/
    # CWE-1188, GHSA-8764-fh3m-wf7g). Checked in the npm tarballs: 1.0.0 and
    # 1.10.1 have the pass-through and the 0.0.0.0 default; 1.11.0 (e70bd051,
    # 384394a8) makes the template's apiKey required, defaults a keyless server
    # to loopback and refuses to start a non-loopback listener without a key.
    # The scanner reads the version a project declares, never the template
    # default or the App Service setting. `latest` is 1.21.0, fixed, so a stated
    # version is required; PyPI has no d365fo-mcp.
    _Pin("AAK-MCP-D365FO-CVE-2026-114123-001", "d365fo-mcp", ("d365fo-mcp",), (1, 11, 0),
         fix_label="1.11.0",
         requires_version=True, ecosystem="js"),
    # --- 2026-10-23 (#1081) ---
    # LiteLLM sealed UI and CLI session tokens with `encrypt_value_helper`, the
    # helper that seals secrets at rest, and from 1.87.0 (#27141, 3b2ce201) the key
    # API seals a key's `callback_vars` metadata with the same helper, so an
    # internal user could have a forged proxy_admin session sealed for them and
    # present it as a bearer token (CVE-2026-114612, CVSS 3.1 9.9, CWE-269/CWE-345/
    # CWE-441, GHSA-7hp6-4w63-5g45). 1.87.0 to 1.90.x accept that token only with
    # EXPERIMENTAL_UI_LOGIN turned on; from 1.91.0 it is accepted unless the
    # variable is false. Checked at every release tag and in the PyPI sdists: the
    # fix (`encrypt_bearer_token`, its prefix doubling as the AES-GCM associated
    # data) is in 1.100.4, 1.101.3, 1.102.2, 1.103.1, 1.104.0rc2 and every later
    # release, and absent from 1.100.3, 1.101.2, 1.102.1, 1.103.0 and 1.104.0rc1;
    # 1.86.7 never seals callback_vars. The 1.101 to 1.103 lines sort above the
    # 1.100.4 floor, so they are `also` ranges on this row. 1.104.0rc1 reads as
    # 1.104.0 (a pre-release folds into its release), which is fixed, so it cannot
    # be a range here. The older litellm row's 1.84.0 floor sits below 1.87.0, so
    # this is its own rule. `latest` is 1.106.2, fixed, so a stated version is
    # required, and npm's `litellm` is a JavaScript port on its own 0.x line.
    _Pin("AAK-MCP-LITELLM-CVE-2026-114612-001", "litellm", ("litellm",), (1, 100, 4),
         introduced=(1, 87, 0),
         also=(((1, 101, 0), (1, 101, 3)), ((1, 102, 0), (1, 102, 2)),
               ((1, 103, 0), (1, 103, 1))),
         fix_label="1.100.4, 1.101.3, 1.102.2, 1.103.1 or 1.104.0 (affected from 1.87.0)",
         requires_version=True, ecosystem="py"),
    # --- 2026-10-24 (#1083 to #1092) ---
    # Uni-CLI (npm `@zenalexa/unicli`) served its legacy JSON-RPC-over-HTTP MCP
    # transport on loopback without checking a browser's Origin, so a web page's
    # CORS-simple POST to the local /mcp endpoint reached the dispatcher and drove
    # tools/call (CVE-2026-58497, CVSS 4.0 8.6, CWE-346/CWE-352,
    # GHSA-v3f4-w7r7-v3hm). Checked in the npm tarballs: 0.207.1, the first release,
    # has no HTTP transport; 0.208.0 adds one with no Origin check; 0.225.1 still has
    # none; 0.225.2 (d675c267) routes every request through the shared
    # `isOriginAllowed` guard. `latest` is 1.3.0, fixed, so a stated version is
    # required. npm's `uni-cli` is another project.
    _Pin("AAK-MCP-UNICLI-CVE-2026-58497-001", "@zenalexa/unicli", ("@zenalexa/unicli",),
         (0, 225, 2), introduced=(0, 208, 0), fix_label="0.225.2 (affected from 0.208.0)",
         requires_version=True, ecosystem="js"),
    # obsidian-tc, two more flaws fixed in 1.31.4 (GHSA-737x-cwfr-5vvc,
    # GHSA-r3g7-r4hr-m258, both CVSS 4.0 7.1). CVE-2026-115477, 1.13.0 to 1.31.3: on
    # a Streamable HTTP deployment with auth.jwtSecret set, a dispatch-gated
    # destructive call could still complete after the human declined the elicitation
    # form, because an authentic call-bound requestState was taken as approval.
    # CVE-2026-115478, 1.0.1 to 1.31.3: the memory tools rewrote a note at its computed
    # path without checking who owned it. Checked in the npm tarballs: 1.31.3 carries
    # neither fix, 1.31.4 both (101c91c6, 99f7914c). The CRITICAL row above is fixed at
    # 1.3.1 and 1.3.1 to 1.31.3 are affected here, so a raised floor would report those
    # releases as the vault-binding flaw: this is its own HIGH rule, from 1.0.1, the
    # first 1.x release. `latest` is 1.33.1, fixed.
    _Pin("AAK-MCP-OBSIDIANTC-CVE-2026-115477-001", "obsidian-tc", ("obsidian-tc",),
         (1, 31, 4), introduced=(1, 0, 1), fix_label="1.31.4 (affected from 1.0.1)",
         requires_version=True, ecosystem="js"),
    # mcp-from-openapi: CVE-2026-115750 (2.5.0 to 2.8.x) carries the caller's
    # Authorization and Cookie headers when safeFetch follows a cross-origin
    # redirect, and CVE-2026-115751 (2.2.0 to 2.8.x) lets a trailing-dot hostname
    # past ssrf.blockedHosts (CVSS 3.1 3.7 each, GHSA-ff5q-5r4v-fw4v). Checked in the
    # tarballs: `blockedHosts` first ships in 2.2.0 and `safeFetch` in 2.5.0, and
    # 2.9.0 (47fb7a65) adds `normalizeHostname` and keeps credentials on their origin.
    # The 2.5.0 row above is HIGH for another SSRF, fixed in 2.5.0, so this is its own
    # LOW rule rather than a raised floor. `latest` is 2.9.1, fixed. PyPI's
    # mcp-from-openapi is another project.
    _Pin("AAK-MCP-FROMOPENAPI-CVE-2026-115750-001", "mcp-from-openapi",
         ("mcp-from-openapi",), (2, 9, 0), introduced=(2, 2, 0),
         fix_label="2.9.0 (affected from 2.2.0)", requires_version=True, ecosystem="js"),
    # LangGraph CLI from 0.4.15 printed the temporary registry push token that
    # `langgraph deploy --verbose` hands to `docker login --password-stdin`, since its
    # subprocess helper echoes a command's input in verbose mode (CVE-2026-115885,
    # CVSS 4.0 4.1, CWE-532, GHSA-8prr-f582-jqq3). Checked in the sdists: 0.4.14 has
    # no `--password-stdin`, 0.4.15 adds it; 0.4.31 runs that docker login with
    # `verbose=verbose`, 0.4.32 with `verbose=False`. `latest` is 0.4.38, fixed. npm's
    # LangGraph CLI is the scoped `@langchain/langgraph-cli`, another package.
    _Pin("AAK-MCP-LANGGRAPH-CLI-CVE-2026-115885-001", "langgraph-cli", ("langgraph-cli",),
         (0, 4, 32), introduced=(0, 4, 15), fix_label="0.4.32 (affected from 0.4.15)",
         requires_version=True, ecosystem="py"),
)

_CANDIDATE_NAMES = (
    "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    ".mcp.json", "mcp.json", "claude_desktop_config.json",
)
_CANDIDATE_GLOBS = ("requirements*.txt", "*.mcp.yaml", "*.mcp.yml")


# Manifests whose registry is unambiguous from the filename alone. Anything not
# listed here -- .mcp.json, claude_desktop_config.json, *.mcp.yaml -- can name a
# package from either registry (`npx -y @scope/x` next to `uvx y`), so it stays
# unclassified and every pin is still tried against it.
_PY_MANIFESTS = frozenset({
    "pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock",
})
_JS_MANIFESTS = frozenset({
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
})


def _ecosystem_of(path: Path) -> str | None:
    """Return "py" / "js" for a registry-specific manifest, else None."""
    name = path.name.lower()
    if name in _PY_MANIFESTS:
        return "py"
    if name in _JS_MANIFESTS:
        return "js"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "py"
    return None


def _pin_applies(pin: _Pin, ecosystem: str | None) -> bool:
    """False only when the registry is known AND the pin names another.

    `ecosystem` is a lockfile's registry, or a declaration's: a manifest's for
    its entries, the launcher's for an MCP config entry (`npx` is npm, `uvx`
    PyPI), and None for a program run by name.
    """
    if pin.ecosystem is None or ecosystem is None:
        return True
    return pin.ecosystem == ecosystem


def _fires(pin: _Pin, version: _Ver | None) -> bool:
    # `introduced` is checked FIRST, before the presence-only shortcut. It used to
    # sit last, which was unreachable for a presence-only pin (`floor is None`
    # returned True immediately) -- harmless only for as long as no presence-only
    # pin carried an `introduced` bound. `knowns` is the first that does: it is
    # presence-only because CVE-2026-88938 has no fixed release, and it needs the
    # 0.1.1 bound to stay off the unrelated PyPI `knowns` stub whose only release
    # is 0.1.0. Without this ordering that false positive comes straight back.
    #
    # No behaviour changes for the pins that have a floor: `introduced` is always
    # below `floor`, so a version at or above the floor is also at or above
    # `introduced`, and the early return yields what the old order did.
    if version is not None and any(lo <= version < hi for lo, hi in pin.also):
        return True
    if version is not None and pin.introduced is not None and version < pin.introduced:
        return False
    if pin.floor is None:
        return True
    if version is None:
        return True
    return version < pin.floor


def _passes(argv: tuple[str, ...], option: str) -> bool:
    """Does a command line pass `option`, as its own token, as `option=value`, or
    inside a quoted shell line (`supergateway --stdio "npx -y pkg ... --flag"`)?"""
    return any(
        token == option or token.startswith(option + "=") or option in token.split()
        for token in argv
    )


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
            if p.is_file() and p not in seen and not in_skip_dir(p, project_root):
                out.append(p)
                seen.add(p)
    return out


def _canonical(name: str, ecosystem: str | None) -> str:
    """A package name as its registry compares it.

    npm compares names case-insensitively. PyPI normalises them (PEP 503):
    every run of `-`, `_` and `.` is one `-`, so `awslabs.healthlake-mcp-server`,
    `awslabs-healthlake-mcp-server` (the spelling uv.lock records) and
    `awslabs_healthlake_mcp_server` are one package. Matching the dotted
    spelling only left every other awslabs.* spelling silent.
    """
    lowered = name.strip().lower()
    return re.sub(r"[-_.]+", "-", lowered) if ecosystem == "py" else lowered


def _names_match(pin: _Pin, declaration: Declaration) -> bool:
    ecosystem = declaration.ecosystem
    if ecosystem is None:
        # A program run by name: its registry is unknown, so either spelling counts.
        spellings = {_canonical(declaration.name, "py"), _canonical(declaration.name, "js")}
        return any(_canonical(n, "py") in spellings or _canonical(n, "js") in spellings
                   for n in pin.names)
    target = _canonical(declaration.name, ecosystem)
    return any(_canonical(n, ecosystem) == target for n in pin.names)


def _declaration_index(found: list[Declaration]) -> dict[str, list[int]]:
    """Where each package is declared in `found`: canonical name -> positions.

    Every pin used to filter every declaration of the file, about 150 passes, so
    a 16,000-line requirements file took 7 s. A declaration is filed under each
    spelling `_names_match` could accept for it (both registries' for a program
    run by name), so a pin reads only the declarations of its own names.
    """
    index: dict[str, list[int]] = {}
    for position, declaration in enumerate(found):
        ecosystems = ("py", "js") if declaration.ecosystem is None else (declaration.ecosystem,)
        for key in {_canonical(declaration.name, ecosystem) for ecosystem in ecosystems}:
            index.setdefault(key, []).append(position)
    return index


def _pin_candidates(
    pin: _Pin, found: list[Declaration], index: dict[str, list[int]]
) -> list[Declaration]:
    """The declarations that may name `pin`'s packages, in file order: a superset
    of what `_deciding_declaration` keeps, so its verdict does not change."""
    keys = {_canonical(name, ecosystem) for name in pin.names for ecosystem in ("py", "js")}
    return [found[i] for i in sorted({i for key in keys for i in index.get(key, ())})]


def _affected(pin: _Pin) -> tuple[_Ver, _Ver]:
    """The pin's affected versions as one half-open span."""
    return pin.introduced or ZERO, pin.floor or TOP


def _admits_affected(pin: _Pin, declaration: Declaration) -> bool:
    """Does the declaration allow a version the pin covers?

    A declaration that states no version AAK can read (a bare name, `*`, a
    dist-tag, a git or file reference) is reported, the house default for an
    unpinned reference, unless the pin requires a stated version.
    """
    return _spans_admit_affected(pin, parse_range(declaration.version, declaration.dialect))


def _combined(declarations: list[Declaration]) -> Spans | None:
    """The versions every readable one of `declarations` admits, or None.

    pip and uv merge all the specifiers one install names for a package, so a
    group is the intersection of its members. A member that states no version
    (`pkg`, a VCS reference) adds no constraint; a group of only those is None.
    """
    stated = [s for s in (parse_range(d.version, d.dialect) for d in declarations) if s is not None]
    return intersect_all(stated) if stated else None


def _spans_admit_affected(pin: _Pin, spans: Spans | None) -> bool:
    if spans is None:
        return not pin.requires_version
    lo, hi = _affected(pin)
    return admits(spans, lo, hi) or any(admits(spans, a_lo, a_hi) for a_lo, a_hi in pin.also)


def _deciding_declaration(pin: _Pin, found: list[Declaration]) -> Declaration | None:
    """The declaration a finding for `pin` reports, or None when the file is clear.

    Every declaration of the package is judged, never just the first: the old
    scan stopped at the first textual match, so a comment that named the
    package with a version hid the real pin below it.

    A range is judged by what it admits. It is reported when it admits an
    affected version, wherever its bounds are written, so `<1.84.0` (every
    version affected), `<2.0.0,>=1.0.0` and `>=1.0.0,<2.0.0` read alike, and a
    caret that reaches a vulnerable branch (`^2.29.8` admits n8n 2.30.0) is
    reported too. This is the conservative reading: a manifest range says
    which versions the project accepts, and a resolver may pick any of them.

    Launches (a launcher in an MCP config or a package.json script) run
    independently, so each is judged alone: an affected one is reported even
    when another server runs a patched release.

    A manifest's declarations are judged by the install they constrain, and a
    pin constrains only that install. An override (npm `overrides`, Yarn
    `resolutions`, `pnpm.overrides`, uv `override-dependencies`, PDM
    resolution overrides) replaces the regular entries, so when one exists it
    alone is judged: `"pkg": "^1.0.0"` beside an override `"pkg": "1.9.0"`
    installs 1.9.0. Otherwise the regular declarations are grouped by section
    and marker, and each group is the intersection of its members, which is
    how pip reads `pkg>=1.0` beside `pkg==1.9.0` in one file, narrowed by any
    global constraint (uv `constraint-dependencies`). A group is reported when
    what it still admits includes an affected version. A pin in another section
    does not clear it: a dev group's or an extra's `pkg==1.9.0` leaves the
    production install's `pkg>=1.0` free to resolve below the fix, and an
    earlier version of this rule let any exact patched pin in the file clear
    every range in it, which silenced exactly that. Declarations under
    different markers are alternatives for different environments, not
    constraints on one another.
    """
    matching = [d for d in found if _pin_applies(pin, d.ecosystem) and _names_match(pin, d)]
    if pin.requires_arg is not None:
        # Only a launch can show the option, so nothing else is judged.
        matching = [d for d in matching if d.kind == "launch" and _passes(d.argv, pin.requires_arg)]
    for declaration in matching:
        if declaration.kind == "launch" and _admits_affected(pin, declaration):
            return declaration
    manifest = [d for d in matching if d.kind != "launch"]
    overrides = [d for d in manifest if d.kind == "override"]
    if overrides:
        return next((d for d in overrides if _admits_affected(pin, d)), None)
    constraints = [d for d in manifest if d.kind == "constraint"]
    groups: dict[tuple[str, str], list[Declaration]] = {}
    for declaration in manifest:
        if declaration.kind == "dependency":
            groups.setdefault((declaration.section, declaration.marker), []).append(declaration)
    if not groups:
        # Constraints with nothing else to narrow still pin whatever installs
        # the package transitively, so they are judged as a group of their own.
        return constraints[0] if constraints and _spans_admit_affected(pin, _combined(constraints)) else None
    narrowing = _combined(constraints)
    for members in groups.values():
        spans = _combined(members)
        if narrowing is not None:
            spans = narrowing if spans is None else intersect(spans, narrowing)
        if _spans_admit_affected(pin, spans):
            return members[0]
    return None


@dataclass(frozen=True)
class _RepoPin:
    """A project that ships from its GitHub repository and no registry.

    CVE-2026-46555 (GHSA-7jj9-4qqq-4xc4) names verygoodplugins/whatsapp-mcp,
    which publishes a clone, release wheels (`whatsapp_mcp_server-<v>-py3-none-
    any.whl`) and a bridge binary, and nothing on npm or PyPI. The registries'
    `whatsapp-mcp` packages are other projects: npm's is Candombe/whatsapp-mcp
    (0.0.1 to 0.1.3), PyPI's links no repository (0.1.0, 0.1.1), and PyPI's
    `whatsapp-mcp-server`, the wheels' own name, is msaelices's 0.2.1. A pin on
    either name reported somebody else's package, and no upgrade cleared it.

    What states a release of the project is a reference to its repository that
    names a tag: a pip or uv git URL with `@v0.2.0` or `@refs/tags/v0.2.0`, a
    lockfile's git source with `rev=` or `tag=`, a `/releases/download/v0.2.0/`
    asset or an `/archive/` tarball, and the TOML tables that name the tag in a
    key of its own beside the URL: uv's sources and Poetry's `tag` or `rev`,
    Pipfile's `ref`, and poetry.lock's `reference`. The README's own install, a
    clone run with `uv --directory <path> run main.py`, names none, and neither
    does a commit or a branch, so those are not reported.
    """

    rule_id: str
    display: str
    repository: str     # owner/name on github.com
    floor: _Ver
    fix_label: str


_REPO_PINS: tuple[_RepoPin, ...] = (
    _RepoPin("AAK-MCP-WHATSAPP-CVE-2026-46555-001", "WhatsApp MCP",
             "verygoodplugins/whatsapp-mcp", (0, 2, 1), "v0.2.1"),
)


def _repo_ref_re(repository: str) -> re.Pattern[str]:
    """A reference to `repository` on github.com that names a release tag: a
    git URL's `@v0.2.0` or `@refs/tags/v0.2.0`, a release asset, an archive
    tarball, or a lockfile's `rev=` or `tag=`.

    The host is bounded on the left, so `notgithub.com/...` is another host. A
    browse URL (`/tree/v0.2.0`, a package.json `homepage`) installs nothing and
    is not read. Each part is a literal or bounded, so a crafted line costs one
    pass.
    """
    return re.compile(
        r"(?<![\w.-])(?:www\.)?github\.com[/:]" + re.escape(repository) + r"(?:\.git)?"
        r"(?:@(?:refs/tags/)?|/releases/download/|/archive/(?:refs/tags/)?"
        r"|\?(?:[^#\s\"'?]{0,256}&)?(?:rev|tag)=)"
        r"v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?!\d)",
        re.IGNORECASE,
    )


def _repo_url_re(repository: str) -> re.Pattern[str]:
    """The repository's URL alone, as a TOML `git` or `url` value states it."""
    return re.compile(
        r"(?<![\w.-])(?:www\.)?github\.com[/:]" + re.escape(repository)
        + r"(?:\.git)?/?(?![\w.-])",
        re.IGNORECASE,
    )


_REPO_REF_RES = {pin.repository: _repo_ref_re(pin.repository) for pin in _REPO_PINS}
_REPO_URL_RES = {pin.repository: _repo_url_re(pin.repository) for pin in _REPO_PINS}
# uv's `[tool.uv.sources]`, Poetry's dependency tables and Pipfile name the
# repository in one key and the tag in another (`{ git = "https://github.com/o/r",
# tag = "v0.2.0" }`, `ref = "v0.2.0"`), which a URL search cannot pair. Those two
# manifests are read as TOML; they are under the manifest size limit and already
# parsed for their declarations. poetry.lock, which may reach the lockfile limit,
# is read line by line instead: Poetry writes a git source as `url = ...` with
# its `reference = ...` a line or two below.
_TOML_REPO_FILES = frozenset({"pyproject.toml", "pipfile"})
_TAG_KEYS = ("tag", "rev", "ref", "reference")
_RELEASE_TAG_RE = re.compile(r"v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})")
_POETRY_SOURCE_RE = re.compile(
    r'^url[ \t]*=[ \t]*"([^"\n]{1,2048})"[ \t]*\r?\n(?:[^\[\n][^\n]*\n){0,8}?'
    r'reference[ \t]*=[ \t]*"([^"\n]{1,256})"',
    re.MULTILINE,
)
# Where a comment starts depends on the format.
#
# TOML: a `#` outside a quoted string, anywhere on the line (a string or a `#`
# is matched, so a `#` inside quotes is not read as a comment).
# requirements and yarn.lock: pip's rule, a `#` at the start of a line or after a
# space; quotes mean nothing there, and `#egg=` inside a URL is not a comment.
# YAML: a `#` at the start of a line or after a space, outside a quoted scalar;
# a quote opens a scalar only where one starts (after `: `, `- `, `[`, `{` or
# `,`), so the apostrophe in a plain `note: it's pinned` opens nothing.
#
# A quote with no partner runs to the end of its line, so every character is read
# once: had the closing quote been required, a line of escaped quotes (`"\` over
# and over) would be searched to its end again from every quote in it.
_HASH_COMMENT_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"?|\'[^\'\n]*\'?|#')
_PIP_COMMENT_RE = re.compile(r"(?:^|(?<=[ \t]))#[^\n]*", re.MULTILINE)
_YAML_MARK_RE = re.compile(r"[\"'#]")
_YAML_DOUBLE_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"?')
_YAML_SINGLE_RE = re.compile(r"'(?:[^'\n]|'')*'?")


def _toml_comment_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    at, n = 0, len(text)
    while True:
        m = _HASH_COMMENT_RE.search(text, at)
        if m is None:
            return spans
        if m.group() == "#":
            end = text.find("\n", m.start())
            end = n if end < 0 else end
            spans.append((m.start(), end))
            at = end
        else:
            at = m.end()


def _yaml_comment_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    at, n = 0, len(text)
    while True:
        m = _YAML_MARK_RE.search(text, at)
        if m is None:
            return spans
        i, mark = m.start(), m.group()
        before = text[i - 1] if i else "\n"
        if mark == "#":
            if before in " \t\n":
                end = text.find("\n", i)
                end = n if end < 0 else end
                spans.append((i, end))
                at = end
            else:
                at = i + 1
            continue
        # The last character before the quote that is not a space; each run of
        # spaces is passed once, by the one quote that follows it.
        j = i - 1
        while j >= 0 and text[j] in " \t":
            j -= 1
        lead = text[j] if j >= 0 else "\n"
        if before in "\n[{," or (before in " \t" and lead in "\n:-?[{,"):
            quoted = (_YAML_DOUBLE_RE if mark == '"' else _YAML_SINGLE_RE).match(text, i)
            at = quoted.end() if quoted else i + 1
        else:
            at = i + 1


def _comment_spans(text: str, file_name: str) -> list[tuple[int, int]]:
    """(start, end) of every comment in a candidate file, in one pass, by the
    rules of its format (see `_HASH_COMMENT_RE`). A comment runs to the end of
    its line however long the line is, which a look-back of fixed length did not
    see past."""
    if file_name.endswith((".yaml", ".yml")):
        return _yaml_comment_spans(text)
    if file_name.endswith(".txt") or file_name == "yarn.lock":
        return [(m.start(), m.end()) for m in _PIP_COMMENT_RE.finditer(text)]
    return _toml_comment_spans(text)


def _in_spans(spans: list[tuple[int, int]], starts: list[int], offset: int) -> bool:
    index = bisect.bisect_right(starts, offset) - 1
    return index >= 0 and offset < spans[index][1]


def _toml_repo_refs(
    text: str, url_re: re.Pattern[str]
) -> list[tuple[_Ver, tuple[str | int, ...], str]]:
    """(version, path of the URL key, evidence) for every TOML table that points
    `git` or `url` at the repository and names a release tag beside it."""
    try:
        # pyproject.toml and Pipfile, which `declarations` parses too and
        # reports when it refuses; the screen keeps a long dotted key out.
        data = loads_toml(text, None)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return []
    refs: list[tuple[_Ver, tuple[str | int, ...], str]] = []
    stack: list[tuple[object, tuple[str | int, ...]]] = [(data, ())]
    while stack:
        node, where = stack.pop()
        if isinstance(node, dict):
            for url_key in ("git", "url"):
                url = node.get(url_key)
                if not isinstance(url, str) or not url_re.search(url):
                    continue
                for tag_key in _TAG_KEYS:
                    tag = node.get(tag_key)
                    tag_m = _RELEASE_TAG_RE.fullmatch(tag.strip()) if isinstance(tag, str) else None
                    if tag_m:
                        version = (int(tag_m.group(1)), int(tag_m.group(2)), int(tag_m.group(3)))
                        refs.append((version, where + (url_key,),
                                     f"{url_key} = {url!r}, {tag_key} = {tag!r}"))
                        break
            stack.extend((value, where + (key,)) for key, value in node.items())
        elif isinstance(node, list):
            stack.extend((value, where + (index,)) for index, value in enumerate(node))
    return refs


def _first_repo_reference(pin: _RepoPin, file_name: str, text: str) -> tuple[int, str] | None:
    """(line, evidence) of the earliest reference in the file to an affected
    release, outside comments, or None. Line 0 means its position is unknown."""
    hits: list[tuple[int, str]] = []
    searched = text
    in_comment: Callable[[int], bool] = lambda offset: False  # noqa: E731
    if file_name.endswith(".json"):
        # MCP clients read these as JSONC; comments become spaces, offsets kept.
        try:
            searched = strip_jsonc(text)
        except ValueError:
            pass
    else:
        spans = _comment_spans(text, file_name)
        starts = [start for start, _ in spans]
        in_comment = lambda offset: _in_spans(spans, starts, offset)  # noqa: E731
    for m in _REPO_REF_RES[pin.repository].finditer(searched):
        if in_comment(m.start()):
            continue
        version = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if version < pin.floor:
            hits.append((
                searched.count("\n", 0, m.start()) + 1,
                f"{pin.display} referenced at {m.group(1)}.{m.group(2)}.{m.group(3)} "
                f"({m.group(0)!r}) — fixed in {pin.fix_label}; pin the patched release.",
            ))
            break
    if file_name in _TOML_REPO_FILES:
        refs = [ref for ref in _toml_repo_refs(text, _REPO_URL_RES[pin.repository])
                if ref[0] < pin.floor]
        positions = _toml_positions(text) if refs else {}
        for version, where, shown in refs:
            hits.append((
                positions.get(where, 0),
                f"{pin.display} referenced at {'.'.join(map(str, version))} ({shown}) — "
                f"fixed in {pin.fix_label}; pin the patched release.",
            ))
    elif file_name == "poetry.lock":
        for m in _POETRY_SOURCE_RE.finditer(text):
            tag_m = _RELEASE_TAG_RE.fullmatch(m.group(2).strip())
            if tag_m is None or not _REPO_URL_RES[pin.repository].search(m.group(1)):
                continue
            version = (int(tag_m.group(1)), int(tag_m.group(2)), int(tag_m.group(3)))
            if version < pin.floor:
                hits.append((
                    text.count("\n", 0, m.start()) + 1,
                    f"{pin.display} referenced at {'.'.join(map(str, version))} "
                    f"(url = {m.group(1)!r}, reference = {m.group(2)!r}) — fixed in "
                    f"{pin.fix_label}; pin the patched release.",
                ))
                break
    if not hits:
        return None
    return min(hits, key=lambda hit: (hit[0] == 0, hit[0]))


def _repo_findings(rel: str, file_name: str, text: str) -> list[Finding]:
    """One finding per repository pin per file, on its earliest reference to an
    affected release."""
    findings: list[Finding] = []
    lowered = text.lower()
    for pin in _REPO_PINS:
        if pin.repository.lower() not in lowered:
            continue
        hit = _first_repo_reference(pin, file_name.lower(), text)
        if hit is not None:
            line, evidence = hit
            findings.append(make_finding(pin.rule_id, rel, evidence, line or None))
    return findings


def _evidence(pin: _Pin, declaration: Declaration) -> str:
    stated = parse_range(declaration.version, declaration.dialect) is not None
    how = "" if stated else ", which states no version AAK can read"
    return (
        f"{pin.display} referenced as {declaration.text!r}{how} — fixed in "
        f"{pin.fix_label}; pin the patched release."
    )


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
        lockfile = path.name.lower() in _LOCKFILES
        # A lockfile grows with the resolved graph and gets the larger limit;
        # skipping one at the manifest limit was a silent all-clear on the
        # projects with the most dependencies (see MAX_LOCKFILE_BYTES).
        limit = MAX_LOCKFILE_BYTES if lockfile else MAX_MANIFEST_BYTES
        try:
            if path.stat().st_size > limit:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        # Every candidate file that was opened and read counts as scanned, not
        # only the ones that produced a finding. `engine.run_scan` reports
        # `len(all_scanned_files)` as files_scanned, so gating this on a match
        # under-reported the denominator and made a clean repo look unscanned.
        scanned.add(rel)
        findings.extend(_repo_findings(rel, path.name, text))
        if lockfile:
            findings.extend(_lockfile_findings(path, rel, text))
            continue
        found = declarations(path, text)
        index = _declaration_index(found)
        lines: Callable[[Declaration], int | None] | None = None
        for pin in _PINS:
            declaration = _deciding_declaration(pin, _pin_candidates(pin, found, index))
            if declaration is not None:  # one finding per pin per file
                if lines is None:  # the file's positions, read once at its first finding
                    lines = declaration_lines(path, text)
                findings.append(make_finding(
                    pin.rule_id, rel, _evidence(pin, declaration), lines(declaration),
                ))

    return findings, scanned


def _lockfile_findings(path: Path, rel: str, text: str) -> list[Finding]:
    """Pins on a lockfile, judged on the versions it actually resolves.

    A lockfile pins a resolved graph, so the name and its version are not
    adjacent text and only the resolved versions are read. A pin fires when any
    of them is affected; an absent or unparseable package yields no finding, so
    a correct upgrade and re-lock clears the rule instead of forcing a
    suppression.
    """
    findings: list[Finding] = []
    file_ecosystem = _ecosystem_of(path)
    filename = path.name.lower()
    # Parsed once, not once a pin: a hundred pins re-parsed a large lockfile a
    # hundred times.
    index = _lockfile_index(text, filename, path)
    hits: list[tuple[_Pin, _Ver]] = []
    for pin in _PINS:
        if not _pin_applies(pin, file_ecosystem) or pin.requires_arg is not None:
            continue
        resolved = _lockfile_lookup(index, filename, pin.names)
        affected = [v for v in resolved if _fires(pin, v)]
        if affected:
            hits.append((pin, affected[0]))
    if not hits:
        return findings
    # Where the entries of the reported packages sit, read once for all of them.
    entries = _lockfile_entries(
        text, filename, {_lockfile_canon(n, filename) for pin, _ in hits for n in pin.names})
    for pin, version in hits:
        shown = ".".join(str(x) for x in version)
        findings.append(make_finding(
            pin.rule_id,
            rel,
            f"{pin.display} resolves to {shown} in {path.name} — fixed "
            f"in {pin.fix_label}; upgrade and re-lock.",
            _lockfile_line(entries, filename, pin.names, version),
        ))
    return findings


# Where a lockfile writes a package's own entry, as against the dependency lists
# of other packages, which name it too, read in one pass the first time a
# lockfile has a finding. package-lock.json keys an entry `node_modules/<name>`
# (lockfileVersion 1 nests `"<name>": {` objects under `dependencies`), yarn v1
# starts one at column 0 with `<name>@`, pnpm writes `<name>@<version>`, uv.lock
# and poetry.lock open one with `[[package]]`, and Pipfile.lock keys it
# `"<name>": {`. An entry's version is read inside the entry, up to the next
# one, and compared whole: a window of fixed length reached into the next entry,
# and a substring test read 1.0.1 inside 1.0.10. Every pattern is bounded.
_NPM_LOCK_KEY_RE = re.compile(r'node_modules/((?:@[^"/\\\n]{1,214}/)?[^"/\\\n]{1,214})"[ \t]*:[ \t]*\{')
_JSON_OBJECT_KEY_RE = re.compile(r'"((?:[^"\\\n]|\\.){1,214})"[ \t]*:[ \t]*\{')
_JSON_VERSION_RE = re.compile(r'"version"[ \t]*:[ \t]*"([^"\\\n]{0,64})"')
_YARN_HEADER_RE = re.compile(r'^(?![ \t#\r\n])"?((?:@[^@"\s/]{1,214}/)?[^@"\s/,:]{1,214})@', re.MULTILINE)
_YARN_VERSION_RE = re.compile(r'^[ \t]+version:?[ \t]+"?([0-9][\w.\-]{0,64})', re.MULTILINE)
_TOML_PACKAGE_RE = re.compile(r"^\[\[package\]\]", re.MULTILINE)
_TOML_NAME_RE = re.compile(r'^name[ \t]*=[ \t]*"([^"\n]{1,214})"', re.MULTILINE)
_TOML_VERSION_RE = re.compile(r'^version[ \t]*=[ \t]*"([0-9][^"\n]{0,64})"', re.MULTILINE)


def _entry_versions(
    text: str, filename: str, heads: list[tuple[int, int, str]],
    version_re: re.Pattern[str], wanted: set[str],
) -> list[tuple[int, str, str]]:
    """(offset, name, version) for each entry head of a wanted package, its
    version read between the head and the next head."""
    out: list[tuple[int, str, str]] = []
    for i, (start, end, name) in enumerate(heads):
        if _lockfile_canon(name, filename) not in wanted:
            continue
        stop = heads[i + 1][0] if i + 1 < len(heads) else len(text)
        m = version_re.search(text, end, stop)
        out.append((start, name, m.group(1) if m else ""))
    return out


def _lockfile_entries(
    text: str, filename: str, wanted: set[str]
) -> dict[str, list[tuple[int, _Ver | None]]]:
    """Each entry the lockfile writes for a package in `wanted` (canonical
    names): canonical name -> [(line, version)], in file order.

    One pass over the file, for every reported package at once: the line of a
    finding used to be searched for from the top of the file for each finding.
    """
    found: list[tuple[int, str, str]] = []
    if filename in ("package-lock.json", "pipfile.lock"):
        heads = [] if filename == "pipfile.lock" else [
            (m.start(), m.end(), m.group(1)) for m in _NPM_LOCK_KEY_RE.finditer(text)]
        if not heads:
            heads = [(m.start(), m.end(), _json_key('"' + m.group(1) + '"'))
                     for m in _JSON_OBJECT_KEY_RE.finditer(text)]
        found = [(offset, name, version.lstrip("=")) for offset, name, version
                 in _entry_versions(text, filename, heads, _JSON_VERSION_RE, wanted)]
    elif filename == "yarn.lock":
        heads = [(m.start(), m.end(), m.group(1)) for m in _YARN_HEADER_RE.finditer(text)]
        found = _entry_versions(text, filename, heads, _YARN_VERSION_RE, wanted)
    elif filename == "pnpm-lock.yaml":
        # pnpm states the version in the entry itself.
        found = [(m.start(), m.group(1), m.group(2)) for m in _PNPM_ENTRY_RE.finditer(text)
                 if m.group(1).lower() in wanted]
    elif filename in ("uv.lock", "poetry.lock"):
        starts = [m.start() for m in _TOML_PACKAGE_RE.finditer(text)] + [len(text)]
        for start, stop in zip(starts, starts[1:]):
            name_m = _TOML_NAME_RE.search(text, start, stop)
            if name_m is None or _lockfile_canon(name_m.group(1), filename) not in wanted:
                continue
            version_m = _TOML_VERSION_RE.search(text, start, stop)
            if version_m is not None:
                found.append((name_m.start(), name_m.group(1), version_m.group(1)))
    entries: dict[str, list[tuple[int, _Ver | None]]] = {}
    line, last = 1, 0
    for offset, name, version in found:  # in file order
        line += text.count("\n", last, offset)
        last = offset
        entries.setdefault(_lockfile_canon(name, filename), []).append((line, _semver3(version)))
    return entries


def _lockfile_line(
    entries: dict[str, list[tuple[int, _Ver | None]]], filename: str,
    names: tuple[str, ...], version: _Ver,
) -> int | None:
    """The first entry of one of `names` that resolves to `version`, else the
    package's first entry, else None."""
    lines = [entry for name in names for entry in entries.get(_lockfile_canon(name, filename), ())]
    exact = [line for line, resolved in lines if resolved == version]
    if exact:
        return min(exact)
    return min((line for line, _ in lines), default=None)
