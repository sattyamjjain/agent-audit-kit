# AAK-KNOWN-VULN-003

**An MCP config launches, without pinning a release, a package a published advisory lists as affected**

| Field | Value |
|---|---|
| Severity | The advisory's when every release the launch can fetch is affected (the advisory names no end, or a range admits only affected releases); MEDIUM otherwise |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.34 |
| Scanner | `agent_audit_kit/scanners/known_vulns.py` |
| Feed | the advisory feed of `agent_audit_kit/advisory_feed.py`, the one [AAK-KNOWN-VULN-001](AAK-KNOWN-VULN-001.md) reads |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities) |

## Why it exists

DBHub (`@bytebase/dbhub`) is a database MCP server, and its README starts it
straight from an MCP config:

```json
{"mcpServers": {"dbhub": {"command": "npx", "args": ["-y", "@bytebase/dbhub"]}}}
```

On 2 Nov 2026 GitHub published GHSA-j656-3hf2-fvjc: below 0.22.6, MySQL and
MariaDB comment syntax slipped past DBHub's read-only SQL validation, so a caller
in read-only mode could still run writes and DDL. OSV lists it with a CVE alias
(in the table below); GitHub's own record names no CVE.

[AAK-KNOWN-VULN-001](AAK-KNOWN-VULN-001.md) checks every release a project
resolves against the advisory feed, but a launch like the one above names no
release, and a declaration without one was not judged. Yet the launch runs
whichever release npx resolves, or finds in its cache, and the config does not
say which. [AAK-MALICIOUS-RELEASE-002](AAK-MALICIOUS-RELEASE-002.md) already asks
this question of malware; this rule asks it of every advisory in the feed.

## What it catches

A launch in an MCP client config (`.mcp.json`, `mcp.json` such as
`.vscode/mcp.json`, `claude_desktop_config.json`, `*.mcp.json`, `*.mcp.yaml`,
`*.mcp.yml`), through the launch grammar AAK-SUPPLY-001 reads (npx, pnpx, bunx,
`npm exec`, `pnpm dlx`, `yarn dlx`, uvx, `uv tool run`, `pipx run`, and `--with`
packages), of a PyPI or npm package from its registry, when the launch:

- names no version (`npx -y @bytebase/dbhub`, `uvx vllm`), or a tag (`@latest`,
  whatever the registry says today): it can fetch any release;
- names a range: it can fetch the releases the range admits, read on release
  triples as the version pins read ranges;

and the advisory feed holds an advisory whose affected releases it admits.

| Launch | Result |
|---|---|
| `npx -y @bytebase/dbhub` | MEDIUM: the advisory names a fix, 0.22.6 |
| `npx -y @bytebase/dbhub@latest` | MEDIUM |
| `npx -y @bytebase/dbhub@^0.23.0` | nothing: the range admits no affected release |
| `npx -y @bytebase/dbhub@0.22.5` | [AAK-KNOWN-VULN-001](AAK-KNOWN-VULN-001.md), as before: one release |
| `npx -y @bytebase/dbhub@0.22.6` | nothing |
| `npx -y github:bytebase/dbhub` | nothing: not the registry |
| a package whose advisory names no fixed release | the advisory's severity |
| `npx -y lodash@<4.17.0` (every release it admits affected) | the advisory's severity |

One finding per launch and advisory: two servers that launch one package are two
launches.

## Severity

The release that runs is the launcher's choice. When the advisory names a fix,
the newest release may well be the fixed one (DBHub 0.22.6 shipped in June 2026,
months before the advisory), so the finding is MEDIUM: the config does not
protect the server, but it may not run an affected release either. When every
release the launch can fetch is affected, because the advisory names no end or
the range admits only affected releases, the finding takes the advisory's own
severity.

## One launch, one finding

The same launch is also an unpinned launch to AAK-SUPPLY-001 ("no version pin",
MEDIUM) and AAK-MCP-007 (LOW). The fix is the same pin, and this finding names
the release to pin, so the scan stands both down on a launch this rule reports
at or above their severity. The evidence opens with the same
`Server '<name>' arg: <spec>` head the other two print; a launch outside a
top-level `mcpServers` or `servers` map has no such head, and there the other
findings stay. Where a version pin reports every CVE id of the advisory on the
same line of the same file at or above this finding's severity, as the MCPHub
version pin does for an unpinned `@samanhappy/mcphub`, only the pin's finding is
kept.

## Checking the launcher cache

A launch without a release may already have fetched an affected one. With
`aak scan --include-user-config`, [AAK-KNOWN-VULN-001](AAK-KNOWN-VULN-001.md)
reads the launchers' caches on this host, as AAK-MALICIOUS-RELEASE-001 does:
npm's npx cache (`<cache>/_npx/<hash>/node_modules/<name>/package.json`) and
uv's tool environments (`<cache>/environments-v*/`). A cached release an
advisory lists is reported at the advisory's severity, with evidence such as
`npx cache at ~/.npm/_npx/0123456789abcdef/node_modules/@bytebase/dbhub holds @bytebase/dbhub 0.22.4`.

## What it does not see

- A launch outside an MCP config: a shell script, a Makefile, a package.json
  `scripts` entry, or a program a config runs by name.
- What the launch actually ran: the rule does not know the registry's newest
  release, so an advisory fixed long ago is still reported, at MEDIUM. The cache
  check above says what was fetched.
- A pre-release beside an affected release counts as it when a range is read.
- Without `aak update` the feed is the few records bundled with AAK (npm's open,
  @modelcontextprotocol/inspector, opencode-ai and @samanhappy/mcphub among
  them), so nothing else is known.
- A config over 2 MB.

## How to fix

Pin the launch to a release outside the advisory's range, the fix the finding
names or later (`npx -y @bytebase/dbhub@0.22.6`, `uvx vllm==0.32.0`), and restart
the server. Then run `aak scan --include-user-config` to check whether npx or uv
already cached an affected release, and clear that cache entry if so. Where the
advisory names no fixed release, stop launching the package or keep the flawed
component unreachable. Run `aak update` so the scan reads the current
advisories.

## Related advisories

| Package | Advisory | Range | Fixed | In the bundled feed |
|---|---|---|---|---|
| @bytebase/dbhub, read-only SQL bypass on MySQL and MariaDB | GHSA-j656-3hf2-fvjc (OSV alias CVE-2026-61789) | below 0.22.6 | 0.22.6 | no; `aak update` reads it from OSV |

A finding reads:

```text
Server 'dbhub' arg: @bytebase/dbhub is launched by `npx @bytebase/dbhub` in .mcp.json with no
version pinned, and GHSA-j656-3hf2-fvjc (CVE-2026-61789, GitHub rates it MEDIUM) lists
@bytebase/dbhub below 0.22.6 as affected, fixed in 0.22.6. The release that runs is whichever
npx resolves or finds in its cache, which this config does not control. Pin a release outside
the advisory's range: `npx -y @bytebase/dbhub@0.22.6` or later. ...
```
