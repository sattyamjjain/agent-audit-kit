# AAK-MALICIOUS-RELEASE-002

**An MCP config launches a package with releases listed as malware, without pinning a safe one**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.31 |
| Scanner | `agent_audit_kit/scanners/malicious_releases.py` |
| Feed | `agent_audit_kit/malicious_feed.py`, the feed [AAK-MALICIOUS-RELEASE-001](AAK-MALICIOUS-RELEASE-001.md) reads |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities) |
| Incident | local-commander-agent 0.3.52, 31 Oct 2026 ([GHSA-7j62-5j84-72fv](https://github.com/advisories/GHSA-7j62-5j84-72fv), [OSV MAL-2026-18425](https://osv.dev/vulnerability/MAL-2026-18425)) |

## Why it exists

On 31 Oct 2026 GitHub published local-commander-agent 0.3.52 as malware
(GHSA-7j62-5j84-72fv, mirrored by OSV as MAL-2026-18425). The package is an MCP
bridge, and most MCP configs start a server without a version:

```json
{"mcpServers": {"lc": {"command": "npx", "args": ["-y", "local-commander-agent"]}}}
```

On 0.6.30 that config drew one MEDIUM AAK-SUPPLY-001, "no version pin", which
names no malware. AAK-MALICIOUS-RELEASE-001 stayed quiet by design: it matches a
version-specific entry only against an exact version, because nothing else says
which release was installed. But a launch without a version runs whichever
release the registry, or the launcher's cache, hands it. 0.3.52 was published
on 23 Oct 2026 at 14:37 UTC and stayed the newest release until 0.3.53 on
25 Oct at 12:21 UTC (npm's `time` record, read 1 Nov), so for those 46 hours
such a launch fetched the malware, and npx keeps what it fetched in its cache.
npm has since removed 0.3.52.

This rule reports the launch itself whenever the package has any
version-specific entry in the feed, so the whole class is covered: the next
version-specific malware record for a package an MCP config launches is
reported as soon as the feed lists it.

## What it catches

A launch in an MCP client config (`.mcp.json`, `mcp.json` such as
`.vscode/mcp.json` or `.cursor/mcp.json`, `claude_desktop_config.json`,
`*.mcp.json`, `*.mcp.yaml`, `*.mcp.yml`) of a PyPI or npm package, through the
launch grammar AAK-SUPPLY-001 reads (npx, pnpx, bunx, `npm exec`, `pnpm dlx`,
`yarn dlx`, uvx, `uv tool run`, `pipx run`, and `--with` packages), when the
launch:

- names no version (`npx -y local-commander-agent`, `uvx litellm`);
- names a tag (`local-commander-agent@latest`), which is whatever the registry
  says today;
- names a range that admits a listed release (`@^0.3.0`, `@~0.3.50`), read on
  release triples as the version pins read ranges;

and the feed lists particular releases of the package as malicious. Both
`mcpServers` and VS Code's `servers` map are read.

It stays quiet for:

- an exact pin: a listed one is AAK-MALICIOUS-RELEASE-001's (CRITICAL), any
  other is safe by the feed (`local-commander-agent@0.3.61`);
- a range that admits no listed release (`@^0.3.53`, `@>=0.4.0`);
- a package the feed lists in every release (most typosquats), which
  AAK-MALICIOUS-RELEASE-001 already reports whatever the launch names;
- a git URL or a local path, which the registry does not serve.

## One launch, one finding

The same launch is also an unpinned launch to AAK-SUPPLY-001 (MEDIUM) and
AAK-MCP-007 (LOW). The fix is the same pin, and this finding says which
releases to keep out, so the scan stands both down on a launch this rule
reports at or above their severity. The evidence opens with the same
`Server '<name>' arg: <spec>` head the other two print. A launch that is not an
entry of a top-level `mcpServers` or `servers` map has no such head, and there
the other findings stay.

## Checking the launcher cache

A launch without a version may already have fetched a listed release. Run
`aak scan --include-user-config` to read the launchers' caches on this host, as
[AAK-MALICIOUS-RELEASE-001](AAK-MALICIOUS-RELEASE-001.md) does with that flag:

| Launcher | Cache directory | What is read |
|---|---|---|
| npx (npm 7+) | `npm_config_cache` if set, else `~/.npm`, or `%LocalAppData%\npm-cache` on Windows | `<cache>/_npx/<hash>/node_modules/<name>/package.json`, its `version` |
| uvx | `UV_CACHE_DIR` if set, else `$XDG_CACHE_HOME/uv` or `~/.cache/uv`, or `%LOCALAPPDATA%\uv\cache` on Windows | `<cache>/environments-v*/<hash>/<hash>/`, the venv `uvx` runs a tool in, and its `<name>-<version>.dist-info` directories |

The npx layout is npm's own (`npxCache` is `<cache>/_npx`, and each install
directory is named for a hash of the packages it holds). The uv locations are
the ones uv documents; on uv 0.9 each environment entry is a link into the
cache's `archive-v0/`. A listed release in either cache is reported as
AAK-MALICIOUS-RELEASE-001, with evidence such as
`npx cache at ~/.npm/_npx/0123456789abcdef/node_modules/local-commander-agent holds local-commander-agent 0.3.52`.

## What it does not see

- A launch outside an MCP config: a shell script, a Makefile, a package.json
  `scripts` entry, or a program a config runs by name.
- Whether a listed release was ever fetched: the rule reports what the launch
  could run. The cache check above says what was.
- A pre-release beside a listed release counts as it when a range is read,
  since ranges are read on release triples.
- More than ten listed versions per entry are counted, not named.
- The bundled feed lists two packages with version-specific entries (litellm
  and local-commander-agent), so without `aak update` nothing else is known.
- A config over 2 MB.

## How to fix

Pin the launch to one release outside the list the finding names
(`npx -y local-commander-agent@0.3.61`, `uvx litellm==1.106.2`), or stop
launching the package. Then run `aak scan --include-user-config`, and if a
listed release is in the npx or uv cache, delete that cache entry and treat the
machine that ran it as compromised: rotate every credential it could reach.
Run `aak update` so the scan reads the current feed rather than the bundled
entries.

## Related advisories

| Package | Record | Listed releases | In the bundled feed |
|---|---|---|---|
| local-commander-agent (npm) | MAL-2026-18425, GHSA-7j62-5j84-72fv | 0.3.52 | yes |
| litellm (PyPI) | MAL-2026-2144 | 1.82.7, 1.82.8, 1.107.0 | yes |

A finding on the first reads:

```text
Server 'lc' arg: local-commander-agent is launched by `npx local-commander-agent` in
.mcp.json with no version pinned, and the malicious-release feed lists releases of
local-commander-agent: MAL-2026-18425 (GHSA-7j62-5j84-72fv) lists local-commander-agent
0.3.52 (https://osv.dev/vulnerability/MAL-2026-18425). An unpinned launch runs whichever
release the registry or the launcher's cache hands it. Pin a release outside the list,
and check the launcher cache (`aak scan --include-user-config` reads npx's and uv's).
Feed: the bundled copy generated 2026-11-01T10:12:39Z.
```
