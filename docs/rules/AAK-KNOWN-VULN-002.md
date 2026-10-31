# AAK-KNOWN-VULN-002

**A launched MCP server, binary or image is a release a published advisory lists as affected**

| Field | Value |
|---|---|
| Severity | The advisory's for a launch whose release is in its range: CRITICAL from CVSS 9.0, HIGH from 7.0, MEDIUM below that; MEDIUM for a launch whose release could not be read |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.30 |
| Scanner | `agent_audit_kit/scanners/known_vulns_launch.py` |
| Feed | the `launch` list of `agent_audit_kit/advisory_feed.py`, filled by `agent_audit_kit/nvd_feed.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities) |

## Why it exists

[AAK-KNOWN-VULN-001](AAK-KNOWN-VULN-001.md) checks the releases a project
installs from PyPI and npm against the advisory feed. Plenty of MCP servers and
agent apps are on neither registry: a Go binary a config starts by its path, a
module started with `go run`, an image a compose file pins. On 30 Oct 2026 NVD
published two critical records of that kind. MoLing, a Go MCP server, took no
authentication on its SSE endpoints before 0.5.0 (CVSS 9.6). TAKO, an Okta
agent app shipped as a Docker Hub image, let anyone create its first
administrator before 3.0.1-beta (CVSS 9.8). Each record names a vendor and a
product and no package, so no package row could map it, and a project that ran
MoLing 0.4.0 from `.mcp.json` passed every rule.

This rule reads what a project launches and matches it against those records,
through reviewed launch rows that say how each project starts its software.

## What it catches

A launch of software a launch row names, in a release the record lists as
affected:

- in a JSON MCP client config (`.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`,
  `claude_desktop_config.json` and every other `*mcp*.json`), any server of
  `mcpServers` or VS Code's `servers`:
  - its `command`, by file name: `/usr/local/bin/moling` and `C:\tools\moling.exe`
    are both `moling`;
  - `go run <module>@<version>`, the module matched at a path boundary, so a
    package inside it (`github.com/gojue/moling/cli`) counts and
    `github.com/gojue/molingx` does not;
  - the image a `docker`, `podman` or `nerdctl` `run` starts, also spelled
    `docker.io/...` for a Docker Hub image;
  - an argument that is itself a `github.com/<owner>/<repo>` URL, with the release
    its `@v1.2.3`, `#v1.2.3`, `/releases/tag/`, `/releases/download/`, `/tree/`
    or `/archive/` part names;
  - any of these behind `sh -c`, `bash -c`, `cmd /c` or PowerShell's `-Command`,
    two levels deep;
- in YAML files (compose files, Kubernetes manifests, Helm values) and
  Dockerfiles, a reference to a launch row's image where an image goes: an
  `image:` value, a `FROM` line, a quoted string, or a Helm `repository` with its
  `tag`. A commented-out line is skipped.

A launch whose release is in the advisory's range is reported at the advisory's
severity. A launch that names no release AAK can read is MEDIUM, and the
finding says why: a bare command, `latest`, an untagged or digest-only image, a
branch or a commit. A launch whose release is outside the range is quiet. One
finding per file and advisory, at the first launch in its range (counting the
others), else at the first one whose release could not be read.

## The launch rows

The rows live beside the package rows in
`agent_audit_kit/data/cna_package_map.json`, under `launch`. Each names a
project by its repository and by the vendor and product its CNA writes, and
lists the names a project starts it by. Every name comes from the project's own
repository, never from a name alone:

| Software | Read from | `commands` | `go_modules` | `images` |
|---|---|---|---|---|
| gojue/moling | README (`"command": "/usr/local/bin/moling"`), go.mod | `moling` | `github.com/gojue/moling` | none (no Dockerfile or compose file; the README calls MoLing dependency-free) |
| fctr-id/okta-ai-agent (TAKO) | docker-compose.yml | none | none | `fctrid/ai-agent-for-okta` |

An NVD record maps to a row by the CNA's repository, else by its vendor and
product, as a package row maps one. `aak update` reads the matching records
into the feed's `launch` list and prints the ten (vendor, product) pairs that
most often mapped to nothing, so the next rows come from evidence.

## How a release is read

As semver 2.0 with a leading `v` dropped, the order GitHub writes these ranges
in. A Go pseudo-version is a pre-release of the release after it, so a commit
after 0.4.0 reads as 0.4.1-something and stays in a `< 0.5.0` range. TAKO's
releases are named `-beta`, and its own compose file at the fixed tag runs the
image tag `3.0.1-alpha`, which Docker Hub received an hour before the fix
commit: semver puts `3.0.1-alpha` below `3.0.1-beta`, and reports it.

A two-part tag or Go query (`3.1`, `@v0.4`) floats over its line. It is reported
at the advisory's severity when every release on the line is affected, is
quiet when none is, and is MEDIUM when the line holds both.

## What it does not see

- Software no launch row names. Two rows exist on 31 Oct 2026; a record that
  maps to no row is counted and dropped.
- A launch outside an MCP config or an image reference: a shell script, a
  Makefile, a systemd unit, or a YAML MCP config's `command` (a YAML file is read
  for image references only).
- An argument that only links into a repository (`/blob/...`), and a GitHub
  shorthand such as `github:owner/repo`.
- An image tag's suffix is a semver pre-release, so a variant tag of the first
  fixed release (`1.2.3-alpine` for a fix in 1.2.3) reads affected.
- The feature in use: MoLing's flaw is in its SSE mode (`-l`), and a stdio
  launch of 0.4.0 is reported all the same, because the release is the flawed one.
- A file over 2 MB.

## How to fix

Pin the launch to a release outside the advisory's range, the fix the finding
names or later: `go run module@vX.Y.Z`, an image tag naming the release, or the
binary's release. Then restart the server or redeploy. For a launch AAK could
not read, check which release it runs and pin it. Where the advisory lists no
fixed release, stop running the software or keep the flawed component
unreachable. Run `aak update` so the scan reads the current NVD records rather
than the bundled few.

## Related advisories

The records that showed the gap, as NVD listed them on 2026-10-31. They are
context, not this rule's references: the rule reports whatever launch entry the
feed holds.

| Software | CVE | CNA range | Fixed | In the bundled feed |
|---|---|---|---|---|
| MoLing, SSE endpoints with no authentication | CVE-2026-62863 | `< 0.5.0` | 0.5.0 | yes (CVSS 3.x 9.6) |
| TAKO, unauthenticated first-administrator setup | CVE-2026-63377 | `< 3.0.1-beta` | 3.0.1-beta | yes (CVSS 3.x 9.8) |
| TAKO, any signed-in user runs Python | CVE-2026-63378 | `< 3.0.1-beta` | 3.0.1-beta | yes (CVSS 3.x 8.8) |

A finding on the MoLing one reads:

```text
`go run github.com/gojue/moling@v0.4.0` in .mcp.json launches gojue/moling v0.4.0, which
CVE-2026-62863 (NVD CNA record, CVSS 3.x 9.6) lists as affected; it is fixed in 0.5.0
(https://nvd.nist.gov/vuln/detail/CVE-2026-62863).
```
