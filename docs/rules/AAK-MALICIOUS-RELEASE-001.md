# AAK-MALICIOUS-RELEASE-001

**A declared, locked, installed or deployed release is listed as malware**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/malicious_releases.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |
| Incident | litellm 1.107.0, 21 Oct 2026 ([OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144), [LiteLLM's post](https://docs.litellm.ai/blog/security-incident-oct-21-2026)); the ARTEX AI images on Docker Hub, 5 Nov 2026 ([The Hacker News](https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html)) |

## What it catches

A release that a source has published as malware, wherever the project names it:

- a declaration that pins it: `litellm==1.107.0` in `requirements.txt`, an exact
  version in `pyproject.toml`, `Pipfile` or `package.json`, or a launch such as
  `uvx litellm==1.107.0` or `npx -y pkg@1.2.3` in an MCP config;
- a lockfile that resolves it: `uv.lock`, `poetry.lock`, `Pipfile.lock`,
  `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1),
  `Cargo.lock`, and a `go.mod`'s `require` lines (`go.sum` is not read, and a
  `Cargo.toml` without its `Cargo.lock` resolves nothing). A `Cargo.lock` holding

  ```toml
  [[package]]
  name = "env-test-guard"
  version = "0.3.0"
  source = "registry+https://github.com/rust-lang/crates.io-index"
  ```

  is reported at its `[[package]]` line, and so is the same crate spelled
  `env_test_guard`: cargo treats `-` and `_` in a crate name alike;
- an installed `litellm-1.107.0.dist-info` in a site-packages directory, a
  project's `.venv` and an unpacked image root filesystem included;
- an image reference by digest, such as
  `litellm/litellm@sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e`,
  in a Dockerfile, a compose or Kubernetes file, or an MCP config;
- any reference to a repository the feed lists whole, because an attacker owns
  it and every build is the payload: `image: tomicdd/artex:latest` in a compose
  or Kubernetes file, a Helm `repository:` with its `tag:`, or
  `FROM docker.io/tomicdd/artex`, by any tag, by digest or bare;
- with `aak scan --include-user-config`, a release a launcher fetched onto this
  host: a package in npm's npx cache
  (`<npm cache>/_npx/<hash>/node_modules/<name>/package.json`) or a
  `<name>-<version>.dist-info` in one of uv's tool environments
  (`<uv cache>/environments-v*/`, where `uvx` runs a tool). The evidence reads
  `npx cache at <path> holds <name> <version>`. Without the flag a scan reads
  nothing outside the project.

An MCP config that launches a listed package with no version
(`npx -y local-commander-agent`) is [AAK-MALICIOUS-RELEASE-002](AAK-MALICIOUS-RELEASE-002.md):
nothing says which release it installed, so this rule cannot report it.

A version pin cannot catch this. litellm 1.107.0 sat above every pinned floor
while it ran a credential stealer at every Python start.

## The feed

A scan reads `~/.agent-audit-kit/malicious_releases.json` when `aak update` has
written it, else the copy bundled with AAK, and never touches the network. The
SARIF run's `properties.dataFeeds` and the console summary say which copy was
read and when it was generated.

- The bundled copy lists OSV MAL-2026-2144 (litellm 1.82.7, 1.82.8 and 1.107.0),
  OSV MAL-2026-18425 (local-commander-agent 0.3.52, GHSA-7j62-5j84-72fv),
  OSV MAL-2026-2307 (axios 0.30.4 and 1.14.1, GHSA-fw8c-xr5c-95f9), OSV MAL-2026-2306
  (every release of plain-crypto-js, GHSA-2x9r-6wxq-hrr7), OSV MAL-2026-18776 (the
  crate env-test-guard 0.2.0 and 0.3.0, which GitHub lists as GHSA-7w47-jmjx-gvm2: its
  `GitEnv::detect()` sends CI tokens out from a runner) and
  the image index digest from LiteLLM's incident post. That post names the
  Docker Hub tags without the repository; `docker.io/litellm/litellm` carries
  them. Its GHCR digests are truncated, so none is listed.
- It also lists `docker.io/tomicdd/artex` and `docker.io/congdonglinux/artex`
  whole. [The Hacker News](https://thehackernews.com/2026/11/backdoored-docker-image-for-artex-ai.html) reported on 5 Nov 2026 that both carry a
  hidden `verifyCaptcha()` in the ARTEX AI console's login handler that runs
  part of the CAPTCHA field through `sh -c` as root before any credential
  check, and named no tag or digest. The six other namespaces it names as
  publishing an `artex` image are not called backdoored and are not listed.
- `aak update` rebuilds the cached copy from OSV's exports for PyPI, npm,
  crates.io and Go (about 280 MB), keeping only `MAL-` records, the OpenSSF
  Malicious Packages data: 11,960 PyPI and 222,857 npm records on 2026-10-28, and
  21 crates.io and 20 Go records on 2026-11-07, withdrawn ones dropped. The
  advisory feed AAK-KNOWN-VULN-001 reads comes out of the same downloads.
- `aak update --github-malware`, with `GITHUB_TOKEN` or `GH_TOKEN` set, also
  reads GitHub's malware advisories for npm, pip, rust and go: 109,402 for npm
  and 11,915 for pip on 2026-10-28, about 1,200 API requests. A failed update keeps the cached copy as
  it was and exits non-zero.

## How a version matches

- Exactly: PEP 440 normalised for PyPI (`1.107` is `1.107.0`), as written for
  npm and crates.io, and without its leading `v` for Go (`v0.3.0` is `0.3.0`). `litellm==1.107.0rc1` is not reported; OSV says the release candidates
  were clean.
- A range, or a declaration with no version, matches only an entry that lists
  every release of a package (most typosquats). A range does not say which
  release was installed.
- An image tag never matches a digest entry, only a digest, and a digest
  matches whatever registry name the reference gives it.
- A whole-repository entry matches its repository by any tag, by digest or
  bare, with Docker Hub spelt `docker.io/`, `index.docker.io/`,
  `registry-1.docker.io/` or not at all, and only in an image slot. It does not
  match the same path on another registry (`ghcr.io/tomicdd/artex`), a longer
  name (`tomicdd/artex-pro`), a `docker run` argument, or the name in a comment
  or in prose.
- npm's `0.0.1-security` placeholder, which replaces a removed package, never
  matches.

## How to fix

Pin a version the feed does not list (for axios 1.14.1 or 0.30.4, 1.14.0 or 0.30.3,
and delete `node_modules/plain-crypto-js`, as
[the axios postmortem](https://github.com/axios/axios/issues/10636) advises; for
litellm, 1.106.2, the version LiteLLM
named), re-lock, and rebuild the environment or image from scratch. Treat every
environment, host or cluster that installed or ran the release as compromised:
rotate each credential it could reach and review its outbound traffic.
