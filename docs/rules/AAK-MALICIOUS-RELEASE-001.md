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
| Incident | litellm 1.107.0, 21 Oct 2026 ([OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144), [LiteLLM's post](https://docs.litellm.ai/blog/security-incident-oct-21-2026)) |

## What it catches

A release that a source has published as malware, wherever the project names it:

- a declaration that pins it: `litellm==1.107.0` in `requirements.txt`, an exact
  version in `pyproject.toml`, `Pipfile` or `package.json`, or a launch such as
  `uvx litellm==1.107.0` or `npx -y pkg@1.2.3` in an MCP config;
- a lockfile that resolves it: `uv.lock`, `poetry.lock`, `Pipfile.lock`,
  `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1);
- an installed `litellm-1.107.0.dist-info` in a site-packages directory, a
  project's `.venv` and an unpacked image root filesystem included;
- an image reference by digest, such as
  `litellm/litellm@sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e`,
  in a Dockerfile, a compose or Kubernetes file, or an MCP config.

A version pin cannot catch this. litellm 1.107.0 sat above every pinned floor
while it ran a credential stealer at every Python start.

## The feed

A scan reads `~/.agent-audit-kit/malicious_releases.json` when `aak update` has
written it, else the copy bundled with AAK, and never touches the network. The
SARIF run's `properties.dataFeeds` and the console summary say which copy was
read and when it was generated.

- The bundled copy lists OSV MAL-2026-2144 (litellm 1.82.7, 1.82.8 and 1.107.0)
  and the image index digest from LiteLLM's incident post. That post names the
  Docker Hub tags without the repository; `docker.io/litellm/litellm` carries
  them. Its GHCR digests are truncated, so none is listed.
- `aak update` rebuilds the cached copy from OSV's exports for PyPI and npm
  (about 260 MB), keeping only `MAL-` records, the OpenSSF Malicious Packages
  data: 11,960 PyPI and 222,857 npm records on 2026-10-28, withdrawn ones dropped.
- `aak update --github-malware`, with `GITHUB_TOKEN` or `GH_TOKEN` set, also
  reads GitHub's malware advisories: 109,402 for npm and 11,915 for pip on
  2026-10-28, about 1,200 API requests. A failed update keeps the cached copy as
  it was and exits non-zero.

## How a version matches

- Exactly: PEP 440 normalised for PyPI (`1.107` is `1.107.0`), as written for
  npm. `litellm==1.107.0rc1` is not reported; OSV says the release candidates
  were clean.
- A range, or a declaration with no version, matches only an entry that lists
  every release of a package (most typosquats). A range does not say which
  release was installed.
- An image tag never matches, only a digest, and a digest matches whatever
  registry name the reference gives it.
- npm's `0.0.1-security` placeholder, which replaces a removed package, never
  matches.

## How to fix

Pin a version the feed does not list (for litellm, 1.106.2, the version LiteLLM
named), re-lock, and rebuild the environment or image from scratch. Treat every
environment, host or cluster that installed or ran the release as compromised:
rotate each credential it could reach and review its outbound traffic.
