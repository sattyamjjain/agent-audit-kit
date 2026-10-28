# AAK-STARTUP-HOOK-SITECUSTOMIZE-001

**sitecustomize or usercustomize module where Python imports it at every start**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/startup_hooks.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |
| Incident | litellm 1.107.0, 21 Oct 2026 ([OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144)) |

## What it catches

Python's `site` module imports `sitecustomize`, and then `usercustomize`, at
every interpreter start, before any script runs. A module of either name on the
path runs in every Python process of that environment or image. litellm 1.107.0
installed a `sitecustomize.py` that started a background process fetching and
running remote code every hour.

The rule reports every form Python can import, at the top of a site-packages or
dist-packages directory:

- `sitecustomize.py`, or a sourceless `sitecustomize.pyc`
- an extension module (`sitecustomize.cpython-312-x86_64-linux-gnu.so`, `.pyd`)
- a package: `sitecustomize/__init__.py`
- a compiled copy in `__pycache__`. Python loads that copy only beside its
  source, so on its own it shows the module was installed there. LiteLLM's clean-up
  advice was to delete both.

The same names are reported in a directory a Dockerfile puts on `PYTHONPATH`:
the directory under the scan root when the root is an unpacked image, or a
build-context directory that a `COPY` or `ADD` places at that path.

## What it does not catch

- A `PYTHONPATH` set outside a Dockerfile: an image's config, a compose file, a
  CI job or a shell.
- The standard library directory, where Debian and Ubuntu ship a
  `sitecustomize.py` of their own.

## How to fix

Read the module. If no package you installed on purpose, and no file of your
own, put it there, delete it and any `__pycache__` copy, rebuild the environment
or image from a pinned lockfile, and rotate every credential it could reach. A
hook of your own belongs in your application's start-up code, where it is seen
and tested.
