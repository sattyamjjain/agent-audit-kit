# AAK-STARTUP-HOOK-PTH-001

**Startup code in a site-packages .pth or .start file**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.28 |
| Scanner | `agent_audit_kit/scanners/startup_hooks.py` |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |
| Incident | litellm 1.107.0, 21 Oct 2026 ([OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144), [LiteLLM's post](https://docs.litellm.ai/blog/security-incident-oct-21-2026)) |

## What it catches

When Python starts, its `site` module reads every `*.pth` file at the top of
each site-packages directory and runs each line that starts with `import`.
Nothing has to import the package that shipped the file: `pip`, `pytest` and an
MCP server started from that environment all run it first. litellm 1.107.0 put
`cook.pth`, containing `import cook`, at the top of site-packages, and `cook.py`
stole credentials at every interpreter start.

Python 3.15 adds `<name>.start` files (PEP 829): each line names a
`pkg.module:callable` that Python calls at start-up. The rule reports those too.

## How a line is read

| Python | What runs |
|---|---|
| 3.9 to 3.11 | a line that starts with `import ` or `import<TAB>`, as written |
| 3.12 to 3.14 | the same test, after a leading BOM is dropped and the file is split with `str.splitlines()` |
| 3.15 | the same test after the line is stripped, so an indented `import` runs too; plus every entry point in a `.start` file |

(Read from the `site.py` of CPython 3.9.25, 3.10.19, 3.11.14, 3.12.12, 3.13.11,
3.14.2 and 3.15.2.)

The rule reports the union: a line that runs under any of them. A line that only
names a directory is not code and is not reported.

## What is not reported

- Files AAK built in clean environments on 2026-10-28 and lists in
  `agent_audit_kit/data/startup_hook_allowlist.json`: setuptools'
  `distutils-precedence.pth`, the `_virtualenv.pth` that virtualenv and uv
  write, and coverage's `a1_coverage.pth`. A file matches only by its name and
  the sha256 of its normalised content together, never by name alone: a
  malicious `.pth` can call itself `distutils-precedence.pth`.
- A setuptools editable install's finder (`__editable__.<project>-<version>.pth`)
  is named after its project, so only the placeholder AAK built is allowlisted.
  Your own `pip install -e .` is reported; it runs your checkout's code at every
  start. Exclude its path with `--ignore-paths` once you have looked.
- The module a reported line imports is not read.

## Where it looks

Every directory named `site-packages` or `dist-packages` up to 12 levels below
the scan root, including inside `.venv/`, `venv/`, `env/`, `.tox/` and
`vendor/`, which every other rule skips. An MCP server's own environment under
the project is read the same way. To read an image, unpack its root filesystem
and scan that directory: see [Scan a container image's files](../scan-image-rootfs.md).

## How to fix

Open the file and the module it imports. If no package you installed on purpose
wrote it (a package's `.dist-info/RECORD` lists every file it installed), delete
the file, its module and any `__pycache__` copy, rebuild the environment or
image from a pinned lockfile rather than repairing it in place, and rotate every
credential the environment could reach.
