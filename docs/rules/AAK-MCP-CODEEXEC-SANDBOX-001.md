# AAK-MCP-CODEEXEC-SANDBOX-001

**FastMCP's GenerativeUI runs caller code in a prefab-ui sandbox with open Deno permissions**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `SUPPLY_CHAIN` |
| Shipped | v0.6.34 |
| Scanner | `agent_audit_kit/scanners/mcp_codeexec_sandbox.py` |
| CVE | CVE-2026-120338 |
| OWASP MCP | MCP04:2025 (Software Supply Chain Attacks & Dependency Tampering), MCP05:2025 (Command Injection & Execution) |
| OWASP Agentic | ASI04 (Agentic Supply Chain Vulnerabilities), ASI05 (Unexpected Code Execution) |

## Why it exists

FastMCP's Generative UI provider adds a `generate_prefab_ui` tool to a server:

```python
from fastmcp.apps.generative import GenerativeUI

mcp.add_provider(GenerativeUI())
```

The tool takes Python code from its caller (normally the model) and runs it in
prefab-ui's sandbox: Pyodide, inside a Deno subprocess. From 0.14.0 up to 0.21.0,
prefab-ui started that subprocess with `deno run --allow-read --allow-write
--allow-net` and kept those permissions while it ran the code, and Python in
Pyodide can reach Deno's API. So whoever can call the tool, anyone at all on a
server without authentication, can read and write files as the server's user
and persist by writing a `.pth` file into the server's environment. JFrog
published this as CVE-2026-120338 (CVSS 3.1 10.0) on 1 Nov 2026; prefab-ui
0.21.0 fixes it (PrefectHQ/prefab PR 538).

fastmcp's `apps` extra asks for `prefab-ui>=0.18.0`, so a project that installs
`fastmcp[apps]` without pinning prefab-ui can resolve an affected release.
[AAK-KNOWN-VULN-001](AAK-KNOWN-VULN-001.md) reports the locked release from JFrog's
record; this rule says the tool that reaches the flaw is registered.

## What it catches

A registration, in Python source:

- `add_provider(GenerativeUI(...))`, or `add_provider(x)` where `x = GenerativeUI(...)`
  in the same module;
- with `GenerativeUI` imported from `fastmcp.apps.generative`, under any alias, or
  named on the module (`gen.GenerativeUI`, `fastmcp.apps.generative.GenerativeUI`);

in a project where prefab-ui is 0.14.0 up to 0.21.0, read from:

- the PyPI lockfiles AAK-KNOWN-VULN-001 reads (uv.lock, poetry.lock, Pipfile.lock);
- installed `prefab_ui-<version>.dist-info` directories in a site-packages directory;
- exact pins in requirements*.txt, pyproject.toml and Pipfile;

or where none of those gives a release and no manifest range keeps prefab-ui at
0.21.0 or later. One finding per registration, on its `add_provider` line.

| Project | Result |
|---|---|
| GenerativeUI, uv.lock prefab-ui 0.20.2 | CRITICAL |
| GenerativeUI, uv.lock prefab-ui 0.21.0 | nothing |
| GenerativeUI, `prefab-ui>=0.21.0` and no lockfile | nothing |
| GenerativeUI, `fastmcp[apps]` and nothing else | CRITICAL (nothing pins prefab-ui) |
| uv.lock prefab-ui 0.20.2, no GenerativeUI | nothing here; AAK-KNOWN-VULN-001 reports the release |

## What it does not see

- A provider built in another module, passed through a factory or a list, or
  registered any way other than `add_provider`.
- Which lockfile belongs to which server: any lockfile under the root counts.
- Whether the server has authentication, or whether the tool was ever called.
- A 0.21.0 pre-release counts as affected (PEP 440 puts it before 0.21.0).
- A source file over 512 KB, or a lockfile over 32 MiB.

## How to fix

Upgrade prefab-ui to 0.21.0 or later and re-lock. fastmcp's `apps` extra does not
require it, so pin `prefab-ui>=0.21.0` beside `fastmcp[apps]`. Until then, keep the
`generate_prefab_ui` tool off any server a caller you do not trust can reach.
Check the server's environment for `.pth` files nobody installed
([AAK-STARTUP-HOOK-PTH-001](AAK-STARTUP-HOOK-PTH-001.md) reads them) and rotate
what its user could read.

## Related advisories

| Software | CVE | Range | Fixed |
|---|---|---|---|
| prefab-ui, Generative UI sandbox | CVE-2026-120338 (GHSA-595q-jv4r-q7j9, a repository advisory only) | 0.14.0 up to 0.21.0 | 0.21.0 |

A finding reads:

```text
`server.py:5` registers FastMCP's GenerativeUI provider, whose `generate_prefab_ui` tool runs
Python its caller supplies in prefab-ui's Pyodide sandbox, and uv.lock:10 gives prefab-ui 0.20.2.
prefab-ui 0.14.0 up to 0.21.0 starts that sandbox's Deno runtime with unscoped read, write and
network permissions the code can reach (CVE-2026-120338, CVSS 10.0); it is fixed in 0.21.0. ...
```

See also [AAK-MCP-CODEEXEC-SANDBOX-002](AAK-MCP-CODEEXEC-SANDBOX-002.md), the class
rule for any Deno sandbox started with open permissions.
