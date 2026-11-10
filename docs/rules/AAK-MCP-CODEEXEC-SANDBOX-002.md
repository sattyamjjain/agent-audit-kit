# AAK-MCP-CODEEXEC-SANDBOX-002

**A code-execution sandbox starts Deno with open permissions and hands it caller code**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `MCP_CONFIG` |
| Shipped | v0.6.34 |
| Scanner | `agent_audit_kit/scanners/mcp_codeexec_sandbox.py` |
| CVE | CVE-2026-120338 |
| OWASP MCP | MCP05:2025 (Command Injection & Execution) |
| OWASP Agentic | ASI05 (Unexpected Code Execution) |

## Why it exists

A WASM interpreter does not contain code that can reach the runtime hosting it.
prefab-ui's Generative UI sandbox ran the Python a caller sent in Pyodide, under
Deno, and Python in Pyodide can call Deno's API. Below 0.21.0 the launcher in
`_pyodide.py` started the runner like this:

```python
subprocess.Popen([deno, "run", "--unstable-detect-cjs",
                  "--allow-read", "--allow-write", "--allow-net", str(RUNNER_JS)])
```

and `runner.js` passed each request's code to `pyodide.runPythonAsync(...)`. The
caller's Python had the server's own file and network access (CVE-2026-120338,
CVSS 10.0). prefab-ui 0.21.0 still passes `--allow-read` and `--allow-write`,
which its bootstrap needs. But it scopes `--allow-net` to its CDN
(`--allow-net=cdn.jsdelivr.net:443`), adds `--no-prompt`, and revokes read, write
and net in the runner before it takes any code:

```js
for (const name of ["read", "write", "net"]) {
  await Deno.permissions.revoke({ name });
}
```

This rule is the class: any sandbox that starts Deno with an open permission and
hands it code a caller supplies, MCP tool or not.

## What it catches

A Deno launch in Python or JS/TS source:

- `deno` (a word, a path ending in it, or `Deno.execPath()`) followed by `run`,
  as an argument list (`[deno, "run", ...]`, `spawn("deno", ["run", ...])`,
  `new Deno.Command(Deno.execPath(), { args: ["run", ...] })`) or a command string
  (`"deno run -A ..."`);
- with an open permission: `-A`, `--allow-all`, or `--allow-read`, `--allow-write`,
  `--allow-net`, `--allow-run`, `--allow-env`, `--allow-ffi`, `--allow-sys` or
  `--allow-import` with no value. `-A` opens read, write, net, run, env, ffi and sys;

where caller code reaches the runtime, in the launching file (if it is JS/TS) or
in a JS/TS script whose name the launching file writes, found beside it:

- a Pyodide `runPython(...)` or `runPythonAsync(...)`, an `eval(...)` or a
  `new Function(...)` whose code argument is not a plain string literal (a template
  with `${...}` counts);

and the script does not revoke the open permission (`Deno.permissions.revoke`
with its name). One finding per launch, on the launch's line.

| Source | Result |
|---|---|
| `spawn("deno", ["run", "-A", script])` and `runPythonAsync(code)` | HIGH |
| prefab-ui 0.20.2's launcher and runner | HIGH, at the launch in `_pyodide.py` |
| prefab-ui 0.21.0's launcher and runner (scoped net, revoke loop) | nothing |
| `--allow-read=/srv/assets` | nothing (scoped) |
| `--no-prompt` and no allow flag | nothing |
| `deno run -A server.ts` with no code hand-off | nothing |

## What it does not see

- Data flow: a call whose argument is a variable counts as caller code even when
  the variable is a constant, and whether a caller's text really reaches it is not
  traced.
- `deno eval`, a launch whose flags sit in another variable or are built in
  pieces, a shell script, a Dockerfile, and flags set through `DENO_*` variables.
- A script the launching file does not name as a string literal, one outside the
  scan root, and more than 32 named scripts per file.
- When a revocation runs: a `Deno.permissions.revoke` naming the permission
  anywhere in the script counts, before or after the code runs.
- A scoped flag is not read as open, however wide its scope (`--allow-read=/`).
- Flags more than 1,500 characters past `run`, and a source file over 512 KB.

## How to fix

Start the sandbox's runtime with no permissions, or scoped ones
(`--allow-read=<dir>`, `--allow-net=<host>`), and pass `--no-prompt`. If bootstrap
needs more, revoke it with `Deno.permissions.revoke({ name })` before reading any
code to run, as prefab-ui 0.21.0's runner does. Check the environment the server
runs in for unexpected `.pth` files
([AAK-STARTUP-HOOK-PTH-001](AAK-STARTUP-HOOK-PTH-001.md) reads them).

## Related advisories

| Software | CVE | Range | Fixed |
|---|---|---|---|
| prefab-ui, Generative UI sandbox | CVE-2026-120338 (GHSA-595q-jv4r-q7j9) | 0.14.0 up to 0.21.0 | 0.21.0 |

A finding reads:

```text
`_pyodide.py:12` starts Deno with --allow-read --allow-write --allow-net, which leaves net, read,
write open, and `runner.js:9` hands that runtime code to run (`runPythonAsync(...)` of text that
is not a fixed literal), and nothing revokes them. Code a caller supplies then has the server's
own access to files, network or processes, ...
```

See also [AAK-MCP-CODEEXEC-SANDBOX-001](AAK-MCP-CODEEXEC-SANDBOX-001.md), which
reports FastMCP's GenerativeUI on an affected prefab-ui.
