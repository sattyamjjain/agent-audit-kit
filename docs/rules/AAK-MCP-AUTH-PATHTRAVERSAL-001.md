# AAK-MCP-AUTH-PATHTRAVERSAL-001

**MCP bearer-token joined into a session file path (path traversal)**

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Category | `MCP_CONFIG` |
| Shipped | v0.3.43 (2026-07-04) |
| Scanner | `agent_audit_kit/scanners/mcp_auth_pathtraversal.py` |
| CWE | CWE-22 (Path Traversal) |
| OWASP MCP | MCP07:2025 (Authentication / Authorization) |
| OWASP Agentic | ASI03 |
| AICM | IAM-01, IVS-04 |
| CVE | [CVE-2026-52830](https://nvd.nist.gov/vuln/detail/CVE-2026-52830) (CVSS 9.4) |

## What it catches

MCP server authentication code that concatenates or `os.path.join`-es an
**untrusted token / bearer credential** into a filesystem path used for a
**session existence / read check**, without rejecting path separators / `..`
or resolving-and-containing the result.

Because the caller controls the token, they control the path. A token value
like `../../etc/passwd` or `../<another-user-session>` escapes the intended
session directory — turning what looks like an auth check into arbitrary-file
access and cross-session takeover.

CVE-2026-52830 (`fast-mcp-telegram < 0.19.1`, CVSS 9.4) is the canonical
example: the server joined the caller-supplied bearer token straight into the
session file path used to test whether a session existed, so a crafted token
traversed out of the session directory. Fixed in 0.19.1.

## Detection

Python is analysed with the stdlib `ast` taint mechanism the repo already uses
(no new engine — issue #22's tree-sitter migration is separate). Per function:

1. **Source** — a value read from a request header / bearer extraction
   (`request.headers.get("Authorization")`, `headers["authorization"]`), or a
   parameter whose name looks like a token/credential (`token`, `bearer`,
   `auth`, `credential`, `api_key`, `session_id`).
2. **Flow into a path** — that tainted value reaches `os.path.join(...)`,
   `Path(...) / token`, `pathlib` division, or an f-string / `+` concatenation
   that builds a path-like string.
3. **Sink** — the constructed path reaches `os.path.exists` / `os.path.isfile` /
   `open` / `Path.exists` / `Path.is_file` / `Path.open` / `os.stat`.
4. **Suppressed** when the same function normalizes / rejects: a separator or
   `..` check on the token, `os.path.normpath` / `realpath` / `abspath` +
   `startswith` containment, `Path.resolve()` + `is_relative_to` / `relative_to`,
   or `werkzeug.utils.secure_filename`.

TS/JS/Rust servers use the analogous comment-stripped regex: a request-token
value concatenated (`path.join` / template literal / `format!` / `PathBuf`)
into a path with an `existsSync` / `open` / `read` sink and no separator /
normalize guard.

## What it does NOT catch

- Cross-function flow where the token is extracted in one helper and the path
  built in another — detection is within a single function body. Consolidate,
  or silence with `# aak: ignore[AAK-MCP-AUTH-PATHTRAVERSAL-001]` if the
  cross-function design has its own reject-and-contain guard.
- A resource-handler traversal on a request *path* parameter (that is
  `AAK-MCP-015`) — this rule is specifically the auth-*token*-as-filename case.

## Vulnerable

```python
def load_session(request):
    token = request.headers.get("Authorization").removeprefix("Bearer ")
    session_path = os.path.join(SESSION_DIR, token + ".session")  # token controls the path
    if os.path.exists(session_path):                              # traversal reaches the fs
        return open(session_path).read()
```

## Remediation

Reject separators and `..`, then resolve-and-contain:

```python
def load_session(request):
    token = request.headers.get("Authorization").removeprefix("Bearer ")
    if "/" in token or "\\" in token or ".." in token:
        raise ValueError("invalid token")
    session_path = os.path.realpath(os.path.join(SESSION_DIR, token + ".session"))
    if not session_path.startswith(SESSION_DIR + os.sep):
        raise ValueError("path traversal")
    if os.path.exists(session_path):
        return open(session_path).read()
```

- Prefer a hashed / opaque session id over the raw token as a filename.
- **Upgrade `fast-mcp-telegram` to >= 0.19.1.**

## References

- [CVE-2026-52830](https://nvd.nist.gov/vuln/detail/CVE-2026-52830)
