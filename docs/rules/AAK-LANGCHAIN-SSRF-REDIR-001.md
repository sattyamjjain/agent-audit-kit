# AAK-LANGCHAIN-SSRF-REDIR-001

**Validate-then-fetch SSRF (redirects enabled past allow-list)**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `TRANSPORT_SECURITY` |
| Shipped | v0.3.5 (2026-04-25) |
| Scanner | `agent_audit_kit/scanners/ssrf_redirect.py` |
| CWE | CWE-601 (Open Redirect) + CWE-918 (SSRF) |
| OWASP MCP | MCP05:2025 |
| OWASP Agentic | ASI04, ASI09 |
| AICM | IVS-04, AIS-08 |
| CVE | [CVE-2026-41481](https://nvd.nist.gov/vuln/detail/CVE-2026-41481) |
| Advisory | [GHSA-fv5p-p927-qmxr](https://advisories.gitlab.com/pypi/langchain-text-splitters/GHSA-fv5p-p927-qmxr/) |

## What it catches

A function calls a known SSRF guard helper
(`validate_safe_url`, `is_safe_url`, `validateSafeUrl`, `ensure_safe_url`,
`check_safe_url`, `ssrf_guard`, `is_url_safe`) and then fetches the same
URL via `requests.get` / `httpx.get` / `urllib.request.urlopen` /
`fetch` / `axios.get` / `got` without disabling redirects.

The allow-list fires once on the URL the caller supplied, but
`requests` follows 3xx by default. A 302 from an attacker-controlled
host into `http://169.254.169.254/...`, `http://localhost`, or another
blocked target bypasses the guard and pulls the response back into the
calling context.

CVE-2026-41481 is the canonical example: `langchain-text-splitters <
1.1.2`'s `HTMLHeaderTextSplitter.split_text_from_url()` did exactly
this. Same shape applies in any agent-tooling code that does
validate→fetch without `allow_redirects=False`.

## Detection

The Python pass walks the AST and orders calls by source line (`ast.walk`
is BFS, so naive walk-order would visit `requests.get` before
`validate_safe_url` when the validator is inside an `if` and the fetch
is on the next line). For each function:

1. First call to a `_VALIDATOR_NAMES` helper sets `validator_seen=True`.
2. Subsequent call whose attribute name is in `_FETCH_NAMES` fires the
   rule unless one of these kwargs disables redirects:
   - `allow_redirects=False`
   - `follow_redirects=False`
   - `max_redirects=0`
   - `redirect="manual"` / `redirect="error"`

The TS/JS pass is a regex pair: `_TS_VALIDATOR_RE` followed within 2 KB
by `_TS_FETCH_RE`, suppress on `_TS_REDIRECT_OFF_RE`.

The rule also ships a pin check across `requirements*.txt`,
`pyproject.toml`, `poetry.lock`, `Pipfile.lock`, and `uv.lock` for
`langchain-text-splitters < 1.1.2`.

## What it does NOT catch

- Two-statement validate/fetch where the URL flows through an
  intermediate variable that is not the first argument to the fetch.
  Use AAK-SSRF-TOCTOU-001 (sibling rule) for the DNS-rebind class
  shape that does not require redirect-following.
- Manual redirect handling that re-validates each hop. We currently
  only check the kwargs at the fetch call site; if the caller manages
  redirects in a loop with their own validator we cannot prove safety
  without flow analysis. False positives here can be silenced with a
  `# aak: ignore[AAK-LANGCHAIN-SSRF-REDIR-001]` comment.

## Remediation

Disable redirects at the fetch call:

```python
# Python — requests
response = requests.get(url, allow_redirects=False, timeout=5)

# Python — httpx
response = httpx.get(url, follow_redirects=False)

# Python — urllib
opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
opener.open(url)  # or override redirect_request()
```

```typescript
// TypeScript — fetch
const r = await fetch(url, { redirect: 'manual' });

// Node — got
const r = await got(url, { followRedirect: false });

// Node — axios
const r = await axios.get(url, { maxRedirects: 0 });
```

Or revalidate the URL on every redirect hop (tighter but more code).

For `langchain-text-splitters`, bump to `>= 1.1.2`.

## Sister rule

[AAK-SSRF-TOCTOU-001](./AAK-SSRF-TOCTOU-001.md) covers the
DNS-rebinding shape: validate-then-fetch-with-fresh-DNS-resolution
(CVE-2026-41488).
