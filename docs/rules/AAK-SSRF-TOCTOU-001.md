# AAK-SSRF-TOCTOU-001

**Validate-then-fetch DNS-rebind / TOCTOU on URL allow-list**

| Field | Value |
|---|---|
| Severity | MEDIUM |
| Category | `TRANSPORT_SECURITY` |
| Shipped | v0.3.5 (2026-04-25) |
| Scanner | `agent_audit_kit/scanners/ssrf_toctou.py` |
| CWE | CWE-367 (TOCTOU) + CWE-918 (SSRF) |
| OWASP MCP | MCP05:2025 |
| OWASP Agentic | ASI04 |
| AICM | IVS-04, AIS-08 |
| CVE | [CVE-2026-41488](https://nvd.nist.gov/vuln/detail/CVE-2026-41488) |
| Advisory | [GHSA-r7w7-9xr2-qq2r](https://advisories.gitlab.com/pypi/langchain-openai/GHSA-r7w7-9xr2-qq2r/) |

## What it catches

A function validates a URL via an SSRF guard, then performs a separate
network fetch that triggers an *independent* DNS resolution. Between
the two resolutions a malicious hostname can rotate from a public IP
to a private/localhost/cloud-metadata IP (DNS rebinding), bypassing
the allow-list.

CVE-2026-41488 (`langchain-openai < 1.1.14`'s `_url_to_size`) is the
canonical example. The validator did its own DNS resolution to check
the IP, then `requests.get(url)` did a fresh resolution against the
same hostname — long enough for the attacker's authoritative DNS
server to flip the answer.

## Detection

Python AST walk, calls sorted by source line. For each function:

1. First call to `_VALIDATOR_NAMES` sets `validator_seen`.
2. Subsequent call whose attribute is in `_FETCH_NAMES` fires the rule
   unless an IP-pinning marker is reachable in the same function:
   - `socket.getaddrinfo`
   - `HTTPAdapter` / `requests.adapters.HTTPAdapter`
   - `session.mount` / `session.get_adapter`
   - `resolved_ip`, `pinned_ip`, `resolved_host`, `resolve_once`,
     `dns_pin`, `host_header_pin`

The pin check covers `langchain-openai < 1.1.14` across
`requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`,
`uv.lock`.

## What it does NOT catch

- Cross-function flow where the validator runs in one helper and the
  fetch in another — we look only within a single function body.
  Refactor to consolidate, or silence with
  `# aak: ignore[AAK-SSRF-TOCTOU-001]` if the cross-function design
  has its own TTL-bounded DNS pin.
- Any pattern AAK-LANGCHAIN-SSRF-REDIR-001 already catches — when both
  rules would fire on the same code, the redirect-bypass rule wins
  by being CRITICAL-class.

## Remediation

Resolve once, pin the IP, reuse the pinned `Session`:

```python
import socket
import requests
from requests.adapters import HTTPAdapter

def url_to_size(url: str) -> int:
    if not validate_safe_url(url):
        raise ValueError("unsafe url")
    # Resolve ONCE.
    resolved_ip = socket.getaddrinfo(url, 443)[0][4][0]
    # Reuse the resolved IP for the fetch.
    session = requests.Session()
    session.mount("https://", HTTPAdapter())
    response = session.get(
        url,
        headers={"Host": resolved_ip},
        timeout=5,
    )
    return len(response.content)
```

For `langchain-openai`, bump to `>= 1.1.14`.

## Sister rule

[AAK-LANGCHAIN-SSRF-REDIR-001](./AAK-LANGCHAIN-SSRF-REDIR-001.md)
covers the redirect-bypass shape: validate-then-fetch-with-redirects
(CVE-2026-41481).
