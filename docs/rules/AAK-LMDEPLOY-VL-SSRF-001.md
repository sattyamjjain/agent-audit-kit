# AAK-LMDEPLOY-VL-SSRF-001

**LMDeploy VL image loader fetches user-controlled URLs without allow-list**

| Field | Value |
|---|---|
| Severity | HIGH |
| Category | `TRANSPORT_SECURITY` |
| Shipped | v0.3.6 |
| Scanner | `agent_audit_kit/scanners/ssrf_redirect.py` (extension) |
| CWE | CWE-918 |
| OWASP MCP | MCP05:2025 |
| OWASP Agentic | ASI04, ASI09 |
| CVE | CVE-2026-33626 (GHSA-only at v0.3.6 cut — NVD enrichment pending) |

## What it catches

Vision-language pipelines that call `lmdeploy.serve.vl_engine.*`
preprocessing helpers (`preprocess_image_url`, `load_image(url=...)`,
`encode_image(url=...)`) without an SSRF guard. Same shape as
[AAK-LANGCHAIN-SSRF-REDIR-001](./AAK-LANGCHAIN-SSRF-REDIR-001.md)
but tied to the VL image loader.

## Detection

1. File must import `lmdeploy`.
2. File must call a `lmdeploy.serve.vl_engine.VLEngine` /
   `preprocess_image_url(...)` / `load_image(url=...)` /
   `encode_image(url=...)` shape.
3. Suppress if the same file has a known SSRF guard
   (`validate_safe_url`, `is_safe_url`, `ensure_safe_url`,
   `ssrf_guard`, `ALLOWED_HOSTS`, `TrustedHostMiddleware`).

## Remediation

Wrap the URL with an SSRF guard before passing it to the VL loader.
Resolve the hostname once, validate the resolved IP against an
allow-list, and pin the resolved IP for the actual request. See
AAK-SSRF-TOCTOU-001 for the canonical pinning recipe.

## Note on metadata

NVD enrichment was pending at v0.3.6 cut (2026-04-26). The rule cites
the GHSA index entry as the primary advisory. CVSS / CWE will tighten
once NVD lands.
