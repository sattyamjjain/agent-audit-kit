# AAK-MCP-001 adjudication codebook

One code per hit. A hit is one `AAK-MCP-001` finding: one server entry, in one
config, whose `url` the rule reported as having no authentication. Judge the
**server the URL points at**, as the evidence shows it on the probe date, not
the rule and not the config's style. Look things up (the provider's docs, the
registry page, the repository) whenever the sheet is not enough, and say so in
the note. When two codes fit, take the first one in this list that does.

| Code | Use it when |
|------|-------------|
| `loopback` | The URL points at the local machine or a private network: `localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`, RFC 1918 / link-local / CGNAT addresses, or a name that only resolves inside a LAN or container network (`host.docker.internal`, a single-label name such as `mcp-server`). Not reachable from the internet, whatever it does or does not check. |
| `hosted-oauth` | The server refuses an unauthenticated client and expects the credential to be obtained **at connect time**, not stored in the config: an HTTP 401/403 carrying a `Bearer` challenge, RFC 9728 protected-resource metadata naming an authorization server, or provider documentation saying the client signs in through OAuth. The config is correct to carry no header. |
| `auth-other` | The server enforces authentication by some other means: an API key or token in a header the rule does not recognize, a credential in the URL (a key query parameter, a capability path), or a 401/403 that asks for a static key the config does not hold. Not open; not OAuth at connect time. If the credential is a literal written into a public config, still use this code and write `literal credential` in the note: that is a secret-exposure problem, not an unauthenticated server. |
| `public-by-design` | The server accepts unauthenticated clients **on purpose**, and what it exposes is meant to be public: documentation or code search over public repositories, public reference data, a free read-only lookup, a demo the publisher labels as public. The publisher's own description or docs should say so, or the tool surface should make it plain. |
| `truly-open` | The server accepts unauthenticated clients and should not: it acts on a user's accounts or private data, writes, sends, deploys, spends, executes, exposes an organisation's internal system, or its own documentation says it requires authentication that it does not enforce. This is the true positive the rule exists to find. |
| `unknown` | The evidence does not decide it: no answer from the server (DNS failure, timeout, TLS or 5xx error), an answer that is neither a refusal nor an MCP reply, a templated or placeholder host, or an open server whose purpose cannot be determined. Write what is missing in the note. |

Decision notes:

- A 401 or 403 is a refusal, so the server is not open. Pick `hosted-oauth` or
  `auth-other` by the mechanism; if the mechanism cannot be told, `auth-other`.
  A 402 Payment Required is an access gate (x402 and the like): `auth-other`.
- A JSON-RPC `result` to the unauthenticated `initialize` means the server
  accepted the client. It does not by itself make the server `truly-open`: some
  servers accept `initialize` and authenticate later, per tool call or once a
  tool needs an account. Use `hosted-oauth` when that later step is OAuth (the
  server also serves RFC 9728 metadata, or its docs say so) and `auth-other`
  when it is something else. Otherwise choose between `public-by-design` and
  `truly-open` by what the server exposes and what its publisher says.
- A 404, 405 or 406 to the `initialize` POST usually means the URL is not the
  MCP endpoint the probe assumed (an older SSE transport, a path the client
  rewrites). Decide from the registry and docs, or use `unknown`.
- Write a one-line reason in `note` for every `truly-open` and every
  `public-by-design` verdict. Those two are the codes most open to dispute.
