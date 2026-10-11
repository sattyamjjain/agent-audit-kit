# AAK CVE-to-Rule Ledger (test excerpt, fictional ids)

## 2099-03-05 (v9.9.2): the image reader lands

| CVE | CVSS | Package | What changed | Issue |
|---|---|---|---|---|
| CVE-2099-20001 | 6.8 | gateway (container image `ghcr.io/example/gateway`) | **New pin** `AAK-MCP-EXAMPLE-CVE-2099-20001-001`: below 0.0.109. | #9001 |
| CVE-2099-20002 | 5.3 | Example plugin (wordpress.org plugin) | **Out of scope**, non-pinnable. Upgrade the plugin to 1.2.0 or later. | #9002 |
| CVE-2099-20003 | 7.7 | `example-atlassian` | No new rule, no new pin. Fixed 0.22.0, this pin's existing floor. Recorded against `AAK-MCP-EXAMPLE-PIN-CVE-2099-1-001` and `AAK-MCP-HTTP-NOAUTH-SERVER-001`. | #9003 |
| CVE-2099-20004 | 8.8 | Example MCP (no registry artifact) | **Arm added** to `AAK-MCP-015`: a tool argument through `path.join` to an fs read with no containment. | #9004 |
| CVE-2099-20005 | 6.5 | `example-remote` (npm) | No new rule, no new pin. Inside the 0.1.16-0.1.38 range; recorded against `AAK-MCP-EXAMPLE-PIN-CVE-2099-1-001`. | #9005 |
| CVE-2099-20006 | 7.3 | `fetcher` (PyPI) | No new rule, no pin: no fixed release. Recorded against `AAK-MCP-SSRF-001`, which fires on the shape. | #9006 |

## 2099-03-05 (v9.9.1): an earlier call on the same day

| CVE | CVSS | Package | What changed | Issue |
|---|---|---|---|---|
| CVE-2099-20001 | 6.8 | gateway (container image) | **Out of scope**, non-pinnable: on neither PyPI nor npm. | #9001 |

## 2099-02-10 (v9.8.0): the older table shape

| CVE | Reference | AAK rule / disposition | Triaged |
|---|---|---|---|
| CVE-2099-10101 (CVSS 7.6), CVE-2099-10102 (6.9) — `example-agent` < 4.6.58: an origin check uses `startswith` | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2099-10101) | **In scope, already covered - no rule change.** `AAK-MCP-EXAMPLE-PIN-CVE-2099-1-001` has carried a floor of `>= 4.6.78`, above this fix. (#8001, #8002) | 2099-02-10 |
| CVE-2099-10110 … CVE-2099-10112 (Example Hub, three advisories - a route with no role check) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2099-10110) | **In scope, rule shipped** `AAK-MCP-HUB-CVE-2099-10110-001` (SUPPLY_CHAIN, **CRITICAL**): floor `@example/hub >= 1.0.32`. (#8010–#8012) | 2099-02-10 |
| CVE-2099-10120 (`example-fetch`, CWE-918 - `isSafeUrl` reads `.hostname`, and `.replace(/^\[\|\]$/g, "")` is the fix) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2099-10120) | **In scope, rule shipped** `AAK-SSRF-EXAMPLE-HOST-001` (TRANSPORT_SECURITY, **HIGH**). No version pin: a pin would cover one package. (#8020) | 2099-02-10 |
| CVE-2099-10130 (Example CLI, CWE-150 - a parser desync) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2099-10130) | **In scope, detection rule (not pinned)** `AAK-MCP-EXAMPLE-CLI-CVE-2099-10130-001` (MCP_CONFIG, CRITICAL). (#8030) | 2099-02-10 |
| CVE-2099-10140 (`example-stata` < 1.19.0, CWE-94 - package install concatenates input) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2099-10140) | **In scope, pinned + pattern rules.** Pin `AAK-MCP-STATA-EXAMPLE-001` floor moved 1.17.3 → 1.19.0. | 2099-02-10 |

## 2099-01-01 (v9.0.0): before the window

| CVE | CVSS | Package | What changed | Issue |
|---|---|---|---|---|
| CVE-2099-00500 | 9.8 | `old` | **New pin** `AAK-MCP-OLD-CVE-2099-00500-001`. | #7000 |

## Older CVE ledger

| CVE-2099-00001 | ignored | ignored | ignored | ignored |
