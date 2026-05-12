# Test fixture licensing

Some fixtures under `tests/fixtures/` are minimised reproductions of
upstream third-party code so AAK's scanners have realistic detection
targets. This file declares derivation + license per fixture set.

| Fixture path | Upstream | License | Notes |
|--------------|----------|---------|-------|
| `crewai/`                        | `crewai` 0.x sandbox-tools APIs | MIT | Minimised reproductions of `CodeInterpreterTool`, `JSONSearchTool`, `RagTool` call shapes only. No upstream code copied verbatim. |
| `langchain_prompt_loader/`        | `langchain` `load_prompt` API | MIT | Minimised call-site shape only. |
| `langgraph/`                      | `langgraph.prebuilt.ToolNode` | MIT | Minimised call-site shape only. |
| `deepseek/`                       | `openai`-compatible client + DeepSeek `base_url` | MIT (openai-python) | Minimised. |
| `social_agents/`                  | `tiktok_api`, `instagrapi`, `tweepy`, `discord` call shapes | MIT/Apache-2.0 (per upstream) | Synthetic reproductions; no upstream copy. |
| `project_deal/`                   | `anthropic-python` client | MIT | Minimised reproduction of `client.messages.create` call shape. |
| `pipelock/`                        | Pipelock v2.3 YAML schema | MIT (Joshua Waldrep / Pipelock) | Hand-written policies illustrating supported keys. |
| `openclaw/`                        | OpenClaw `OpenClawAgent` constructor shape | TBD (provisional) | Fixtures synthesised pending public CVE assignment + license confirmation. |
| `cves/cve-2026-7591-astro-mcp/`   | TimBroddin/astro-mcp-server import + query-construction shape | MIT (TimBroddin/astro-mcp-server) | Hand-written reproductions of the unsafe / safe SQL-call shapes only; no upstream code copied verbatim. CVE-2026-7591 anchor: NVD 2026-05-01. |
| `cves/cve-2026-30623-litellm/`    | BerriAI/litellm pyproject pin shape | MIT (BerriAI/litellm) | Pin-floor manifests only (no source). v1.83.7 fix anchor: BerriAI/litellm release 2026-04-30. |
| `cves/cve-2026-7061-chatgpt-mcp/` | Toowiredd/chatgpt-mcp-server package.json pin shape | MIT (Toowiredd/chatgpt-mcp-server) | Pin-only manifests (git+https + github: shorthand variants). CVE-2026-7061 anchor: NVD; no upstream patch as of ship date. |
| `cves/cve-2026-26015-docsgpt/`    | arc53/DocsGPT package.json + .mcp.json transport-flip shape | MIT (arc53/DocsGPT) | Pin manifests (npm + git+https variants) + .mcp.json server configs illustrating transport=stdio override paths. CVE-2026-26015 anchor: OX MCP 2026-05-01 disclosure. |
| `cves/cve-2025-65720-gpt-researcher/` | assafelovic/gpt-researcher requirements.txt + package.json + .mcp.json shapes | MIT (assafelovic/gpt-researcher) | Pin manifests (PyPI requirements + git+https variants) + .mcp.json server configs. CVE-2025-65720 anchor: OX MCP 2026-05-01 disclosure batch. |
| `cves/cve-2026-40068-claudecode/` | Anthropic Claude Code package.json scoped-pin shape | MIT (Anthropic Claude Code documentation; pin-only fixtures contain no upstream code) | Two pin manifests (`@anthropic-ai/claude-code` ^2.1.81 vulnerable + ^2.1.83 safe). CVE-2026-40068 anchor: vendor patched in 2.1.83 on 2026-05-04. |
| `cves/cve-2026-26030-semantic-kernel/` | Microsoft Semantic Kernel Python SDK requirements.txt pin shape | MIT (Microsoft Semantic Kernel Python; pin-only fixtures contain no upstream code) | Three pin manifests (1.39.3 vulnerable + 1.39.4 safe + `>=1.39.4,<2.0` floor). CVE-2026-26030 anchor: MSRC 2026-05-07 disclosure, patched in `python-1.39.4`. |

If you redistribute these fixtures (e.g. as part of an AAK fork), please
preserve this attribution table and the upstream project's own license
where it applies.
