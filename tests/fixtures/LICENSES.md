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

If you redistribute these fixtures (e.g. as part of an AAK fork), please
preserve this attribution table and the upstream project's own license
where it applies.
