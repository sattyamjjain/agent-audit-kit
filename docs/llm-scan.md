# LLM scan (`scan --llm-scan`)

AAK's scan is deterministic and offline. `--llm-scan` is the one opt-in step
that sends text to a model: it asks the model you name whether each tool's
metadata tries to manipulate the agent that reads it. Use it as a second
opinion next to the AAK-POISON rules, never in their place. Nothing runs it
unless you pass the flag.

```bash
# Local, nothing leaves the machine (needs a running Ollama daemon)
agent-audit-kit scan . --llm-scan

# Anthropic
ANTHROPIC_API_KEY=... agent-audit-kit scan . --llm-scan --llm claude-haiku-5-5
```

## Providers

The `--llm` prefix picks the provider, and AAK never switches provider or model
on its own, so you always know which endpoint saw your metadata.

| `--llm` | Provider | Credential |
|---|---|---|
| `ollama/<model>` (default `ollama/gemma2:2b`) | Ollama on `localhost:11434` | none |
| `claude-haiku-5-5`, `claude-sonnet-5-5`, `claude-opus-5-5` | Anthropic Messages API | `ANTHROPIC_API_KEY` |
| `gpt-*` | OpenAI Chat Completions | `OPENAI_API_KEY` |
| `gemini-*` | Google Gemini | `GEMINI_API_KEY` (sent as a header) |

With a hosted provider, the tool metadata AAK reads is sent to that provider
under your account's terms. Do not use a hosted model on metadata you may not
share.

## What it reads

- Inline tools in MCP client configs (`.mcp.json`, `.cursor/mcp.json` and the
  other files the AAK-POISON rules read): name, description, input schema
  description and every parameter description.
- Saved `tools/list` responses: any `*tools*.json` holding `{"tools": [...]}`
  or a JSON-RPC response with `result.tools`. This is how to analyze a server
  whose tools exist only at runtime: save what it returns from `tools/list`.
- Python tools: functions under a `.tool` attribute decorator (the MCP Python
  SDK's servers) or a bare `tool` decorator, with the description from the
  decorator or the docstring and parameter descriptions from `Field(...)`, plus
  `Tool(name=..., description=...)` constructions.
- TypeScript and JavaScript tools: `server.tool("name", "description", ...)`
  and `registerTool("name", { description: ... })` string literals, including
  `.describe("...")` parameter descriptions.
- `SKILL.md` files: frontmatter name and description, and the instructions
  below it.

It never runs a server. A description built at runtime, concatenated from
several strings, or returned only by a live `tools/list` is never seen.

## What it reports

Every tool ends in exactly one state:

| State | Finding |
|---|---|
| The model judged the metadata manipulative | **AAK-LLM-001** (HIGH), with the model's reason, category and request id |
| The model judged it clean | none |
| Not analyzed: no credential, a rejected key, an unknown model, a failed request, a refusal, a reply cut off before the verdict | **AAK-LLM-002** (INFO), with the reason |

A refusal is "not analyzed", never "clean". When a model declines to read a
tool's description, read it yourself.

Any AAK-LLM-002 makes the run **INCOMPLETE**: the JSON report says
`"complete": false`, SARIF says `executionSuccessful: false`, and the scan exits
1. This is the same contract as a crashed scanner (#743): a run that did not
cover what you asked it to cover cannot pass as clean. Pass
`--allow-scanner-failure` to accept the gap and exit 0. A summary line always
prints to stderr:

```text
LLM scan (anthropic, claude-haiku-5-5): 12 of 12 tool(s) analyzed, 1 flagged, 0 not analyzed.
```

An unknown `--llm` model exits 2. A project with no tool metadata prints that
it found none and is not an error.

## How the request is built

For the current Claude models, each tool is one Messages API request:

- A fixed system prompt explains the task and says that everything between
  `<tool_metadata>` tags is untrusted data, never an instruction. Text inside
  that addresses the model or asks for a verdict counts as evidence of
  manipulation. A closing tag inside the metadata is escaped, so a description
  cannot end the fence early.
- Structured outputs constrain the reply to a JSON verdict:
  `{"reason", "category", "suspicious"}`.
- `effort: "low"` and `max_tokens: 4096`. Thinking counts toward `max_tokens`,
  and Opus 5.5 always thinks. The 256-token cap used through 0.6.22 could end a
  reply before the verdict.
- No server-side fallback: a refused request is reported as refused, not
  re-run on another model. No temperature either: the current models accept
  only the default, so verdicts can vary between runs.
- Rate limits, overload and server errors are retried with backoff. A rejected
  key or unknown model stops the run at once, and so do three failed tools in a
  row: every further call would fail the same way.

Identical metadata in several files is sent once.

## What it is not

A model's verdict is not proof. It can miss manipulation phrased as ordinary
documentation, and it can flag benign text. Adaptive attacks have bypassed 12
published defenses against jailbreaks and prompt injection, most of them more
than 90% of the time ([Nasr et al., 2025](https://arxiv.org/abs/2510.09023)),
so treat this layer as a recall booster with its own false-positive cost, not
as a security boundary.

## Canary

`.github/workflows/llm-scan-canary.yml` runs `scripts/llm_canary.py` every
Monday against the live API: ten synthetic tools (five poisoned, five benign)
on Haiku 5.5 and Sonnet 5.5. It fails when any tool goes unanalyzed, a reply
comes from a different model than requested, or detection falls below a loose
bar. It needs a repository secret named `LLM_CANARY_ANTHROPIC_API_KEY`;
without it the job skips.
