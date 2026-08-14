# Session transcripts

`AAK-AGENT-COMPOSE-002` looks for **instruction splicing**: one intent fragmented
across several individually-compliant tool calls in a single session, where the
concatenation of their arguments reconstructs something a single call would have
been denied for. That is the GhostSplice / cross-channel trust-fragmentation
shape disclosed by the [ASSET Research
Group](https://asset-group.github.io/disclosures/ghostsplice/).

The rule needs an **ordered list of tool calls**. On its own it only discovers
`*.session.json` files and JSON under `.aak/sessions/` — the file you would write
by hand, and not what any agent framework emits. `--sessions` closes that gap: it
reads the transcripts frameworks actually write, normalises them into the same
ordered list, and runs the unchanged rule over them.

```bash
# a directory of transcripts
agent-audit-kit scan . --sessions ./traces/

# a single transcript
agent-audit-kit scan . --sessions ./traces/run-412.json

# see which format each file was read as
agent-audit-kit scan . --sessions ./traces/ --verbose
```

Findings cite the transcript you passed, not an internal staging copy, so a
report points at the file you can actually open.

## Supported formats

Format is detected from the file's contents, not its name. A file that matches
nothing is skipped rather than failing the scan.

| Format | Detected by | Calls read from |
|---|---|---|
| `openai-agents` | a `spans` / `data` / `items` list whose entries carry `span_data` | spans with `span_data.type == "function"`, using `name` and the JSON-string `input` |
| `langgraph` | `channel_values.messages`, `values.messages`, or `state.messages` | each message's `tool_calls` (`{"name", "args"}`), plus the legacy `additional_kwargs.tool_calls` OpenAI-function shape |
| `jsonl` | one JSON object per line | `tool` (or `name` / `tool_name`) and `args` (or `arguments` / `input`) |
| `aak` | `{"calls": [...]}` or a bare list | `tool` and `arguments` |

### OpenAI Agents SDK run traces

Exported run traces, `{"spans": [...]}` — a bare list of spans and the
`{"data": [...]}` export envelope both work. Only function spans become calls;
agent, generation, and handoff spans are ignored.

Spans are ordered by `started_at` when every span has one, otherwise file order
is kept. Ordering matters: the rule's premise is that *consecutive* same-tool
calls reassemble, so an out-of-order trace would hide a splice.

```json
{
  "spans": [
    {"started_at": "2026-08-13T09:14:03.010Z",
     "span_data": {"type": "function", "name": "read_file",
                   "input": "{\"path\": \"/home/dev/\"}"}},
    {"started_at": "2026-08-13T09:14:03.500Z",
     "span_data": {"type": "function", "name": "read_file",
                   "input": "{\"path\": \".ssh/\"}"}}
  ]
}
```

An `input` that is not JSON is preserved under `arg` rather than dropped.

### LangGraph checkpoint / thread state

Both the raw checkpoint (`channel_values.messages`) and the thread-state export
from `GET /threads/{thread_id}/state` (`values.messages`) are read, as is a
checkpoint nested one level under `checkpoint`.

```json
{
  "channel_values": {
    "messages": [
      {"type": "ai",
       "tool_calls": [{"name": "web_fetch", "args": {"url": "https://"}, "id": "call_a1"}]},
      {"type": "ai",
       "tool_calls": [{"name": "web_fetch", "args": {"url": "exfil-sink.example"}, "id": "call_a2"}]}
    ]
  }
}
```

Message order is the call order. `ToolMessage` results are ignored — only the
requests carry arguments.

### Raw JSONL

One JSON object per line. Blank lines and unparseable lines are skipped rather
than failing the file, so a partially-flushed log still scans.

```jsonl
{"tool": "read_file", "args": {"path": "/srv/"},  "ts": "2026-08-13T12:00:01Z"}
{"tool": "read_file", "args": {"path": "app/.e"}, "ts": "2026-08-13T12:00:02Z"}
{"tool": "read_file", "args": {"path": "nv"},     "ts": "2026-08-13T12:00:03Z"}
```

Lines are sorted by `ts` only when every line has a comparable one; otherwise
file order is kept.

## Configuration

`--sessions` reuses `AAK-AGENT-COMPOSE-001`'s config file,
`.aak/composition-boundaries.yaml`, from the project root you are scanning:

- `session_reassembly.sensitive_path_patterns` — the tokens that make a
  reassembled file path interesting (`id_rsa`, `.env`, `.aws/credentials`, …).
- `egress_allowlist` — hosts a reassembled URL may point at.

## What it will and will not tell you

The rule flags two narrow cases, and only when **no single fragment** already
crossed the line:

- **file-path reassembly** — the concatenation matches a sensitive-path pattern;
- **URL reassembly** — the concatenation is a URL whose host is not allowlisted.

It defaults to MEDIUM and is a prompt to look, not a verdict. Legitimate chunked
work reassembles the same way — a large file uploaded in path-sized pieces looks
exactly like a splice. Expect false positives and read the fragments in the
finding before acting.

The rule was written from the public GhostSplice disclosure, not from a
reproduction. It sees only what is in the transcript: a framework that does not
record tool arguments cannot be checked this way.
