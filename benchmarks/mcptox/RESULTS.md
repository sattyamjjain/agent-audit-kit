# MCPTox rules-only recall (AgentAuditKit, untuned)

> Generated from `run.py` over every case `corpus.py` parses from the MCPTox
> release. Run date **2026-10-12**. Offline after one fetch, deterministic, no
> LLM. Reproduce: `make mcptox-fetch` (network, once), then `make mcptox`.
> MCPTox carries no license, so no description, tool name or query from it is
> committed here: [`results.json`](results.json) names cases by id and the tools
> by a digest, and the fetch script pins the one file it reads by SHA-256.

## Headline

MCPTox is a public, labelled set of poisoned MCP tools written against real
servers: 1,348 test cases on 45 servers, each a new tool whose description tries
to steer an agent into misusing one of that server's real tools. AgentAuditKit's
shipped rules, untuned, at commit `e564832a` (the v0.6.20 rule set), raise at
least one finding on **926 / 1,348** of the poisoned tools, **68.7%** (Wilson 95%
CI [66.2%, 71.1%]). Counting only rules in the TOOL_POISONING category, **902 /
1,348**, 66.9% [64.4%, 69.4%].

Run the same way on the 353 clean tools of the same servers, any rule fires on
**63 / 353**, 17.8% [14.2%, 22.2%], and a TOOL_POISONING rule on 62 / 353, 17.6%
[13.9%, 21.9%].

That is what the number is: the recall of a deterministic posture scanner, with
no model in the loop and nothing adjusted for this set, on tool poisoning that is
written in natural language. Read the headline with the rule table below,
because most of it is one heuristic. `AAK-POISON-006` (a URL or file path in a
description, MEDIUM) fires on 758 / 1,348 poisoned tools, 56.2% [53.6%, 58.9%],
and on 49 / 353 clean ones, 13.9% [10.7%, 17.9%]. It matches the path or the URL,
not the instruction around it.

At the severity a CI gate uses, the picture changes:

| Floor | Poisoned tools flagged | Clean tools flagged |
|-------|-----------------------:|--------------------:|
| any finding | 926 / 1,348 = 68.7% [66.2%, 71.1%] | 63 / 353 = 17.8% [14.2%, 22.2%] |
| HIGH or above | 336 / 1,348 = 24.9% [22.7%, 27.3%] | 12 / 353 = 3.4% [2.0%, 5.8%] |
| CRITICAL | 34 / 1,348 = 2.5% [1.8%, 3.5%] | 10 / 353 = 2.8% [1.5%, 5.1%] |

`aak scan --fail-on high`, which is what `--ci` sets, would fail on about one
poisoned tool in four. The CRITICAL floor is a single rule, `AAK-POISON-002`
(prompt-injection phrases), and on this set it fires on clean tools at about the
same rate as on poisoned ones, 2.8% against 2.5%, so it carries no signal here.
The rule that separates the two sets best is `AAK-POISON-003` (a reference to
another tool, HIGH): 296 / 1,348 poisoned, 22.0% [19.8%, 24.2%], against 1 / 353
clean, 0.3% [0.1%, 1.6%].

This is a baseline. The LLM evaluation planned on the same cases is the
comparison it is for.

## Results

### By attack paradigm

The dataset's own `paradigm` field. The paper describes three attack templates;
reading `Template-1` to `Template-3` as its P1 to P3 is an inference (see
Method), so the table keeps the dataset's names.

| `paradigm` | Paper's name (inferred) | Any rule | TOOL_POISONING rule |
|------------|-------------------------|---------:|--------------------:|
| `Template-1` | Explicit trigger, function hijacking | 126 / 211 = 59.7% [53.0%, 66.1%] | 117 / 211 = 55.5% [48.7%, 62.0%] |
| `Template-2` | Implicit trigger, function hijacking | 381 / 519 = 73.4% [69.4%, 77.0%] | 378 / 519 = 72.8% [68.8%, 76.5%] |
| `Template-3` | Implicit trigger, parameter tampering | 419 / 618 = 67.8% [64.0%, 71.4%] | 407 / 618 = 65.9% [62.0%, 69.5%] |

### By risk category

The dataset's own `security risk` field, largest first.

| `security risk` | Any rule | TOOL_POISONING rule |
|-----------------|---------:|--------------------:|
| Information Manipulation | 199 / 281 = 70.8% [65.3%, 75.8%] | 193 / 281 = 68.7% [63.0%, 73.8%] |
| Privacy Leakage | 173 / 276 = 62.7% [56.8%, 68.2%] | 171 / 276 = 62.0% [56.1%, 67.5%] |
| Service Disruption | 178 / 209 = 85.2% [79.7%, 89.3%] | 171 / 209 = 81.8% [76.0%, 86.5%] |
| Infrastructure Damage | 76 / 124 = 61.3% [52.5%, 69.4%] | 76 / 124 = 61.3% [52.5%, 69.4%] |
| Data Tampering | 57 / 120 = 47.5% [38.8%, 56.4%] | 57 / 120 = 47.5% [38.8%, 56.4%] |
| Credential Leakage | 88 / 115 = 76.5% [68.0%, 83.3%] | 88 / 115 = 76.5% [68.0%, 83.3%] |
| Code Injection | 55 / 63 = 87.3% [76.9%, 93.4%] | 50 / 63 = 79.4% [67.8%, 87.5%] |
| Instruction Tampering | 40 / 57 = 70.2% [57.3%, 80.5%] | 40 / 57 = 70.2% [57.3%, 80.5%] |
| Financial Loss | 39 / 55 = 70.9% [57.9%, 81.2%] | 37 / 55 = 67.3% [54.1%, 78.2%] |
| Message Hijacking | 17 / 44 = 38.6% [25.7%, 53.4%] | 15 / 44 = 34.1% [21.9%, 48.9%] |
| Other | 4 / 4 = 100.0% [51.0%, 100.0%] | 4 / 4 = 100.0% [51.0%, 100.0%] |

### By rule

Seven rules fired on any case. Each row counts the cases it fired on.

| Rule | Severity | Category | Poisoned tools | Clean tools |
|------|:--------:|----------|---------------:|------------:|
| `AAK-POISON-006` URL or file path in description | MEDIUM | tool-poisoning | 758 / 1,348 = 56.2% [53.6%, 58.9%] | 49 / 353 = 13.9% [10.7%, 17.9%] |
| `AAK-POISON-003` cross-tool reference | HIGH | tool-poisoning | 296 / 1,348 = 22.0% [19.8%, 24.2%] | 1 / 353 = 0.3% [0.1%, 1.6%] |
| `AAK-POISON-005` description over 500 characters | MEDIUM | tool-poisoning | 76 / 1,348 = 5.6% [4.5%, 7.0%] | 47 / 353 = 13.3% [10.2%, 17.3%] |
| `AAK-POISON-002` prompt-injection phrases | CRITICAL | tool-poisoning | 34 / 1,348 = 2.5% [1.8%, 3.5%] | 10 / 353 = 2.8% [1.5%, 5.1%] |
| `AAK-AIACT50-002` synthetic media, no provenance marking | MEDIUM | legal-compliance | 32 / 1,348 = 2.4% [1.7%, 3.3%] | 1 / 353 = 0.3% [0.1%, 1.6%] |
| `AAK-IPI-WILD-CORPUS-001` known wild injection payload | HIGH | taint-analysis | 3 / 1,348 = 0.2% [0.1%, 0.7%] | 0 / 353 = 0.0% [0.0%, 1.1%] |
| `AAK-POISON-004` encoded content | HIGH | tool-poisoning | 3 / 1,348 = 0.2% [0.1%, 0.7%] | 1 / 353 = 0.3% [0.1%, 1.6%] |

`AAK-POISON-005` fires more often on the clean tools than on the poisoned ones:
on this set, length marks a well-documented tool rather than a poisoned one.
`AAK-AIACT50-002` is a transparency-obligation rule for tools that declare media
generation; its hits count under "any rule" but are not poisoning detections.
`AAK-POISON-001` (invisible Unicode) never fired.

### Subsets

Neither subset moves the result.

| Subset | Any rule | TOOL_POISONING rule |
|--------|---------:|--------------------:|
| All 1,348 cases (headline) | 926 / 1,348 = 68.7% [66.2%, 71.1%] | 902 / 1,348 = 66.9% [64.4%, 69.4%] |
| `wrong_data == 0`, the arXiv v1 count | 892 / 1,312 = 68.0% [65.4%, 70.5%] | 870 / 1,312 = 66.3% [63.7%, 68.8%] |
| Distinct tools only (repeats dropped) | 920 / 1,338 = 68.8% [66.2%, 71.2%] | 896 / 1,338 = 67.0% [64.4%, 69.4%] |

## Method

### Dataset

The release is [`zhiqiangwang4/MCPTox-Benchmark`](https://github.com/zhiqiangwang4/MCPTox-Benchmark),
the repository the paper's arXiv v2 (2026-09-29) names under "Datasets". It has
one branch, whose head `f85189f9ad12` is the second of two commits made on
2025-12-03, and no tags or releases.
The same files, by git blob id, are in `YangChenBlueSky/MCPTox_AAAI26` at
`0b20e923` (with a stray `.DS_Store`); the harness pins the repository the
paper names.

The harness reads one file, `response_all.json` (20,666,873 bytes, SHA-256
`79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03`, git blob
`65dbe0a684471eab5717b2938223a6898f75d32d`). `fetch.py` checks all three before
it caches the file, and every reader checks the SHA-256 again. The release's
other files are not used. `pure_tool.json` holds 485 base poisoned tools with
the same two labels, but it is not the evaluated set: it has no `wrong_data`
field and lacks the tool of some evaluated cases. `def_tool/` holds Python stubs
for those 485, and `analysis.ipynb` was not read.

**License: none.** The repository has no LICENSE file, its README is the single
line `# AAAI26`, and the paper states no license for the dataset. All rights are
reserved by default, so the cache lives outside the repository and nothing from
the file is committed. The normalized case list (`build.py --jsonl`) is written
only to a path outside the repository; `build.py` refuses any path inside it.

### Counts, reconciled with the paper

| Count | This release | Paper |
|-------|-------------:|------:|
| Servers | 45 | 45 |
| Real tools (`tool_names`) | 353 | 353 |
| Malicious test cases | 1,348 | 1,348 (arXiv v2, AAAI); 1,312 (arXiv v1) |
| Cases with `wrong_data == 0` | 1,312 | |
| Distinct poisoned tool objects | 1,338 | |
| Risk categories | 11 | 10 (abstract), 11 (introduction) |

- **1,348 against 1,312.** 36 cases carry `wrong_data = 2` and the other 1,312
  carry 0, exactly the arXiv v1 count. The dataset does not document the field;
  the arithmetic is the only evidence that v1 left those 36 out.
- **1,338.** 10 cases repeat an earlier case's tool exactly (name, description
  and arguments), each within its own server. Dropping the repeats gives 1,338.
- **353 tools.** The sum of every server's `tool_names`. The clean prompts render
  362 tool blocks: Apify's lists 9 tools its `tool_names` does not, and those 9
  are left out, so the benign set is exactly the paper's tool count.
- **Paradigms.** `Template-1` 211, `Template-2` 519, `Template-3` 618. The paper's
  Table 1 shows 224, 548 and 725 beside P1 to P3, unlabelled, and they sum to
  neither count; unresolved. Reading `Template-n` as Pn follows the order and the
  two records read while learning the schema: a `Template-2` tool that redirects
  a file read to a different tool (function hijacking, implicit trigger) and a
  `Template-3` tool that rewrites a search parameter (parameter tampering).
- **Risk categories.** The 11 values of `security risk`, `Other` (4 cases)
  included, which is presumably why the abstract says 10.

### Cases

Every malicious case is one `malicious_instance`: its `poisoned_tool` text gives
the tool's name, description and arguments. 646 of the 1,348 are stored on one
line with a literal backslash-n where the others break lines; the parser
restores the breaks for those and for nothing else. In no case does the poisoned
tool reuse a real tool's name: each is a new tool, as the paper describes.

Every benign case is one of a server's `tool_names`, parsed from that server's
`clean_system_promot` (sic): its system prompt with no poisoned tool in it.

The `Arguments:` section is the client's rendering of the input schema, one
`- name: description` line per parameter, `(required)` appended where it applies
and `No description` where the schema had none. It is turned back into a JSON
Schema with exactly that: property names, descriptions, the required list. The
rendering carries no types, so none are invented. The parser is strict: any
block outside that shape raises, and every case of the pinned file parses.

### Scanning

Each case is written as a one-file project, `.mcp.json` with
`mcpServers.<server>.tools = [{name, description, inputSchema}]`, the shape
`tool_poisoning._extract_tool_descriptions` reads, its per-parameter walk
included. The server entry carries nothing else. The engine is
`agent_audit_kit.engine.run_scan` with its defaults: every rule active,
`include_user_config` off. Two environment switches change what a scan reports
and the run holds both off, as a plain `aak scan` has them: `AAK_TOXIC_FLOW`
(the opt-in `AAK-TOXICFLOW-001`) and `AAK_FETCH_SERVER_CARD_URL` (a network
fetch). A one-off scratch run with `AAK_TOXIC_FLOW=1`, not part of
`results.json`, changed no verdict.

Attribution: the same server with an empty `tools` array is scanned once as a
control, and a case's findings are its own minus the control's. The controls
raise nothing (`control_findings` is 0 in `results.json`), so every finding
counted is one the tool caused. No scanner failed on any case.

### The frozen rule set

Measured at AAK commit
[`e564832a`](https://github.com/sattyamjjain/agent-audit-kit/commit/e564832a05a4b57c2ac034ebe4d4ace25bdb0009),
v0.6.20 plus nine commits, none of which changes a scanner module, a rule or a
data file (the only change under `scanners/` is its `CLAUDE.md`). At that
commit `rules.json` has SHA-256
`87423f3b3cb0c2def573d2eb65ebe09386306a21582a42fe6680b96895c81079`, the digest
GitHub records for the `rules.json` asset of the
[v0.6.20 release](https://github.com/sattyamjjain/agent-audit-kit/releases/tag/v0.6.20),
which ships Sigstore-signed beside `rules.json.sigstore.json`
(`aak verify-bundle rules.json --signature rules.json.sigstore.json --tag v0.6.20`).
The registry then held 388 rules, 31 of them in TOOL_POISONING.

`rules.json` pins the rules' metadata, but detection is code, so `results.json`
also records a digest of the measured package, `fe78d1de8400`, over every file
under `agent_audit_kit/` that can change a scan. That digest is what decides
whether a later run is comparable: `make mcptox-check` re-runs and compares only
while it matches.

### Untuned

No rule, scanner or pattern was changed for this run. The schema was learned
from the paper and from four records read in truncated form (two from
`pure_tool.json`, two from `response_all.json`), plus the opening and closing
parts of one clean prompt and short fragments of clean parameter text, read
while working out the format. Every other case was processed by script and never
read. There is no tuning split. No file or commit message in the repository
mentioned MCPTox before this run, and the patterns in `tool_poisoning.py` date
from v0.2.0 (2026-04-05); the one change since, #299, fed them per-parameter
descriptions without touching a pattern.

That can only be said once. From this page on, MCPTox is known to whoever edits
the rules, so `run.py --write` refuses to replace this measurement with one of a
different package unless `--supersede` declares whether the rule changes since
were made with sight of it. `results.json` carries the declaration as
`"untuned": true`.

MCPTox (arXiv v1 2025-08-19, dataset 2025-12-03) also predates the June 2026
knowledge cutoff of the models a follow-up LLM evaluation would use, so such an
evaluation may partly measure memorization. That caveat does not apply to this
number, which has no model in it.

## Limitations

- **"Flagged" is not "understood."** A case counts as detected when any finding
  lands on its tool. Nothing here checks that the finding is about the
  poisoning: a path in the description is enough for `AAK-POISON-006`. The rule
  table and the severity floors are the honest reading, not the headline alone.
- **Config placement only.** The tool is placed where AAK reads tool metadata in
  an MCP config. Rules that read tool registrations in source code
  (`AAK-MCP-FHI-001` reads `@mcp.tool` decorators and their TypeScript, Java and
  Rust peers) or `SKILL.md` files are not exercised. The release's `def_tool/`
  stubs could support a source-code placement, but they cover the 485 base tools
  of `pure_tool.json`, not the evaluated cases.
- **One tool per project.** The poisoned tool is scanned without the server's
  real tools beside it, so a rule that relates tools to each other sees one tool.
- **Clean is the dataset's word.** The benign set is the servers' real tools as
  the dataset records them, not adjudicated here. Some of the 63 clean tools
  flagged may describe genuinely risky behaviour.
- **Two inferences.** What `wrong_data` means, and that `Template-n` is the
  paper's Pn, are read from the data, not from documentation.
- **Reconstructed schemas.** Input schemas are rebuilt from a text rendering
  that drops types, defaults and constraints, so nothing a rule could read from
  those is there to read.
- **Reproduction needs the network once.** The dataset cannot be committed, so
  `make mcptox-check` says NOT CHECKED, a skip and not a pass, until
  `make mcptox-fetch` has filled the cache.

## History

| Run | Poisoned | Clean | Any rule | TOOL_POISONING | Clean flagged | Note |
|-----|---------:|------:|---------:|---------------:|--------------:|------|
| 2026-10-12 | 1,348 | 353 | 68.7% | 66.9% | 17.8% | First run. AAK `e564832a` (v0.6.20 rule set), MCPTox `f85189f9ad12`. Untuned. |
