# Skill scanning: per-artifact pre-screen and the composition check

This page describes what the per-skill rules provably do **not** catch, and the
set-level rule that closes that gap.

## The per-skill rules are a pre-screen, not a control

`AAK-AGENT-TRUST-001..004` (and the `AAK-SKILL-*` family) inspect **one artifact
at a time**: a workflow, a settings file, a single `SKILL.md`. That is useful and
cheap, and you should run it early. It is **not** a boundary control, and the docs
now say so on each rule (`RuleDefinition.limitations`).

Two results make the limit concrete:

- **ColluSkill** (arXiv:2608.09732) composes benign skills so that their combined
  behaviour is malicious while each piece passes review. It reports a **96.0%
  average attack success rate across six skill scanners**. Single-artifact
  scanning cannot see intent split across several individually-benign skills.
- **SkillsMetric** (arXiv:2608.08468) measured per-skill detection at **0% for
  host-destruction via common shell commands** and **42% for natural-language
  prompt injection**. A benign-looking skill can carry real capability that only
  a behavioural or composition view surfaces.

So treat `AAK-AGENT-TRUST-*` / `AAK-SKILL-*` as a first pass, not a guarantee.

## The composition check: `AAK-AGENT-COMPOSE-001`

This rule operates on the **set** of skills that would load into one agent context
(all `SKILL.md` under a common container such as `.claude/skills/`), not one file
at a time. It computes the **union** of declared capability across the set and
flags a union that crosses a risk boundary **that no single skill in the set
requested** — i.e. the risk exists only because the skills were composed.

### Capability vocabulary (six)

Derived from each skill's `allowed-tools` frontmatter (tool → capability), an
explicit `capabilities:` list, and an `egress:` list of network destinations:

| Capability | Declared by |
|---|---|
| `filesystem_read` | `Read`, `Grep`, `Glob`, `LS`, `NotebookRead`, … |
| `filesystem_write` | `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, … |
| `network_egress` | `WebFetch`, `WebSearch`, `curl`, … or any `egress:` entry |
| `shell_execution` | `Bash`, `Shell`, `Execute`, … |
| `credential_access` | `capabilities: [credential_access]`, `secrets`, `keychain` |
| `memory_write` | `Memory`, `capabilities: [memory_write]` |

### The default boundary, and why

Shipped in [`agent_audit_kit/data/composition_boundaries.yaml`](../../agent_audit_kit/data/composition_boundaries.yaml):

> **{filesystem read OR credential access} + {network egress to a non-allowlisted
> destination} = exfiltration path, flag HIGH — even when every contributing skill
> is individually clean.**

The reasoning: a skill that can read files or credentials is harmless on its own,
and a skill that can post to a URL is harmless on its own. Loaded into the same
context, the first can hand data to the second. That is the exact shape ColluSkill
exploits. A destination is "non-allowlisted" when it is not in `egress_allowlist`,
or when the egress skill declares a network tool but names no destination (an
unspecified destination cannot be verified safe).

The finding names **which skill contributed which capability** and emits every
contributor as a SARIF related location, so it is navigable in a code-scanning UI.

### Configuring the boundary

The default is a starting point, not a mandate. Commit
`.aak/composition-boundaries.yaml` at your repo root (same schema) to replace it —
tighten it, loosen it, add boundaries, or allowlist the destinations your skills
legitimately contact:

```yaml
egress_allowlist: [docs.python.org, telemetry.mycorp.example]
```

### What this rule does not do

It reasons about **declared** capability, not data flow. A skill that
under-declares its tools, or reaches a capability through an MCP server it does not
name, is out of scope here — the per-skill scanners and the Python taint analysis
cover in-body behaviour. `AAK-AGENT-COMPOSE-001` flags a *possible* exfiltration
path from the capability union, not a proven one.

## v0.3.84: from a set to a graph (`AAK-COMPOSE-001/002/003`)

Everything above is a **set** predicate. `AAK-AGENT-COMPOSE-001` takes the
`SKILL.md` files in one container, unions their declared capabilities, and asks
whether the set spans a boundary no single member spans. That is unordered by
construction: it has no notion of direction, of one component's output being
another's input, of how many hops a path takes, or of anything that is not a
skill.

CompoSkill (arXiv:2608.16246) describes the thing that predicate cannot express:
an **ordered chain** assembled from components that each pass an individual
scanner. Three rules add the graph.

### `AAK-COMPOSE-001` — an ordered path to egress (HIGH)

Components are skills *and* MCP servers. An edge runs from A to B when A's
declared output is one of B's declared inputs, or when both are registered for
the same agent and B accepts free-form text. The rule fires on a path of two or
three components that carries untrusted input to network egress through something
that reads secrets or local state, **while no single component on the path holds
all three roles** — a component that did would be reported on its own.

Paths are capped at three components. That is CompoSkill's own result: attack
success falls off once a chain runs longer than three skills, so the dangerous
chains are the short ones, and a deeper search costs the node count raised to the
depth for cases that are already less likely to work.

Why the cross-kind case is the point: a chain made only of skills in one directory
is usually already reported by `AAK-AGENT-COMPOSE-001`, and this rule stands down
rather than repeating it. What the union rule structurally cannot see is a skill
handing data to an MCP server, because it only reads `SKILL.md`.

### `AAK-COMPOSE-002` — an undeclared shared path (HIGH)

Two or more skills that load together both reference the same writable filesystem
path, none of them declares a write capability or names the path as an output, and
at least one of them demonstrably writes it. That is ColluSkill's channel stated
directly: one writes what the other reads, through an interface neither manifest
describes. A declared-capability union cannot see it by construction, because the
relevant capability is precisely the one nobody declared. A path everyone only
reads is shared configuration, not a channel, and does not fire.

### `AAK-COMPOSE-003` — a manifest narrower than its code (MEDIUM)

A skill whose body or adjacent scripts exercise a capability its frontmatter does
not admit to. This is what keeps the other two honest: both build their graph from
manifests, so an under-declared component makes every chain through it look
narrower than it is. It is reported separately because the fix is different — the
manifest is wrong whether or not a chain currently runs through it.

### Why a composition finding sometimes does not appear

These rules only earn their place by reporting something no per-artifact rule
does. So a composition finding stands down when any component on its path already
carries a finding **at or above the composition finding's own severity**.

Severity, not mere presence, is the test, and the difference matters: 
`AAK-MCP-ATTEST-001` (MEDIUM) fires on virtually every MCP config, so
"suppress if anything was reported on this component" would make every
MCP-server chain permanently unreportable while the guard still looked correct. A
CRITICAL `AAK-MCP-001` on the egress server does stand the chain down, because at
that point the operator is already being told about that artifact at a higher
priority than the chain would add.

The check runs in `engine.py` rather than in the scanner, because a scanner is
handed a project root and nothing about what its peers found — and re-deriving
every rule's predicate inside the composition scanner would be a second copy of
the whole registry.

### Measured behaviour

Across the 748 public MCP configs in `benchmarks/data`, `AAK-COMPOSE-001` reports
2 chains in 2 configs (0.27%) before suppression and 0 after, because those
corpus projects are configs alone with no skills, and every chain found in them
runs through a component already reported at HIGH or above. An earlier draft of
the predicate treated *any* remote server as a source of untrusted input; that
version reported 253 chains across 33.8% of the corpus, which is what a
composition rule looks like when its roles are vacuous.
