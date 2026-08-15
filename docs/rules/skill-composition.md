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
