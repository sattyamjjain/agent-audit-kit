"""Capability-graph composition pass (AAK-COMPOSE-001/002/003).

Every other rule in the registry evaluates one artifact. `AAK-AGENT-COMPOSE-001`
(`skill_composition`) is the one existing exception and it is deliberately narrow:
it computes an unordered capability **union** over the set of `SKILL.md` files in
one container, from *declared* frontmatter only, and asks whether the set spans a
boundary no single member spans. That is a set predicate, not a graph one. It has
no notion of direction, of one component's output being another's input, of a hop
count, or of anything outside `SKILL.md`.

This module adds the graph. The distinction matters because the two papers this
implements describe an ordered chain, not a co-resident set:

  * CompoSkill (arXiv:2608.16246) assembles a risk chain from skills that each
    pass an individual scanner. Its own mitigation result is the reason for the
    depth cap here: attack success falls off once a chain runs longer than three
    skills, so the dangerous chains are the short ones and a deeper search buys
    combinatorial cost for cases that are already less likely to work.
  * ColluSkill (arXiv:2608.09732) is the collusion channel: skills cooperating
    through a shared medium neither of them declares. `AAK-COMPOSE-002` looks for
    that medium directly, as a filesystem path two skills both touch, which is
    something a declared-capability union cannot see by construction.

What each rule holds
--------------------
`AAK-COMPOSE-001` — an ordered path of 2 or 3 components carries untrusted input
    to network egress, passing through something that reads secrets or local
    state, while **no single component on the path holds all three roles**. A
    component that held all three would be reported on its own, and reporting it
    twice is worse than not having this pass at all.
`AAK-COMPOSE-002` — two or more skills in one container both reference the same
    writable path, and neither declares a write capability or names the path as
    an output. That undeclared shared path is a channel between them.
`AAK-COMPOSE-003` — a skill's body or its adjacent scripts exercise a capability
    wider than its manifest declares. This is what makes the other two rules
    conservative: a graph built from manifests understates the real graph exactly
    as far as manifests understate their own components.

Deduplication
-------------
"No single node would fire an existing rule" cannot be answered inside a scanner:
the contract is `scan(project_root) -> (findings, evaluated_rules)` and gives no
view of what anything else found. Re-deriving each rule's predicate here would be
a second copy of every rule, which is the failure this project already fixed once
for remediation keys. So the check lives where the information is: `engine.py`
drops a composition finding when any component on its path sits in a file that
another rule already reported. That is deliberately conservative — it suppresses
on file granularity, so an unrelated finding elsewhere in a shared `.mcp.json`
stands the whole chain down — and conservative is the correct direction for a
rule whose entire value proposition is reporting something nothing else does.

Every node here is derived from extraction that already exists: skills through
`skill_composition._extract_skill`, MCP servers through
`mcp_config._find_mcp_configs`, secret-shaped environment keys through
`secret_exposure.MCP_ENV_SECRET_KEYS`. Nothing in this module parses a config
format for the second time.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, find_line_number, make_finding
from agent_audit_kit.scanners.mcp_config import _find_mcp_configs
from agent_audit_kit.scanners.secret_exposure import MCP_ENV_SECRET_KEYS
from agent_audit_kit.scanners.skill_composition import (
    _as_list,
    _extract_skill,
    _parse_frontmatter,
)

_RULE_CHAIN = "AAK-COMPOSE-001"
_RULE_SHARED_STATE = "AAK-COMPOSE-002"
_RULE_UNDERDECLARED = "AAK-COMPOSE-003"

RULE_IDS = frozenset({_RULE_CHAIN, _RULE_SHARED_STATE, _RULE_UNDERDECLARED})

# CompoSkill's own numbers concentrate at chains of three or fewer, and the path
# count grows as O(n**depth), so this is both the useful bound and the affordable
# one. Raising it is a deliberate decision, not a tuning knob.
MAX_PATH_NODES = 3

# Refuse to build a graph for absurd containers rather than melting on one. A
# config with more servers than this has a bigger problem than composition, and
# AAK-MCP-004 already reports it at a threshold of 10.
_MAX_NODES_PER_CONTAINER = 60
_MAX_FILE_BYTES = 512_000
# Upper bound on how many lines one server block may claim for suppression.
_MAX_BLOCK_LINES = 200

# Frontmatter keys that declare data flow. These are a convention rather than a
# standard -- see `limitations` on AAK-COMPOSE-001. When absent, edges come from
# co-registration instead, which is why the rule does not depend on them.
_INPUT_KEYS = ("inputs", "consumes", "reads-state", "reads_state")
_OUTPUT_KEYS = ("outputs", "produces", "writes-state", "writes_state", "state")

# Paths that look like shared mutable state. Anchored on a real path prefix so a
# bare word in prose cannot match -- the 0.3.82 `cline` lesson, applied to paths.
_STATE_PATH_RE = re.compile(
    r"(?<![\w-])(?:/tmp/|/var/tmp/|~/\.[\w.-]+/|\./?\.?[\w.-]*(?:cache|state|shared|scratch|tmp)[\w./-]*)"
    r"[\w./-]*",
    re.IGNORECASE,
)

# Capability signals in a skill *body* (or an adjacent script), used only by
# AAK-COMPOSE-003 to compare against what the manifest declared.
_BODY_CAPABILITY_SIGNALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("network_egress", re.compile(
        r"(?<![\w-])(?:curl|wget|https?://|requests\.(?:get|post)|fetch\(|urllib|httpx)",
        re.IGNORECASE)),
    ("shell_execution", re.compile(
        r"(?<![\w-])(?:subprocess\.|os\.system|child_process|exec\(|eval\(|```(?:bash|sh|shell|zsh))",
        re.IGNORECASE)),
    ("filesystem_write", re.compile(
        r"(?<![\w-])(?:open\([^)]*['\"][wa]['\"]|>>\s*[\w./-]+|writeFileSync|\.write_text\(|"
        r"shutil\.copy|mv\s+[\w./-]+|tee\s)",
        re.IGNORECASE)),
    ("credential_access", re.compile(
        r"(?<![\w-])(?:os\.environ\[|process\.env\.|\.aws/credentials|\.ssh/id_|"
        r"API_KEY|SECRET_KEY|ACCESS_TOKEN)",
        re.IGNORECASE)),
)

# Tool-name shapes that pull content from outside the trust boundary. A component
# with one of these is where an untrusted chain can start.
_UNTRUSTED_SOURCE_RE = re.compile(
    r"(?<![\w-])(?:webfetch|websearch|fetch|browser|browse|crawl|scrape|search|"
    r"read_?webpage|http_?get|rss|inbox|email|mail|issue|comment|ticket|slack|"
    r"discord|telegram|webhook)",
    re.IGNORECASE,
)


@dataclass
class _Caps:
    """The five-way capability tuple this pass reasons over."""

    reads_untrusted_input: bool = False
    reads_local_secrets: bool = False
    writes_local_state: bool = False
    performs_network_egress: bool = False
    executes_code: bool = False

    def as_tuple(self) -> tuple[bool, bool, bool, bool, bool]:
        return (
            self.reads_untrusted_input,
            self.reads_local_secrets,
            self.writes_local_state,
            self.performs_network_egress,
            self.executes_code,
        )

    @property
    def touches_sensitive(self) -> bool:
        """The middle role: reads a secret, or reads/writes local state."""
        return self.reads_local_secrets or self.writes_local_state

    @property
    def holds_whole_chain(self) -> bool:
        """One component that already spans untrusted input -> sensitive -> egress.

        Such a component is a single-artifact finding for the rules that already
        exist, so the chain rule must not also claim it.
        """
        return (
            self.reads_untrusted_input
            and self.touches_sensitive
            and self.performs_network_egress
        )


@dataclass
class _Node:
    kind: str  # "skill" | "mcp-server"
    name: str
    rel: str
    line: Optional[int]
    caps: _Caps
    container: str
    line_end: Optional[int] = None
    inputs: frozenset[str] = frozenset()
    outputs: frozenset[str] = frozenset()
    accepts_free_text: bool = True
    state_paths: frozenset[str] = frozenset()
    declared_caps: frozenset[str] = frozenset()
    body_caps: frozenset[str] = frozenset()
    detail: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.rel, self.name)

    def label(self) -> str:
        return f"{self.name} ({self.kind}, {self.rel})"


# --------------------------------------------------------------------------
# Node extraction — every branch delegates to an existing parser.
# --------------------------------------------------------------------------


def _norm_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _skill_nodes(project_root: Path) -> list[_Node]:
    nodes: list[_Node] = []
    for path in sorted(project_root.rglob("SKILL.md")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        skill = _extract_skill(path, project_root)
        if skill is None:
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fm = _parse_frontmatter(raw)
        body = raw.split("---", 2)[-1] if raw.startswith("---") else raw

        declared = frozenset(skill.caps)
        tools = _as_list(
            fm.get("allowed-tools") or fm.get("allowed_tools") or fm.get("tools")
        )
        untrusted = any(_UNTRUSTED_SOURCE_RE.search(t) for t in tools)

        caps = _Caps(
            reads_untrusted_input=untrusted,
            reads_local_secrets="credential_access" in declared
            or "filesystem_read" in declared,
            writes_local_state="filesystem_write" in declared
            or "memory_write" in declared,
            performs_network_egress="network_egress" in declared,
            executes_code="shell_execution" in declared,
        )

        inputs = {
            _norm_token(v) for k in _INPUT_KEYS for v in _as_list(fm.get(k)) if v
        }
        outputs = {
            _norm_token(v) for k in _OUTPUT_KEYS for v in _as_list(fm.get(k)) if v
        }

        nodes.append(_Node(
            kind="skill",
            name=str(fm.get("name") or path.parent.name),
            rel=path.relative_to(project_root).as_posix(),
            line=1,
            caps=caps,
            container=path.parent.parent.relative_to(project_root).as_posix() or ".",
            inputs=frozenset(inputs),
            outputs=frozenset(outputs),
            # A component that declares what it consumes is not also an arbitrary
            # free-text sink. Without this the co-registration arm makes the graph
            # complete, every long chain has a short-cut, and the depth cap can
            # never bind on anything.
            accepts_free_text=not inputs,
            state_paths=frozenset(_state_paths(body) | _script_state_paths(path.parent)),
            declared_caps=declared,
            body_caps=frozenset(_body_caps(body, path.parent)),
            detail=", ".join(sorted(tools)) or "no declared tools",
        ))
    return nodes


def _mcp_nodes(project_root: Path) -> list[_Node]:
    nodes: list[_Node] = []
    for config_path in _find_mcp_configs(project_root):
        try:
            if config_path.stat().st_size > _MAX_FILE_BYTES:
                continue
            raw = config_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            continue
        try:
            rel = config_path.relative_to(project_root).as_posix()
        except ValueError:
            continue

        # Where each server's block starts, so a finding anywhere inside it can be
        # matched to that server. Line-exact matching does not work: AAK-MCP-001
        # reports on the `url` line, one below the name line this node is keyed to.
        name_lines = {
            str(n): (find_line_number(raw, f'"{n}"') or 0) for n in servers
        }
        ordered = sorted(name_lines.items(), key=lambda kv: kv[1])
        total_lines = raw.count("\n") + 1
        spans: dict[str, tuple[int, int]] = {}
        for idx, (n, start) in enumerate(ordered):
            end = ordered[idx + 1][1] - 1 if idx + 1 < len(ordered) else total_lines
            spans[n] = (start, max(start, end))

        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            url = cfg.get("url") or cfg.get("serverUrl") or ""
            command = cfg.get("command") or ""
            args = [str(a) for a in (cfg.get("args") or []) if isinstance(a, (str, int))]
            env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}

            surface = " ".join([str(name), str(command), " ".join(args)])
            secret_env = any(
                MCP_ENV_SECRET_KEYS.search(str(k)) for k in (env or {})
            )
            caps = _Caps(
                # Deliberately NOT `bool(url)`. Every tool returns content into
                # the context, so treating any remote server as an untrusted
                # source makes the role vacuous and the rule fires on a third of
                # all real configs. "Untrusted input" means content authored
                # outside the trust boundary -- pages, mail, issues, tickets --
                # which is what the server's own name and argv have to say.
                reads_untrusted_input=bool(_UNTRUSTED_SOURCE_RE.search(surface)),
                reads_local_secrets=secret_env,
                # An explicit write/output flag or a declared local store. A bare
                # "db" or "store" substring matched too much of the corpus.
                writes_local_state=bool(
                    re.search(
                        r"(?<![\w-])(?:--write|--output|--data-dir|--db-path|"
                        r"sqlite|\.db\b|memory-bank|filesystem)",
                        surface,
                        re.I,
                    )
                ),
                performs_network_egress=bool(url),
                executes_code=bool(command),
            )
            nodes.append(_Node(
                kind="mcp-server",
                name=str(name),
                rel=rel,
                line=spans.get(str(name), (None, None))[0] or find_line_number(raw, str(name)),
                caps=caps,
                container=rel,
                line_end=spans.get(str(name), (0, 0))[1] or None,
                accepts_free_text=True,
                detail=str(url or command or "no transport declared"),
            ))
    return nodes


def _body_caps(body: str, skill_dir: Path) -> set[str]:
    """Capabilities the body (and adjacent scripts) actually exercise."""
    text = body
    for script in sorted(skill_dir.rglob("*")):
        if not script.is_file() or script.name == "SKILL.md":
            continue
        if script.suffix.lower() not in {".py", ".sh", ".js", ".ts", ".bash", ".zsh"}:
            continue
        try:
            if script.stat().st_size > _MAX_FILE_BYTES:
                continue
            text += "\n" + script.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return {cap for cap, rx in _BODY_CAPABILITY_SIGNALS if rx.search(text)}


def _state_paths(text: str) -> set[str]:
    out = set()
    for m in _STATE_PATH_RE.finditer(text):
        candidate = m.group(0).rstrip(".,;:)`'\"")
        # A bare directory prefix is not a channel; require something after it.
        if len(candidate) > 6 and not candidate.endswith("/"):
            out.add(candidate)
    return out


def _script_state_paths(skill_dir: Path) -> set[str]:
    out: set[str] = set()
    for script in sorted(skill_dir.rglob("*")):
        if not script.is_file() or script.name == "SKILL.md":
            continue
        if script.suffix.lower() not in {".py", ".sh", ".js", ".ts", ".bash", ".zsh"}:
            continue
        try:
            if script.stat().st_size > _MAX_FILE_BYTES:
                continue
            out |= _state_paths(script.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return out


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------


def _edges(nodes: list[_Node]) -> dict[tuple[str, str], set[tuple[str, str]]]:
    """A -> B when A's declared output is one of B's declared inputs, or when both
    are registered for the same agent and B accepts free-form text.

    The co-registration arm treats one scanned project as one agent scope. That is
    what makes a cross-kind chain visible at all: a skill under `.claude/skills/`
    and a server in `.mcp.json` load into the same context but share no directory,
    so a directory-based grouping would never connect them -- and the skill-only
    chains such a grouping *would* find are already the union rule's job. It
    over-approximates a monorepo holding several independent agent configs, which
    the rule's `limitations` states.
    """
    adj: dict[tuple[str, str], set[tuple[str, str]]] = {n.key: set() for n in nodes}
    if len(nodes) > _MAX_NODES_PER_CONTAINER:
        return adj

    for a in nodes:
        for b in nodes:
            if a.key == b.key:
                continue
            if a.outputs & b.inputs:
                adj[a.key].add(b.key)
            elif b.accepts_free_text:
                adj[a.key].add(b.key)
    return adj


def _chain_findings(nodes: list[_Node]) -> list[Finding]:
    """Ordered paths of 2..MAX_PATH_NODES carrying untrusted input to egress.

    One finding per untrusted source, not per (source, sink) pair. A project that
    registers a browser tool alongside ten remote services has one composition
    problem with ten destinations, not ten problems, and emitting it ten times
    would bury the shape in its own repetitions.
    """
    findings: list[Finding] = []
    if len(nodes) < 2:
        return findings

    by_key = {n.key: n for n in nodes}
    adj = _edges(nodes)
    # source key -> (representative shortest path, every reachable egress node)
    hits: dict[tuple[str, str], tuple[list[_Node], dict[tuple[str, str], _Node]]] = {}

    def _qualifies(path: list[_Node]) -> bool:
        # Every node must individually pass: a node holding the whole chain is a
        # single-artifact finding and belongs to whichever rule already owns it.
        if any(n.caps.holds_whole_chain for n in path):
            return False
        if not path[0].caps.reads_untrusted_input:
            return False
        if not path[-1].caps.performs_network_egress:
            return False
        # The middle role has to be carried by somebody other than the egress
        # node, otherwise this is a two-role pair the single-artifact rules
        # already describe.
        return any(n.caps.touches_sensitive for n in path[:-1])

    def walk(path: list[_Node]) -> None:
        head = path[-1]
        if len(path) >= 2 and _qualifies(path):
            rep, sinks = hits.setdefault(path[0].key, (list(path), {}))
            if len(path) < len(rep):
                hits[path[0].key] = (list(path), sinks)
            sinks[head.key] = head
        if len(path) >= MAX_PATH_NODES:
            return
        for nxt_key in sorted(adj.get(head.key, ())):
            nxt = by_key[nxt_key]
            if any(nxt.key == p.key for p in path):
                continue
            walk(path + [nxt])

    for node in nodes:
        if node.caps.reads_untrusted_input and not node.caps.holds_whole_chain:
            walk([node])

    for source_key in sorted(hits):
        path, sinks = hits[source_key]
        arrow = " -> ".join(n.label() for n in path)
        roles = []
        for n in path:
            held = [
                label for label, flag in (
                    ("untrusted-input", n.caps.reads_untrusted_input),
                    ("secrets", n.caps.reads_local_secrets),
                    ("local-state", n.caps.writes_local_state),
                    ("egress", n.caps.performs_network_egress),
                    ("exec", n.caps.executes_code),
                ) if flag
            ]
            roles.append(f"{n.name}[{'+'.join(held) or 'none'}]")
        extra = ""
        if len(sinks) > 1:
            others = sorted(n.name for k, n in sinks.items() if k != path[-1].key)
            extra = (
                f" The same source also reaches {len(others)} further egress "
                f"component(s): {', '.join(others)}."
            )
        related = {n.key: n for n in path}
        related.update(sinks)
        findings.append(make_finding(
            _RULE_CHAIN,
            path[0].rel,
            f"{len(path)}-node composition reaches network egress from untrusted "
            f"input while no single component spans the chain: {arrow}. "
            f"Capabilities: {', '.join(roles)}.{extra}",
            path[0].line,
            related_locations=[
                {
                    "file_path": n.rel,
                    "line_number": n.line,
                    "end_line": n.line_end,
                    "message": n.label(),
                }
                for n in sorted(related.values(), key=lambda n: (n.rel, n.line or 0))
            ],
        ))
    return findings


def _shared_state_findings(nodes: list[_Node]) -> list[Finding]:
    """ColluSkill's channel: one writable path, two skills, nobody declaring it."""
    findings: list[Finding] = []
    by_container: dict[str, list[_Node]] = {}
    for n in nodes:
        if n.kind == "skill":
            by_container.setdefault(n.container, []).append(n)

    for container, group in sorted(by_container.items()):
        by_path: dict[str, list[_Node]] = {}
        for n in group:
            for p in n.state_paths:
                by_path.setdefault(p, []).append(n)
        for state_path, sharers in sorted(by_path.items()):
            if len(sharers) < 2:
                continue
            # Declared by anyone? Then it is a documented interface, not a channel.
            if any(
                "filesystem_write" in s.declared_caps
                or _norm_token(state_path) in s.outputs
                for s in sharers
            ):
                continue
            # A path everyone only reads is shared configuration, not a channel.
            # Require evidence that somebody actually writes it, which is exactly
            # the write nobody declared.
            if not any("filesystem_write" in s.body_caps for s in sharers):
                continue
            names = ", ".join(sorted(s.name for s in sharers))
            findings.append(make_finding(
                _RULE_SHARED_STATE,
                sorted(s.rel for s in sharers)[0],
                f"{len(sharers)} skills in `{container}` both reference the writable "
                f"path `{state_path}` and none of them declares a write capability or "
                f"names it as an output: {names}. A path two components share without "
                "declaring is a channel between them, which a declared-capability "
                "union cannot see.",
                1,
                related_locations=[
                    {"file_path": s.rel, "line_number": s.line, "message": s.label()}
                    for s in sorted(sharers, key=lambda s: s.rel)
                ],
            ))
    return findings


def _underdeclared_findings(nodes: list[_Node]) -> list[Finding]:
    """A manifest narrower than the code it ships understates the whole graph."""
    findings: list[Finding] = []
    for node in nodes:
        if node.kind != "skill":
            continue
        wider = node.body_caps - node.declared_caps
        if not wider:
            continue
        findings.append(make_finding(
            _RULE_UNDERDECLARED,
            node.rel,
            f"`{node.name}` declares {sorted(node.declared_caps) or 'no capabilities'} "
            f"but its body or adjacent scripts exercise {sorted(wider)}. The "
            "composition graph is built from manifests, so an under-declared "
            "component makes every chain through it look narrower than it is.",
            1,
        ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Run the composition pass over the whole tree.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    nodes = _skill_nodes(project_root) + _mcp_nodes(project_root)
    findings: list[Finding] = []
    findings.extend(_chain_findings(nodes))
    findings.extend(_shared_state_findings(nodes))
    findings.extend(_underdeclared_findings(nodes))

    scanned = {n.rel for n in nodes} if findings else set()
    return findings, scanned


def suppression_keys(finding: Finding) -> set[str]:
    """Identity keys for every component on a composition finding's path.

    `engine.py` stands a composition finding down when another rule already
    reported one of its components. Granularity differs by component kind, and
    getting that wrong breaks the rule in one direction or the other:

    * A `SKILL.md` is one artifact, so any finding in that file is about that
      skill. Key on the file.
    * An MCP config holds many servers, so keying on the file would let one
      unrelated finding anywhere in `.mcp.json` stand down every chain through
      it -- which would suppress essentially all MCP composition. Key on the
      server's own line instead.

    This lives here rather than in the engine because it depends on what a
    component *is*, which is this module's concern.
    """
    keys: set[str] = set()
    locations: list[tuple[str, Optional[int], Optional[int]]] = [
        (finding.file_path, finding.line_number, None)
    ]
    for loc in finding.related_locations or []:
        if isinstance(loc, dict) and loc.get("file_path"):
            locations.append((
                str(loc["file_path"]),
                loc.get("line_number"),
                loc.get("end_line"),
            ))

    for file_path, line, end_line in locations:
        if not file_path:
            continue
        if file_path.endswith("SKILL.md"):
            keys.add(f"file:{file_path}")
            continue
        start = line or 0
        stop = end_line or start
        # A server occupies a block, and a rule may report on any line in it, so
        # the node claims the whole span rather than just its name line.
        for ln in range(start, min(stop, start + _MAX_BLOCK_LINES) + 1):
            keys.add(f"node:{file_path}:{ln}")
    return keys


def covering_keys(file_path: str, line_number: Optional[int]) -> set[str]:
    """Keys a non-composition finding covers, in the same vocabulary."""
    if not file_path:
        return set()
    return {f"file:{file_path}", f"node:{file_path}:{line_number}"}
