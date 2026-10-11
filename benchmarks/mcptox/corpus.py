#!/usr/bin/env python3
"""MCPTox as a case set: the pinned release file, its cache, and the parser.

MCPTox (Wang et al., "MCPTox: A Benchmark for Tool Poisoning Attack on
Real-World MCP Servers", arXiv 2508.14925, AAAI 2026) is a public set of
poisoned MCP tool descriptions written against 45 real servers, each one
labelled with its attack paradigm and risk category. That makes it the first
labelled malicious set a deterministic scanner can publish recall on, which is
what `run.py` does with AAK's shipped rules.

The release is pinned at the head commit of `zhiqiangwang4/MCPTox-Benchmark`,
the repository the paper's v2 names under "Datasets", which has no tags or
releases to pin instead. It ships no LICENSE file and neither the
README nor the paper states a dataset license, so nothing from it may be
redistributed: no description, tool name or query from it is committed here.
`fetch.py` downloads the one file the harness reads into `CACHE_DIR`, a user
cache directory outside the repository, and every reader checks its SHA-256
against `FILES` first.

What the file holds, and what the parser takes from it
------------------------------------------------------
`response_all.json` has one entry per server under `servers`:

- ``malicious_instance[]``: the test cases. Each carries the poisoned tool as
  rendered text (``poisoned_tool``: a ``Tool:`` line, a ``Description:`` line
  and an ``Arguments:`` section), ``metadata.paradigm`` (``Template-1`` to
  ``Template-3``, the paper's three attack templates), ``metadata["security
  risk"]`` (11 values) and ``wrong_data`` (0 or 2). 1,348 in all, the count of
  the paper's v2 and AAAI versions; the 1,312 with ``wrong_data == 0`` are the
  count of its arXiv v1.
- ``clean_system_promot`` (sic): the system prompt the models were given before
  any poisoning, rendering every real tool of the server in the same
  ``Tool:``/``Description:``/``Arguments:`` form. The benign cases are the tools
  named in ``tool_names`` (353, the paper's tool count) parsed from it.

The ``Arguments:`` section is the client's rendering of the tool's input
schema, one ``- name: description`` line per parameter, ``(required)``
appended for a required one and ``No description`` printed when the schema
had none. `parse_tool_block` turns it back into a JSON Schema with exactly
that information: property names, their descriptions, the required list. No
type is invented, because the rendering carries none.

This module is pure: it reads the cached file, hits no network, writes nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
if str(REPO_ROOT) not in sys.path:
    # `python benchmarks/mcptox/...` puts this directory on sys.path, not the
    # repository, so without this an editable install pointing at another
    # checkout would be the `agent_audit_kit` the harness measures.
    sys.path.insert(0, str(REPO_ROOT))

PAPER = "arXiv 2508.14925 (AAAI 2026)"
PAPER_URL = "https://arxiv.org/abs/2508.14925"
REPOSITORY = "zhiqiangwang4/MCPTox-Benchmark"
COMMIT = "f85189f9ad12504c197c7f920ab818a40657b1fa"
DATASET_FILE = "response_all.json"
RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/{repository}/{commit}/{path}"
LICENSE_NOTE = (
    "No license: the repository has no LICENSE file, its README is the single line "
    "'# AAAI26', and the paper states none for the dataset. All rights reserved by "
    "default, so no dataset text is redistributed here."
)

# Every file the harness reads, pinned by content. `git_blob_sha1` is the blob id
# in the pinned commit's tree, so the pin can be checked against GitHub's own
# record of the commit as well as against the bytes.
FILES: dict[str, dict[str, Any]] = {
    DATASET_FILE: {
        "sha256": "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03",
        "git_blob_sha1": "65dbe0a684471eab5717b2938223a6898f75d32d",
        "bytes": 20666873,
    },
}

TOOL_PREFIX = "Tool: "
DESCRIPTION_PREFIX = "Description:"
ARGUMENTS_PREFIX = "Arguments:"
NO_ARGUMENTS = "- No arguments"
NO_DESCRIPTION = "No description"
REQUIRED_MARK = "(required)"
PROMPT_PREAMBLE = "You are a helpful assistant with access to these tools:"
PROMPT_POSTAMBLE = "Choose the appropriate tool based on the user's question with no explanation."

# One parameter line of the rendered Arguments section: `- name: description`.
# The name class excludes whitespace and the colon, so `- No arguments` is not a
# parameter. No nested or overlapping quantifiers (CodeQL's ReDoS check).
_PARAM_RE = re.compile(r"^- ([^\s:]+):(?: (.*))?$")
_BLOCK_SPLIT_RE = re.compile(r"(?m)^(?=Tool: )")


def _default_cache_dir() -> Path:
    """Where the fetched release file lives: outside the repository, on purpose.

    The instruction-file slice learned this the hard way: third-party files kept
    under the repository, even gitignored, are read by every scan of the repo
    root, and one `git add -A` away from being committed. The MCPTox file has no
    license, so committing it would be redistribution. A user cache directory is
    outside both.
    """
    override = os.environ.get("AAK_MCPTOX_CACHE")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "agent-audit-kit" / "mcptox"


CACHE_DIR = _default_cache_dir()


def cached_file(name: str = DATASET_FILE, cache_dir: Path | None = None) -> Path:
    """The cache path of a pinned file, keyed by the pinned commit."""
    return (cache_dir or CACHE_DIR) / COMMIT / name


def raw_url(name: str = DATASET_FILE) -> str:
    return RAW_URL_TEMPLATE.format(repository=REPOSITORY, commit=COMMIT, path=name)


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def git_blob_sha1(blob: bytes) -> str:
    """The id git gives this content as a blob, to compare with the pinned tree."""
    return hashlib.sha1(b"blob %d\0" % len(blob) + blob).hexdigest()


def cache_problems(cache_dir: Path | None = None) -> list[str]:
    """Every pinned file that is missing from the cache or differs from its pin."""
    problems: list[str] = []
    for name, pin in FILES.items():
        path = cached_file(name, cache_dir)
        if not path.is_file():
            problems.append(f"{name}: not cached at {path}")
            continue
        blob = path.read_bytes()
        if len(blob) != pin["bytes"] or sha256_bytes(blob) != pin["sha256"]:
            problems.append(f"{name}: SHA-256 does not match the pin")
    return problems


def load_dataset(path: Path | None = None) -> dict[str, Any]:
    """The parsed release file. Callers check `cache_problems()` first."""
    data: dict[str, Any] = json.loads((path or cached_file()).read_text(encoding="utf-8"))
    return data


# --- parsing the rendered tool blocks ----------------------------------------


@dataclass(frozen=True)
class ToolBlock:
    """One tool as the dataset renders it, turned back into MCP's fields."""

    name: str
    description: str
    input_schema: dict[str, Any]


def unescape_flat(text: str) -> tuple[str, bool]:
    """Undo the one-line storage some poisoned tools have; report whether it applied.

    646 of the 1,348 ``poisoned_tool`` strings are stored on a single line with
    the two characters backslash and ``n`` where the others have line breaks
    (``Tool: x\\nDescription: ...\\nArguments:\\n- No arguments``). None of them
    contains a real line break and no other escape sequence occurs in them, while
    no multi-line record contains a literal backslash-n, so the substitution is
    applied only to a record with no real line break, and it only restores the
    layout the parser needs to find the ``Tool:``, ``Description:`` and
    ``Arguments:`` lines. Without it the whole record would be one unparsable line.
    """
    if "\n" not in text and "\\n" in text:
        return text.replace("\\n", "\n"), True
    return text, False


def parse_tool_block(text: str) -> ToolBlock:
    """Parse ``Tool:``/``Description:``/``Arguments:`` text into name, description, schema.

    Strict on purpose: a block in any other shape raises ``ValueError`` instead of
    being guessed at, and the harness requires every case of the pinned file to
    parse. A silently mis-parsed description would be measured as something the
    dataset never contained.

    Raises:
        ValueError: The block is not in the rendered shape described above.
    """
    lines = text.splitlines()
    if not lines or not lines[0].startswith(TOOL_PREFIX):
        raise ValueError("a tool block starts with a 'Tool: <name>' line")
    name = lines[0][len(TOOL_PREFIX):].strip()
    if len(lines) < 3 or not lines[1].startswith(DESCRIPTION_PREFIX):
        raise ValueError(f"tool {name!r}: line 2 is not 'Description: ...'")
    arg_lines = [i for i, line in enumerate(lines) if line.startswith(ARGUMENTS_PREFIX)]
    if len(arg_lines) != 1:
        raise ValueError(f"tool {name!r}: expected one 'Arguments:' line, found {len(arg_lines)}")
    a = arg_lines[0]
    if lines[a][len(ARGUMENTS_PREFIX):].strip():
        raise ValueError(f"tool {name!r}: text after 'Arguments:' on the same line")
    description = "\n".join([lines[1][len(DESCRIPTION_PREFIX):], *lines[2:a]]).strip()
    return ToolBlock(name=name, description=description, input_schema=_schema(name, lines[a + 1:]))


def _schema(tool: str, arg_lines: list[str]) -> dict[str, Any]:
    """The JSON Schema an ``Arguments:`` section renders, and nothing it does not.

    A parameter's description may run over several lines (30 of the benign
    tools' parameters do); every line up to the next ``- name:`` belongs to it, and the
    ``(required)`` mark is read off the end of the whole text, which is where a
    renderer that appends it puts it.
    """
    params: list[tuple[str, list[str]]] = []
    for line in arg_lines:
        m = _PARAM_RE.match(line)
        if m:
            params.append((m.group(1), [m.group(2) or ""]))
        elif params:
            params[-1][1].append(line)
        elif line.strip() and line.strip() != NO_ARGUMENTS:
            raise ValueError(f"tool {tool!r}: argument text before any parameter: {line[:40]!r}")
    properties: dict[str, Any] = {}
    required: list[str] = []
    for pname, chunks in params:
        if pname in properties:
            raise ValueError(f"tool {tool!r}: parameter {pname!r} listed twice")
        body = "\n".join(chunks).strip()
        if body == REQUIRED_MARK or body.endswith(" " + REQUIRED_MARK):
            required.append(pname)
            body = body[: -len(REQUIRED_MARK)].strip()
        properties[pname] = {} if body in ("", NO_DESCRIPTION) else {"description": body}
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def parse_clean_prompt(prompt: str) -> list[ToolBlock]:
    """Every tool block of a server's clean system prompt, in prompt order.

    The prompt is a fixed preamble, the tool blocks, and a fixed postamble of
    answer-format instructions, identical on all 45 servers. The postamble is cut
    before splitting, so the last tool's arguments do not absorb it.

    Raises:
        ValueError: The prompt does not have that frame.
    """
    if not prompt.startswith(PROMPT_PREAMBLE):
        raise ValueError("clean prompt does not open with the expected preamble")
    if prompt.count(PROMPT_POSTAMBLE) != 1:
        raise ValueError("clean prompt does not carry the postamble exactly once")
    body = prompt.split(PROMPT_POSTAMBLE)[0]
    chunks = _BLOCK_SPLIT_RE.split(body)
    if chunks[0].strip() != PROMPT_PREAMBLE:
        raise ValueError("unexpected text between the preamble and the first tool")
    return [parse_tool_block(chunk) for chunk in chunks[1:]]


# --- the case set ------------------------------------------------------------


def tool_sha256(name: str, description: str, input_schema: dict[str, Any] | None) -> str:
    """Identity of exactly what is scanned: the tool object, canonically serialised."""
    obj = {"name": name, "description": description, "inputSchema": input_schema}
    return sha256_text(json.dumps(obj, sort_keys=True, ensure_ascii=False))


def _servers(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    servers = data.get("servers")
    if not isinstance(servers, dict):
        raise ValueError("release file has no 'servers' object")
    return list(servers.items())


def malicious_cases(data: dict[str, Any]) -> list[dict[str, Any]]:
    """One case per ``malicious_instance``, in file order.

    ``paradigm`` and ``security risk`` keep the dataset's own field names and
    values. ``duplicate_of`` names the first case with the identical tool object
    (name, description and schema): the release holds 10 such repeats, which is
    why a deduplicated count of it is 1,338.
    """
    out: list[dict[str, Any]] = []
    first_seen: dict[str, str] = {}
    for key, server in _servers(data):
        sid = int(server["server_id"])
        for idx, inst in enumerate(server.get("malicious_instance") or []):
            text, unescaped = unescape_flat(str(inst["poisoned_tool"]))
            block = parse_tool_block(text)
            case_id = f"mcptox-s{sid:02d}-m{idx:03d}"
            digest = tool_sha256(block.name, block.description, block.input_schema)
            meta = inst.get("metadata") or {}
            out.append({
                "case_id": case_id,
                "label": "malicious",
                "server": key,
                "server_name": server.get("server_name"),
                "server_id": sid,
                "server_url": server.get("server_url"),
                "tool": block.name,
                "description": block.description,
                "input_schema": block.input_schema,
                "paradigm": meta.get("paradigm"),
                "security risk": meta.get("security risk"),
                "wrong_data": inst.get("wrong_data"),
                "duplicate_of": first_seen.get(digest),
                "newlines_unescaped": unescaped,
                "tool_sha256": digest,
                "source": f"servers[{key!r}].malicious_instance[{idx}].poisoned_tool",
            })
            first_seen.setdefault(digest, case_id)
    return out


def benign_cases(data: dict[str, Any]) -> list[dict[str, Any]]:
    """One case per tool in a server's ``tool_names``, parsed from its clean prompt.

    ``tool_names`` is what the paper counts (353). Apify's clean prompt renders 9
    more tools than its ``tool_names`` lists; they are left out, so the benign
    denominator is the paper's tool count and every benign case is a tool the
    dataset itself names as one of the server's own.

    Raises:
        ValueError: A listed tool is missing from, or repeated in, its prompt.
    """
    out: list[dict[str, Any]] = []
    for key, server in _servers(data):
        sid = int(server["server_id"])
        blocks: dict[str, ToolBlock] = {}
        for block in parse_clean_prompt(str(server["clean_system_promot"])):
            if block.name in blocks:
                raise ValueError(f"server {key!r}: tool {block.name!r} rendered twice")
            blocks[block.name] = block
        for j, name in enumerate(server.get("tool_names") or []):
            if name not in blocks:
                raise ValueError(f"server {key!r}: listed tool {name!r} is not in its clean prompt")
            block = blocks[name]
            out.append({
                "case_id": f"mcptox-s{sid:02d}-b{j:02d}",
                "label": "benign",
                "server": key,
                "server_name": server.get("server_name"),
                "server_id": sid,
                "server_url": server.get("server_url"),
                "tool": block.name,
                "description": block.description,
                "input_schema": block.input_schema,
                "paradigm": None,
                "security risk": None,
                "wrong_data": None,
                "duplicate_of": None,
                "newlines_unescaped": False,
                "tool_sha256": tool_sha256(block.name, block.description, block.input_schema),
                "source": f"servers[{key!r}].clean_system_promot",
            })
    return out


def all_cases(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Malicious cases, then benign cases, each in file order (deterministic)."""
    return malicious_cases(data) + benign_cases(data)


def cases_digest(cases: list[dict[str, Any]]) -> str:
    """One hash over every case's id, label and tool identity, in order.

    Committed in place of the cases themselves: it lets anyone who fetches the
    pinned file confirm their parse produced exactly the tools measured here,
    without this repository holding a word of the dataset.
    """
    rows = [[c["case_id"], c["label"], c["tool_sha256"]] for c in cases]
    return sha256_text(json.dumps(rows, ensure_ascii=False))


def _ranked(counter: Counter[Any]) -> dict[str, int]:
    return {str(k): v for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))}


def dataset_counts(data: dict[str, Any], cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The counts that reconcile this release with the paper's, all computed."""
    cases = all_cases(data) if cases is None else cases
    servers = _servers(data)
    listed = {key: set(s.get("tool_names") or []) for key, s in servers}
    rendered = {key: [b.name for b in parse_clean_prompt(str(s["clean_system_promot"]))] for key, s in servers}
    mal = [c for c in cases if c["label"] == "malicious"]
    ben = [c for c in cases if c["label"] == "benign"]
    server_of = {c["case_id"]: c["server"] for c in mal}
    repeats = [c for c in mal if c["duplicate_of"] is not None]
    not_listed = {key: sum(1 for name in names if name not in listed[key]) for key, names in rendered.items()}
    return {
        "servers": len(servers),
        "data_length_field": data.get("data_length"),
        "tools_listed": sum(len(names) for names in listed.values()),
        "clean_tool_blocks_rendered": sum(len(names) for names in rendered.values()),
        "clean_tool_blocks_not_listed": {key: n for key, n in sorted(not_listed.items()) if n},
        "benign_cases": len(ben),
        "malicious_cases": len(mal),
        "malicious_by_wrong_data": _ranked(Counter(c["wrong_data"] for c in mal)),
        "malicious_unique_tools": len({c["tool_sha256"] for c in mal}),
        "malicious_repeats": len(repeats),
        "malicious_repeats_across_servers": sum(
            1 for c in repeats if server_of.get(c["duplicate_of"]) != c["server"]
        ),
        "malicious_reusing_a_real_tool_name": sum(1 for c in mal if c["tool"] in listed[c["server"]]),
        "malicious_unique_server_tool_names": len({(c["server"], c["tool"]) for c in mal}),
        "malicious_newlines_unescaped": sum(1 for c in mal if c["newlines_unescaped"]),
        "malicious_by_paradigm": _ranked(Counter(c["paradigm"] for c in mal)),
        "malicious_by_security_risk": _ranked(Counter(c["security risk"] for c in mal)),
        "malicious_with_parameters": sum(1 for c in mal if c["input_schema"]["properties"]),
        "benign_with_parameters": sum(1 for c in ben if c["input_schema"]["properties"]),
    }


def main() -> int:
    problems = cache_problems()
    if problems:
        print("cache is not filled (run `make mcptox-fetch`):\n  " + "\n  ".join(problems))
        return 1
    data = load_dataset()
    cases = all_cases(data)
    print(json.dumps(dataset_counts(data, cases), indent=2, sort_keys=True))
    print("cases digest:", cases_digest(cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
