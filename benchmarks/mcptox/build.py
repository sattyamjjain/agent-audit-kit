#!/usr/bin/env python3
"""Turn MCPTox cases into what AAK scans: a minimal project per case, and a JSONL.

A case becomes a one-file project: `.mcp.json` holding one server, keyed by the
dataset's server name, whose `tools` array holds exactly the case's tool as
`{name, description, inputSchema}`. That is the first shape
`tool_poisoning._extract_tool_descriptions` reads (`mcpServers.<name>.tools[]`),
and `inputSchema` is the key it walks for per-parameter descriptions, so every
rule that reads tool metadata from an MCP config sees the whole tool. The server
entry carries nothing else: no `command`, `url` or `env`, so no config-level
rule has anything of its own to report, and `run.py` scans the same server with
an empty `tools` array as a control to make sure of it.

The JSONL is the normalized case set, malicious and benign, for the LLM
evaluation that follows this one. The dataset carries no license, so both
outputs are refused anywhere inside the repository: they hold its text.

    python benchmarks/mcptox/build.py --jsonl PATH       # normalized cases
    python benchmarks/mcptox/build.py --projects DIR     # one project per case
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.mcptox import corpus  # noqa: E402

MCP_CONFIG_NAME = ".mcp.json"

# The JSONL field order. `paradigm` and `security risk` are the dataset's own
# field names, kept verbatim (the space included) as the task of the next
# evaluation is to be read against the dataset's labels.
JSONL_FIELDS: tuple[str, ...] = (
    "case_id", "label", "server", "server_name", "server_id", "server_url",
    "tool", "description", "input_schema", "paradigm", "security risk",
    "wrong_data", "duplicate_of", "newlines_unescaped", "tool_sha256", "source",
)


def tool_object(case: dict[str, Any]) -> dict[str, Any]:
    """The case's tool as an MCP tool object, the way a server would list it."""
    tool: dict[str, Any] = {"name": case["tool"], "description": case["description"]}
    if case.get("input_schema") is not None:
        tool["inputSchema"] = case["input_schema"]
    return tool


def project_config(case: dict[str, Any]) -> dict[str, Any]:
    return {"mcpServers": {case["server"]: {"tools": [tool_object(case)]}}}


def control_config(server: str) -> dict[str, Any]:
    """The same server with no tools: whatever fires on it is not the tool's doing."""
    return {"mcpServers": {server: {"tools": []}}}


def write_project(config: dict[str, Any], root: Path) -> Path:
    """Write `config` as `root/.mcp.json`; return the file's path."""
    root.mkdir(parents=True, exist_ok=True)
    path = root / MCP_CONFIG_NAME
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def refuse_inside_repo(path: Path) -> None:
    """Raise if `path` is inside the repository.

    Raises:
        ValueError: The path resolves under `REPO_ROOT`, where dataset text could
            be scanned as AAK's own surface or committed by a `git add -A`.
    """
    resolved = path.expanduser().resolve()
    if resolved == REPO_ROOT or resolved.is_relative_to(REPO_ROOT):
        raise ValueError(
            f"{path} is inside the repository; MCPTox has no license, so its text "
            "must stay outside it (use a path under the cache or a scratch directory)"
        )


def jsonl_lines(cases: list[dict[str, Any]]) -> list[str]:
    return [json.dumps({k: c[k] for k in JSONL_FIELDS}, ensure_ascii=False) for c in cases]


def write_jsonl(cases: list[dict[str, Any]], path: Path) -> None:
    refuse_inside_repo(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(jsonl_lines(cases)) + "\n", encoding="utf-8")


def write_projects(cases: list[dict[str, Any]], out_dir: Path) -> int:
    refuse_inside_repo(out_dir)
    for case in cases:
        write_project(project_config(case), out_dir / case["case_id"])
    return len(cases)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--jsonl", default=None,
        help=f"Write the normalized cases here (default: {corpus.cached_file('cases.jsonl')}).",
    )
    ap.add_argument("--projects", default=None, help="Also write one project directory per case here.")
    args = ap.parse_args()

    problems = corpus.cache_problems()
    if problems:
        print("cache is not filled (run `make mcptox-fetch`):\n  " + "\n  ".join(problems))
        return 1
    cases = corpus.all_cases(corpus.load_dataset())
    jsonl = Path(args.jsonl) if args.jsonl else corpus.cached_file("cases.jsonl")
    try:
        write_jsonl(cases, jsonl)
        n_projects = write_projects(cases, Path(args.projects)) if args.projects else 0
    except ValueError as exc:
        print(f"refusing: {exc}")
        return 1
    mal = sum(1 for c in cases if c["label"] == "malicious")
    print(f"wrote {jsonl}: {len(cases)} cases ({mal} malicious, {len(cases) - mal} benign)")
    if n_projects:
        print(f"wrote {n_projects} projects under {args.projects}")
    print("cases digest:", corpus.cases_digest(cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
