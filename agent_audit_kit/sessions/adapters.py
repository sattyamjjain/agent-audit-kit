"""Normalise real agent-framework transcripts into AAK's canonical call list.

`AAK-AGENT-COMPOSE-002` (session-scoped instruction splice, shipped in 0.3.74)
consumes an ordered list of tool calls:

    {"calls": [{"tool": "read_file", "arguments": {"path": "..."}}, ...]}

The rule discovers those only as `*.session.json` or JSON under `.aak/sessions/`.
That is the file a user writes by hand; it is not what any framework emits. This
module reads the transcripts frameworks actually produce and returns the
canonical list, so `aak scan --sessions <path>` makes the existing rule fire on
real data with no change to the rule.

Supported inputs
----------------

``openai-agents``
    An OpenAI Agents SDK run trace: ``{"spans": [...]}`` (or a bare list of
    spans, or ``{"data": [...]}`` as the export endpoint returns). Function-call
    spans carry ``span_data.type == "function"`` with ``name`` and a JSON-string
    ``input``. Spans are ordered by ``started_at`` when present, else by file
    order.

``langgraph``
    A LangGraph checkpoint or thread state: ``channel_values.messages`` (a raw
    checkpoint) or ``values.messages`` (``GET /threads/{id}/state``). Assistant
    messages carry ``tool_calls`` as ``{"name": ..., "args": {...}}``; the legacy
    ``additional_kwargs.tool_calls`` OpenAI-function shape is read too.

``jsonl``
    One JSON object per line, ``{"tool": ..., "args": {...}, "ts": ...}``. Lines
    are kept in file order unless every line carries a sortable ``ts``. Blank
    lines and unparseable lines are skipped rather than failing the file.

``aak``
    AAK's own canonical shape, so a path that already holds `*.session.json`
    files can be passed to ``--sessions`` too.

Every adapter returns calls in the order they occurred, because the rule's whole
premise is that consecutive same-tool calls reassemble into something no single
call requested. An adapter that cannot recognise its format returns ``None`` so
the next one gets a turn.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Optional

SUPPORTED_FORMATS = ("openai-agents", "langgraph", "jsonl", "aak")

_MAX_FILE_BYTES = 20_000_000
_JSON_SUFFIXES = {".json"}
_JSONL_SUFFIXES = {".jsonl", ".ndjson"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _as_arguments(raw: Any) -> dict:
    """Coerce a framework's argument payload into a plain dict.

    Frameworks variously hand back a dict, a JSON string, or a bare scalar. The
    rule reads named keys first and falls back to any string value, so a scalar
    is preserved under ``arg`` rather than dropped.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
            except ValueError:
                return {"arg": raw}
            if isinstance(parsed, dict):
                return parsed
            return {"arg": parsed if isinstance(parsed, str) else raw}
        return {"arg": raw}
    if raw is None:
        return {}
    return {"arg": str(raw)}


def _call(tool: Any, arguments: Any) -> Optional[dict]:
    if not isinstance(tool, str) or not tool:
        return None
    return {"tool": tool, "arguments": _as_arguments(arguments)}


def _sorted_by(items: list[dict], key: str) -> list[dict]:
    """Stable-sort by ``key`` only when every item carries a comparable value."""
    values = [i.get(key) for i in items]
    if not values or any(v is None for v in values):
        return items
    if not all(isinstance(v, (str, int, float)) for v in values):
        return items
    if len({type(v) for v in values}) != 1:
        return items
    return sorted(items, key=lambda i: i[key])  # type: ignore[index,return-value]


# --------------------------------------------------------------------------
# openai-agents
# --------------------------------------------------------------------------

def _openai_spans(raw: Any) -> Optional[list[dict]]:
    if isinstance(raw, dict):
        for key in ("spans", "data", "items"):
            value = raw.get(key)
            if isinstance(value, list):
                return [s for s in value if isinstance(s, dict)]
        return None
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]
    return None


def from_openai_agents(raw: Any) -> Optional[list[dict]]:
    """OpenAI Agents SDK run trace → canonical calls."""
    spans = _openai_spans(raw)
    if spans is None:
        return None

    function_spans = [
        s for s in spans
        if isinstance(s.get("span_data"), dict)
        and s["span_data"].get("type") == "function"
    ]
    if not function_spans:
        return None

    calls: list[dict] = []
    for span in _sorted_by(function_spans, "started_at"):
        data = span["span_data"]
        call = _call(data.get("name"), data.get("input"))
        if call is not None:
            calls.append(call)
    return calls or None


# --------------------------------------------------------------------------
# langgraph
# --------------------------------------------------------------------------

def _langgraph_messages(raw: Any) -> Optional[list[dict]]:
    if not isinstance(raw, dict):
        return None
    for container in ("channel_values", "values", "state"):
        holder = raw.get(container)
        if isinstance(holder, dict) and isinstance(holder.get("messages"), list):
            return [m for m in holder["messages"] if isinstance(m, dict)]
    # A bare checkpoint sometimes nests one level deeper under "checkpoint".
    checkpoint = raw.get("checkpoint")
    if isinstance(checkpoint, dict):
        return _langgraph_messages(checkpoint)
    return None


def _message_tool_calls(message: dict) -> list[dict]:
    """Pull tool calls out of one message, across LangChain's shapes."""
    out: list[dict] = []

    for entry in message.get("tool_calls") or []:
        if not isinstance(entry, dict):
            continue
        # Modern LangChain: {"name": ..., "args": {...}}
        call = _call(entry.get("name"), entry.get("args"))
        if call is None:
            # Legacy OpenAI-function: {"function": {"name":..., "arguments": "..."}}
            fn = entry.get("function")
            if isinstance(fn, dict):
                call = _call(fn.get("name"), fn.get("arguments"))
        if call is not None:
            out.append(call)

    extra = message.get("additional_kwargs")
    if isinstance(extra, dict):
        for entry in extra.get("tool_calls") or []:
            if not isinstance(entry, dict):
                continue
            fn = entry.get("function")
            if isinstance(fn, dict):
                call = _call(fn.get("name"), fn.get("arguments"))
                if call is not None:
                    out.append(call)

    return out


def from_langgraph(raw: Any) -> Optional[list[dict]]:
    """LangGraph checkpoint / thread state → canonical calls."""
    messages = _langgraph_messages(raw)
    if messages is None:
        return None
    calls: list[dict] = []
    for message in messages:
        calls.extend(_message_tool_calls(message))
    return calls or None


# --------------------------------------------------------------------------
# jsonl
# --------------------------------------------------------------------------

def from_jsonl(text: str) -> Optional[list[dict]]:
    """Raw JSONL of ``{tool, args, ts}`` → canonical calls."""
    rows: list[dict] = []
    saw_json_object = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if not isinstance(parsed, dict):
            continue
        saw_json_object = True
        tool = parsed.get("tool") or parsed.get("name") or parsed.get("tool_name")
        if not isinstance(tool, str) or not tool:
            continue
        args = parsed.get("args")
        if args is None:
            args = parsed.get("arguments")
        if args is None:
            args = parsed.get("input")
        rows.append({"tool": tool, "arguments": _as_arguments(args), "ts": parsed.get("ts")})

    if not saw_json_object or not rows:
        return None

    ordered = _sorted_by(rows, "ts")
    return [{"tool": r["tool"], "arguments": r["arguments"]} for r in ordered]


# --------------------------------------------------------------------------
# aak canonical
# --------------------------------------------------------------------------

def from_aak(raw: Any) -> Optional[list[dict]]:
    """AAK's own ``{"calls": [...]}`` (or a bare list) → canonical calls."""
    if isinstance(raw, dict) and isinstance(raw.get("calls"), list):
        seq = raw["calls"]
    elif isinstance(raw, list):
        seq = raw
    else:
        return None
    calls: list[dict] = []
    for entry in seq:
        if not isinstance(entry, dict):
            continue
        call = _call(entry.get("tool"), entry.get("arguments"))
        if call is not None:
            calls.append(call)
    return calls or None


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------

# Order matters: the framework formats are checked before the permissive
# canonical reader, which would otherwise swallow a bare list of spans.
_JSON_ADAPTERS: tuple[tuple[str, Callable[[Any], Optional[list[dict]]]], ...] = (
    ("openai-agents", from_openai_agents),
    ("langgraph", from_langgraph),
    ("aak", from_aak),
)


def normalize(raw: Any) -> Optional[tuple[str, list[dict]]]:
    """Normalise already-parsed JSON. Returns ``(format_name, calls)``."""
    for name, adapter in _JSON_ADAPTERS:
        try:
            calls = adapter(raw)
        except (AttributeError, TypeError, ValueError):
            continue
        if calls:
            return name, calls
    return None


def detect_format(path: Path) -> Optional[str]:
    """The format name AAK would read ``path`` as, or ``None``."""
    result = normalize_path(path)
    return result[0] if result else None


def normalize_path(path: Path) -> Optional[tuple[str, list[dict]]]:
    """Read one transcript file. Returns ``(format_name, calls)`` or ``None``."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    suffix = path.suffix.lower()

    if suffix in _JSONL_SUFFIXES:
        calls = from_jsonl(text)
        return ("jsonl", calls) if calls else None

    if suffix in _JSON_SUFFIXES:
        try:
            raw = json.loads(text)
        except ValueError:
            # A .json file holding JSON-lines is common enough to be worth trying.
            calls = from_jsonl(text)
            return ("jsonl", calls) if calls else None
        return normalize(raw)

    return None


def load_transcripts(target: Path) -> list[tuple[Path, str, list[dict]]]:
    """Load every recognisable transcript at ``target`` (a file or a directory).

    Returns ``(path, format_name, calls)`` per readable transcript, sorted by
    path so a run is reproducible.
    """
    if target.is_file():
        candidates = [target]
    elif target.is_dir():
        candidates = sorted(
            p for p in target.rglob("*")
            if p.is_file() and p.suffix.lower() in (_JSON_SUFFIXES | _JSONL_SUFFIXES)
        )
    else:
        return []

    out: list[tuple[Path, str, list[dict]]] = []
    for path in candidates:
        result = normalize_path(path)
        if result is None:
            continue
        fmt, calls = result
        out.append((path, fmt, calls))
    return out


# --------------------------------------------------------------------------
# scan integration
# --------------------------------------------------------------------------

def scan_sessions(target: Path, config_root: Optional[Path] = None) -> list[Any]:
    """Run the session-scoped rules over normalised transcripts at ``target``.

    The rules discover transcripts by walking a project root, so normalised
    calls are staged into a throwaway root as `.aak/sessions/*.json` and the
    rule is pointed at that. Findings are then rewritten to cite the real
    source transcript rather than the staging copy, so a report names the file
    the user actually passed.

    ``config_root`` is the real project root, used only so the rule keeps
    reading the project's `.aak/composition-boundaries.yaml` (egress allowlist
    and sensitive-path patterns) instead of falling back to the defaults.

    Returns the findings; the caller merges them into the scan result.
    """
    import shutil
    import tempfile

    from agent_audit_kit.scanners import session_splice

    transcripts = load_transcripts(target)
    if not transcripts:
        return []

    staging = Path(tempfile.mkdtemp(prefix="aak-sessions-"))
    try:
        sessions_dir = staging / ".aak" / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)

        # Carry the project's composition config across, so --sessions honours
        # the same allowlist a normal scan would.
        if config_root is not None:
            src_cfg = config_root / ".aak" / "composition-boundaries.yaml"
            if src_cfg.is_file():
                shutil.copy2(src_cfg, staging / ".aak" / "composition-boundaries.yaml")

        # staged relative path -> the transcript the user actually passed
        origin: dict[str, str] = {}
        for index, (path, _fmt, calls) in enumerate(transcripts):
            staged = sessions_dir / f"{index:04d}-{path.name}.json"
            if staged.suffix != ".json":
                staged = staged.with_suffix(".json")
            staged.write_text(json.dumps({"calls": calls}), encoding="utf-8")
            origin[staged.relative_to(staging).as_posix()] = _display_path(path, target)

        findings, _evaluated = session_splice.scan(staging)

        for finding in findings:
            real = origin.get(finding.file_path)
            if real is None:
                continue
            finding.evidence = finding.evidence.replace(finding.file_path, real)
            finding.file_path = real
            for related in finding.related_locations:
                if related.get("file_path") in origin:
                    related["file_path"] = origin[related["file_path"]]
        return findings
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _display_path(path: Path, target: Path) -> str:
    """How a transcript should be named in a finding."""
    try:
        if target.is_dir():
            return path.relative_to(target).as_posix()
    except ValueError:
        pass
    return path.as_posix()
