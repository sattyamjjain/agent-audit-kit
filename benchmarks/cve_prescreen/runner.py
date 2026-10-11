"""One `claude -p` call per record, on the Claude subscription.

Isolation, each piece of which was checked on Claude Code 2.1.296:

* **Fresh empty working directory** per call (`tempfile.TemporaryDirectory`),
  so no project `CLAUDE.md`, settings or MCP config is in reach.
* **`--safe-mode`**. An empty directory is not enough: the user-level
  `~/.claude/CLAUDE.md` still loads from one. Measured on 2026-10-12 with a
  probe asking the model to quote it: without `--safe-mode` the reply quoted the
  user's global instructions and the call carried 8,429 cache-creation tokens;
  with it the reply was `NONE` at 2,652. Safe mode also turns off hooks,
  skills, plugins and MCP servers, while keeping OAuth (subscription) auth.
* **`--strict-mcp-config --mcp-config '{"mcpServers":{}}'`** and
  **`--tools ""`**: no MCP server, no built-in tool. A classifier with no tools
  can be steered by an injected advisory into a wrong label, and nothing else.
* **`--system-prompt`** replaces Claude Code's agent prompt with the
  classifier's own, and **`--json-schema`** makes the answer structured.
  `--no-session-persistence` keeps the call out of the session history, and
  `--disable-slash-commands` keeps skills out even if safe mode changes.
* **Environment**: `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1` (a refusal shows up
  as a refusal instead of being retried on another model) and
  `ENABLE_CLAUDEAI_MCP_SERVERS=false`; `ANTHROPIC_API_KEY` and
  `ANTHROPIC_AUTH_TOKEN` are removed, so the only credential left is the
  claude.ai login. Every other `CLAUDE*` variable is dropped too: a parent
  Claude Code session exports its own session id and messaging socket, and a
  child that inherits them is not an isolated call.
* **The prompt goes on stdin.** `--mcp-config` and `--tools` are variadic, so a
  trailing positional prompt would be read as one more tool name.

The model that answered is read from the result's `modelUsage`, never assumed
from `--model`, so a silent fallback shows up as a mismatch. `total_cost_usd` is
what the CLI reports; on a subscription it is a list-price figure
(`costBasis: "list"`), not a charge.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping

DEFAULT_CLAUDE = "claude"
#: Environment variables removed before every call. Prefix match.
SCRUBBED_PREFIXES = ("ANTHROPIC_", "CLAUDE", "_CLAUDE")
FORCED_ENV = {
    "CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK": "1",
    "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
}
EMPTY_MCP_CONFIG = '{"mcpServers":{}}'
DEFAULT_TIMEOUT = 300.0

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def scrubbed_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The child environment: no API credentials, no parent-session variables."""
    source = os.environ if base is None else base
    env = {k: v for k, v in source.items() if not k.startswith(SCRUBBED_PREFIXES)}
    env.update(FORCED_ENV)
    return env


def build_command(
    claude: str, model: str, system_prompt: str, schema_json: str
) -> list[str]:
    """The exact argv. The prompt is not in it: it goes on stdin."""
    return [
        claude, "-p",
        "--model", model,
        "--output-format", "json",
        "--json-schema", schema_json,
        "--system-prompt", system_prompt,
        "--safe-mode",
        "--no-session-persistence",
        "--disable-slash-commands",
        "--strict-mcp-config", "--mcp-config", EMPTY_MCP_CONFIG,
        "--tools", "",
    ]


@dataclass
class CallResult:
    """What one call returned, normalised. Raw text is kept only on failure."""

    model_requested: str
    ok: bool = False
    structured: dict[str, Any] | None = None
    models_used: list[str] = field(default_factory=list)
    model_mismatch: bool = False
    refusal: bool = False
    refusal_signal: str = ""
    error: str = ""
    exit_code: int | None = None
    is_error: bool | None = None
    subtype: str | None = None
    stop_reason: str | None = None
    terminal_reason: str | None = None
    api_error_status: Any = None
    cost_usd: float | None = None
    cost_basis: str | None = None
    duration_ms: int | None = None
    duration_api_ms: int | None = None
    wall_seconds: float = 0.0
    num_turns: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_creation_input_tokens: int | None = None
    cache_read_input_tokens: int | None = None
    raw_excerpt: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


_REFUSAL_TEXT = ("i can't help", "i cannot help", "i won't", "i'm not able to help", "i am not able to help")


def _family(model: str) -> str:
    """`haiku` for "haiku" or "claude-haiku-5-5": the part a fallback would change."""
    low = model.lower()
    for fam in ("haiku", "sonnet", "opus", "fable"):
        if fam in low:
            return fam
    return low


def parse_result(
    stdout: str, stderr: str, exit_code: int, model_requested: str, wall: float
) -> CallResult:
    """Normalise the CLI's `--output-format json` result. Pure; fixture-tested."""
    out = CallResult(model_requested=model_requested, exit_code=exit_code, wall_seconds=round(wall, 3))
    try:
        payload = json.loads(stdout) if stdout.strip() else None
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        out.error = f"no JSON result (exit {exit_code})"
        out.raw_excerpt = (stderr or stdout)[:500]
        return out

    out.is_error = payload.get("is_error")
    out.subtype = payload.get("subtype")
    out.stop_reason = payload.get("stop_reason")
    out.terminal_reason = payload.get("terminal_reason")
    out.api_error_status = payload.get("api_error_status")
    out.cost_usd = payload.get("total_cost_usd")
    out.duration_ms = payload.get("duration_ms")
    out.duration_api_ms = payload.get("duration_api_ms")
    out.num_turns = payload.get("num_turns")
    usage = payload.get("usage") or {}
    out.input_tokens = usage.get("input_tokens")
    out.output_tokens = usage.get("output_tokens")
    out.cache_creation_input_tokens = usage.get("cache_creation_input_tokens")
    out.cache_read_input_tokens = usage.get("cache_read_input_tokens")

    model_usage = payload.get("modelUsage") or {}
    out.models_used = sorted(model_usage)
    bases = {str((v or {}).get("costBasis")) for v in model_usage.values() if isinstance(v, dict)}
    out.cost_basis = ",".join(sorted(b for b in bases if b != "None")) or None
    wanted = _family(model_requested)
    out.model_mismatch = bool(out.models_used) and any(_family(m) != wanted for m in out.models_used)

    signals = []
    if str(out.stop_reason or "").lower() == "refusal":
        signals.append("stop_reason=refusal")
    if "refus" in str(out.terminal_reason or "").lower():
        signals.append(f"terminal_reason={out.terminal_reason}")
    if (payload.get("safety_stops") or 0) > 0:
        signals.append(f"safety_stops={payload.get('safety_stops')}")
    structured = payload.get("structured_output")
    text = str(payload.get("result") or "")
    if not isinstance(structured, dict) and text.strip().lower().startswith(_REFUSAL_TEXT):
        signals.append("refusal text")
    out.refusal = bool(signals)
    out.refusal_signal = ";".join(signals)

    if isinstance(structured, dict):
        out.structured = structured
        out.ok = not out.is_error and exit_code == 0
    if not out.ok:
        out.error = out.error or (
            f"subtype={out.subtype} is_error={out.is_error} exit={exit_code}"
            + (f" api_error_status={out.api_error_status}" if out.api_error_status else "")
        )
        out.raw_excerpt = text[:500] if text else (stderr or "")[:500]
    return out


def resolve_claude(claude: str | None = None) -> str:
    """The real binary. A shell function or alias named `claude` is bypassed."""
    found = shutil.which(claude or DEFAULT_CLAUDE)
    if not found:
        raise FileNotFoundError("claude CLI not found on PATH")
    return found


def run_claude(
    prompt: str,
    *,
    model: str,
    system_prompt: str,
    schema_json: str,
    claude: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Runner = subprocess.run,
    env: Mapping[str, str] | None = None,
) -> CallResult:
    """One isolated call. Never raises for a model-side failure; it is recorded."""
    binary = resolve_claude(claude) if runner is subprocess.run else (claude or DEFAULT_CLAUDE)
    argv = build_command(binary, model, system_prompt, schema_json)
    child_env = scrubbed_env(env)
    if "ANTHROPIC_API_KEY" in child_env:  # pragma: no cover - scrubbed_env removes it
        raise RuntimeError("refusing to run with ANTHROPIC_API_KEY set: subscription only")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="aak-cve-prescreen-") as workdir:
        if os.listdir(workdir):  # pragma: no cover - a fresh TemporaryDirectory is empty
            raise RuntimeError(f"working directory {workdir} is not empty")
        try:
            proc = runner(
                argv, input=prompt, capture_output=True, text=True,
                cwd=workdir, env=child_env, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            result = CallResult(model_requested=model, error=f"timeout after {timeout:.0f}s")
            result.wall_seconds = round(time.monotonic() - started, 3)
            return result
    return parse_result(proc.stdout or "", proc.stderr or "", int(proc.returncode), model,
                        time.monotonic() - started)


def auth_status(claude: str | None = None, runner: Runner = subprocess.run) -> dict[str, Any]:
    """`claude auth status --json`, reduced to the method and plan.

    The backtest refuses to run unless this says `claude.ai`, which is the
    subscription login. Email, org id and org name are dropped here so they
    never reach a result file.
    """
    binary = resolve_claude(claude) if runner is subprocess.run else (claude or DEFAULT_CLAUDE)
    proc = runner(
        [binary, "auth", "status", "--json"], capture_output=True, text=True,
        env=scrubbed_env(), timeout=60, check=False,
    )
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        data = {}
    return {
        "loggedIn": data.get("loggedIn"),
        "authMethod": data.get("authMethod"),
        "apiProvider": data.get("apiProvider"),
        "subscriptionType": data.get("subscriptionType"),
    }


def cli_version(claude: str | None = None, runner: Runner = subprocess.run) -> str:
    binary = resolve_claude(claude) if runner is subprocess.run else (claude or DEFAULT_CLAUDE)
    proc = runner([binary, "--version"], capture_output=True, text=True, timeout=60,
                  env=scrubbed_env(), check=False)
    return (proc.stdout or "").strip()
