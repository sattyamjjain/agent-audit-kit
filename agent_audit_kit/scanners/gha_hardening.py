"""AAK-GHA-IMMUTABLE-001 — non-SHA-pinned third-party GitHub Actions.

GitHub's April 2026 Security Roadmap ships Immutable Actions and makes
SHA pinning the default policy. This scanner walks `.github/workflows/*.yml`
and flags every `uses: owner/action@ref` where `ref` is a tag or branch
name instead of a 40-character commit SHA.

First-party Actions (`actions/*` and `github/*`) are exempt — GitHub
publishes them as Immutable Actions.

Local composite Actions (`uses: ./path/to/action`) are exempt — they
ship in the caller's own repo.

Docker-ref Actions (`uses: docker://image:tag`) get their own warning:
Docker refs are not SHA-pinned by default; Immutable Actions apply only
to the `owner/action@ref` form.

AAK-GHA-SECRET-DUMP-001 reads the same workflows' `run:` steps for one that
prints secrets through an encoder; see the block above `_secret_dump_findings`.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding, Severity

from ._helpers import CONFIG_MAX_BYTES, load_yaml, make_finding, placed, read_text_capped

_WORKFLOWS_DIR = ".github/workflows"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_OWNER_EXEMPT = frozenset({"actions", "github"})


def _iter_workflows(project_root: Path) -> list[Path]:
    wf_dir = project_root / _WORKFLOWS_DIR
    if not wf_dir.is_dir():
        return []
    out: list[Path] = []
    for path in wf_dir.iterdir():
        if not path.is_file():
            continue
        if path.suffix not in (".yml", ".yaml"):
            continue
        out.append(path)
    return out


def _walk_uses(obj, hits: list[str]) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key == "uses" and isinstance(val, str):
                hits.append(val)
            else:
                _walk_uses(val, hits)
    elif isinstance(obj, list):
        for item in obj:
            _walk_uses(item, hits)


def _is_sha_pinned(ref: str) -> bool:
    return bool(_SHA_RE.match(ref))


def _classify(uses: str) -> tuple[str, str, str] | None:
    """Return (owner, action, ref) or None if not an owner/action@ref form."""
    if not uses or uses.startswith("./") or uses.startswith("docker://"):
        return None
    if "@" not in uses:
        return None
    before, _, ref = uses.partition("@")
    if "/" not in before:
        return None
    owner, _, action = before.partition("/")
    return owner.strip(), action.strip(), ref.strip()


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for wf in _iter_workflows(project_root):
        rel = str(wf.relative_to(project_root))
        scanned.add(rel)
        try:
            text = read_text_capped(wf, CONFIG_MAX_BYTES, errors="replace")
        except OSError:
            continue
        try:
            doc = load_yaml(text, wf)
        except yaml.YAMLError:
            continue

        # Prefer the parsed YAML walk so we handle every job/step shape.
        # Fall back to regex line-scan so findings still get accurate line
        # numbers (yaml.safe_load drops source positions).
        parsed_uses: list[str] = []
        _walk_uses(doc, parsed_uses)

        seen: set[str] = set()
        unplaced: list[tuple[Finding, str]] = []
        for uses in parsed_uses:
            if uses in seen:
                continue
            seen.add(uses)
            classified = _classify(uses)
            if classified is None:
                continue
            owner, action, ref = classified
            if owner.lower() in _OWNER_EXEMPT:
                continue
            if _is_sha_pinned(ref):
                continue
            unplaced.append((make_finding(
                "AAK-GHA-IMMUTABLE-001",
                rel,
                f"`uses: {owner}/{action}@{ref}` is pinned by tag/branch, not by "
                "40-character commit SHA. GitHub's 2026 Security Roadmap "
                "requires SHA pinning for third-party Actions.",
            ), f"{owner}/{action}@{ref}"))
        # Every reported step's line in one pass over the file, not one search of it per step.
        findings.extend(placed(text, unplaced))
        findings.extend(_secret_dump_findings(wf, rel, text, doc))
    return findings, scanned


# ---------------------------------------------------------------------------
# AAK-GHA-SECRET-DUMP-001: a run step that prints secrets through an encoder.
#
# GitHub masks a secret in the log only where its value appears verbatim. The
# Gheist campaign (Wiz, 2026-10-25) pushed `ci-sync-<6 chars>` branches adding
# `.github/workflows/sync-check.yml`, whose one step ran `env | base32 -w 120`
# and `echo -n '${{ toJSON(secrets) }}' | base32 -w 120`: the encoded secrets
# print in full, the tool downloads the log and deletes the run. A command is
# reported when it expands the secrets context (`toJSON(secrets)`, `secrets.X`,
# or an env var an `env:` mapping sets from a secrets expression) or the whole
# environment (`env`, `printenv`, `set`, `export -p`, `declare -p`/`-x`) and
# passes it through an encoder or transformer (base32, base64, basenc, xxd, od,
# hexdump, rev, gzip, bzip2, xz, zstd, uuencode, `openssl enc` or `openssl
# base64`) whose output reaches the log: down a pipeline that ends in a program
# that prints, or into the encoder through a here-string, a heredoc or a process
# substitution. Output written to a file other than stdout, stderr or the step
# summary, or handed to a program that consumes it (`docker login
# --password-stdin`, `gpg --import`, `kubectl apply -f -`), is not reported:
# `echo "${{ secrets.CERT }}" | base64 -d > cert.p12` is how a stored file
# reaches disk. The finding is CRITICAL when the workflow carries a published
# marker of the campaign: the file name `sync-check.yml` together with the step
# `toJSON(secrets) }}' | base32 -w 120`, or the string `===== gdmp-pivot:`.
# ---------------------------------------------------------------------------

_DUMP_RULE = "AAK-GHA-SECRET-DUMP-001"
_SECRET_EXPR_RE = re.compile(
    r"\$\{\{\s*(?:tojson\s*\(\s*secrets\s*\)|secrets\s*(?:\.[\w-]+|\[[^\]]{1,200}\]))\s*\}\}", re.I
)
_ENV_SECRET_RE = re.compile(r"\$\{\{\s*(?:tojson\s*\(\s*secrets\s*\)|secrets\b)", re.I)
_ENV_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_ENCODERS = frozenset({
    "base32", "base64", "basenc", "xxd", "od", "hexdump", "rev", "gzip", "bzip2", "xz", "zstd", "uuencode",
})
# The last program of a pipeline whose output still reaches the log.
_PRINTERS = frozenset({
    "cat", "tee", "fold", "tr", "sed", "awk", "head", "tail", "cut", "sort", "uniq", "jq", "column", "paste",
    "nl", "fmt", "grep", "echo", "printf",
}) | _ENCODERS
_VISIBLE_FILES = frozenset({"/dev/stdout", "/dev/stderr", "$GITHUB_STEP_SUMMARY", "${GITHUB_STEP_SUMMARY}"})
_REDIRECT_RE = re.compile(r"(?<![<\d&])>{1,2}\s*([^\s;&|]+)")
_HEREDOC_START_RE = re.compile(r"<<-?\s*([\"']?)([A-Za-z_][A-Za-z0-9_]{0,63})\1")
# Wiz's published indicators.
_CAMPAIGN_STEP = "toJSON(secrets) }}' | base32 -w 120"
_CAMPAIGN_STRING = "===== gdmp-pivot:"


# Every reader below costs the length of the run script once. A first version
# re-sliced a stage's word list for each leading `VAR=value` word, searched every
# later pipeline stage again for each stage that reads a secret, read a heredoc body
# again for each stage and each `;` piece that fed it, and rebuilt a joined line for
# each backslash continuation: 250,000 stages of `env|` in one step (1 MB) would
# have run for hours. A step that names no encoder at all is skipped before any of
# it, which is what keeps a large workflow of ordinary steps at the YAML parse's cost.
_ENCODER_WORD_RE = re.compile(
    r"(?<![^\s()/|;&])(?:base32|base64|basenc|xxd|od|hexdump|rev|gzip|bzip2|xz|zstd|uuencode|openssl)(?![^\s()|;&\\])"
)
_EXPR_EVENT_RE = re.compile(r"\$\{\{|\}\}")
_DOUBLE_QUOTE_EVENT_RE = re.compile(r'[\\"]')
_SPLIT_EVENT_RES: dict[tuple[str, ...], re.Pattern[str]] = {}


def _quote_end(text: str, i: int, quote: str) -> int:
    """Where the quoted run that opened just before `i` ends: past its closing quote,
    or the end of `text`. A backslash escapes the next character in double quotes only."""
    if quote == "'":
        j = text.find("'", i)
        return len(text) if j < 0 else j + 1
    while True:
        m = _DOUBLE_QUOTE_EVENT_RE.search(text, i)
        if m is None:
            return len(text)
        if m.group() == '"':
            return m.end()
        i = m.start() + 2


def _split_unquoted(text: str, separators: tuple[str, ...]) -> list[str]:
    """`text` split at each separator outside quotes and `${{ }}` expressions, in one
    pass that jumps from one quote, expression bracket or separator to the next."""
    events = _SPLIT_EVENT_RES.get(separators)
    if events is None:
        events = _SPLIT_EVENT_RES[separators] = re.compile(
            "|".join([r"\$\{\{", "['\"]", *(re.escape(s) for s in separators)])
        )
    parts: list[str] = []
    start = i = depth = 0
    while i < len(text):
        if depth:
            m = _EXPR_EVENT_RE.search(text, i)
            if m is None:
                break
            depth += 1 if m.group() == "${{" else -1
            i = m.end()
            continue
        m = events.search(text, i)
        if m is None:
            break
        token = m.group()
        if token == "${{":
            depth, i = 1, m.end()
        elif token in ("'", '"'):
            i = _quote_end(text, m.end(), token)
        else:
            parts.append(text[start:m.start()])
            i = start = m.end()
    parts.append(text[start:])
    return parts


def _program(segment: str) -> tuple[str, list[str]]:
    """The program a pipeline stage runs and its arguments, past `sudo`,
    `command`, `exec` and leading `VAR=value` assignments."""
    words = segment.replace("(", " ").replace(")", " ").split()
    k = 0
    while k < len(words) and (
        ("=" in words[k] and not words[k].startswith(("-", "/", "$"))) or words[k] in ("sudo", "command", "exec")
    ):
        k += 1
    if k == len(words):
        return "", []
    return words[k].rsplit("/", 1)[-1], words[k + 1:]


def _secret_vars(*envs: object) -> set[str]:
    """Names an `env:` mapping (workflow, job or step) sets from a secrets expression."""
    names: set[str] = set()
    for env in envs:
        if isinstance(env, dict):
            names.update(str(k) for k, v in env.items() if isinstance(v, str) and _ENV_SECRET_RE.search(v))
    return names


def _source(segment: str, secret_vars: set[str]) -> str | None:
    """The secret material a command puts on its output, or None."""
    m = _SECRET_EXPR_RE.search(segment)
    if m:
        return f"`{m.group(0)}`"
    program, args = _program(segment)
    if program == "env" and not any("=" in a and not a.startswith("-") for a in args):
        return "the whole environment (`env`)"
    if program == "printenv":
        if not args:
            return "the whole environment (`printenv`)"
        named = [a for a in args if a in secret_vars]
        if named:
            return f"`{named[0]}`, set from a secret"
    if program == "set" and not args:
        return "the whole environment (`set`)"
    if (program == "export" and args[:1] == ["-p"]) or (program == "declare" and args[:1] in (["-p"], ["-x"])):
        return f"the whole environment (`{program} {args[0]}`)"
    for name in _ENV_REF_RE.findall(segment):
        if name in secret_vars:
            return f"`${name}`, set from a secret"
    return None


def _is_encoder(segment: str) -> bool:
    program, args = _program(segment)
    if program == "openssl":
        return bool(args) and args[0] in ("enc", "base64")
    return program in _ENCODERS


def _reaches_log(last: str) -> bool:
    """Does the last stage's output reach the job log? Not when it goes to a file
    other than stdout, stderr or the step summary, or the stage consumes it."""
    program, _ = _program(last)
    if program not in _PRINTERS and not _is_encoder(last):
        return False
    return all(
        m.group(1).strip("\"'") in _VISIBLE_FILES or m.group(1).startswith("&")
        for m in _REDIRECT_RE.finditer(last)
    )


def _dump_in(command: str, body: str, secret_vars: set[str], body_sources: dict[str, str | None]) -> str | None:
    """The secret material `command` prints encoded, or None. `body` is the
    heredoc the command feeds, if any; what it holds is read once per step,
    through `body_sources`, however many stages and commands it feeds."""
    stages = [s.strip() for s in _split_unquoted(command, ("|&", "|"))]
    encoders = [_is_encoder(s) for s in stages]
    if not any(encoders) or not _reaches_log(stages[-1]):
        return None
    # Is there an encoder further down the pipeline than each stage?
    encoded_later = [False] * len(stages)
    for i in range(len(stages) - 2, -1, -1):
        encoded_later[i] = encoded_later[i + 1] or encoders[i + 1]
    for stage, later in zip(stages, encoded_later):
        if later:
            source = _source(stage, secret_vars)
            if source is not None:
                return source
    for stage, encoder in zip(stages, encoders):
        if not encoder:
            continue
        if "<<<" in stage:
            source = _source(stage.split("<<<", 1)[1], secret_vars)
        elif "<(" in stage:
            source = _source(stage.split("<(", 1)[1], secret_vars)
        elif _HEREDOC_START_RE.search(stage):
            if body not in body_sources:
                body_sources[body] = _source(body, secret_vars)
            source = body_sources[body]
        else:
            continue
        if source is not None:
            return source
    return None


def _commands(script: str) -> list[tuple[str, str, str]]:
    """(command, heredoc body, first physical line) for each command of a run
    script: backslash continuations joined, heredoc bodies kept out of the lines,
    and `;`, `&&` and `||` lists split."""
    lines = script.splitlines()
    out: list[tuple[str, str, str]] = []
    i = 0
    while i < len(lines):
        first = lines[i].rstrip().rstrip("\\").strip()
        # The joined line, kept as pieces and joined once: what `rstrip()` would drop
        # from its end is popped, and the continuation backslash cut from the piece
        # that ends in it.
        pieces = [lines[i]]
        while i + 1 < len(lines):
            while pieces and not pieces[-1].rstrip():
                pieces.pop()
            if not pieces or not pieces[-1].rstrip().endswith("\\"):
                break
            pieces[-1] = pieces[-1].rstrip()[:-1]
            i += 1
            pieces.extend((" ", lines[i].strip()))
        line = "".join(pieces)
        i += 1
        body: list[str] = []
        m = _HEREDOC_START_RE.search(line)
        if m:
            while i < len(lines) and lines[i].strip() != m.group(2):
                body.append(lines[i])
                i += 1
            i += 1
        joined = "\n".join(body)
        for piece in _split_unquoted(line, (";", "&&", "||")):
            if piece.strip() and not piece.strip().startswith("#"):
                out.append((piece.strip(), joined, first))
    return out


def _steps(doc: object) -> list[tuple[str, set[str]]]:
    """(run script, names its env maps from secrets) for every step of every job."""
    if not isinstance(doc, dict):
        return []
    top = _secret_vars(doc.get("env"))
    found: list[tuple[str, set[str]]] = []
    jobs = doc.get("jobs")
    for job in (jobs.values() if isinstance(jobs, dict) else ()):
        if not isinstance(job, dict):
            continue
        job_vars = top | _secret_vars(job.get("env"))
        for step in job.get("steps") or ():
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                found.append((step["run"], job_vars | _secret_vars(step.get("env"))))
    return found


def _secret_dump_findings(path: Path, rel: str, text: str, doc: object) -> list[Finding]:
    if path.name == "sync-check.yml" and _CAMPAIGN_STEP in text:
        marker: str | None = f"the file `sync-check.yml` with the step `{_CAMPAIGN_STEP}`"
    elif _CAMPAIGN_STRING in text:
        marker = f"the string `{_CAMPAIGN_STRING}`"
    else:
        marker = None
    unplaced: list[tuple[Finding, str]] = []
    for script, secret_vars in _steps(doc):
        if not _ENCODER_WORD_RE.search(script):
            continue
        body_sources: dict[str, str | None] = {}
        for command, body, first in _commands(script):
            source = _dump_in(command, body, secret_vars, body_sources)
            if source is None:
                continue
            shown = command if len(command) <= 160 else command[:160] + "…"
            evidence = (
                f"`{shown}` passes {source} through an encoder whose output reaches the job log, "
                "where GitHub masks a secret only where it appears verbatim."
            )
            if marker is not None:
                evidence += (
                    f" The workflow carries a published marker of the Gheist campaign (Wiz, 2026-10-25): "
                    f"{marker}. Rotate every secret it could read, and look for `ci-sync-*` branches and "
                    "workflow runs deleted soon after they finished."
                )
            finding = make_finding(_DUMP_RULE, rel, evidence)
            if marker is not None:
                # A published marker of the Gheist campaign: the step is the attack, not a slip.
                finding = dataclasses.replace(finding, severity=Severity.CRITICAL)
            unplaced.append((finding, first))
    return placed(text, unplaced)
