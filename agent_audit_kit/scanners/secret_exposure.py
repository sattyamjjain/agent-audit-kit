from __future__ import annotations

import fnmatch
import json
import math
import re
from bisect import bisect_right
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    find_line_number,
    in_skip_dir,
    iter_mcp_servers,
    loads_jsonc,
    make_finding,
)

# API key patterns
ANTHROPIC_KEY = re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}")
# OpenAI issues two families of key, and both are read here (#951).
#
# - Legacy user keys: ``sk-`` and alphanumerics only.
# - Project (``sk-proj-``), service-account (``sk-svcacct-``) and admin
#   (``sk-admin-``) keys, the formats issued since 2024. Their bodies carry ``-``
#   and ``_``, so the legacy branch stops at the first hyphen and never matched
#   one. gitleaks' ``openai-api-key`` rule and OpenRouter's secret-format
#   guardrail docs both list these three prefixes.
#
# The look-behind on the prefixed branch keeps a word that merely ends in "sk"
# ("task-admin-dashboard-settings", "disk-proj-...") from reading as a key. The
# legacy branch has never had one and is left as it was. Both branches are a
# literal and one unbounded class with nothing after it, so a scan stays linear.
#
# Secret scanners usually also require the ``T3BlbkFJ`` marker (base64 for
# "OpenAI") that real keys carry mid-body. This does not: like the legacy branch
# and ``ANTHROPIC_KEY``, it asks a key for nothing beyond a prefix and a length, so
# a key OpenAI re-shapes stays detectable. The price is that a placeholder of 20 or
# more URL-safe characters after a family prefix is reported.
OPENAI_KEY = re.compile(
    r"(?<![A-Za-z0-9])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}"
    r"|sk-[a-zA-Z0-9]{20,}"
)
AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
AWS_SECRET_KEY = re.compile(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}")
# GitHub prefixes every token with its type (docs.github.com, "About
# authentication to GitHub"): ``ghp_`` is a personal access token (classic) and
# ``github_pat_`` a fine-grained one, 22 characters, an underscore, then 59 more
# (gitleaks ``github-fine-grained-pat`` reads the same shape as ``\w{82}``).
# ``gho_``, ``ghu_``, ``ghs_`` and ``ghr_`` are OAuth, GitHub App and refresh
# tokens, not personal access tokens, and are not read here.
GITHUB_TOKEN = re.compile(
    r"ghp_[a-zA-Z0-9]{36}"
    r"|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"
)
GITLAB_TOKEN = re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}")
GCP_SERVICE_ACCOUNT = re.compile(r'"type"\s*:\s*"service_account"')

# Secret key name patterns
SECRET_KEY_NAMES = re.compile(
    r"(SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|API_KEY)", re.IGNORECASE
)

# AAK-SECRET-005 by name. A keystore or a PuTTY key is a private key by its extension:
# PKCS#12 encrypts its entries, so nothing short of the password says what they are.
# A Java keystore lists its entry types in the clear, and one that holds only trusted
# certificates (a trust store) is not reported (`_keystore_holds_key`).
KEYSTORE_EXTENSIONS = frozenset({".p12", ".pfx", ".jks", ".keystore", ".jceks", ".ppk"})
_JAVA_KEYSTORE_EXTENSIONS = frozenset({".jks", ".keystore", ".jceks"})
# ssh-keygen's default private key names, the FIDO (`-sk`) ones included.
PRIVATE_KEY_FILENAMES = frozenset({"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"})
# Files that are a key or a certificate by name, where a private-key header is enough.
# `.pem`, `.key` and `.p8` are keys unless the PEM text inside says otherwise.
PEM_KEY_EXTENSIONS = frozenset({".pem", ".key", ".p8"})
CERTIFICATE_EXTENSIONS = frozenset({".crt", ".cer"})
# Files that hold no text, so no pasted key: never read for one.
_BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".psd",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".mp3", ".mp4", ".m4a", ".mov",
    ".avi", ".wav", ".flac", ".ogg", ".webm", ".zip", ".gz", ".tgz", ".bz2", ".xz",
    ".zst", ".7z", ".rar", ".jar", ".war", ".whl", ".so", ".dylib", ".dll", ".exe",
    ".o", ".a", ".class", ".pyc", ".wasm", ".sqlite", ".db", ".parquet", ".npy",
    ".pt", ".onnx", ".safetensors",
})
# A PEM private-key header: RFC 7468's PRIVATE KEY and ENCRYPTED PRIVATE KEY, the
# algorithm forms OpenSSL and OpenSSH write (RSA, EC, DSA, OPENSSH) and OpenPGP's
# PRIVATE KEY BLOCK. At most three words come before PRIVATE, so a read is bounded.
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----")
_PRIVATE_KEY_END = re.compile(r"-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----")
# Any PEM header: a certificate, a public key, a request or parameters.
_PEM_HEADER = re.compile(r"-----BEGIN [A-Z0-9 ]{1,40}-----")
# What may sit between a private-key header and its END marker in a key that is
# written out: base64 lines, the RFC 1421 and OpenPGP armor headers (`Proc-Type:`,
# `DEK-Info:`, `Version:`), blank lines and line breaks, escaped as in a JSON string.
_ARMOR_HEADER = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,40}: ")
_KEY_LINE = re.compile(r"[A-Za-z0-9+/=_-]+")
_ESCAPED_BREAK = re.compile(r"\\r\\n|\\n|\\r")
# A key is a few KB of text (an RSA-4096 key 3.2 KB); a block longer than this is
# not read, which also bounds the work one header can cost.
_MAX_KEY_BLOCK = 16_384
_MAX_FILE_BYTES = 1_000_000

# MCP server env secret patterns (for non-mcp config files)
MCP_ENV_SECRET_KEYS = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API_KEY|ANTHROPIC|OPENAI|AWS_)", re.IGNORECASE
)

# Directories to skip: the shared `_helpers.SKIP_DIRS`, tested below the
# project root by `in_skip_dir`. This module used to keep a private copy of
# the same set, which only invited the two to drift.

# File extensions to scan for secrets. `.mjs`, `.cjs`, `.jsx` and `.tsx` were missing
# beside `.js` and `.ts`, so a token in `src/config.mjs` or `app/page.tsx` was never
# read while the same line in `config.js` was reported.
#
# Markdown is left out on a measurement. With a stand-in filter (a body of one repeated
# character, REPLACE, YOUR, EXAMPLE, PLACEHOLDER, CHANGEME or a run of `x` in the value,
# AWS's documented example key), these rules found 16 values in 1,909 README and docs
# files from 1,883 public MCP repositories (2026-10-17), all AAK-SECRET-004, and at most
# 9 of them had a credential's shape; the rest were URLs and prose. The prefix rules
# (001, 002, 003, 008) found nothing there. AAK-SECRET-005 does read Markdown, for a
# private key written out whole (`_check_private_key_files`).
SCANNABLE_EXTENSIONS = frozenset({
    ".env", ".json", ".yml", ".yaml", ".toml", ".cfg",
    ".ini", ".conf", ".xml", ".properties", ".sh", ".bash",
    ".zsh", ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".dockerfile", ".tf", ".hcl",
})

# What documentation writes where a key goes: REPLACE, YOUR, EXAMPLE, PLACEHOLDER,
# CHANGEME or a run of four `x`, in any case.
_PLACEHOLDER_WORDS = re.compile(r"replace|your|example|placeholder|changeme|x{4}", re.IGNORECASE)

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


_find_line_number = find_line_number
_make_finding = make_finding

# The separators ``str.splitlines`` splits on, so a line number taken from a match
# offset agrees with ``find_line_number`` and with the per-line entropy walk
# below wherever a key is not repeated.
_LINE_BREAK = re.compile(r"\r\n|[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")


class LineIndex:
    """1-based line numbers for offsets into one file's text.

    A regex finding used to locate its line by searching the file for the first 12
    characters of its own match, which lands on the first line containing them. Every
    Anthropic key starts ``sk-ant-api03``, so a file holding several reported them
    all on one line, and GitHub code scanning folds findings that share a rule and a
    line into one alert (#951; ``agent_config`` moved to match offsets for the same
    reason in #792).

    The line starts are indexed once, on first use, and each lookup is a bisect: a
    file full of matches costs one pass over the text, not one per match.
    """

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts: list[int] | None = None

    def at(self, offset: int) -> int:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in _LINE_BREAK.finditer(self._text)]
        return bisect_right(self._starts, offset)


# AAK-SECRET-004 reads two shapes, each a secret-looking name followed by a value:
#
#   "NAME": "value"  or  NAME = 'value'    a quoted value after ":" or "=" (either quote
#                                          may close it), the name optionally quoted
#   NAME=value                             everything up to the next whitespace
#
# and, in a YAML file only, a third:
#
#   NAME: value                            an unquoted value after ":" and whitespace,
#                                          up to the next whitespace
#
# where NAME is a run of word characters that contains SECRET, PASSWORD, TOKEN, KEY,
# CREDENTIAL or API_KEY in any case (``SECRET_KEY_NAMES``). The third shape is YAML's
# plain scalar, as in a compose file's `environment:` map (`SECRET_KEY: <value>`), which
# the first two never matched. It is not read elsewhere: in code, `name: value` is a
# TypeScript object property or a Python annotation, whose value is an expression.
#
# These were two ``re.findall`` patterns that opened ``\w*(?:SECRET|...)\w*``. Run from
# every start position along a long stretch of word characters with no "=" after it,
# the leading ``\w*`` reached the end of the stretch and backed off one character at a
# time looking for a keyword, so the time grew with the square of the line: 3.4 s for
# a 10 KB line, 13.7 s for 20 KB, 54 s for 40 KB, and hours at the 1 MB file limit. Any
# repository under scan could stall a run with one crafted line.
#
# Nothing in the grammar needs that backtracking. A name is a whole run of word
# characters (a keyword can sit anywhere in it, and the character after it is never a
# word character), and every step after it is a class that cannot overlap the next
# token: whitespace, then "=" or ":", then whitespace, then a quote or a non-space.
# So the line is cut into word runs once, each run is tested for a keyword, and what
# follows is read with a class that always matches and so cannot backtrack. The
# patterns below are single classes for that reason; none is followed by a token that
# could make it give characters back. Like ``findall``, a read resumes where the last
# one ended, so a name inside an earlier value is not read again.
_WORD_RUN = re.compile(r"\w+")
_SPACE_RUN = re.compile(r"\s*")
_NON_SPACE_RUN = re.compile(r"\S*")
_NON_QUOTE_RUN = re.compile(r"""[^"']*""")
_QUOTES = frozenset("\"'")
_ASSIGNERS = frozenset(":=")


def _run_end(pattern: re.Pattern[str], line: str, at: int) -> int:
    """Where the run ``pattern`` reads from ``at`` ends. Each pattern passed in is one class
    followed by ``*``, so it always matches, if only the empty run."""
    match = pattern.match(line, at)
    return match.end() if match else at


def _bare_value(line: str, at: int) -> tuple[str, int] | None:
    """``\\s*=\\s*(\\S+)`` read at ``at``: the value and where it ends, or None."""
    i = _run_end(_SPACE_RUN, line, at)
    if line[i : i + 1] != "=":
        return None
    start = _run_end(_SPACE_RUN, line, i + 1)
    end = _run_end(_NON_SPACE_RUN, line, start)
    return (line[start:end], end) if end > start else None


def _quoted_value(line: str, at: int) -> tuple[str, int] | None:
    """``["']?\\s*[:=]\\s*["']([^"']+)["']`` read at ``at``: the value and where it ends, or None."""
    i = at + 1 if line[at : at + 1] in _QUOTES else at
    i = _run_end(_SPACE_RUN, line, i)
    if line[i : i + 1] not in _ASSIGNERS:
        return None
    i = _run_end(_SPACE_RUN, line, i + 1)
    if line[i : i + 1] not in _QUOTES:
        return None
    close = _run_end(_NON_QUOTE_RUN, line, i + 1)
    # Empty, or no quote left on the line to close it
    if close == i + 1 or close >= len(line):
        return None
    return line[i + 1 : close], close + 1


# What cannot open a YAML plain scalar that holds a literal: a quote (the quoted shape
# reads it), a block (`|`, `>`), an anchor or alias (`&`, `*`), a tag (`!`), a flow
# collection, a comment and the reserved indicators.
_NOT_PLAIN = frozenset("\"'|>&*!{[#%@`")


def _colon_value(line: str, at: int) -> tuple[str, int] | None:
    """YAML's ``["']?\\s*:\\s+(\\S+)`` read at ``at``: the value and where it ends, or None.

    A mapping needs whitespace after the colon: ``key:value`` is one plain scalar.
    """
    i = at + 1 if line[at : at + 1] in _QUOTES else at
    i = _run_end(_SPACE_RUN, line, i)
    if line[i : i + 1] != ":":
        return None
    start = _run_end(_SPACE_RUN, line, i + 1)
    if start == i + 1 or start >= len(line) or line[start] in _NOT_PLAIN:
        return None
    end = _run_end(_NON_SPACE_RUN, line, start)
    return line[start:end], end


def _secret_assignments(line: str, yaml: bool = False) -> list[tuple[str, str]]:
    """``(name, value)`` for each secret-looking assignment on one line.

    The quoted shape comes first, then the bare one, each in line order: the order the
    two patterns this replaces were applied in. A line can yield the same assignment
    in both shapes (``SECRET_KEY="..."`` is quoted and also runs to the next space).
    With ``yaml``, YAML's unquoted ``NAME: value`` follows, read the same way.
    """
    quoted: list[tuple[str, str]] = []
    bare: list[tuple[str, str]] = []
    plain: list[tuple[str, str]] = []
    quoted_from = bare_from = plain_from = 0
    for word in _WORD_RUN.finditer(line):
        start, end = word.span()
        if not SECRET_KEY_NAMES.search(line, start, end):
            continue
        if start >= quoted_from:
            found = _quoted_value(line, end)
            if found is not None:
                quoted.append((word.group(), found[0]))
                quoted_from = found[1]
        if start >= bare_from:
            found = _bare_value(line, end)
            if found is not None:
                bare.append((word.group(), found[0]))
                bare_from = found[1]
        if yaml and start >= plain_from:
            found = _colon_value(line, end)
            if found is not None:
                plain.append((word.group(), found[0]))
                plain_from = found[1]
    return quoted + bare + plain


def _should_scan_file(path: Path) -> bool:
    name = path.name
    suffix = path.suffix.lower()
    # Always scan .env files
    if name.startswith(".env") or name.endswith(".env"):
        return True
    if suffix in SCANNABLE_EXTENSIONS:
        return True
    if "mcp" in name.lower() and suffix == ".json":
        return True
    if name.lower().startswith("dockerfile"):
        return True
    if name.lower().startswith("docker-compose"):
        return True
    return False


def _scan_file_for_secrets(file_path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    rel_path = str(file_path.relative_to(project_root))

    try:
        if file_path.stat().st_size > 1_000_000:
            return findings
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    # Each regex finding below takes its line from where its match sits, never from a
    # search for its own prefix, which is the first line holding it (#951).
    lines = LineIndex(content)
    # The walker chose this file by its lower-cased suffix, so every rule below reads
    # it the same way: `KEY.JSON` is a JSON file.
    suffix = file_path.suffix.lower()

    # AAK-SECRET-001: Anthropic API key
    for match in ANTHROPIC_KEY.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-001", rel_path,
            f"Found Anthropic API key: {match.group()[:12]}...",
            lines.at(match.start()),
        ))

    # AAK-SECRET-002: OpenAI API key (exclude Anthropic keys)
    for match in OPENAI_KEY.finditer(content):
        if not match.group().startswith("sk-ant-"):
            findings.append(_make_finding(
                "AAK-SECRET-002", rel_path,
                f"Found OpenAI API key: {match.group()[:12]}...",
                lines.at(match.start()),
            ))

    # AAK-SECRET-003: AWS credentials
    for match in AWS_ACCESS_KEY.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-003", rel_path,
            f"Found AWS access key: {match.group()[:8]}...",
            lines.at(match.start()),
        ))
    for match in AWS_SECRET_KEY.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-003", rel_path,
            "Found AWS secret access key assignment",
            lines.at(match.start()),
        ))

    # AAK-SECRET-008: GitHub/GitLab personal access tokens
    for match in GITHUB_TOKEN.finditer(content):
        token = match.group()
        # The evidence shows the prefix and 4 characters after it: 8 for ``ghp_``, 15
        # for ``github_pat_``. `--verify-secrets` reads the prefix back from it.
        shown = token[:15] if token.startswith("github_pat_") else token[:8]
        findings.append(_make_finding(
            "AAK-SECRET-008", rel_path,
            f"Found GitHub token: {shown}...",
            lines.at(match.start()),
        ))
    for match in GITLAB_TOKEN.finditer(content):
        findings.append(_make_finding(
            "AAK-SECRET-008", rel_path,
            f"Found GitLab token: {match.group()[:10]}...",
            lines.at(match.start()),
        ))

    # AAK-SECRET-009: Google Cloud service account key
    if GCP_SERVICE_ACCOUNT.search(content) and suffix == ".json":
        findings.append(_make_finding(
            "AAK-SECRET-009", rel_path,
            "Google Cloud service account key JSON file",
            _find_line_number(content, "service_account"),
        ))

    # AAK-SECRET-004: Generic high-entropy secrets
    yaml = suffix in (".yml", ".yaml")
    for line_num, line in enumerate(content.splitlines(), 1):
        # Most lines name nothing secret-looking; one pass tells them apart
        if not SECRET_KEY_NAMES.search(line):
            continue
        # Look for KEY=VALUE or "KEY": "VALUE" patterns, and KEY: VALUE in YAML
        for key, value in _secret_assignments(line, yaml):
            # Skip variable references and short values
            if value.startswith("${") or value.startswith("$") or len(value) < 16:
                continue
            # Skip common non-secret values
            if value.lower() in ("true", "false", "null", "none", "undefined"):
                continue
            entropy = _shannon_entropy(value)
            if entropy > 4.5:
                findings.append(_make_finding(
                    "AAK-SECRET-004", rel_path,
                    f"{key} = (high entropy value, Shannon entropy: {entropy:.2f})",
                    line_num,
                ))

    # AAK-SECRET-007: Secret in MCP server environment block (for non-.mcp.json files).
    # Both server maps: VS Code keeps its servers under `servers` in
    # .vscode/mcp.json, and reading `mcpServers` alone passed every literal there.
    if suffix == ".json" and file_path.name != ".mcp.json":
        try:
            data = loads_jsonc(content)
        except json.JSONDecodeError:
            data = None
        for server_name, server_cfg in iter_mcp_servers(data):
            env = server_cfg.get("env", {})
            if not isinstance(env, dict):
                continue
            for key, value in env.items():
                if MCP_ENV_SECRET_KEYS.search(key) and isinstance(value, str):
                    if not re.match(r"^\$\{.+\}$", value) and value:
                        findings.append(_make_finding(
                            "AAK-SECRET-007", rel_path,
                            f"Server '{server_name}' env.{key} = (hardcoded value)",
                            _find_line_number(content, key),
                        ))

    return findings


def _is_key_body(body: str) -> bool:
    """Whether the text between a private-key header and its END marker is a key.

    Every line must be base64 (or an armor header, or blank), with at least 16
    characters of it, more than one distinct character and no placeholder word. So
    documentation that shows where a key goes (`...`, `<paste your key here>`,
    `MIIEowIBAAKCAQEA...`, `YOUR_PRIVATE_KEY_HERE`, a run of `x`) is not a key, and
    neither is a parser's pair of marker constants, whose "body" is the code between
    them.
    """
    material: list[str] = []
    for raw in _ESCAPED_BREAK.sub("\n", body).splitlines():
        line = raw.strip()
        if not line or _ARMOR_HEADER.match(line):
            continue
        if not _KEY_LINE.fullmatch(line):
            return False
        material.append(line)
    text = "".join(material)
    return len(text) >= 16 and len(set(text.lower())) > 1 and not _PLACEHOLDER_WORDS.search(text)


def _private_key_offsets(text: str, written_out: bool) -> list[int]:
    """Offsets of the private-key headers in ``text`` that start a key.

    In a file named as a key or a certificate (``written_out`` False) the header is
    enough. Anywhere else a key must be written out in full: an END marker within
    ``_MAX_KEY_BLOCK`` characters and a body ``_is_key_body`` accepts, so a header that
    only names a key (a parser's constant, a placeholder in a README) is not one.

    The END marker is looked up once and reused until a header lies past it, so a file
    of headers with no END costs one pass, not one search per header.
    """
    offsets: list[int] = []
    end_at = -1
    for header in PRIVATE_KEY_HEADER.finditer(text):
        if not written_out:
            offsets.append(header.start())
            continue
        if end_at < header.end():
            end_at = text.find("-----END ", header.end())
            if end_at < 0:
                break
        if (
            end_at - header.end() <= _MAX_KEY_BLOCK
            and _PRIVATE_KEY_END.match(text, end_at)
            and _is_key_body(text[header.end():end_at])
        ):
            offsets.append(header.start())
    return offsets


def _keystore_holds_key(data: bytes) -> bool:
    """Whether a Java keystore may hold a private or secret key.

    JKS and JCEKS write each entry's type in the clear (sun.security.provider's
    JavaKeyStore): a tag of 1 is a private key, 2 a trusted certificate, 3 a secret key.
    A store whose every entry is a trusted certificate, a trust store such as
    `truststore.jks`, holds no key. Anything else, a store that does not parse and a
    PKCS#12 one included, is taken to hold one.
    """
    if data[:4] not in (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce"):
        return True
    version = int.from_bytes(data[4:8], "big")
    count = int.from_bytes(data[8:12], "big")
    pos = 12
    for _ in range(count):
        if int.from_bytes(data[pos : pos + 4], "big") != 2:
            return True
        pos += 4
        pos += 2 + int.from_bytes(data[pos : pos + 2], "big") + 8  # alias, then the date
        if version == 2:
            pos += 2 + int.from_bytes(data[pos : pos + 2], "big")  # certificate type
        pos += 4 + int.from_bytes(data[pos : pos + 4], "big")  # the certificate
        if pos > len(data):
            return True
    return False


def _check_private_key_files(project_root: Path) -> list[Finding]:
    """AAK-SECRET-005: a private key by its name, or by what a file holds.

    It used to decide by name alone (`.pem`, `.key`, `.p12`, `.pfx`, exactly `id_rsa`
    and three more) and read a PEM header only in the first 200 characters of a `.crt`
    or `.cer`. So the same key as `server-key.txt`, `id_rsa_work`, `deploy_key`, an
    Apple `.p8`, a Java keystore, a PuTTY `.ppk` or a block in a YAML deploy config was
    missed, and a `.pem` holding only a public certificate was reported, because the
    extension decided before the header was read. Now:

    - a keystore (`KEYSTORE_EXTENSIONS`) or an ssh-keygen default name is reported by
      name, a Java trust store excepted;
    - a `.pem`, `.key` or `.p8` is reported for each private-key header it holds, not
      at all when its PEM text is only a certificate, a public key or a request, and
      by name when it holds no PEM text (a DER key);
    - a `.crt` or `.cer` is reported for each private-key header it holds;
    - every other file under 1 MB that can hold text is reported for each private key
      written out in it in full (`_private_key_offsets`).
    """
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if in_skip_dir(path, project_root):
            continue
        if not path.is_file():
            continue
        name = path.name
        suffix = path.suffix.lower()
        rel_path = str(path.relative_to(project_root))
        by_name = f"Private key file: {name}"

        if name in PRIVATE_KEY_FILENAMES:
            findings.append(_make_finding("AAK-SECRET-005", rel_path, by_name))
            continue
        if suffix in _BINARY_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                if suffix in KEYSTORE_EXTENSIONS or suffix in PEM_KEY_EXTENSIONS:
                    findings.append(_make_finding("AAK-SECRET-005", rel_path, by_name))
                continue
            data = path.read_bytes()
        except OSError:
            continue

        if suffix in KEYSTORE_EXTENSIONS:
            if suffix not in _JAVA_KEYSTORE_EXTENSIONS or _keystore_holds_key(data):
                findings.append(_make_finding("AAK-SECRET-005", rel_path, by_name))
            continue
        if b"PRIVATE KEY" not in data:
            if suffix in PEM_KEY_EXTENSIONS and b"-----BEGIN " not in data:
                findings.append(_make_finding("AAK-SECRET-005", rel_path, by_name))
            continue
        text = data.decode("utf-8", errors="ignore")
        named = suffix in PEM_KEY_EXTENSIONS or suffix in CERTIFICATE_EXTENSIONS
        offsets = _private_key_offsets(text, written_out=not named)
        if not offsets and suffix in PEM_KEY_EXTENSIONS and not _PEM_HEADER.search(text):
            findings.append(_make_finding("AAK-SECRET-005", rel_path, by_name))
            continue
        lines = LineIndex(text)
        for offset in offsets:
            findings.append(_make_finding(
                "AAK-SECRET-005", rel_path,
                "File contains PEM private key header",
                lines.at(offset),
            ))
    return findings


# Env files a project is meant to commit: a template that lists the variables, with no
# values, for each developer to copy (`.env.example`, `.env.sample`, `.env.template`
# and Symfony's `.env.dist`).
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")


def _gitignore_ignores(patterns: list[str], name: str) -> bool:
    """Whether a root `.gitignore` ignores the root file ``name``, read as git reads it.

    Each pattern is tried in order and the last one that matches decides, so `!` takes
    a file back out. A comment, a pattern ending in `/` (directories only) and one
    anchored below the root (`config/.env`) never match a root file; `/.env` and
    `**/.env` do. This replaced a substring test, under which `!.env.example`,
    `# .env` and `.envrc` each counted as ignoring `.env`.
    """
    ignored = False
    for raw in patterns:
        pattern = raw.strip()
        if not pattern or pattern.startswith("#"):
            continue
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
        if pattern.endswith("/"):
            continue
        if pattern.startswith("**/"):
            pattern = pattern[3:]
        elif pattern.startswith("/"):
            pattern = pattern[1:]
        if "/" in pattern:
            continue
        if fnmatch.fnmatchcase(name, pattern):
            ignored = not negated
    return ignored


def _check_env_gitignore(project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    env_files = [
        path for path in sorted(list(project_root.glob(".env")) + list(project_root.glob(".env.*")))
        if path.is_file() and not path.name.lower().endswith(_ENV_TEMPLATE_SUFFIXES)
    ]
    if not env_files:
        return findings

    gitignore = project_root / ".gitignore"
    if not gitignore.is_file():
        for env_file in env_files:
            rel_path = str(env_file.relative_to(project_root))
            findings.append(_make_finding(
                "AAK-SECRET-006", rel_path,
                f"{env_file.name} exists but no .gitignore found",
            ))
        return findings

    try:
        patterns = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for env_file in env_files:
        if _gitignore_ignores(patterns, env_file.name):
            continue
        rel_path = str(env_file.relative_to(project_root))
        findings.append(_make_finding(
            "AAK-SECRET-006", rel_path,
            f"{env_file.name} exists but .gitignore does not ignore it",
        ))

    return findings


def scan(project_root: Path, ignore_paths: list[str] | None = None) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned_files: set[str] = set()
    ignore_set = set(ignore_paths or [])

    # Scan files for secret patterns
    for path in project_root.rglob("*"):
        if in_skip_dir(path, project_root):
            continue
        if not path.is_file():
            continue
        rel = str(path.relative_to(project_root))
        if any(rel.startswith(ip) for ip in ignore_set):
            continue
        if _should_scan_file(path):
            scanned_files.add(rel)
            findings.extend(_scan_file_for_secrets(path, project_root))

    # Check for private key files
    findings.extend(_check_private_key_files(project_root))

    # Check .env + .gitignore
    gitignore = project_root / ".gitignore"
    if gitignore.is_file():
        scanned_files.add(".gitignore")
    findings.extend(_check_env_gitignore(project_root))

    return findings, scanned_files
