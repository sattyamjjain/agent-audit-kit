"""Keep credentials out of the evidence a finding carries.

Every output AgentAuditKit writes repeats a finding's evidence: the console,
the JSON report (and the VS Code extension that reads it), SARIF and the
GitHub code-scanning alerts built from it, PR summaries, ``aak notify``
webhooks and the private advisories ``scan --advisories`` files upstream.
Scanners build evidence by quoting what they matched, so through 0.6.20 a
rule about a server URL quoted its ``?token=`` query, a rule about an
unpinned package quoted the value after ``--api-key``, a hook rule quoted a
``curl -H 'Authorization: Bearer ...'`` command whole, and the rule that
flags a credential in a URL quoted the credential.

:func:`redact_evidence` replaces the secret *value* with ``***`` and keeps
the shape around it, so the evidence still says what was found:
``https://***@host/mcp``, ``?token=***``, ``--api-key ***``,
``GITHUB_TOKEN=***``, ``Authorization: Bearer ***``, ``sk-proj-***``.
:class:`~agent_audit_kit.models.Finding` applies it to ``evidence`` and to
each related location's ``message`` whenever either is set, so a finding
built anywhere, or edited after it was built, carries no credential.

What it leaves alone, on purpose:

- ``${VAR}``, ``$VAR``, ``%VAR%``, ``{{ ... }}`` and ``<...>`` placeholders.
  Several rules exist to tell a placeholder from a literal, and the
  evidence has to show which one it saw.
- The truncated prefixes the secret rules print (``sk-ant-api03...``):
  ``scan --verify-secrets`` reads them back to pick a verifier, and they
  are too short to be a credential.
- Hostnames, paths, URLs, package names, versions, hashes and digests, and
  values such as ``none``, ``false`` or ``oauth`` after a credential-named
  key, which say how authentication is set up rather than holding a secret.
- A key named for a pointer to a secret rather than the secret itself
  (``TOKEN_FILE``, ``--api-key-env``, ``auth_url``, ``client_id``).

Every pattern is linear in the length of the text: each one starts at a
literal or behind a negative lookbehind that only a token boundary passes,
and every repetition after it is bounded, so a hostile line cannot make a
scan quadratic (``tests/test_evidence_redaction.py`` holds a 1 MB line to a
time bound).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Callable

MASK = "***"

# Name segments that mark a credential: `OPENAI_API_KEY`, `x-auth-token`,
# `clientSecret`, `DB_PASSWORD`, `sig` (an Azure SAS signature).
_SECRET_SEGMENTS = frozenset({
    "token", "secret", "password", "passwd", "passphrase", "pwd", "pass",
    "apikey", "key", "credential", "credentials", "creds", "auth",
    "authorization", "bearer", "pat", "cookie", "signature", "sig", "jwt",
    "privatekey", "accesskey", "sas", "otp",
})
# Names that are a credential only as a whole: `session=` and `session_id=`
# hold a session, while `SessionStart` (a hook event) and a server called
# `session-handover-mcp` do not.
_SECRET_WHOLE_NAMES = frozenset({"session", "sessionid", "sid", "sessid", "phpsessid", "jsessionid"})
# Run-together spellings that split into one segment: APIKEY, authtoken.
_SECRET_SUFFIXES = ("apikey", "token", "secret", "password", "passwd", "accesskey", "privatekey")
# A key that names where a secret lives, or describes it, is not the secret:
# TOKEN_FILE, --api-key-env, auth_url, client_id, secret_name, auth_type.
_POINTER_SEGMENTS = frozenset({
    "file", "path", "dir", "url", "uri", "endpoint", "env", "var", "name",
    "type", "mode", "id", "ids", "header", "location", "source", "provider",
    "method", "scheme", "format", "length", "size", "ttl", "expiry",
    "expires", "timeout", "helper", "command", "cmd", "count", "limit",
    "required", "enabled", "disabled", "stdin", "prompt", "store", "manager",
})
# A flag that switches a check on or off takes no secret: --no-auth, --skip-auth.
_FLAG_PREFIXES = frozenset({
    "no", "disable", "enable", "skip", "allow", "require", "use", "with",
    "without", "ignore", "insecure", "show", "print", "verify", "validate",
})
# Values that say how authentication is configured rather than holding a
# credential, so `auth: none`, `requireAuth=false` and the `Bearer` before a
# masked token still read as what they are.
_CONTROL_WORDS = frozenset({
    "true", "false", "yes", "no", "on", "off", "none", "null", "nil",
    "undefined", "disabled", "enabled", "disable", "enable", "required",
    "optional", "oauth", "oauth2", "oidc", "basic", "bearer", "digest",
    "token", "apikey", "api_key", "header", "headers", "query", "cookie",
    "env", "file", "keychain", "keyring", "vault", "default", "auto",
    "anonymous", "public", "private", "redacted", "masked", "hidden",
})
# References to where a secret is kept, not the secret.
_REFERENCE_PREFIXES = ("env:", "vault:", "keychain:", "arn:", "secretsmanager:", "file:")

_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_SEGMENT_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:[\\/]")
_PERCENT_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_RUN_SPLIT_RE = re.compile(r"[-_.~+/=]+")
_DOTTED_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,8}")
_ENV_NAME_RE = re.compile(r"[A-Z][A-Z0-9]{0,63}(?:_[A-Z0-9]{1,63}){1,8}")
_LOGIN_RE = re.compile(r"[a-z][a-z0-9._-]{0,63}")
# A dotted host name with no port: what a WHATWG parser reads before a backslash.
_HOST_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63}){1,8}")
_PLACEHOLDER_USERINFO_RE = re.compile(r"[.*xX…]{1,64}")


def is_secret_name(name: str) -> bool:
    """True when a key, option or header name says its value is a credential.

    The name is split into segments on punctuation and camelCase
    (``clientSecret`` -> ``client``, ``secret``), so ``keyboard``,
    ``author``, ``bypass`` and ``max_tokens`` are not credentials while
    ``API_KEY``, ``x-auth-token`` and ``DB_PASS`` are. A name whose last
    segment points at a secret (``TOKEN_FILE``, ``api-key-env``,
    ``auth_url``) or whose first is a switch (``no-auth``) is not.
    """
    if not name or len(name) > 64:
        return False
    spaced = _CAMEL_RE.sub(r"\1_\2", name)
    segments = [s.lower() for s in _SEGMENT_SPLIT_RE.split(spaced) if s]
    if not segments:
        return False
    joined = "".join(segments)
    if joined in _SECRET_WHOLE_NAMES:
        return True
    if segments[-1] in _POINTER_SEGMENTS or segments[0] in _FLAG_PREFIXES:
        return False
    if any(s in _SECRET_SEGMENTS for s in segments):
        return True
    return joined.endswith(_SECRET_SUFFIXES)


def is_secret_option(arg: str) -> bool:
    """True for a command-line option whose *next* argument is a credential.

    ``--api-key``, ``--token`` and ``--password`` qualify; ``--api-key=v``
    (its value is part of the same argument), ``--no-auth`` and
    ``--token-file`` do not.
    """
    return arg.startswith("-") and "=" not in arg and is_secret_name(arg.lstrip("-"))


def shown_arg(args: list, index: int) -> object:
    """``args[index]`` as finding evidence may quote it.

    Launcher rules quote one argument without the option before it, so the
    value of ``--api-key`` reads as a bare word that :func:`redact_evidence`
    cannot recognise as a credential. When the previous argument is a
    credential option the value is masked here, where that context exists.
    """
    previous = args[index - 1] if index > 0 else None
    if isinstance(previous, str) and is_secret_option(previous):
        return MASK
    return args[index]


def _entropy(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def _looks_random(value: str) -> bool:
    """A value long and varied enough to be a generated credential.

    Percent-escapes are decoded first, and a list or a phrase is not a
    credential: Supabase's ``features=docs%2Caccount%2Cdatabase`` is varied
    enough to pass an entropy test only because of its ``%2C`` commas. A
    generated token mixes letters and digits inside one run
    (``9f3a7b21``, a UUID's ``e29b``); words and numbers joined by dashes,
    such as the tracking id ``WT.mc_id=academic-105485-koreyst``, do not.
    """
    if "%" in value:
        value = _PERCENT_RE.sub(lambda m: chr(int(m.group(1), 16)), value)
    if len(value) < 16 or "://" in value or any(c in value for c in ",; \t"):
        return False
    mixed = any(
        any(c.isdigit() for c in run) and any(c.isalpha() for c in run)
        for run in _RUN_SPLIT_RE.split(value)
    )
    return mixed and _entropy(value) >= 3.5


def _keep_value(value: str) -> bool:
    """True when the value after a credential-named key is not a credential."""
    v = value.strip().strip("\"'").strip()
    if not v or MASK in v or v.endswith(("...", "…")):
        return True
    if v[0] in "$%{<([@*" or v.startswith("-----"):
        return True  # placeholders, references, PEM armor (pass 1 masks its body)
    low = v.lower()
    if low in _CONTROL_WORDS or low.startswith(_REFERENCE_PREFIXES):
        return True
    if "://" in v:  # a URL: its userinfo and query are redacted on their own
        return True
    if v.startswith(("/", "./", "../", "~/", "~\\")) or _WINDOWS_PATH_RE.match(v):
        return True
    if v.isdigit() and len(v) <= 8:  # ports, limits, counts
        return True
    if _DOTTED_NAME_RE.fullmatch(v) or _ENV_NAME_RE.fullmatch(v):
        return True  # os.environ, process.env.X, OPENAI_API_KEY: a reference
    return False


def _credential_shaped(value: str) -> bool:
    """A value that could be a credential rather than a word: long, or mixed."""
    v = value.strip("\"'")
    if " " in v:
        return False
    if len(v) >= 16:
        return True
    return len(v) >= 8 and any(c.isdigit() for c in v) and any(c.isalpha() for c in v)


def _mask_quoted(value: str) -> str:
    """Mask a value, keeping the quotes it was written with."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return f"{value[0]}{MASK}{value[0]}"
    return MASK


# 1. Credentials whose format identifies them wherever they appear. The
# prefix is kept so the evidence still says what kind of credential it was.
# Each body has a minimum length, so the 8-12 character prefixes the secret
# rules print (`sk-ant-api03...`) are left as they are.
_TOKEN_FORMATS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(r"(?<![A-Za-z0-9_-])" + pattern)
    for pattern in (
        r"(sk-ant-)[A-Za-z0-9_-]{16,4096}",
        r"(sk-(?:proj|svcacct|admin)-)[A-Za-z0-9_-]{16,4096}",
        r"(sk-)[A-Za-z0-9]{20,4096}",
        r"((?:sk|rk)_(?:live|test)_)[A-Za-z0-9]{16,4096}",
        r"(gh[pousr]_)[A-Za-z0-9]{20,4096}",
        r"(github_pat_)[A-Za-z0-9_]{20,4096}",
        r"(glpat-)[A-Za-z0-9_-]{20,4096}",
        r"(xox[abposr]-)[A-Za-z0-9-]{10,4096}",
        r"(xapp-)[A-Za-z0-9-]{10,4096}",
        r"(npm_)[A-Za-z0-9]{36}(?![A-Za-z0-9])",
        r"(hf_)[A-Za-z0-9]{30,4096}",
        r"(AIza)[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])",
        r"((?:AKIA|ASIA))[0-9A-Z]{16}(?![0-9A-Za-z])",
        r"(eyJ)[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}",
        r"(GOCSPX-)[A-Za-z0-9_-]{20,128}",
        # A credential that is a URL path: the path is the secret.
        r"(hooks\.slack\.com/(?:services|workflows|triggers)/)[A-Za-z0-9/_-]{16,512}",
        r"(discord(?:app)?\.com/api/webhooks/[0-9]{5,30}/)[A-Za-z0-9_-]{16,512}",
        r"((?:bot)?[0-9]{6,12}:)[A-Za-z0-9_-]{30,64}",
        r"(-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----)[^-]{16,16384}",
    )
)

# 2. URL userinfo: `https://user:pass@host`, `https://<token>@host`.
_USERINFO_RE = re.compile(r"(?<=://)([^/?#@\s\"'<>]{1,512})@")

# 3. URL query parameters (and `;`-separated ones in connection strings).
_QUERY_RE = re.compile(r"([?&;])([A-Za-z0-9_.~%\[\]-]{1,64})=([^&#\s\"'<>(){}\[\],;|]{0,4096})")

# 4. A credential after an HTTP auth scheme, wherever it appears.
_AUTH_SCHEME_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(Bearer|Basic|Token|Digest)(\s{1,8})([A-Za-z0-9._~+/=-]{8,4096})",
    re.IGNORECASE,
)

# 5. Command-line options: `--api-key VALUE`, `--token=VALUE`, `-u user:pass`.
# A value never starts like an option, or `-y --api-key VALUE` would read
# `--api-key` as the value of `-y` and resume the scan after it.
_OPTION_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(--?)([A-Za-z][A-Za-z0-9_-]{0,63})(=|\s{1,8})(?!--?[A-Za-z])"
    r"(\"[^\"\n]{0,4096}\"|'[^'\n]{0,4096}'|[^\s\"'<>]{1,4096})"
)
_USER_OPTIONS = frozenset({"u", "user", "proxy-user"})

# 6. Assignments: `GITHUB_TOKEN=v`, `"apiKey": "v"`, `X-Api-Key: v`, `password=v`.
_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9_.$-])([\"']?)([A-Za-z_][A-Za-z0-9_.-]{0,63})\1(\s{0,4}[:=]\s{0,4})"
    r"(\"[^\"\n]{0,4096}\"|'[^'\n]{0,4096}'|[^\s\"'<>,;&|(){}\[\]]{1,4096})"
)


def _sub_token_format(match: re.Match[str]) -> str:
    return match.group(1) + MASK


def _sub_userinfo(match: re.Match[str]) -> str:
    """Mask the userinfo of a URL, but never a host a client would contact.

    Clients read a backslash in an `http(s)` authority two ways. A WHATWG URL
    parser (browsers, Node's `fetch`, and so Claude Code) ends the authority
    there, and so do requests and Rust's `url` crate: in
    `https://attacker.example\\@api.anthropic.com` the host is
    `attacker.example` and `@api.anthropic.com` is path. curl, httpx and
    `urlsplit` keep the backslash inside the authority, read
    `attacker.example\\` as userinfo and connect to api.anthropic.com. Masking
    the whole run printed `https://***@api.anthropic.com`, so a correct
    AAK-TRUST-002 finding hid the host Claude Code contacts and showed only the
    one the second family does.

    So when a userinfo run that would be masked holds a backslash, a piece
    before a backslash that reads as a host or login name is kept and every
    other piece is masked, which leaves both hosts on the line. To the second
    family such a piece is a user name, never a password: a piece with a `:` is
    masked. Nothing else changes: a run kept before is kept whole, and a run
    without a backslash is masked whole, as before, so the output never shows
    more of a credential than it did.
    """
    userinfo = match.group(1)
    if _keep_userinfo(userinfo):
        return match.group(0)
    if "\\" not in userinfo:
        return f"{MASK}@"
    *before, last = userinfo.split("\\")
    pieces = [piece if _reads_as_host(piece) else (piece and MASK) for piece in before]
    pieces.append(last and MASK)
    return "\\".join(pieces) + "@"


def _keep_userinfo(userinfo: str) -> bool:
    if ":" not in userinfo and _LOGIN_RE.fullmatch(userinfo) and not _looks_random(userinfo):
        return True  # `git@`, `deploy@`, a decoy hostname: a login name, not a secret
    # `https://...@host`, `https://${KEY}@host`: a placeholder
    return bool(_PLACEHOLDER_USERINFO_RE.fullmatch(userinfo)) or _keep_value(userinfo)


def _reads_as_host(piece: str) -> bool:
    """A piece before a backslash that is a host or login name, not a secret."""
    return (
        ":" not in piece
        and not _looks_random(piece)
        and bool(_LOGIN_RE.fullmatch(piece) or _HOST_NAME_RE.fullmatch(piece))
    )


def _sub_query(match: re.Match[str]) -> str:
    sep, name, value = match.group(1), match.group(2), match.group(3)
    if _keep_value(value):
        return match.group(0)
    if is_secret_name(name) or _looks_random(value):
        return f"{sep}{name}={MASK}"
    return match.group(0)


def _sub_auth_scheme(match: re.Match[str]) -> str:
    credential = match.group(3)
    if MASK in credential or not (any(c.isdigit() for c in credential) or len(credential) >= 20):
        return match.group(0)  # `Basic authentication`, `Bearer token-based`: prose
    return f"{match.group(1)}{match.group(2)}{MASK}"


def _sub_option(match: re.Match[str]) -> str:
    dashes, name, sep, value = match.group(1), match.group(2), match.group(3), match.group(4)
    if name.lower() in _USER_OPTIONS:
        login, colon, password = value.strip("\"'").partition(":")
        # curl's `-u user:pass`; docker's `-u 1000:1000` is a uid and gid.
        if colon and password and MASK not in password and not password.isdigit():
            return f"{dashes}{name}{sep}{login}:{MASK}"
        return match.group(0)
    if not is_secret_name(name) or _keep_value(value):
        return match.group(0)
    return f"{dashes}{name}{sep}{_mask_quoted(value)}"


def _assign_replacer(text: str) -> Callable[[re.Match[str]], str]:
    def _sub_assign(match: re.Match[str]) -> str:
        quote, name, sep, value = match.group(1), match.group(2), match.group(3), match.group(4)
        if not is_secret_name(name) or _keep_value(value):
            return match.group(0)
        # A single-quoted name is how AAK's own evidence quotes a server, tool
        # or event (`server 'better-auth': 'node' invoked ...`) as well as a
        # Python dict key, so after one only a credential-shaped value goes.
        if quote == "'" and not _credential_shaped(value):
            return match.group(0)
        # An unquoted identifier followed by `(` or `[` is code that reads the
        # secret (`token = get_token()`), not the secret.
        if value[0] not in "\"'" and text[match.end():match.end() + 1] in ("(", "["):
            return match.group(0)
        return f"{quote}{name}{quote}{sep}{_mask_quoted(value)}"
    return _sub_assign


def redact_evidence(text: str) -> str:
    """Return ``text`` with every credential value replaced by ``***``.

    Idempotent: a value that already holds ``***`` is left alone, so
    re-redacting redacted text changes nothing.
    """
    if not text:
        return text
    for pattern in _TOKEN_FORMATS:
        text = pattern.sub(_sub_token_format, text)
    if "://" in text:
        text = _USERINFO_RE.sub(_sub_userinfo, text)
    if "=" in text:
        text = _QUERY_RE.sub(_sub_query, text)
    text = _AUTH_SCHEME_RE.sub(_sub_auth_scheme, text)
    if "-" in text:
        text = _OPTION_RE.sub(_sub_option, text)
    if "=" in text or ":" in text:
        text = _ASSIGN_RE.sub(_assign_replacer(text), text)
    return text


def redact_related_locations(locations: list[dict]) -> list[dict]:
    """``locations`` with each ``message`` redacted.

    The list is returned as given when no message holds a credential, so a
    caller that edits the entries afterwards (the sessions adapter rewrites
    each ``file_path``) still edits the finding's own list.
    """
    redacted: list[dict] = []
    changed = False
    for loc in locations:
        message = loc.get("message") if isinstance(loc, dict) else None
        if isinstance(message, str):
            clean = redact_evidence(message)
            if clean != message:
                loc = {**loc, "message": clean}
                changed = True
        redacted.append(loc)
    return redacted if changed else locations
