#!/usr/bin/env python3
"""Pure URL helpers for the AAK-MCP-001 measurement. No network, no I/O.

Every other module in this directory classifies, probes, redacts or samples
the URLs that ``AAK-MCP-001`` fires on, and all of them need the same answers
to the same four questions. They live here once, so the probe cannot disagree
with the classification about which hosts are private, or the redactor with the
probe about which URLs carry a credential:

1. **Where does the URL point?** ``classify_url`` returns the scheme, host and a
   ``host_class``: ``loopback``, ``private`` (RFC 1918, link-local, CGNAT,
   unique-local, a single-label or LAN-suffix name), ``public``, ``placeholder``
   (an RFC 2606 / RFC 6761 example name), ``template`` (the host is a variable)
   or ``invalid``. This is syntax only. A public-looking name can still resolve
   to a private address, which is why the probe resolves every host itself and
   re-checks the addresses with ``is_public_ip`` before it connects.
2. **Does the URL carry a credential?** ``url_credential`` looks at userinfo,
   query parameters (by name, and by the shape of the value) and path segments
   (known token prefixes, JWTs, UUID capability paths, long random runs). The
   probe never sends such a URL, and the population redacts it.
3. **What would RFC 9728 discovery fetch?** ``prm_urls`` builds the
   path-inserted and root ``/.well-known/oauth-protected-resource`` URLs for an
   endpoint, and ``parse_www_authenticate`` reads a ``resource_metadata`` URL out
   of a challenge. The parser is a hand-written scanner, not a regex: it runs on
   response headers from third-party servers.
4. **What may a record show?** ``redact_url`` and ``redact_text`` remove
   anything credential-shaped before a record leaves memory.

Every regex here is a single character class between fixed delimiters or an
anchored alternation of literals, so none can backtrack super-linearly.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

REDACTED = "<redacted>"

HOST_CLASSES = ("public", "loopback", "private", "placeholder", "template", "invalid")

# A variable where a literal belongs: ${VAR}, {{VAR}}, {var} (RFC 6570, which the
# MCP Registry's `remotes[].variables` use), $VAR, %VAR% (three or more name
# characters, so a percent-encoded `%E2%` is not mistaken for one) and <your-key>.
TEMPLATE_RE = re.compile(
    r"\$\{[^{}]*\}"
    r"|\{\{[^{}]*\}\}"
    r"|\{[^{}/?#]*\}"
    r"|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|%[A-Za-z_][A-Za-z0-9_]{2,}%"
    r"|<[^<>/]+>"
)
# Stands in for a variable while a templated authority is parsed. Letters only,
# so it is a legal host label and an illegal port.
_TEMPLATE_SENTINEL = "aakmcpzerotemplatevar"

# Names that resolve only inside a network: LAN and container suffixes.
_PRIVATE_SUFFIXES = (
    ".local", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".intranet",
    ".localdomain", ".private",
)
# RFC 2606 / RFC 6761 names that exist to be examples.
_RESERVED_TLDS = (".test", ".example", ".invalid")
_EXAMPLE_DOMAINS = ("example.com", "example.net", "example.org")
# A label that announces it is a placeholder: your-domain, your_host, yourserver.
# Deliberately narrow (a "your-"/"your_" prefix, or "your" + a generic noun), so a
# real name that merely starts with "your" is still probed.
_PLACEHOLDER_LABEL_RE = re.compile(
    r"(?:^|\.)your(?:[\-_][a-z0-9\-_]*|domain|server|company|app|site|host|instance"
    r"|org|name|project|workspace|tenant|subdomain|url)(?:$|\.)"
)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")

# Query-parameter and header names that carry a credential. Matched after a
# camelCase split ("authToken" -> "auth_token"), bounded by separators so
# "keyword" or "monkey" are not "key".
_CRED_NAME_RE = re.compile(
    r"(?:^|[_.\-])(?:api[_\-]?key|apikey|key|token|access[_\-]?token|auth|authorization"
    r"|secret|client[_\-]?secret|password|passwd|pwd|sig|signature|jwt|bearer"
    r"|credentials?|session|sessionid)(?:$|[_.\-])"
)
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

# Token shapes. Each is anchored, or a single class between fixed delimiters.
# A known prefix counts only when the body after it looks random (a digit, or
# 16+ characters), so a slug such as "sk-learn-mcp" is not a key.
_TOKEN_PREFIX_RE = re.compile(
    r"^(?:sk-ant-|sk-proj-|sk-svcacct-|sk-|sk_|pk_|rk_|ghp_|gho_|ghu_|ghs_|ghr_"
    r"|github_pat_|glpat-|xox[abposr]-|hf_|shpat_|ctx7sk-|ctx7sk|SG\.|AKIA|ASIA|AIza"
    r"|ya29\.)"
)
_PREFIX_BODY_RE = re.compile(r"^[A-Za-z0-9_.\-]{8,}$")
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*$")
_UUID_SEARCH_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]{20,}$")
_ALNUM_RE = re.compile(r"^[A-Za-z0-9]{16,}$")
_LOWER_ALNUM_RE = re.compile(r"^[a-z0-9]{20,}$")
_LONG_RUN_RE = re.compile(r"^[A-Za-z0-9_+/=\-]{40,}$")
_PART_SPLIT_RE = re.compile(r"[_.:~,;]")

# A query value short and plain enough to keep in a redacted URL.
_PLAIN_VALUE_RE = re.compile(r"^[A-Za-z0-9._\-]{1,24}$")

# Free-text scrubbing (titles, descriptions): known token prefixes, JWTs, long
# hex and long base64 runs. Each alternative starts with a literal or a \b and
# is followed by one bounded-below character class, so a failed attempt costs
# at most the minimum length, never a rescan of the rest of the input. The
# lookbehind keeps "task-scheduler" from reading as an "sk-" key.
_TOKEN_IN_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])(?:sk-ant-|sk-proj-|sk-svcacct-|sk-|sk_|pk_|rk_|ghp_|gho_|ghu_"
    r"|ghs_|ghr_|github_pat_|glpat-|xox[abposr]-|hf_|shpat_|ctx7sk|AKIA|ASIA|AIza|ya29\.)"
    r"[A-Za-z0-9_\-]{12,}"
    r"|(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*"
    r"|\b[0-9a-fA-F]{32,}\b"
    r"|\b[A-Za-z0-9+/]{40,}"
)
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>`]+")
# "Bearer <token>" literals in prose. The lookahead skips a challenge's
# auth-param ("Bearer resource_metadata=..."), which names no credential.
_BEARER_IN_TEXT_RE = re.compile(r"(?i)\bbearer\s+(?![a-z_]+=)[A-Za-z0-9_.\-+/=]{8,}")


# ---------------------------------------------------------------------------
# Hosts and addresses
# ---------------------------------------------------------------------------


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An IP literal in any form a resolver would accept, or None.

    `ipaddress` alone misses the inet_aton shorthands ("127.1", "0x7f.0.0.1")
    that getaddrinfo still resolves to loopback, so dotted numeric names go
    through `socket.inet_aton` as well. Pure: inet_aton parses, it never resolves.
    """
    h = host.strip().strip("[]")
    if "%" in h:  # IPv6 zone id: fe80::1%eth0
        h = h.split("%", 1)[0]
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if h and all(c in "0123456789abcdefx." for c in h.lower()) and any(c.isdigit() for c in h):
        labels = h.lower().split(".")
        if all(lbl and (lbl.isdigit() or lbl.startswith("0x")) for lbl in labels):
            try:
                return ipaddress.IPv4Address(socket.inet_aton(h))
            except (OSError, ValueError):
                return None
    return None


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for a globally routable unicast address.

    Excludes loopback, private, link-local, CGNAT (100.64.0.0/10), multicast,
    reserved, unspecified and unique-local addresses, and looks through the IPv6
    forms that embed an IPv4 address (mapped, 6to4, NAT64) so a public-looking
    IPv6 address cannot smuggle a request onto a private IPv4 network. Uses the
    explicit flags rather than `is_global` alone because `is_global`'s coverage
    has moved between Python versions and CI runs 3.9 to 3.12.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_ip(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            return is_public_ip(ip.sixtofour)
        if ip.teredo is not None or ip in _NAT64 or ip in _NAT64_LOCAL:
            return False
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return False
    return bool(ip.is_global)


def classify_host(host: str) -> str:
    """``host_class`` of a bare host name or IP literal (syntax only, no DNS)."""
    h = host.strip().lower().rstrip(".")
    if not h:
        return "invalid"
    if TEMPLATE_RE.search(h):
        return "template"
    ip = _parse_ip(h)
    if ip is not None:
        # 0.0.0.0 / :: in a client config connects to the local machine.
        if ip.is_loopback or ip.is_unspecified:
            return "loopback"
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            mapped = ip.ipv4_mapped
            if mapped.is_loopback or mapped.is_unspecified:
                return "loopback"
        return "public" if is_public_ip(ip) else "private"
    if h == "localhost" or h.endswith(".localhost"):
        return "loopback"
    if h in _EXAMPLE_DOMAINS or h.endswith(tuple("." + d for d in _EXAMPLE_DOMAINS)):
        return "placeholder"
    if h.endswith(_RESERVED_TLDS) or _PLACEHOLDER_LABEL_RE.search(h):
        return "placeholder"  # before the single-label test: YOUR_API_URL
    if "." not in h:
        return "private"  # single label: a LAN or container-network name
    if h.endswith(_PRIVATE_SUFFIXES):
        return "private"
    return "public"


def classify_url(url: str) -> dict[str, Any]:
    """Scheme, host, port and ``host_class`` of a configured server URL."""
    raw = (url or "").strip()
    out: dict[str, Any] = {
        "scheme": "",
        "host": "",
        "port": None,
        "path": "",
        "host_class": "invalid",
        "has_template": bool(TEMPLATE_RE.search(raw)),
    }
    try:
        parts = urlsplit(raw)
    except ValueError:
        return out
    scheme = parts.scheme.lower()
    out["scheme"] = scheme
    if not parts.netloc and out["has_template"]:
        out["host_class"] = "template"  # the whole URL is a variable: ${MCP_URL}
        return out
    if TEMPLATE_RE.search(parts.netloc):
        # A variable in the authority. If it is only the port
        # (http://localhost:${PORT:-8080}/mcp) the host is still known, and a
        # loopback server with a templated port is still a loopback server. Swap
        # each variable for a sentinel and let urlsplit find the host, so a colon
        # inside the variable cannot be mistaken for the port separator.
        probe = urlsplit("//" + TEMPLATE_RE.sub(_TEMPLATE_SENTINEL, parts.netloc))
        host = (probe.hostname or "").lower()
        if not host or _TEMPLATE_SENTINEL in host:
            out["host_class"] = "template"
            return out
        out.update(host=host, path=parts.path or "/", host_class=classify_host(host))
        return out
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return out
    if not host or scheme not in ("http", "https"):
        return out
    out.update(host=host, port=port, path=parts.path or "/", host_class=classify_host(host))
    return out


# ---------------------------------------------------------------------------
# Credentials in URLs
# ---------------------------------------------------------------------------


def credential_name(name: str) -> bool:
    """True when a query-parameter or header NAME says it carries a credential."""
    norm = _CAMEL_RE.sub("_", str(name)).lower()
    return bool(_CRED_NAME_RE.search(norm))


def _random_part(part: str) -> bool:
    """A run that reads as random rather than as words: long hex, mixed-case
    base62 with digits, digit-heavy lower-case base36, or a 40+ character token
    with digits in it. Hyphenated slugs of words fail every branch."""
    if len(part) < 16:
        return False
    digits = sum(c.isdigit() for c in part)
    letters = sum(c.isalpha() for c in part)
    if _HEX_RE.match(part) and digits and letters:
        return True
    if _ALNUM_RE.match(part) and digits >= 2 and letters >= 2:
        if any(c.isupper() for c in part) and any(c.islower() for c in part):
            return True
    if _LOWER_ALNUM_RE.match(part) and digits * 4 >= len(part):
        return True
    if _LONG_RUN_RE.match(part) and digits >= 4:
        return any(c.isupper() for c in part) or digits * 5 >= len(part)
    return False


def _prefixed_token(v: str) -> bool:
    m = _TOKEN_PREFIX_RE.match(v)
    if m is None:
        return False
    body = v[m.end():]
    if not _PREFIX_BODY_RE.match(body):
        return False
    return len(body) >= 16 or any(c.isdigit() for c in body)


def credential_shaped(value: str) -> bool:
    """True when a VALUE looks like a secret: a known token prefix, a JWT, a
    UUID capability, or a long random run. A slug of short words is not."""
    v = unquote(str(value)).strip()
    if len(v) < 12:
        return False
    if _prefixed_token(v) or _JWT_RE.match(v) or _UUID_SEARCH_RE.search(v):
        return True
    if _random_part(v):
        return True
    return any(_random_part(p) for p in _PART_SPLIT_RE.split(v))


def _template_names_credential(segment: str) -> bool:
    """A placeholder whose own name says credential: {api_key}, ${TOKEN}, <your-key>."""
    return any(credential_name(m.group(0).strip("${}<>%")) for m in TEMPLATE_RE.finditer(segment))


def url_credential(url: str) -> dict[str, Any]:
    """Whether a URL carries a credential, where, and whether it is a literal.

    ``status`` is ``literal`` when an actual credential value is present,
    ``template`` when the URL has a credential-named placeholder (the server
    expects a key in the URL, the config does not hold it), else ``none``.
    ``where`` lists the parts that triggered it: ``userinfo``, ``query``, ``path``.
    """
    where: list[str] = []
    literal = False
    template = False
    raw = (url or "").strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        return {"status": "none", "where": []}
    netloc = parts.netloc
    if "@" in netloc:
        where.append("userinfo")
        userinfo = netloc.rsplit("@", 1)[0]
        if TEMPLATE_RE.search(userinfo) and not TEMPLATE_RE.sub("", userinfo).strip(":"):
            template = True  # ${USER}:${PASS}@host
        else:
            literal = True
    query_hit = False
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        is_template = bool(TEMPLATE_RE.search(value))
        if credential_name(name):
            query_hit = True
            if is_template or not value.strip():
                template = True
            else:
                literal = True
        elif is_template and _template_names_credential(value):
            query_hit, template = True, True
        elif not is_template and credential_shaped(value):
            query_hit, literal = True, True
    if query_hit:
        where.append("query")
    path_hit = False
    for segment in parts.path.split("/"):
        if not segment:
            continue
        if TEMPLATE_RE.search(segment):
            if _template_names_credential(segment):
                path_hit, template = True, True
        elif credential_shaped(segment):
            path_hit, literal = True, True
    if path_hit:
        where.append("path")
    status = "literal" if literal else "template" if template else "none"
    return {"status": status, "where": where}


def query_is_plain(url: str) -> bool:
    """True when nothing in the query or path could be a credential the shape
    rules missed: every query value short and plain (or empty), no
    credential-named parameter, and no path segment of 64 or more characters.
    The probe sends only URLs that pass this as well as ``url_credential``."""
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return False
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if credential_name(name) or credential_shaped(name) or credential_shaped(value):
            return False
        if value and not _PLAIN_VALUE_RE.match(value):
            return False
    return all(len(seg) < 64 for seg in parts.path.split("/"))


# ---------------------------------------------------------------------------
# Endpoints and RFC 9728 discovery
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _hostport(scheme: str, host: str, port: int | None) -> str:
    h = f"[{host}]" if ":" in host else host
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return h
    return f"{h}:{port}"


def endpoint_key(url: str) -> str:
    """Normalised endpoint: lower-case scheme and host, no userinfo, no default
    port, no fragment; path (``/`` when empty) and query kept exactly."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    out = f"{scheme}://{_hostport(scheme, host, parts.port)}{parts.path or '/'}"
    if parts.query:
        out += "?" + parts.query
    return out


def prm_urls(endpoint: str) -> list[str]:
    """RFC 9728 section 3.1 well-known URLs for an endpoint, most specific first.

    The well-known suffix goes between the host and the path (and query):
    ``https://h/mcp`` gives ``https://h/.well-known/oauth-protected-resource/mcp``.
    An endpoint with no path or query has only the root form, which the MCP
    authorization specification also tells clients to try as the fallback, so
    both are returned when they differ.
    """
    parts = urlsplit(endpoint.strip())
    scheme = parts.scheme.lower()
    base = f"{scheme}://{_hostport(scheme, (parts.hostname or '').lower(), parts.port)}"
    root = base + "/.well-known/oauth-protected-resource"
    path = parts.path if parts.path not in ("", "/") else ""
    if not path and not parts.query:
        return [root]
    inserted = root + path + (("?" + parts.query) if parts.query else "")
    return [inserted, root]


def resource_identifier(endpoint: str) -> str:
    """The resource identifier RFC 9728 section 3.3 compares ``resource`` with:
    the endpoint URL without fragment (and with its query, if any)."""
    parts = urlsplit(endpoint.strip())
    scheme = parts.scheme.lower()
    out = f"{scheme}://{_hostport(scheme, (parts.hostname or '').lower(), parts.port)}{parts.path}"
    if parts.query:
        out += "?" + parts.query
    return out


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _read_token(s: str, i: int) -> tuple[str, int]:
    j = i
    while j < len(s) and s[j] not in " \t,=\"":
        j += 1
    return s[i:j], j


def _read_quoted(s: str, i: int) -> tuple[str, int]:
    """Read a quoted-string starting at the opening quote; returns (value, next)."""
    out: list[str] = []
    j = i + 1
    while j < len(s):
        c = s[j]
        if c == "\\" and j + 1 < len(s):
            out.append(s[j + 1])
            j += 2
            continue
        if c == '"':
            return "".join(out), j + 1
        out.append(c)
        j += 1
    return "".join(out), j


def parse_www_authenticate(value: str) -> list[dict[str, Any]]:
    """Parse a WWW-Authenticate value into ``[{"scheme", "params"}]`` (RFC 9110 11.6.1).

    A linear scanner with no regex, because the input is a third-party response
    header. Tolerant: an unparseable remainder ends the parse rather than
    raising. Parameter names are lower-cased; values are kept as sent.
    """
    s = (value or "")[:4096]
    challenges: list[dict[str, Any]] = []
    i = 0
    current: dict[str, Any] | None = None
    while i < len(s):
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == ",":
            i += 1
            continue
        tok, j = _read_token(s, i)
        if not tok:
            break
        k = _skip_ws(s, j)
        if k < len(s) and s[k] == "=" and current is not None:
            # auth-param: name = token / quoted-string (a token68 ends in '=' too,
            # but in a challenge with params it is a name).
            k = _skip_ws(s, k + 1)
            if k < len(s) and s[k] == '"':
                val, k = _read_quoted(s, k)
            else:
                val, k = _read_token(s, k)
            current["params"][tok.lower()] = val
            i = k
            continue
        # A new scheme starts a new challenge.
        current = {"scheme": tok, "params": {}}
        challenges.append(current)
        i = j
    return challenges


def resource_metadata_url(challenges: list[dict[str, Any]]) -> str | None:
    """The first ``resource_metadata`` URL named by any challenge (RFC 9728 5.1)."""
    for ch in challenges:
        val = ch.get("params", {}).get("resource_metadata")
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def redact_url(url: str) -> str:
    """A URL safe to show a labeler: userinfo dropped, credential-shaped path
    segments and query values replaced, fragment dropped. Placeholders such as
    ``{api_key}`` are kept, because they are evidence (the server wants a key in
    the URL) and contain no secret."""
    raw = (url or "").strip()
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return _scrub_tokens(_strip_userinfo(raw.split("?", 1)[0].split("#", 1)[0]))
    if not parts.scheme or not host or TEMPLATE_RE.search(parts.netloc):
        # A template host or a bare variable: keep the template shape, drop the
        # query and fragment wholesale, scrub anything token-shaped that is left.
        base = _strip_userinfo(raw.split("?", 1)[0].split("#", 1)[0])
        tail = "?" + REDACTED if "?" in raw else ""
        return _scrub_tokens(base) + tail
    netloc = _hostport(parts.scheme.lower(), host, port)
    if "@" in parts.netloc:
        netloc = f"{REDACTED}@{netloc}"
    segments = []
    for seg in parts.path.split("/"):
        if seg and not TEMPLATE_RE.search(seg) and credential_shaped(seg):
            segments.append(REDACTED)
        else:
            segments.append(seg)
    tail = "/".join(segments)
    if parts.query:
        kept = []
        for name, value in parse_qsl(parts.query, keep_blank_values=True):
            safe_name = name if not credential_shaped(name) else REDACTED
            if TEMPLATE_RE.fullmatch(value.strip() or "-") and not credential_shaped(value):
                kept.append(f"{safe_name}={value}")
            elif credential_name(name) or credential_shaped(value):
                kept.append(f"{safe_name}={REDACTED}")
            elif _PLAIN_VALUE_RE.match(value) or not value:
                kept.append(f"{safe_name}={value}")
            else:
                kept.append(f"{safe_name}={REDACTED}")
        tail += "?" + "&".join(kept)
    if parts.fragment:
        tail += "#" + REDACTED
    # Backstop: anything token-shaped the per-part rules let through.
    return f"{parts.scheme.lower()}://{netloc}{_scrub_tokens(tail)}"


def _strip_userinfo(raw: str) -> str:
    """Drop ``user:pass@`` from a URL-ish string without parsing it as a URL."""
    scheme, sep, rest = raw.partition("://")
    if not sep:
        return raw
    authority, slash, tail = rest.partition("/")
    if "@" in authority:
        authority = REDACTED + "@" + authority.rsplit("@", 1)[1]
    return f"{scheme}://{authority}{slash}{tail}"


def _scrub_tokens(s: str) -> str:
    s = _BEARER_IN_TEXT_RE.sub("Bearer " + REDACTED, s)
    return _TOKEN_IN_TEXT_RE.sub(REDACTED, s)


def redact_text(text: str, limit: int = 2000) -> str:
    """Free text with URLs redacted and token-shaped runs replaced, truncated."""
    s = str(text or "")[: limit * 2]
    s = _URL_IN_TEXT_RE.sub(lambda m: redact_url(m.group(0)), s)
    return _scrub_tokens(s)[:limit]


# ---------------------------------------------------------------------------
# Leak check: an independent pattern set run over anything about to be written
# ---------------------------------------------------------------------------

# Written separately from the redactor on purpose: a checker that reused the
# redactor's own regexes could only ever confirm the redactor. These are the
# shapes AAK's secret scanner looks for (scanners/secret_exposure.py), the ones
# it misses (#951: sk-proj-, github_pat_), and URL-level leaks.
_LEAK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9]{20,}")),
    ("aws-access-key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}")),
    ("gitlab-token", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("slack-token", re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("huggingface-token", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----")),
    ("bearer-literal", re.compile(r"(?i)\bbearer\s+(?![a-z_]+=)[A-Za-z0-9_.\-+/=]{12,}")),
    ("long-hex", re.compile(r"\b[0-9a-fA-F]{40,}\b")),
)
_LEAK_CRED_PARAM_RE = re.compile(
    r"(?i)[?&](?:api[_\-]?key|apikey|key|token|access[_\-]?token|secret|password|auth"
    r"|sig|signature|jwt|client[_\-]?secret)=([^&\s\"]*)"
)
_LEAK_USERINFO_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://[^/@\s]*:[^/@\s]*@", re.IGNORECASE)


def leak_report(text: str) -> list[str]:
    """Names of the secret patterns found in ``text`` (never the matches).

    Returns one entry per match, so ``len()`` is the match count. Applied to the
    population before it is written and to the committed artifacts in the tests.
    """
    found: list[str] = []
    for name, pattern in _LEAK_PATTERNS:
        found.extend(name for _ in pattern.finditer(text))
    for m in _URL_IN_TEXT_RE.finditer(text):
        url = m.group(0)
        if _LEAK_USERINFO_RE.match(url):
            found.append("url-userinfo")
        if _UUID_SEARCH_RE.search(url):
            found.append("url-uuid-capability")
        for pm in _LEAK_CRED_PARAM_RE.finditer(url):
            value = unquote(pm.group(1))
            if value and value != REDACTED and not TEMPLATE_RE.fullmatch(value):
                found.append("url-credential-param")
    return found
