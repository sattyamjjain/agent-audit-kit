"""`_helpers.url_readings` and the host helpers built on it.

Every WHATWG expectation here was read off Node 22's `new URL()`, the parser
Claude Code, VS Code and the MCP TypeScript SDK connect with, except that a port
which is not a number leaves the host standing (Node fails the URL). Every
RFC 3986 one matches urlsplit, and httpx and curl 8.9 read these hosts the same
way; its numeric hosts match macOS's resolver (`getaddrinfo`).
"""
from __future__ import annotations

import time

import pytest

from agent_audit_kit.scanners._helpers import (
    UrlReading,
    is_loopback_url,
    url_host,
    url_hosts,
    url_readings,
)

_BS = "\\"
_FULLWIDTH_LOCALHOST = "".join(chr(0xFF00 + ord(c) - 0x20) for c in "localhost")
_IDEOGRAPHIC_STOP = chr(0x3002)
_SOFT_HYPHEN = chr(0xAD)


@pytest.mark.parametrize(("value", "readings"), [
    # One reading when the two families agree.
    ("https://api.anthropic.com/v1", [("https", "api.anthropic.com", None)]),
    ("HTTPS://API.Anthropic.COM.:443/v1", [("https", "api.anthropic.com.", None)]),
    ("http://user:pass@localhost:0443/", [("http", "localhost", 443)]),
    ("ws://a@b@localhost:80/", [("ws", "localhost", None)]),
    # A backslash ends the authority for WHATWG and is ordinary for RFC 3986.
    ("http://evil.example" + _BS + "@localhost/", [("http", "evil.example", None), ("http", "localhost", None)]),
    ("http://localhost" + _BS + "@evil.example/", [("http", "localhost", None), ("http", "evil.example", None)]),
    # A backslash left inside the host is no host to RFC 3986, so only Node's counts.
    ("https://evil.example" + _BS + ".github.com/x", [("https", "evil.example", None)]),
    # What WHATWG strips, removes and skips.
    (" \x00http://evil.example/ ", [("http", "evil.example", None)]),
    ("h\tttp://evil.ex\nample/", [("http", "evil.example", None)]),
    ("http:/evil.example/", [("http", "evil.example", None)]),
    ("HTTP:" + _BS + _BS + "evil.example" + _BS + "x", [("http", "evil.example", None)]),
    ("ws:evil.example", [("ws", "evil.example", None)]),
    # Hosts read as Node reads them.
    ("http://127.1/", [("http", "127.0.0.1", None)]),
    ("http://0x7f.1/", [("http", "127.0.0.1", None)]),
    ("http://2130706433/", [("http", "127.0.0.1", None)]),
    # A leading zero is octal to Node; macOS's resolver, behind curl and httpx
    # there, reads a four-part all-digit address as decimal unless a part is over
    # 255 (then octal, as Node does).
    ("http://0177.0.0.1/", [("http", "127.0.0.1", None), ("http", "177.0.0.1", None)]),
    ("http://127.0.0.010/", [("http", "127.0.0.8", None), ("http", "127.0.0.10", None)]),
    ("http://0300.0250.1.1/", [("http", "192.168.1.1", None)]),
    ("http://0177.1/", [("http", "127.0.0.1", None)]),
    ("http://127.0.0.1./", [("http", "127.0.0.1", None)]),
    ("http://%31%32%37.0.0.1/", [("http", "127.0.0.1", None)]),
    ("http://%6c%6f%63%61%6c%68%6f%73%74/", [("http", "localhost", None)]),
    ("http://" + _FULLWIDTH_LOCALHOST + "/", [("http", "localhost", None)]),
    ("http://127" + _IDEOGRAPHIC_STOP + "0" + _IDEOGRAPHIC_STOP + "0" + _IDEOGRAPHIC_STOP + "1/",
     [("http", "127.0.0.1", None)]),
    ("http://local" + _SOFT_HYPHEN + "host/", [("http", "localhost", None)]),
    ("http://gla" + chr(0x1E9E) + ".example/", [("http", "glass.example", None)]),
    ("http://[0:0:0:0:0:0:0:1]/", [("http", "::1", None)]),
    ("http://[::ffff:127.0.0.1]/", [("http", "::ffff:7f00:1", None)]),
    # A port that is not a number leaves the host: the client fills in a template
    # such as `${PORT:-64342}` before it parses. Node fails the literal URL.
    ("http://localhost:${JETBRAINS_MCP_PORT:-64342}/sse", [("http", "localhost", None)]),
    ("http://localhost:$PORT/", [("http", "localhost", None)]),
    ("http://localhost:65536/", [("http", "localhost", None)]),
    # Node fails each of these, and so does the other family.
    ("http://[::1]evil.example/", []),
    ("http://evil.example[::1]/", []),
    ("http://[::1%25eth0]/", []),
    ("http://1.2.3.4.5/", []),
    ("http://999.1.1.1/", []),
    ("http://example.123/", []),
    ("http://ex ample/", []),
    ("http://%zz/", []),
    ("http:///", []),
    ("http://user@/", []),
    # Not an http(s) or ws(s) URL.
    ("ftp://localhost/", []),
    ("localhost:8080", []),
    ("${input:host}", []),
])
def test_url_readings(value: str, readings: list[tuple[str, str, int | None]]) -> None:
    assert url_readings(value) == tuple(UrlReading(*reading) for reading in readings)


@pytest.mark.parametrize(("value", "hosts"), [
    ("api.anthropic.com/v1", ("api.anthropic.com",)),
    ("localhost:8080", ("localhost",)),
    ("evil.example" + _BS + "@api.anthropic.com", ("evil.example", "api.anthropic.com")),
    ("//localhost/", ()),
    (_BS + _BS + "localhost", ()),
    ("${PROXY_URL}", ("${proxy_url}",)),
])
def test_url_hosts_reads_a_value_with_no_scheme_as_an_authority(value: str, hosts: tuple[str, ...]) -> None:
    assert url_hosts(value) == hosts


def test_a_real_idn_stays_unicode_and_never_matches_ascii() -> None:
    """Node punycodes it; here it is kept as mapped, as urlparse kept it, so an
    exact allowlist entry written in Unicode still matches."""
    host = "m" + chr(0xFC) + "nchen.de"
    assert url_hosts("https://" + host.upper() + "/") == (host,)
    assert url_host("https://" + host + "/") is None


@pytest.mark.parametrize("value", [
    "http://" + "0" * 200_000 + "/",
    "http://" + "1" * 200_000 + "/",
    "http://" + "[" * 200_000,
    "http://" + "@" * 200_000 + "localhost/",
    "http://" + "a." * 100_000 + "/",
    "http://" + "%41" * 70_000 + "/",
    " " * 200_000 + "http://localhost/",
])
def test_a_crafted_url_reads_in_linear_time(value: str) -> None:
    """Every step is a single pass; a long IPv4 number is refused on length
    before `int()`, which is quadratic on long digit strings before Python 3.11.
    The bound is loose for slow CI runners."""
    started = time.perf_counter()
    url_readings(value)
    is_loopback_url(value)
    assert time.perf_counter() - started < 5.0


@pytest.mark.parametrize(
    "written, serialized",
    [
        ("::ffff:127.0.0.1", "::ffff:7f00:1"),  # never an embedded IPv4 address
        ("0:0:0:0:0:0:0:1", "::1"),
        ("::", "::"),
        ("2001:0DB8:0000:0000:0000:FF00:0042:8329", "2001:db8::ff00:42:8329"),
        ("1:0:0:2:0:0:0:3", "1:0:0:2::3"),  # the longest run of zeros
        ("1:0:0:2:0:0:3:4", "1::2:0:0:3:4"),  # the first of two equal runs
        ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),  # a single zero piece is kept
    ],
)
def test_an_ipv6_host_is_written_the_way_the_url_standard_writes_it(written: str, serialized: str) -> None:
    """The same on every Python: 3.13 and later 3.12 releases changed what
    `IPv6Address.compressed` gives an IPv4-mapped address, and CI failed on it."""
    import ipaddress

    from agent_audit_kit.scanners._helpers import _ipv6_serialized

    assert _ipv6_serialized(ipaddress.IPv6Address(written)) == serialized
