#!/usr/bin/env python3
"""AAK-MCP-001 Step 1 probe: what the public https endpoints actually do. Opt-in network.

``AAK-MCP-001`` decides "no authentication" from the config alone, and the State
of MCP report says no public server serves RFC 9728 discovery because no config
*mentions* it (``AAK-OAUTH-008`` reads config text). Neither claim was checked
against a server. This module checks both, for every distinct public https
endpoint the rule fires on, with exactly two kinds of request:

1. One unauthenticated MCP ``initialize`` JSON-RPC POST, the standard first
   message any MCP client sends (``Accept: application/json, text/event-stream``,
   ``protocolVersion`` 2025-11-25, the newest revision whose lifecycle makes
   ``initialize`` the first message; servers on later revisions negotiate).
2. GETs of the RFC 9728 protected-resource metadata: the path-inserted and root
   ``/.well-known/oauth-protected-resource`` URLs RFC 9728 section 3.1 defines
   for the endpoint, plus the ``resource_metadata`` URL named in any
   ``WWW-Authenticate`` challenge (section 5.1).

Nothing else is ever sent. The probe never follows a redirect, never fetches
authorization-server metadata, never sends the ``notifications/initialized``
follow-up, and never sends a credential.

Hard limits, enforced here rather than trusted to the caller:

* **No credentials.** A URL with userinfo, a credential-named or
  credential-shaped query parameter, a non-plain query value or a
  credential-shaped path segment is skipped and counted as a "credential in
  URL" skip. ``send_gate`` re-checks every URL immediately before it is sent.
* **No private networks.** Every host is resolved first and skipped if ANY of
  its addresses is loopback, private, link-local, CGNAT, multicast, reserved,
  unspecified or unique-local. The connection is then pinned to the vetted
  address (TLS still verifies the certificate against the host name), so a
  second DNS answer cannot move it onto the LAN.
* **Gentle.** At most 4 concurrent connections overall, at most one in flight
  and at least 1 s between request starts per host, a 10 s timeout, at most one
  retry and only on a network error, at most 64 KiB read from any response.
* **Identified.** ``User-Agent: agent-audit-kit-research (+https://github.com/sattyamjjain/agent-audit-kit)``.
* **Logged.** Every plan entry, DNS lookup, skip and request attempt is one JSON
  line with UTC timestamps in the raw log (``--raw-out``, outside the repo).

Without ``--probe`` it prints the plan and sends nothing. ``--summarize RAW``
turns a raw log into the committed aggregate ``probe-summary.json``: counts and
timings only, no host, URL, header value or response body.

    python benchmarks/aak_mcp_001/probe.py                       # plan, offline
    python benchmarks/aak_mcp_001/probe.py --probe --raw-out /outside/repo/probe-raw.jsonl
    python benchmarks/aak_mcp_001/probe.py --summarize /outside/repo/probe-raw.jsonl --write
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterator
from urllib.parse import urljoin, urlsplit

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import agent_audit_kit  # noqa: E402

SUMMARY_JSON = HERE / "probe-summary.json"

USER_AGENT = "agent-audit-kit-research (+https://github.com/sattyamjjain/agent-audit-kit)"
PROTOCOL_VERSION = "2025-11-25"
TIMEOUT_S = 10.0
MAX_CONNECTIONS = 4
PER_HOST_INTERVAL_S = 1.0
MAX_RETRIES = 1
BODY_CAP = 64 * 1024
# Network errors worth one retry. A TLS failure, an HTTP-protocol error or any
# HTTP status is an answer, not a transient fault, and is never retried.
RETRYABLE = frozenset({"timeout", "refused", "reset", "network-error"})
KINDS = ("initialize", "prm-path", "prm-root", "prm-resource-metadata")


def _load_sibling(name: str) -> ModuleType:
    key = f"aak_mcp_001_{name}"
    if key in sys.modules:
        return sys.modules[key]
    import importlib.util

    spec = importlib.util.spec_from_file_location(key, HERE / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(name)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


endpoints = _load_sibling("endpoints")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# What may be sent
# ---------------------------------------------------------------------------


def send_gate(url: str) -> str | None:
    """None when ``url`` may be sent, else why not. Checked before EVERY request,
    including the ``resource_metadata`` URL a server names, which no corpus vetted."""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname or ""
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return "invalid URL"
    if parts.scheme.lower() != "https":
        return "not https"
    if not host:
        return "invalid URL"
    if "@" in parts.netloc:
        return "credential in URL"
    cls = endpoints.classify_host(host)
    if cls in ("loopback", "private"):
        return "non-public host"
    if cls != "public":
        return f"{cls} host"
    if endpoints.url_credential(url)["status"] != "none":
        return "credential in URL"
    if endpoints.TEMPLATE_RE.search(url):
        return "template in URL"
    if not endpoints.query_is_plain(url):
        return "credential in URL (suspected)"
    return None


def initialize_body() -> bytes:
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "agent-audit-kit-research", "version": agent_audit_kit.__version__},
        },
    }
    return json.dumps(msg, separators=(",", ":")).encode("utf-8")


def request_headers(kind: str) -> dict[str, str]:
    """The complete header set for each request kind. No auth header, no
    cookie, no session id: http.client adds only Host, Accept-Encoding: identity
    and Content-Length."""
    if kind == "initialize":
        return {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Connection": "close",
        }
    return {"User-Agent": USER_AGENT, "Accept": "application/json", "Connection": "close"}


# ---------------------------------------------------------------------------
# DNS, pacing, transport
# ---------------------------------------------------------------------------


class Resolver:
    """Resolve each host once; vet every address; pin one public address.

    ``status`` is ``ok`` (``ip`` is the address to connect to, IPv4 preferred),
    ``dns-error`` or ``non-public`` (at least one address is not globally
    routable, so the host is skipped outright rather than raced).
    """

    def __init__(self, getaddrinfo: Callable[..., Any] = socket.getaddrinfo,
                 log: Callable[[dict[str, Any]], None] | None = None) -> None:
        self._getaddrinfo = getaddrinfo
        self._log = log or (lambda rec: None)
        self._cache: dict[tuple[str, int], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def resolve(self, host: str, port: int) -> dict[str, Any]:
        key = (host, port)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        ts = utcnow()
        try:
            infos = self._getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addrs = sorted({str(info[4][0]).split("%", 1)[0] for info in infos})
        except (OSError, UnicodeError):
            addrs = []
        ips = []
        for a in addrs:
            try:
                ips.append(ipaddress.ip_address(a))
            except ValueError:
                continue
        if not ips:
            res: dict[str, Any] = {"status": "dns-error", "ip": None, "addresses": []}
        elif any(not endpoints.is_public_ip(ip) for ip in ips):
            res = {"status": "non-public", "ip": None, "addresses": [str(i) for i in ips]}
        else:
            v4 = [ip for ip in ips if ip.version == 4]
            res = {"status": "ok", "ip": str((v4 or ips)[0]), "addresses": [str(i) for i in ips]}
        self._log({"event": "dns", "ts": ts, "ts_end": utcnow(), "host": host, "port": port, **res})
        with self._lock:
            self._cache[key] = res
        return res


class HostGate:
    """At most one request in flight per host, and at least ``interval``
    seconds between request starts to the same host, across all workers."""

    def __init__(self, interval: float = PER_HOST_INTERVAL_S,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.interval = interval
        self._clock = clock
        self._sleep = sleep
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._last: dict[str, float] = {}

    @contextmanager
    def slot(self, host: str) -> Iterator[None]:
        with self._guard:
            lock = self._locks.setdefault(host, threading.Lock())
        with lock:
            last = self._last.get(host)
            if last is not None:
                wait = last + self.interval - self._clock()
                if wait > 0:
                    self._sleep(wait)
            self._last[host] = self._clock()
            yield


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a pre-vetted address, with SNI and certificate checks against
    the host name, so DNS cannot change the destination after the check."""

    def __init__(self, host: str, port: int, ip: str, timeout: float,
                 context: ssl.SSLContext) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = ip
        self._ssl_context = context
        self.raw_sock: socket.socket | None = None

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise
        self.raw_sock = self.sock


def _error_kind(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls-certificate"
    if isinstance(exc, ssl.SSLError):
        return "tls-error"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected)):
        return "reset"
    if isinstance(exc, http.client.HTTPException):
        return "http-protocol-error"
    return "network-error"


def _sse_messages(text: str) -> list[Any]:
    """JSON payloads of the complete events in an SSE body."""
    out: list[Any] = []
    events = text.replace("\r\n", "\n").split("\n\n")
    for event in events[:-1] if len(events) > 1 else events:
        data = "\n".join(
            line[5:].lstrip() for line in event.split("\n") if line.startswith("data:")
        )
        if not data:
            continue
        try:
            out.append(json.loads(data))
        except ValueError:
            continue
    return out


def _sse_has_reply(buf: bytes) -> bool:
    msgs = _sse_messages(buf.decode("utf-8", "replace"))
    return any(isinstance(m, dict) and (isinstance(m.get("result"), dict) or isinstance(m.get("error"), dict))
               for m in msgs)


def _read_body(conn: _PinnedHTTPSConnection, resp: http.client.HTTPResponse,
               deadline: float) -> tuple[bytes, bool]:
    """Up to BODY_CAP bytes, within the request deadline. An SSE stream is read
    only until it carries the JSON-RPC reply, then dropped."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    sse = "event-stream" in (resp.getheader("Content-Type") or "").lower()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            truncated = True
            break
        if conn.raw_sock is not None:
            try:
                conn.raw_sock.settimeout(remaining)
            except OSError:
                pass
        try:
            chunk = resp.read1(min(8192, BODY_CAP - total))
        except http.client.IncompleteRead as exc:
            chunks.append(exc.partial)
            break
        except (OSError, http.client.HTTPException, ValueError):
            truncated = True
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= BODY_CAP:
            truncated = True
            break
        if sse and _sse_has_reply(b"".join(chunks)):
            break
    return b"".join(chunks), truncated


def https_request(method: str, url: str, ip: str, headers: dict[str, str],
                  body: bytes | None, timeout: float = TIMEOUT_S,
                  context: ssl.SSLContext | None = None) -> dict[str, Any]:
    """One HTTPS request to a pinned address. Never raises; never redirects."""
    parts = urlsplit(url)
    target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    conn = _PinnedHTTPSConnection(
        parts.hostname or "", parts.port or 443, ip, timeout,
        context or ssl.create_default_context(),
    )
    start = time.monotonic()
    try:
        conn.request(method, target, body=body, headers=headers)
        # Connect and TLS ran under the socket timeout; the wait for the status
        # line and the body read share what is left of the same 10 s budget.
        if conn.raw_sock is not None:
            conn.raw_sock.settimeout(max(0.05, start + timeout - time.monotonic()))
        resp = conn.getresponse()
        headers_ms = int(1000 * (time.monotonic() - start))
        payload, truncated = _read_body(conn, resp, start + timeout)
        resp.close()
        return {
            "ok": True,
            "status": resp.status,
            "reason": str(resp.reason or "")[:80],
            "headers": [(str(k), str(v)) for k, v in resp.getheaders()],
            "body": payload,
            "body_truncated": truncated,
            "headers_ms": headers_ms,
            "elapsed_ms": int(1000 * (time.monotonic() - start)),
        }
    except Exception as exc:  # noqa: BLE001 - every failure is a recorded outcome
        return {
            "ok": False,
            "error": _error_kind(exc),
            "error_type": type(exc).__name__,
            "elapsed_ms": int(1000 * (time.monotonic() - start)),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Reading the answers
# ---------------------------------------------------------------------------


def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [v for k, v in headers if k.lower() == name]


def _snippet(body: bytes) -> str:
    text = " ".join(body[:2048].decode("utf-8", "replace").split())
    return endpoints.redact_text(text, 200)


def parse_jsonrpc(body: bytes, content_type: str) -> dict[str, Any] | None:
    """The initialize reply, reduced to what a labeler needs. None if the body
    holds no JSON-RPC message."""
    text = body.decode("utf-8", "replace")
    if "event-stream" in content_type:
        messages = _sse_messages(text + "\n\n")
    else:
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        messages = parsed if isinstance(parsed, list) else [parsed]
    # A JSON-RPC reply has an object `result` or an object `error`; a REST-style
    # {"error": "invalid_token"} body is not one.
    msg = next((m for m in messages if isinstance(m, dict) and (
        isinstance(m.get("result"), dict) or isinstance(m.get("error"), dict))), None)
    if msg is None:
        return None
    result = msg.get("result") if isinstance(msg.get("result"), dict) else None
    error = msg.get("error") if isinstance(msg.get("error"), dict) else None
    info_raw = (result or {}).get("serverInfo")
    info: dict[str, Any] = info_raw if isinstance(info_raw, dict) else {}
    caps = (result or {}).get("capabilities")
    return {
        "result": result is not None,
        "protocol_version": (
            str(result.get("protocolVersion"))[:40] if result and result.get("protocolVersion") else None
        ),
        "server_name": endpoints.redact_text(str(info.get("name") or ""), 100) or None,
        "server_version": endpoints.redact_text(str(info.get("version") or ""), 40) or None,
        "capabilities": sorted(str(k) for k in caps)[:20] if isinstance(caps, dict) else [],
        "error_code": error.get("code") if error and isinstance(error.get("code"), int) else None,
        "error_message": endpoints.redact_text(str(error.get("message") or ""), 200) if error else None,
    }


def parse_prm(body: bytes, endpoint: str) -> dict[str, Any]:
    """RFC 9728 metadata, reduced: present fields and whether ``resource``
    names this endpoint (section 3.3) or only its origin."""
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return {"json": False}
    if not isinstance(doc, dict):
        return {"json": True, "object": False}
    res = doc.get("resource")
    aus = doc.get("authorization_servers")
    aus_list = [a for a in aus if isinstance(a, str)] if isinstance(aus, list) else []
    ident = endpoints.resource_identifier(endpoint).rstrip("/")
    origin = ident.split("/", 3)
    origin_s = "/".join(origin[:3]) if len(origin) >= 3 else ident
    scopes = doc.get("scopes_supported")
    methods = doc.get("bearer_methods_supported")
    return {
        "json": True,
        "object": True,
        "resource_present": isinstance(res, str),
        "resource_matches_endpoint": isinstance(res, str) and res.rstrip("/") == ident,
        "resource_matches_origin": isinstance(res, str) and res.rstrip("/") == origin_s,
        "authorization_servers": [endpoints.redact_url(a) for a in aus_list[:10]],
        "authorization_servers_count": len(aus_list),
        "scopes_supported_count": len(scopes) if isinstance(scopes, list) else 0,
        "bearer_methods_supported": (
            [str(m)[:20] for m in methods[:5]] if isinstance(methods, list) else []
        ),
    }


def describe_response(kind: str, endpoint: str, res: dict[str, Any]) -> dict[str, Any]:
    """The loggable part of a response. Header VALUES kept are the auth ones
    (WWW-Authenticate) and content type; a session id or cookie is recorded as
    present, never its value; the body is parsed and dropped."""
    if not res.get("ok"):
        return {"ok": False, "error": res["error"], "error_type": res.get("error_type"),
                "elapsed_ms": res.get("elapsed_ms")}
    headers = res["headers"]
    ctype = (_header_values(headers, "content-type") or [""])[0][:100]
    www = [v[:1024] for v in _header_values(headers, "www-authenticate")]
    raw_challenges: list[dict[str, Any]] = []
    for v in www:
        raw_challenges.extend(endpoints.parse_www_authenticate(v))
    # The URL to fetch comes from the raw challenge, resolved against the
    # endpoint (a relative reference names a same-host URL). It is kept verbatim
    # only when send_gate would send it, which means it is credential-free;
    # otherwise only its redacted form is recorded, and it is never fetched.
    rm_raw = endpoints.resource_metadata_url(raw_challenges)
    rm_abs = urljoin(endpoint, rm_raw) if rm_raw else None
    rm_sendable = bool(rm_abs) and send_gate(rm_abs or "") is None
    challenges = [
        {"scheme": ch["scheme"],
         "params": {k: endpoints.redact_text(str(v), 300) for k, v in ch["params"].items()}}
        for ch in raw_challenges
    ]
    locations = _header_values(headers, "location")
    location = locations[0] if locations else None
    body: bytes = res["body"]
    out: dict[str, Any] = {
        "ok": True,
        "status": res["status"],
        "reason": res["reason"],
        "content_type": ctype,
        "www_authenticate": [endpoints.redact_text(v, 1024) for v in www],
        "challenges": challenges,
        "resource_metadata": (
            rm_abs if rm_sendable else endpoints.redact_url(rm_abs) if rm_abs else None
        ),
        "resource_metadata_sendable": rm_sendable,
        "mcp_session_id": bool(_header_values(headers, "mcp-session-id")),
        "set_cookie": bool(_header_values(headers, "set-cookie")),
        "location": endpoints.redact_url(location) if location else None,
        "body_bytes": len(body),
        "body_truncated": res["body_truncated"],
        "headers_ms": res["headers_ms"],
        "elapsed_ms": res["elapsed_ms"],
        "jsonrpc": None,
        "prm": None,
        "body_snippet": None,
    }
    if kind == "initialize":
        out["jsonrpc"] = parse_jsonrpc(body, ctype.lower())
        if out["jsonrpc"] is None or not 200 <= res["status"] < 300:
            out["body_snippet"] = _snippet(body)
    else:
        out["prm"] = parse_prm(body, endpoint) if 200 <= res["status"] < 300 else None
        if out["prm"] is None or not out["prm"].get("object"):
            out["body_snippet"] = _snippet(body)
    return out


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


class RawLog:
    """Append-only JSONL, one line per event, thread-safe."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, rec: dict[str, Any]) -> None:
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)


Transport = Callable[[str, str, str, dict[str, str], "bytes | None"], dict[str, Any]]


class Prober:
    """Runs the plan. Injected transport and resolver keep the logic testable
    offline; the defaults are the only code paths that touch the network."""

    def __init__(self, log: Callable[[dict[str, Any]], None],
                 transport: Transport | None = None,
                 resolver: Resolver | None = None,
                 gate: HostGate | None = None) -> None:
        self.log = log
        self._context = ssl.create_default_context()
        self.transport: Transport = transport or (
            lambda m, u, ip, h, b: https_request(m, u, ip, h, b, TIMEOUT_S, self._context)
        )
        self.resolver = resolver or Resolver(log=log)
        self.gate = gate or HostGate()
        self._get_lock = threading.Lock()
        self._get_done: dict[str, threading.Event] = {}

    def _send(self, kind: str, endpoint: str, method: str, url: str) -> dict[str, Any] | None:
        reason = send_gate(url)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if reason is None:
            dns = self.resolver.resolve(host, parts.port or 443)
            if dns["status"] != "ok":
                reason = f"dns {dns['status']}"
        if reason is not None:
            self.log({"event": "skip", "ts": utcnow(), "kind": kind, "endpoint": endpoint,
                      "url": endpoints.redact_url(url), "reason": reason})
            return None
        body = initialize_body() if kind == "initialize" else None
        desc: dict[str, Any] = {}
        for attempt in range(1, MAX_RETRIES + 2):
            with self.gate.slot(host):
                ts = utcnow()
                res = self.transport(method, url, dns["ip"], request_headers(kind), body)
                ts_end = utcnow()
            desc = describe_response(kind, endpoint, res)
            self.log({"event": "request", "ts": ts, "ts_end": ts_end, "kind": kind,
                      "endpoint": endpoint, "method": method, "url": url, "host": host,
                      "ip": dns["ip"], "attempt": attempt, **desc})
            if desc["ok"] or desc["error"] not in RETRYABLE:
                break
        return desc

    def _get_once(self, kind: str, endpoint: str, url: str) -> None:
        """GET a metadata URL at most once per run, whichever endpoint asks first."""
        key = safe_key(url)
        with self._get_lock:
            if key in self._get_done:
                event, owner = self._get_done[key], False
            else:
                event, owner = threading.Event(), True
                self._get_done[key] = event
        if not owner:
            event.wait()
            return
        try:
            self._send(kind, endpoint, "GET", url)
        finally:
            event.set()

    def probe_endpoint(self, endpoint: str) -> None:
        init = self._send("initialize", endpoint, "POST", endpoint)
        if init is None or not init.get("ok"):
            # Skipped, or no HTTP answer after the retry (DNS, TLS, timeout,
            # refused): the well-known GETs would go to the same dead or
            # unreachable host, so they are not sent at all.
            why = "initialize skipped" if init is None else f"initialize failed: {init.get('error')}"
            self.log({"event": "skip", "ts": utcnow(), "kind": "prm", "endpoint": endpoint,
                      "url": endpoints.redact_url(endpoint), "reason": why})
            return
        variants = endpoints.prm_urls(endpoint)
        if len(variants) == 2:
            self._get_once("prm-path", endpoint, variants[0])
        self._get_once("prm-root", endpoint, variants[-1])
        if init.get("resource_metadata_sendable"):
            self._get_once("prm-resource-metadata", endpoint, init["resource_metadata"])

    def probe_host(self, host_endpoints: list[str]) -> None:
        for ep in host_endpoints:
            try:
                self.probe_endpoint(ep)
            except Exception as exc:  # noqa: BLE001 - one odd endpoint must not end the run
                self.log({"event": "error", "ts": utcnow(), "endpoint": ep,
                          "error_type": type(exc).__name__})


def safe_key(url: str) -> str:
    """``endpoint_key`` that never raises: a malformed URL keys as itself."""
    try:
        return endpoints.endpoint_key(url)
    except ValueError:
        return url


def build_plan(configs: list[dict[str, Any]]) -> dict[str, Any]:
    """Distinct endpoints to probe, with hit counts per source, and the skips."""
    measure = _load_sibling("measure")
    eps: dict[str, dict[str, Any]] = {}
    skipped: Counter[str] = Counter()
    for c in configs:
        for h in c["hits"]:
            reason = measure.probe_candidate(h)
            if reason is None:
                key = endpoints.endpoint_key(h["url"])
                row = eps.setdefault(key, {"endpoint": key, "host": h["host"], "hits": 0,
                                           "hits_by_source": Counter()})
                row["hits"] += 1
                row["hits_by_source"][c["source"]] += 1
            else:
                skipped[reason] += 1
    rows = sorted(eps.values(), key=lambda r: (r["host"], r["endpoint"]))
    for r in rows:
        r["hits_by_source"] = dict(sorted(r["hits_by_source"].items()))
    return {"endpoints": rows, "skipped_hits": dict(sorted(skipped.items()))}


def run_probe(plan: dict[str, Any], raw_out: Path, resume: bool = False,
              transport: Transport | None = None,
              getaddrinfo: Callable[..., Any] = socket.getaddrinfo,
              gate: HostGate | None = None, workers: int = MAX_CONNECTIONS) -> int:
    """Probe every planned endpoint, logging to ``raw_out``. ``transport``,
    ``getaddrinfo`` and ``gate`` exist for the offline tests; the defaults are
    the real network."""
    done: set[str] = set()
    if resume and raw_out.is_file():
        done = {r["endpoint"] for r in read_raw(raw_out)
                if r.get("event") == "request" and r.get("kind") == "initialize"}
    log = RawLog(raw_out)
    prober = Prober(log.write, transport=transport,
                    resolver=Resolver(getaddrinfo=getaddrinfo, log=log.write), gate=gate)
    log.write({"event": "run", "ts": utcnow(), "user_agent": USER_AGENT,
               "protocol_version": PROTOCOL_VERSION, "timeout_s": TIMEOUT_S,
               "max_connections": workers, "per_host_interval_s": PER_HOST_INTERVAL_S,
               "max_retries": MAX_RETRIES, "body_cap": BODY_CAP, "resume": resume,
               "aak_version": agent_audit_kit.__version__})
    by_host: dict[str, list[str]] = {}
    for row in plan["endpoints"]:
        if not resume or row["endpoint"] not in done:
            log.write({"event": "plan", "ts": utcnow(), **row})
        if row["endpoint"] not in done:
            by_host.setdefault(row["host"], []).append(row["endpoint"])
    finished = 0
    with ThreadPoolExecutor(max_workers=min(workers, MAX_CONNECTIONS)) as pool:
        futures = [pool.submit(prober.probe_host, eps) for _, eps in sorted(by_host.items())]
        for fut in as_completed(futures):
            fut.result()
            finished += 1
            if finished % 100 == 0:
                print(f"  {finished}/{len(futures)} hosts done", flush=True)
    log.write({"event": "done", "ts": utcnow()})
    return len(by_host)


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------


def read_raw(path: Path) -> list[dict[str, Any]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def initialize_outcome(desc: dict[str, Any] | None) -> str:
    """One label per initialize answer. ``accepted`` means a JSON-RPC result
    came back to an unauthenticated client, which is the strongest open signal
    the probe can see; ``auth-required`` is any 401/403."""
    if desc is None:
        return "not sent"
    if not desc.get("ok"):
        return f"error: {desc.get('error')}"
    status = int(desc["status"])
    rpc = desc.get("jsonrpc") or {}
    if 200 <= status < 300:
        if rpc.get("result"):
            return "accepted"
        if rpc.get("error_code") is not None:
            return "jsonrpc-error"
        return "2xx-other"
    if status in (401, 403):
        return "auth-required"
    if status == 402:
        return "payment-required"  # an x402-style access gate: not open, not a login
    if 300 <= status < 400:
        return "redirect"
    if status in (404, 410):
        return "not-found"
    if status == 405:
        return "method-not-allowed"
    if 400 <= status < 500:
        return "client-error-other"
    return "server-error"


def summarize_by_endpoint(raw: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per planned endpoint: its DNS fate, the final initialize attempt, and the
    best metadata answer across the RFC 9728 variants. Used for the population."""
    final: dict[tuple[str, str], dict[str, Any]] = {}
    skips: dict[str, str] = {}
    for r in raw:
        if r.get("event") == "request":
            final[(r["method"], safe_key(r["url"]))] = r
        elif r.get("event") == "skip" and r.get("kind") == "initialize":
            skips[r["endpoint"]] = r["reason"]
    out: dict[str, dict[str, Any]] = {}
    for r in raw:
        if r.get("event") != "plan":
            continue
        ep = r["endpoint"]
        init = final.get(("POST", ep))
        variants = endpoints.prm_urls(ep)
        # Keyed by which URL answered, not by which request fetched it: a URL
        # named in the challenge that equals the path-inserted one was fetched
        # once, and counts for both.
        prm_reqs: dict[str, dict[str, Any] | None] = {
            "path-inserted": final.get(("GET", safe_key(variants[0]))) if len(variants) == 2 else None,
            "root": final.get(("GET", safe_key(variants[-1]))),
        }
        rm = (init or {}).get("resource_metadata")
        if rm:
            prm_reqs["named-in-challenge"] = (
                final.get(("GET", safe_key(rm))) if (init or {}).get("resource_metadata_sendable") else None
            )

        def _prm(k: str) -> dict[str, Any]:
            return (prm_reqs.get(k) or {}).get("prm") or {}

        served = {k: bool(v and v.get("ok") and _prm(k).get("object")) for k, v in prm_reqs.items()}
        valid = {k: bool(served[k] and _prm(k).get("resource_present")) for k in prm_reqs}
        with_as = {k: bool(valid[k] and _prm(k).get("authorization_servers_count")) for k in prm_reqs}
        challenges = (init or {}).get("challenges") or []
        out[ep] = {
            "status": "probed" if init is not None else "skipped",
            "skip_reason": skips.get(ep),
            "initialize": {
                "outcome": initialize_outcome(init),
                "http_status": (init or {}).get("status"),
                "error": (init or {}).get("error"),
                "content_type": (init or {}).get("content_type"),
                "www_authenticate_schemes": sorted({str(c.get("scheme", "")).lower() for c in challenges}),
                "www_authenticate": (init or {}).get("www_authenticate") or [],
                "resource_metadata_param": bool(rm),
                "jsonrpc": (init or {}).get("jsonrpc"),
                "mcp_session_id": bool((init or {}).get("mcp_session_id")),
                "body_snippet": (init or {}).get("body_snippet"),
                "elapsed_ms": (init or {}).get("elapsed_ms"),
                "attempts": (init or {}).get("attempt"),
                "ts": (init or {}).get("ts"),
            },
            "prm": {
                "served": any(served.values()),
                "valid": any(valid.values()),
                "with_authorization_servers": any(with_as.values()),
                "by_variant": {
                    k: (None if v is None else
                        {"http_status": v.get("status"), "error": v.get("error"),
                         "served": served[k], "valid": valid[k], "with_authorization_servers": with_as[k],
                         "resource_matches_endpoint": bool((v.get("prm") or {}).get("resource_matches_endpoint")),
                         "authorization_servers": (v.get("prm") or {}).get("authorization_servers") or []})
                    for k, v in prm_reqs.items()
                },
            },
        }
    return out


def _quantiles(values: list[int]) -> dict[str, int | None]:
    if not values:
        return {"n": 0, "p50": None, "p90": None, "max": None}
    s = sorted(values)

    def q(p: float) -> int:
        return s[min(len(s) - 1, int(p * (len(s) - 1) + 0.5))]

    return {"n": len(s), "p50": q(0.5), "p90": q(0.9), "max": s[-1]}


def _ranked(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def _epoch(ts: str) -> float:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def observed_limits(reqs: list[dict[str, Any]]) -> dict[str, Any]:
    """What the log says the run actually did, against the limits it promised:
    the shortest gap between two request starts to one host, and the most
    requests in flight at once (from each request's start and end stamps).
    Millisecond stamps, so a gap is exact to about 1 ms."""
    by_host: dict[str, list[float]] = {}
    events: list[tuple[float, int]] = []
    for r in reqs:
        start, end = _epoch(r["ts"]), _epoch(r["ts_end"])
        by_host.setdefault(r["host"], []).append(start)
        events += [(start, 1), (end, -1)]
    gaps = [b - a for t in by_host.values() for a, b in zip(sorted(t), sorted(t)[1:])]
    peak = cur = 0
    for _, step in sorted(events, key=lambda e: (e[0], e[1])):
        cur += step
        peak = max(peak, cur)
    stamps = sorted(r["ts"] for r in reqs)
    return {
        "min_same_host_start_gap_s": round(min(gaps), 3) if gaps else None,
        "peak_requests_in_flight": peak,
        "methods": _ranked(Counter(r["method"] for r in reqs)),
        "non_https_requests": sum(1 for r in reqs if not str(r["url"]).startswith("https://")),
        "requests_with_userinfo": sum(1 for r in reqs if "@" in urlsplit(str(r["url"])).netloc),
        "duration_s": round(_epoch(stamps[-1]) - _epoch(stamps[0]), 1) if stamps else 0.0,
    }


def build_summary(raw: list[dict[str, Any]]) -> dict[str, Any]:
    """The committed aggregate: counts, never a host, URL or body."""
    runs = [r for r in raw if r.get("event") == "run"]
    plan = {r["endpoint"]: r for r in raw if r.get("event") == "plan"}
    per = summarize_by_endpoint(raw)
    reqs = [r for r in raw if r.get("event") == "request"]
    dns = Counter(r["status"] for r in raw if r.get("event") == "dns")

    ep_outcome: Counter[str] = Counter()
    hit_outcome: Counter[str] = Counter()
    hit_outcome_by_source: dict[str, Counter[str]] = {}
    auth: Counter[str] = Counter()
    accepted: Counter[str] = Counter()
    prm: Counter[str] = Counter()
    prm_hits: Counter[str] = Counter()
    accepted_versions: Counter[str] = Counter()
    for ep, s in per.items():
        o = s["initialize"]["outcome"] if s["status"] == "probed" else f"skipped: {s['skip_reason']}"
        hits = int(plan[ep].get("hits", 1))
        ep_outcome[o] += 1
        hit_outcome[o] += hits
        for src, n in (plan[ep].get("hits_by_source") or {}).items():
            hit_outcome_by_source.setdefault(src, Counter())[o] += int(n)
        if o == "auth-required":
            schemes = s["initialize"]["www_authenticate_schemes"]
            auth["endpoints"] += 1
            auth["hits"] += hits
            auth["with_bearer_challenge"] += int("bearer" in schemes)
            auth["with_resource_metadata_param"] += int(s["initialize"]["resource_metadata_param"])
            auth["with_any_challenge"] += int(bool(schemes))
            auth["with_prm_served"] += int(s["prm"]["served"])
            auth["with_prm_authorization_servers"] += int(s["prm"]["with_authorization_servers"])
        if o == "accepted":
            v = (s["initialize"]["jsonrpc"] or {}).get("protocol_version") or "(none)"
            accepted_versions[v] += 1
            accepted["endpoints"] += 1
            accepted["with_mcp_session_id"] += int(s["initialize"]["mcp_session_id"])
            accepted["with_prm_served"] += int(s["prm"]["served"])
            accepted["hits"] += hits
        if s["status"] == "probed":
            prm["probed_endpoints"] += 1
            prm["served_any_variant"] += int(s["prm"]["served"])
            prm["valid_any_variant"] += int(s["prm"]["valid"])
            prm["with_authorization_servers"] += int(s["prm"]["with_authorization_servers"])
            prm_hits["served_any_variant"] += hits * int(s["prm"]["served"])
            prm_hits["with_authorization_servers"] += hits * int(s["prm"]["with_authorization_servers"])
            for k, v in s["prm"]["by_variant"].items():
                if v is not None and v["served"]:
                    prm[f"served_via_{k}"] += 1
                if v is not None and v["resource_matches_endpoint"]:
                    prm[f"resource_matches_endpoint_via_{k}"] += 1
    attempts = Counter(r["kind"] for r in reqs)
    errors = Counter(r["error"] for r in reqs if not r.get("ok"))
    retried = sum(1 for r in reqs if int(r.get("attempt", 1)) > 1)
    statuses = Counter(str(r["status"]) for r in reqs if r.get("ok") and r["kind"] == "initialize")
    init_ms = [int(r["elapsed_ms"]) for r in reqs
               if r["kind"] == "initialize" and r.get("ok") and r.get("elapsed_ms") is not None]
    days = sorted({str(r.get("ts", ""))[:10] for r in reqs if r.get("ts")})
    return {
        "rule": "AAK-MCP-001",
        "probe": {
            "run_dates_utc": days,
            "runs": len(runs),
            "user_agent": USER_AGENT,
            "protocol_version": PROTOCOL_VERSION,
            "timeout_s": TIMEOUT_S,
            "max_connections": MAX_CONNECTIONS,
            "per_host_interval_s": PER_HOST_INTERVAL_S,
            "max_retries": MAX_RETRIES,
            "request_kinds": list(KINDS),
        },
        "planned_endpoints": len(plan),
        "planned_hits": sum(int(r.get("hits", 1)) for r in plan.values()),
        "dns_lookups": _ranked(dns),
        "requests_sent": len(reqs),
        "requests_by_kind": _ranked(attempts),
        "retried_requests": retried,
        "request_errors": _ranked(errors),
        "initialize_http_status": _ranked(statuses),
        "initialize_outcome_endpoints": _ranked(ep_outcome),
        "initialize_outcome_hits": _ranked(hit_outcome),
        "initialize_outcome_hits_by_source": {
            k: _ranked(v) for k, v in sorted(hit_outcome_by_source.items())
        },
        "auth_required": dict(sorted(auth.items())),
        "accepted": dict(sorted(accepted.items())),
        "accepted_protocol_versions": _ranked(accepted_versions),
        "rfc9728_metadata": dict(sorted(prm.items())),
        "rfc9728_metadata_hits": dict(sorted(prm_hits.items())),
        "initialize_elapsed_ms": _quantiles(init_ms),
        "observed_limits": observed_limits(reqs),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO)
    except ValueError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probe", action="store_true",
                    help="actually send requests (without it: print the plan, send nothing)")
    ap.add_argument("--raw-out", type=Path, default=None, help="raw JSONL log (outside the repo)")
    ap.add_argument("--resume", action="store_true", help="skip endpoints already in --raw-out")
    ap.add_argument("--corpus", type=Path, default=None)
    ap.add_argument("--registry-manifest", type=Path, default=None)
    ap.add_argument("--summarize", type=Path, default=None, metavar="RAW",
                    help="aggregate a raw log (offline)")
    ap.add_argument("--write", action="store_true", help="with --summarize: write probe-summary.json")
    ap.add_argument("--out", type=Path, default=None, help="with --summarize: write here instead")
    args = ap.parse_args(argv)

    if args.summarize:
        summary = build_summary(read_raw(args.summarize))
        blob = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        leaks = endpoints.leak_report(blob)
        if leaks or "://" in blob.replace(USER_AGENT, ""):
            print("refusing: the summary would carry a URL or a secret pattern", file=sys.stderr)
            return 2
        target = args.out or (SUMMARY_JSON if args.write else None)
        if target:
            target.write_text(blob, encoding="utf-8")
            print(f"wrote {target}")
        else:
            print(blob)
        return 0

    measure = _load_sibling("measure")
    corpus = args.corpus or measure.default_corpus()
    manifest = args.registry_manifest or measure.DEFAULT_MANIFEST
    if not corpus.is_dir():
        print(f"corpus {corpus} not found; set --corpus or AAK_MCP001_CORPUS", file=sys.stderr)
        return 2
    plan = build_plan(measure.scan_corpus(corpus, manifest))
    hosts = {r["host"] for r in plan["endpoints"]}
    print(f"plan: {len(plan['endpoints'])} distinct public https endpoints on {len(hosts)} hosts "
          f"({sum(r['hits'] for r in plan['endpoints'])} hits); skipped hits: {plan['skipped_hits']}")
    if not args.probe:
        print("no --probe: nothing sent")
        return 0
    if args.raw_out is None or _inside_repo(args.raw_out):
        print("--probe needs --raw-out outside the repository", file=sys.stderr)
        return 2
    n = run_probe(plan, args.raw_out, resume=args.resume)
    print(f"probed {n} hosts; raw log {args.raw_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
