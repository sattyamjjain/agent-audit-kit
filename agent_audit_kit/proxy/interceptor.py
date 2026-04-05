from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from collections import defaultdict
from pathlib import Path


class RateLimiter:
    """Simple per-client rate limiter using sliding window."""

    def __init__(self, max_requests: int = 100, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, client_id: str) -> bool:
        now = time.time()
        with self._lock:
            timestamps = self._requests[client_id]
            # Remove expired entries
            cutoff = now - self.window
            self._requests[client_id] = [t for t in timestamps if t > cutoff]
            if len(self._requests[client_id]) >= self.max_requests:
                return False
            self._requests[client_id].append(now)
            return True


class McpProxyServer:
    """Local MCP proxy that intercepts tool calls between client and server."""

    def __init__(self, port: int, target: str, max_connections: int = 50) -> None:
        self.port = port
        self.target = target
        self.max_connections = max_connections
        self.running = False
        self.log: list[dict] = []
        self._server_socket: socket.socket | None = None
        self._active_connections = 0
        self._conn_lock = threading.Lock()
        self._rate_limiter = RateLimiter(max_requests=100, window_seconds=60.0)
        self._pid_file = Path.home() / ".agent-audit-kit" / "proxy.pid"

    def _handle_client(self, client_socket: socket.socket, addr: tuple) -> None:
        client_id = f"{addr[0]}:{addr[1]}"
        try:
            # Rate limit check
            if not self._rate_limiter.allow(client_id):
                error_resp = json.dumps({
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": "Rate limit exceeded"},
                    "id": None,
                }).encode()
                client_socket.sendall(error_resp)
                return

            data = client_socket.recv(65536)
            if not data:
                return

            request_str = data.decode("utf-8", errors="replace")
            entry: dict = {
                "timestamp": time.time(),
                "direction": "client->server",
                "size": len(data),
                "client": client_id,
            }

            try:
                body_start = request_str.find("\r\n\r\n")
                body = request_str[body_start + 4:] if body_start > 0 else request_str
                msg = json.loads(body)
                entry["method"] = msg.get("method", "unknown")
                if msg.get("method") == "tools/call":
                    params = msg.get("params", {})
                    entry["tool_name"] = params.get("name", "unknown")
                    entry["tool_args_keys"] = list(params.get("arguments", {}).keys())
            except (json.JSONDecodeError, ValueError):
                entry["method"] = "unparseable"

            self.log.append(entry)

            # Forward to target
            try:
                req = urllib.request.Request(
                    self.target, data=data,
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    response_data = resp.read()
                    client_socket.sendall(response_data)
                    self.log.append({
                        "timestamp": time.time(),
                        "direction": "server->client",
                        "size": len(response_data),
                    })
            except Exception as e:
                error_response = json.dumps({
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": f"Proxy error: {e}"},
                    "id": None,
                }).encode()
                client_socket.sendall(error_response)
        except Exception:
            pass
        finally:
            client_socket.close()
            with self._conn_lock:
                self._active_connections -= 1

    def _write_pid(self) -> None:
        self._pid_file.parent.mkdir(parents=True, exist_ok=True)
        self._pid_file.write_text(str(os.getpid()))

    def _remove_pid(self) -> None:
        self._pid_file.unlink(missing_ok=True)

    def start_proxy(self, port: int | None = None, target: str | None = None) -> None:
        p = port or self.port
        self.running = True
        self._write_pid()
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("127.0.0.1", p))
        self._server_socket.listen(self.max_connections)
        self._server_socket.settimeout(1.0)

        try:
            while self.running:
                try:
                    client_sock, addr = self._server_socket.accept()
                    with self._conn_lock:
                        if self._active_connections >= self.max_connections:
                            client_sock.close()
                            continue
                        self._active_connections += 1
                    thread = threading.Thread(
                        target=self._handle_client, args=(client_sock, addr), daemon=True,
                    )
                    thread.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            self._remove_pid()
            if self._server_socket:
                self._server_socket.close()

    def stop(self) -> None:
        self.running = False

    def get_log(self) -> list[dict]:
        return list(self.log)


def start_proxy(port: int = 8765, target: str = "http://localhost:3000") -> None:
    proxy = McpProxyServer(port=port, target=target)
    proxy.start_proxy()
