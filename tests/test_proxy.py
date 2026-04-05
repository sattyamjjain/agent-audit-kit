"""Tests for agent_audit_kit.proxy.interceptor module.

Covers RateLimiter, McpProxyServer construction, PID file management,
log retrieval, stop/get_log methods, _handle_client with mocked sockets,
and the module-level start_proxy helper -- all without starting an actual
server.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent_audit_kit.proxy.interceptor import McpProxyServer, RateLimiter


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_allows_requests_under_limit(self) -> None:
        rl = RateLimiter(max_requests=5, window_seconds=60.0)
        for _ in range(5):
            assert rl.allow("client1") is True

    def test_blocks_requests_over_limit(self) -> None:
        rl = RateLimiter(max_requests=3, window_seconds=60.0)
        for _ in range(3):
            rl.allow("client1")
        assert rl.allow("client1") is False

    def test_different_clients_independent(self) -> None:
        rl = RateLimiter(max_requests=2, window_seconds=60.0)
        rl.allow("client1")
        rl.allow("client1")
        assert rl.allow("client1") is False
        assert rl.allow("client2") is True

    def test_expired_requests_pruned(self) -> None:
        rl = RateLimiter(max_requests=1, window_seconds=0.01)
        rl.allow("client1")
        assert rl.allow("client1") is False
        time.sleep(0.02)
        assert rl.allow("client1") is True

    def test_zero_max_requests_always_blocks(self) -> None:
        rl = RateLimiter(max_requests=0, window_seconds=60.0)
        assert rl.allow("client1") is False

    def test_default_params(self) -> None:
        rl = RateLimiter()
        assert rl.max_requests == 100
        assert rl.window == 60.0

    def test_single_request_allowed(self) -> None:
        rl = RateLimiter(max_requests=1, window_seconds=60.0)
        assert rl.allow("x") is True
        assert rl.allow("x") is False


# ---------------------------------------------------------------------------
# McpProxyServer construction
# ---------------------------------------------------------------------------


class TestMcpProxyServer:
    def test_construction(self) -> None:
        proxy = McpProxyServer(port=9999, target="http://localhost:8080")
        assert proxy.port == 9999
        assert proxy.target == "http://localhost:8080"
        assert proxy.max_connections == 50
        assert proxy.running is False
        assert proxy.log == []

    def test_custom_max_connections(self) -> None:
        proxy = McpProxyServer(port=9999, target="http://localhost:8080", max_connections=10)
        assert proxy.max_connections == 10

    def test_pid_file_path(self) -> None:
        proxy = McpProxyServer(port=9999, target="http://localhost:8080")
        assert "proxy.pid" in str(proxy._pid_file)

    def test_has_rate_limiter(self) -> None:
        proxy = McpProxyServer(port=9999, target="http://localhost:8080")
        assert isinstance(proxy._rate_limiter, RateLimiter)

    def test_log_starts_empty(self) -> None:
        proxy = McpProxyServer(port=9999, target="http://localhost:8080")
        assert len(proxy.log) == 0

    def test_get_log_returns_copy(self) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        proxy.log.append({"test": True})
        log_copy = proxy.get_log()
        assert len(log_copy) == 1
        assert log_copy[0] == {"test": True}
        # Modifying the copy should not affect the original
        log_copy.clear()
        assert len(proxy.log) == 1

    def test_stop_sets_running_false(self) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        proxy.running = True
        proxy.stop()
        assert proxy.running is False

    def test_server_socket_starts_none(self) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        assert proxy._server_socket is None

    def test_active_connections_starts_zero(self) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        assert proxy._active_connections == 0


# ---------------------------------------------------------------------------
# PID file management
# ---------------------------------------------------------------------------


class TestPidFileManagement:
    def test_write_pid_creates_file(self, tmp_path: Path) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        proxy._pid_file = tmp_path / "proxy.pid"
        proxy._write_pid()
        assert proxy._pid_file.is_file()
        content = proxy._pid_file.read_text().strip()
        assert content == str(os.getpid())

    def test_write_pid_creates_parent_directories(self, tmp_path: Path) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        proxy._pid_file = tmp_path / "nested" / "dir" / "proxy.pid"
        proxy._write_pid()
        assert proxy._pid_file.is_file()

    def test_remove_pid_deletes_file(self, tmp_path: Path) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        proxy._pid_file = tmp_path / "proxy.pid"
        proxy._pid_file.write_text("12345")
        proxy._remove_pid()
        assert not proxy._pid_file.exists()

    def test_remove_pid_no_error_when_missing(self, tmp_path: Path) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        proxy._pid_file = tmp_path / "nonexistent.pid"
        # Should not raise
        proxy._remove_pid()
        assert not proxy._pid_file.exists()

    def test_write_pid_overwrites_existing(self, tmp_path: Path) -> None:
        proxy = McpProxyServer(port=8000, target="http://test:3000")
        proxy._pid_file = tmp_path / "proxy.pid"
        proxy._pid_file.write_text("99999")
        proxy._write_pid()
        assert proxy._pid_file.read_text().strip() == str(os.getpid())


# ---------------------------------------------------------------------------
# Module-level start_proxy function
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _handle_client with mocked sockets
# ---------------------------------------------------------------------------


class TestHandleClient:
    def _make_proxy(self) -> McpProxyServer:
        proxy = McpProxyServer(port=8000, target="http://localhost:3000")
        proxy._active_connections = 1  # simulate being tracked
        return proxy

    def _make_mock_socket(self, recv_data: bytes = b"") -> MagicMock:
        sock = MagicMock()
        sock.recv.return_value = recv_data
        return sock

    def test_rate_limited_client_gets_error_response(self) -> None:
        proxy = self._make_proxy()
        proxy._rate_limiter = RateLimiter(max_requests=0, window_seconds=60.0)
        sock = self._make_mock_socket()
        addr = ("127.0.0.1", 12345)

        proxy._handle_client(sock, addr)

        sock.sendall.assert_called_once()
        response = json.loads(sock.sendall.call_args[0][0].decode())
        assert response["error"]["code"] == -32000
        assert "Rate limit" in response["error"]["message"]
        sock.close.assert_called_once()

    def test_empty_data_returns_early(self) -> None:
        proxy = self._make_proxy()
        sock = self._make_mock_socket(recv_data=b"")
        addr = ("127.0.0.1", 12345)

        proxy._handle_client(sock, addr)

        sock.sendall.assert_not_called()
        sock.close.assert_called_once()

    def test_valid_json_request_logged(self) -> None:
        proxy = self._make_proxy()
        request_body = json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1})
        sock = self._make_mock_socket(recv_data=request_body.encode())
        addr = ("127.0.0.1", 12345)

        # Mock the forwarding to target to avoid real HTTP calls
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"jsonrpc":"2.0","result":"pong"}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.proxy.interceptor.urllib.request.urlopen", return_value=mock_resp):
            proxy._handle_client(sock, addr)

        assert len(proxy.log) >= 1
        entry = proxy.log[0]
        assert entry["direction"] == "client->server"
        assert entry["method"] == "ping"
        sock.close.assert_called_once()

    def test_tools_call_logged_with_tool_name(self) -> None:
        proxy = self._make_proxy()
        request_body = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/etc/passwd"},
            },
            "id": 1,
        })
        sock = self._make_mock_socket(recv_data=request_body.encode())
        addr = ("127.0.0.1", 12345)

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"jsonrpc":"2.0","result":"ok"}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.proxy.interceptor.urllib.request.urlopen", return_value=mock_resp):
            proxy._handle_client(sock, addr)

        entry = proxy.log[0]
        assert entry["tool_name"] == "read_file"
        assert "path" in entry["tool_args_keys"]

    def test_forward_success_logs_response(self) -> None:
        proxy = self._make_proxy()
        request_body = json.dumps({"jsonrpc": "2.0", "method": "test", "id": 1})
        sock = self._make_mock_socket(recv_data=request_body.encode())
        addr = ("127.0.0.1", 12345)

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"result":"ok"}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.proxy.interceptor.urllib.request.urlopen", return_value=mock_resp):
            proxy._handle_client(sock, addr)

        # Should have 2 log entries: client->server and server->client
        assert len(proxy.log) == 2
        assert proxy.log[1]["direction"] == "server->client"

    def test_forward_failure_sends_error_to_client(self) -> None:
        proxy = self._make_proxy()
        request_body = json.dumps({"jsonrpc": "2.0", "method": "test", "id": 1})
        sock = self._make_mock_socket(recv_data=request_body.encode())
        addr = ("127.0.0.1", 12345)

        with patch(
            "agent_audit_kit.proxy.interceptor.urllib.request.urlopen",
            side_effect=ConnectionError("target down"),
        ):
            proxy._handle_client(sock, addr)

        # The second sendall call is the error response
        assert sock.sendall.call_count >= 1
        # The last sendall should be the error response
        last_call = sock.sendall.call_args_list[-1]
        response = json.loads(last_call[0][0].decode())
        assert response["error"]["code"] == -32603
        assert "Proxy error" in response["error"]["message"]

    def test_unparseable_json_sets_method_unparseable(self) -> None:
        proxy = self._make_proxy()
        sock = self._make_mock_socket(recv_data=b"not json at all")
        addr = ("127.0.0.1", 12345)

        with patch(
            "agent_audit_kit.proxy.interceptor.urllib.request.urlopen",
            side_effect=ConnectionError("target down"),
        ):
            proxy._handle_client(sock, addr)

        assert len(proxy.log) >= 1
        assert proxy.log[0]["method"] == "unparseable"

    def test_http_headers_before_json_body(self) -> None:
        proxy = self._make_proxy()
        raw = "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n" + json.dumps(
            {"jsonrpc": "2.0", "method": "test_with_headers", "id": 1}
        )
        sock = self._make_mock_socket(recv_data=raw.encode())
        addr = ("127.0.0.1", 12345)

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"result":"ok"}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.proxy.interceptor.urllib.request.urlopen", return_value=mock_resp):
            proxy._handle_client(sock, addr)

        assert proxy.log[0]["method"] == "test_with_headers"

    def test_connection_count_decremented_on_exit(self) -> None:
        proxy = self._make_proxy()
        proxy._active_connections = 5
        sock = self._make_mock_socket(recv_data=b"")
        addr = ("127.0.0.1", 12345)

        proxy._handle_client(sock, addr)

        assert proxy._active_connections == 4

    def test_exception_in_handler_still_closes_socket(self) -> None:
        proxy = self._make_proxy()
        sock = MagicMock()
        sock.recv.side_effect = RuntimeError("unexpected")
        addr = ("127.0.0.1", 12345)

        proxy._handle_client(sock, addr)

        sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# Module-level start_proxy function
# ---------------------------------------------------------------------------


class TestModuleStartProxy:
    def test_start_proxy_delegates_to_mcp_proxy_server(self) -> None:
        """Verify start_proxy constructs an McpProxyServer and calls start_proxy."""
        with patch.object(McpProxyServer, "start_proxy") as mock_start:
            from agent_audit_kit.proxy.interceptor import start_proxy

            start_proxy(port=1234, target="http://localhost:9000")
            mock_start.assert_called_once()
