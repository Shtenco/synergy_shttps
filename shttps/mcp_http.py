from __future__ import annotations

import asyncio
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .mcp_stdio import MCPBridge


class MCPHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler, bridge: MCPBridge, bearer_token: str):
        super().__init__(server_address, handler)
        self.bridge = bridge
        self.bearer_token = bearer_token


class MCPHandler(BaseHTTPRequestHandler):
    server: MCPHTTPServer

    def _json(self, status: int, value: Any | None) -> None:
        body = b"" if value is None else json.dumps(
            value, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = self.server.bearer_token
        if not expected:
            return self.client_address[0] in {"127.0.0.1", "::1"}
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            return False
        return hmac.compare_digest(value[7:], expected)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            if not self._authorized():
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, {"service": "synergy-mcp-http-gateway", "ok": True})
            return
        self._json(405, {"error": "GET not supported for MCP; use POST /mcp"})

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "invalid content length"})
            return
        if length <= 0 or length > 1024 * 1024:
            self._json(413, {"error": "request too large or empty"})
            return
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("JSON-RPC message must be an object")
            result = asyncio.run(self.server.bridge.handle(value))
        except Exception as exc:
            self._json(400, {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error", "data": str(exc)},
            })
            return
        if result is None:
            self._json(202, None)
        else:
            self._json(200, result)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"MCP_HTTP {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    host = os.getenv("SYNERGY_MCP_HTTP_BIND", "127.0.0.1")
    port = int(os.getenv("SYNERGY_MCP_HTTP_PORT", "8765"))
    token = os.getenv("SYNERGY_MCP_HTTP_BEARER", "")
    if host not in {"127.0.0.1", "::1", "localhost"} and not token:
        raise SystemExit("SYNERGY_MCP_HTTP_BEARER is required for non-loopback binding")
    bridge = MCPBridge()
    server = MCPHTTPServer((host, port), MCPHandler, bridge, token)
    print(f"SYNERGY MCP HTTP gateway listening at http://{host}:{port}/mcp", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
