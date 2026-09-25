from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from typing import Any

from .bootstrap import rpc_client_from_env
from .remote_mcp import REMOTE_MCP_SERVICE

SERVER_NAME = "synergy-remote-mcp"
SERVER_VERSION = "0.2.0"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

TOOLS = [
    {
        "name": "synergy_health",
        "description": "Check the authenticated SYNERGY Remote MCP node.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "synergy_list_dir",
        "description": "List one directory inside the server-side configured filesystem jail.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "default": "."}},
            "additionalProperties": False,
        },
    },
    {
        "name": "synergy_read_file",
        "description": "Read one UTF-8/text file inside the configured filesystem jail.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "synergy_run",
        "description": "Run one allowlisted executable without a shell on the remote node.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "cwd": {"type": "string", "default": "."},
            },
            "required": ["argv"],
            "additionalProperties": False,
        },
    },
]

_TOOL_ROUTE = {
    "synergy_health": "health",
    "synergy_list_dir": "list_dir",
    "synergy_read_file": "read_file",
    "synergy_run": "run",
}


@dataclass
class MCPState:
    initialized: bool = False
    protocol_version: str = SUPPORTED_PROTOCOL_VERSIONS[0]


def _response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    value: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        value["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": value}


def _text_result(value: Any, *, is_error: bool = False) -> dict[str, Any]:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class MCPBridge:
    def __init__(self, prefix: str = "SYNERGY_MCP") -> None:
        self.prefix = prefix
        self.client = rpc_client_from_env(
            prefix,
            host_default="127.0.0.1",
            port_default=9443,
            roles=("mcp-controller",),
        )
        self.state = MCPState()

    async def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        method = str(message.get("method") or "")
        request_id = message.get("id")
        params = message.get("params") or {}

        if method == "notifications/initialized":
            self.state.initialized = True
            return None

        if method == "initialize":
            requested = str(params.get("protocolVersion") or "")
            if requested in SUPPORTED_PROTOCOL_VERSIONS:
                self.state.protocol_version = requested
            else:
                self.state.protocol_version = SUPPORTED_PROTOCOL_VERSIONS[0]
            return _response(request_id, {
                "protocolVersion": self.state.protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": (
                    "Remote actions are executed through authenticated SHTTPS/STCP "
                    "and remain limited by the remote filesystem jail and command allowlist."
                ),
            })

        if method == "ping":
            return _response(request_id, {})

        if method == "tools/list":
            return _response(request_id, {"tools": TOOLS})

        if method == "tools/call":
            name = str(params.get("name") or "")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                return _response(request_id, _text_result("arguments must be an object", is_error=True))
            remote_method = _TOOL_ROUTE.get(name)
            if remote_method is None:
                return _response(request_id, _text_result("unknown tool", is_error=True))
            try:
                value = await self.client.call(
                    REMOTE_MCP_SERVICE,
                    remote_method,
                    arguments,
                    sensitive=remote_method in {"read_file", "run"},
                    metadata={"mcp_tool": name, "frontend": SERVER_NAME},
                )
                return _response(request_id, _text_result(value))
            except Exception as exc:
                return _response(
                    request_id,
                    _text_result(f"{type(exc).__name__}: {exc}", is_error=True),
                )

        if request_id is None:
            return None
        return _error(request_id, -32601, f"Method not found: {method}")


async def _serve_stdio() -> None:
    bridge = MCPBridge()
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
        if not line:
            return
        try:
            message = json.loads(line.decode("utf-8"))
            if not isinstance(message, dict):
                raise ValueError("JSON-RPC message must be an object")
            response = await bridge.handle(message)
        except Exception as exc:
            response = _error(None, -32700, "Parse error", str(exc))
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()


def main() -> None:
    asyncio.run(_serve_stdio())


if __name__ == "__main__":
    main()
