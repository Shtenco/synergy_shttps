from __future__ import annotations

import asyncio

from shttps.mcp_stdio import MCPBridge, MCPState


class FakeRemoteClient:
    async def call(self, service, method, params, *, sensitive=False, metadata=None):
        assert service == "synergy.remote.mcp.v1"
        if method == "health":
            return {"ok": True, "transport": "SHTTPS/2+STCP/1"}
        if method == "list_dir":
            return {"entries": [{"name": "src", "type": "dir", "size": None}]}
        raise RuntimeError("unexpected method")


def bridge() -> MCPBridge:
    b = MCPBridge.__new__(MCPBridge)
    b.prefix = "TEST"
    b.client = FakeRemoteClient()
    b.state = MCPState()
    return b


def test_mcp_initialize_and_tools_list():
    async def scenario():
        b=bridge()
        init=await b.handle({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}},
        })
        assert init["result"]["protocolVersion"]=="2025-06-18"
        tools=await b.handle({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
        names={x["name"] for x in tools["result"]["tools"]}
        assert {"synergy_health","synergy_list_dir","synergy_read_file","synergy_run"} <= names
    asyncio.run(scenario())


def test_mcp_tools_call_routes_to_remote_shttps_service():
    async def scenario():
        b=bridge()
        result=await b.handle({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"synergy_health","arguments":{}},
        })
        assert result["result"]["isError"] is False
        assert "SHTTPS/2+STCP/1" in result["result"]["content"][0]["text"]
    asyncio.run(scenario())


def test_mcp_unknown_tool_fails_closed():
    async def scenario():
        b=bridge()
        result=await b.handle({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"shell_anything","arguments":{}},
        })
        assert result["result"]["isError"] is True
    asyncio.run(scenario())
