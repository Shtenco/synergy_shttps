from pathlib import Path
import tempfile

import pytest

from shttps.rpc import RPCDispatcher, RPCRequest
from shttps.remote_mcp import RemoteMCPGateway, RemoteMCPPolicy, REMOTE_MCP_SERVICE, register_remote_mcp
from shttps.stcp import STCPMux, StreamClass
from shttps.errors import SecurityError


def test_stcp_roundtrip_and_replay_reject():
    tx = STCPMux()
    rx = STCPMux()
    raw = tx.wrap(StreamClass.RPC, 7, b"encrypted-shttps-record")
    frame = rx.unwrap(raw)
    assert frame.stream_id == 7
    assert frame.payload == b"encrypted-shttps-record"
    with pytest.raises(SecurityError):
        rx.unwrap(raw)


def test_remote_mcp_is_jailed_and_allowlisted():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "x.txt").write_text("hello", encoding="utf-8")
        gateway = RemoteMCPGateway(RemoteMCPPolicy(root=root, allowed_commands=("python", "python3")))
        dispatcher = RPCDispatcher()
        register_remote_mcp(dispatcher, gateway)
        ctx = {"authenticated": True, "transport": "SHTTPS/2+STCP/1"}

        read = dispatcher.dispatch(RPCRequest(REMOTE_MCP_SERVICE, "read_file", {"path": "x.txt"}), ctx)
        assert read.ok and read.result["text"] == "hello"

        denied = dispatcher.dispatch(RPCRequest(REMOTE_MCP_SERVICE, "run", {"argv": ["sh", "-c", "echo bad"]}), ctx)
        assert not denied.ok

        escaped = dispatcher.dispatch(RPCRequest(REMOTE_MCP_SERVICE, "read_file", {"path": "../outside"}), ctx)
        assert not escaped.ok
