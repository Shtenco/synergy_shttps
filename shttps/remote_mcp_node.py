from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from .bootstrap import rpc_server_from_env
from .remote_mcp import RemoteMCPGateway, RemoteMCPPolicy, register_remote_mcp
from .rpc import RPCDispatcher


def _allowed(raw: str) -> tuple[str, ...]:
    values = tuple(x.strip() for x in raw.split(",") if x.strip())
    if not values:
        raise ValueError("at least one allowlisted command is required")
    return values


async def _run(args: argparse.Namespace) -> None:
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"remote MCP root is not a directory: {root}")

    policy = RemoteMCPPolicy(
        root=root,
        allowed_commands=_allowed(args.allow_commands),
        max_read_bytes=args.max_read_bytes,
        max_output_bytes=args.max_output_bytes,
        command_timeout_seconds=args.command_timeout,
    )
    gateway = RemoteMCPGateway(policy)
    dispatcher = RPCDispatcher()
    register_remote_mcp(dispatcher, gateway)

    server = rpc_server_from_env(
        args.prefix,
        dispatcher,
        host_default=args.bind,
        port_default=args.port,
        roles=("mcp-node",),
    )
    print(
        f"SYNERGY Remote MCP node listening on {args.bind}:{args.port}; "
        f"root={root}; allow={','.join(policy.allowed_commands)}",
        flush=True,
    )
    await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="synergy-remote-mcp-node",
        description="Serve capability-bounded Remote MCP methods over authenticated SHTTPS.",
    )
    parser.add_argument("--prefix", default="SYNERGY_NODE")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--root", required=True)
    parser.add_argument("--allow-commands", default="git,python,python3,cargo,rustc")
    parser.add_argument("--max-read-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--max-output-bytes", type=int, default=512 * 1024)
    parser.add_argument("--command-timeout", type=float, default=30.0)
    args = parser.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
