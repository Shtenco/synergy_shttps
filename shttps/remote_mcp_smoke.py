from __future__ import annotations

import argparse
import asyncio
import json

from .bootstrap import rpc_client_from_env
from .remote_mcp import REMOTE_MCP_SERVICE


async def _run(prefix: str) -> int:
    client = rpc_client_from_env(
        prefix,
        host_default="127.0.0.1",
        port_default=9443,
        roles=("mcp-controller",),
    )
    health = await client.call(REMOTE_MCP_SERVICE, "health", {})
    listing = await client.call(REMOTE_MCP_SERVICE, "list_dir", {"path": "."})
    print(json.dumps({
        "schema": "synergy.remote-mcp-smoke/v1",
        "health": health,
        "root_entry_count": len(listing.get("entries", [])),
        "status": "PASS",
    }, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="synergy-remote-mcp-smoke")
    parser.add_argument("--prefix", default="SYNERGY_MCP")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_run(args.prefix)))


if __name__ == "__main__":
    main()
