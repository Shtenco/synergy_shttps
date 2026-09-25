from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import subprocess
from typing import Any

from .rpc import RPCDispatcher

REMOTE_MCP_SERVICE = "synergy.remote.mcp.v1"


@dataclass(frozen=True)
class RemoteMCPPolicy:
    root: Path
    allowed_commands: tuple[str, ...] = ("git", "python", "python3", "cargo", "rustc")
    max_read_bytes: int = 2 * 1024 * 1024
    max_output_bytes: int = 512 * 1024
    command_timeout_seconds: float = 30.0

    def canonical_root(self) -> Path:
        return self.root.expanduser().resolve()


class RemoteMCPGateway:
    """Capability-bounded remote node control over authenticated SHTTPS RPC."""

    def __init__(self, policy: RemoteMCPPolicy) -> None:
        self.policy = policy
        self.root = policy.canonical_root()

    def _path(self, raw: str) -> Path:
        candidate = (self.root / raw).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError("path escapes remote MCP root") from exc
        return candidate

    def health(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {
            "service": REMOTE_MCP_SERVICE,
            "transport": context.get("transport"),
            "authenticated": bool(context.get("authenticated")),
            "root": str(self.root),
            "shell": False,
        }

    def list_dir(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        path = self._path(str(params.get("path") or "."))
        entries = []
        for item in sorted(path.iterdir(), key=lambda p: p.name)[:2000]:
            entries.append({
                "name": item.name,
                "type": "dir" if item.is_dir() else "file",
                "size": item.stat().st_size if item.is_file() else None,
            })
        return {"path": str(path.relative_to(self.root)), "entries": entries}

    def read_file(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        path = self._path(str(params.get("path") or ""))
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size > self.policy.max_read_bytes:
            raise ValueError("file exceeds remote MCP read limit")
        data = path.read_bytes()
        return {
            "path": str(path.relative_to(self.root)),
            "size": len(data),
            "text": data.decode("utf-8", errors="replace"),
        }

    def run(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        argv = params.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise ValueError("argv must be a non-empty string array")
        executable = os.path.basename(argv[0]).lower()
        allowed = {os.path.basename(x).lower() for x in self.policy.allowed_commands}
        if executable not in allowed:
            raise PermissionError("command is not allowlisted")
        cwd = self._path(str(params.get("cwd") or "."))
        if not cwd.is_dir():
            raise NotADirectoryError(cwd)
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            shell=False,
            capture_output=True,
            timeout=self.policy.command_timeout_seconds,
            check=False,
        )
        out = completed.stdout[: self.policy.max_output_bytes]
        err = completed.stderr[: self.policy.max_output_bytes]
        return {
            "returncode": completed.returncode,
            "stdout": out.decode("utf-8", errors="replace"),
            "stderr": err.decode("utf-8", errors="replace"),
            "truncated": len(completed.stdout) > len(out) or len(completed.stderr) > len(err),
        }


def register_remote_mcp(dispatcher: RPCDispatcher, gateway: RemoteMCPGateway) -> None:
    dispatcher.register(REMOTE_MCP_SERVICE, "health", gateway.health)
    dispatcher.register(REMOTE_MCP_SERVICE, "list_dir", gateway.list_dir)
    dispatcher.register(REMOTE_MCP_SERVICE, "read_file", gateway.read_file)
    dispatcher.register(REMOTE_MCP_SERVICE, "run", gateway.run)
