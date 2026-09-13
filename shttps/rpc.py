from __future__ import annotations

from dataclasses import dataclass, field
import json
import uuid
from typing import Any, Callable

from .canonical import canonical_json
from .errors import ProtocolError

RPC_PROTOCOL = "shttps.rpc/v1"


@dataclass(frozen=True)
class RPCRequest:
    service: str
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: dict[str, Any] = field(default_factory=dict)

    def encode(self) -> bytes:
        if not self.service or not self.method:
            raise ProtocolError("RPC service/method required")
        return canonical_json({
            "schema": "shttps.rpc-request/v1",
            "request_id": self.request_id,
            "service": self.service,
            "method": self.method,
            "params": self.params,
            "metadata": self.metadata,
            "authority": "APPLICATION_POLICY_REQUIRED",
        })

    @classmethod
    def decode(cls, payload: bytes) -> "RPCRequest":
        try:
            data = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise ProtocolError("invalid RPC request JSON") from exc
        if data.get("schema") != "shttps.rpc-request/v1":
            raise ProtocolError("invalid RPC request schema")
        if data.get("authority") != "APPLICATION_POLICY_REQUIRED":
            raise ProtocolError("invalid RPC authority marker")
        params = data.get("params")
        metadata = data.get("metadata")
        if not isinstance(params, dict) or not isinstance(metadata, dict):
            raise ProtocolError("RPC params/metadata must be objects")
        return cls(service=str(data.get("service") or ""), method=str(data.get("method") or ""), params=params, request_id=str(data.get("request_id") or ""), metadata=metadata)


@dataclass(frozen=True)
class RPCResponse:
    request_id: str
    ok: bool
    result: Any = None
    error: str | None = None

    def encode(self) -> bytes:
        return canonical_json({"schema": "shttps.rpc-response/v1", "request_id": self.request_id, "ok": bool(self.ok), "result": self.result, "error": self.error, "authority": "TRANSPORT_NONE"})

    @classmethod
    def decode(cls, payload: bytes) -> "RPCResponse":
        try:
            data = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise ProtocolError("invalid RPC response JSON") from exc
        if data.get("schema") != "shttps.rpc-response/v1" or data.get("authority") != "TRANSPORT_NONE":
            raise ProtocolError("invalid RPC response schema/authority")
        return cls(request_id=str(data.get("request_id") or ""), ok=bool(data.get("ok")), result=data.get("result"), error=str(data["error"]) if data.get("error") is not None else None)


class RPCDispatcher:
    """Explicit allowlist dispatcher. Transport authentication never grants a method."""
    def __init__(self) -> None:
        self._handlers: dict[tuple[str, str], Callable[[dict[str, Any], dict[str, Any]], Any]] = {}

    def register(self, service: str, method: str, handler: Callable[[dict[str, Any], dict[str, Any]], Any]) -> None:
        key = (service, method)
        if not service or not method or key in self._handlers:
            raise ValueError("invalid or duplicate RPC route")
        self._handlers[key] = handler

    def routes(self) -> list[str]:
        return [f"{s}.{m}" for s, m in sorted(self._handlers)]

    def dispatch(self, request: RPCRequest, context: dict[str, Any]) -> RPCResponse:
        handler = self._handlers.get((request.service, request.method))
        if handler is None:
            return RPCResponse(request.request_id, False, error="RPC_METHOD_NOT_ALLOWED")
        try:
            return RPCResponse(request.request_id, True, result=handler(request.params, context))
        except Exception as exc:
            return RPCResponse(request.request_id, False, error=f"{type(exc).__name__}: {exc}")
