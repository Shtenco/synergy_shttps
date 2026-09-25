from __future__ import annotations
from dataclasses import dataclass, field
import json, struct, time, uuid
from typing import Any
from .canonical import canonical_json, sha3_256
from .errors import ProtocolError

_META_LEN = struct.Struct(">I")

@dataclass
class Envelope:
    protocol: str
    source: str
    destination: str
    payload: bytes
    content_type: str = "application/octet-stream"
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    def encode(self) -> bytes:
        meta = {"schema":"shttps.envelope/v1","protocol":self.protocol,"source":self.source,"destination":self.destination,"content_type":self.content_type,"message_id":self.message_id,"correlation_id":self.correlation_id,"created_ms":self.created_ms,"authority":"TRANSPORT_NONE","payload_sha3_256":sha3_256(self.payload).hex(),"metadata":self.metadata}
        blob = canonical_json(meta)
        return _META_LEN.pack(len(blob)) + blob + bytes(self.payload)

    @classmethod
    def decode(cls, data: bytes) -> "Envelope":
        if len(data) < 4: raise ProtocolError("truncated envelope")
        n = _META_LEN.unpack_from(data)[0]
        if n > len(data)-4: raise ProtocolError("truncated envelope metadata")
        try: meta = json.loads(data[4:4+n].decode("utf-8"))
        except Exception as e: raise ProtocolError("invalid envelope metadata") from e
        if meta.get("schema") != "shttps.envelope/v1" or meta.get("authority") != "TRANSPORT_NONE": raise ProtocolError("invalid envelope schema/authority")
        payload=data[4+n:]
        if meta.get("payload_sha3_256") != sha3_256(payload).hex(): raise ProtocolError("payload content hash mismatch")
        return cls(protocol=str(meta["protocol"]),source=str(meta["source"]),destination=str(meta["destination"]),payload=payload,content_type=str(meta.get("content_type","application/octet-stream")),message_id=str(meta["message_id"]),correlation_id=meta.get("correlation_id"),metadata=dict(meta.get("metadata") or {}),created_ms=int(meta.get("created_ms",0)))
