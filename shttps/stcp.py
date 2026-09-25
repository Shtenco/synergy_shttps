from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct

from .errors import ProtocolError, SecurityError

MAGIC = b"STCP"
VERSION = 1
_HEADER = struct.Struct(">4sBBHQQI")
MAX_STCP_PAYLOAD = 16 * 1024 * 1024


class StreamClass(IntEnum):
    CONTROL = 0
    RPC = 1
    INFERENCE = 2
    MODEL = 3
    STORAGE = 4
    EVM = 5
    BRIDGE = 6
    MCP = 7


@dataclass(frozen=True)
class STCPFrame:
    stream_class: StreamClass
    stream_id: int
    sequence: int
    payload: bytes
    flags: int = 0

    def encode(self) -> bytes:
        if not (0 <= self.flags <= 0xFFFF):
            raise ProtocolError("invalid STCP flags")
        if self.stream_id < 0 or self.sequence < 0:
            raise ProtocolError("negative STCP stream id/sequence")
        if not self.payload or len(self.payload) > MAX_STCP_PAYLOAD:
            raise ProtocolError("STCP payload outside limit")
        return _HEADER.pack(
            MAGIC,
            VERSION,
            int(self.stream_class),
            self.flags,
            self.stream_id,
            self.sequence,
            len(self.payload),
        ) + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "STCPFrame":
        if len(data) < _HEADER.size:
            raise ProtocolError("short STCP frame")
        magic, version, stream_class, flags, stream_id, sequence, size = _HEADER.unpack(
            data[:_HEADER.size]
        )
        if magic != MAGIC or version != VERSION:
            raise ProtocolError("invalid STCP magic/version")
        if size <= 0 or size > MAX_STCP_PAYLOAD or len(data) != _HEADER.size + size:
            raise ProtocolError("invalid STCP payload length")
        try:
            sc = StreamClass(stream_class)
        except ValueError as exc:
            raise ProtocolError("unknown STCP stream class") from exc
        return cls(sc, stream_id, sequence, data[_HEADER.size:], flags)


class STCPMux:
    """Ordered per-stream transport metadata for SHTTPS-protected records."""

    def __init__(self) -> None:
        self._send_seq: dict[int, int] = {}
        self._recv_seq: dict[int, int] = {}

    def wrap(self, stream_class: StreamClass, stream_id: int, payload: bytes, *, flags: int = 0) -> bytes:
        seq = self._send_seq.get(stream_id, 0)
        self._send_seq[stream_id] = seq + 1
        return STCPFrame(stream_class, stream_id, seq, payload, flags).encode()

    def unwrap(self, data: bytes) -> STCPFrame:
        frame = STCPFrame.decode(data)
        expected = self._recv_seq.get(frame.stream_id, 0)
        if frame.sequence != expected:
            raise SecurityError("STCP replay/reorder outside ordered stream contract")
        self._recv_seq[frame.stream_id] = expected + 1
        return frame
