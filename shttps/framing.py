from __future__ import annotations
from dataclasses import dataclass
import struct
from .constants import MAGIC, PROTOCOL_VERSION, MAX_FRAME_BYTES, MAX_PLAINTEXT_BYTES, FrameFlags, FrameType, CompressionId, CipherId
from .errors import ProtocolError

HEADER = struct.Struct(">4sBBHHHIQQII")

@dataclass(frozen=True)
class FrameHeader:
    frame_type: FrameType
    flags: FrameFlags
    compression: CompressionId
    cipher: CipherId
    epoch: int
    sequence: int
    stream_id: int
    plaintext_len: int
    body_len: int

    def pack(self) -> bytes:
        if not (0 <= self.epoch < 2**32 and 0 <= self.sequence < 2**64 and 0 <= self.stream_id < 2**64): raise ProtocolError("counter out of range")
        if not (0 <= self.plaintext_len <= MAX_PLAINTEXT_BYTES): raise ProtocolError("plaintext length out of range")
        if not (0 <= self.body_len <= MAX_FRAME_BYTES): raise ProtocolError("body length out of range")
        return HEADER.pack(MAGIC, PROTOCOL_VERSION, int(self.frame_type), int(self.flags), int(self.compression), int(self.cipher), self.epoch, self.sequence, self.stream_id, self.plaintext_len, self.body_len)

    @classmethod
    def unpack(cls, data: bytes) -> "FrameHeader":
        if len(data) != HEADER.size: raise ProtocolError("invalid header size")
        magic, version, ft, flags, comp, cipher, epoch, seq, stream, plain, body = HEADER.unpack(data)
        if magic != MAGIC or version != PROTOCOL_VERSION: raise ProtocolError("unsupported SHTTPS frame")
        if plain > MAX_PLAINTEXT_BYTES or body > MAX_FRAME_BYTES: raise ProtocolError("frame exceeds limits")
        known_flags = int(FrameFlags.COMPRESSED | FrameFlags.SENSITIVE | FrameFlags.PADDED)
        if flags & ~known_flags: raise ProtocolError("unknown/reserved frame flags")
        try:
            return cls(FrameType(ft), FrameFlags(flags), CompressionId(comp), CipherId(cipher), epoch, seq, stream, plain, body)
        except ValueError as e: raise ProtocolError("unknown frame enum") from e

def nonce(epoch: int, sequence: int) -> bytes:
    return struct.pack(">IQ", epoch, sequence)
