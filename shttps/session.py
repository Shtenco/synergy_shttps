from __future__ import annotations
from dataclasses import dataclass, field
import time
from .constants import CipherId, CompressionId, FrameFlags, FrameType, MAX_FRAME_BYTES, MAX_PLAINTEXT_BYTES, REKEY_AFTER_MESSAGES, REKEY_AFTER_SECONDS
from .compression import AICompressAdapter
from .crypto.aead import seal, open_
from .framing import HEADER, FrameHeader, nonce
from .replay import ReplayWindow
from .errors import ProtocolError, SecurityError

@dataclass
class SecureSession:
    session_id: bytes
    send_key: bytes
    recv_key: bytes
    cipher: CipherId = CipherId.CHACHA20_POLY1305
    compression: CompressionId = CompressionId.RAW
    epoch: int = 0
    send_sequence: int = 0
    compression_adapter: AICompressAdapter | None = None
    created_monotonic: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        if len(self.session_id) != 16 or len(self.send_key) != 32 or len(self.recv_key) != 32: raise SecurityError("invalid session key material")
        self.replay = ReplayWindow()
        self.compression_adapter = self.compression_adapter or AICompressAdapter()

    def seal(self, plaintext: bytes, *, stream_id: int = 0, frame_type: FrameType = FrameType.DATA, sensitive: bool = False) -> bytes:
        plaintext = bytes(plaintext)
        if len(plaintext) > MAX_PLAINTEXT_BYTES: raise ProtocolError("plaintext too large")
        decision = self.compression_adapter.compress(plaintext, self.compression, sensitive=sensitive)
        flags = FrameFlags.SENSITIVE if sensitive else FrameFlags.NONE
        if decision.codec != CompressionId.RAW: flags |= FrameFlags.COMPRESSED
        body_len = len(decision.data) + 16
        header = FrameHeader(frame_type, flags, decision.codec, self.cipher, self.epoch, self.send_sequence, stream_id, len(plaintext), body_len)
        aad = header.pack() + self.session_id
        body = seal(self.cipher, self.send_key, nonce(self.epoch, self.send_sequence), decision.data, aad)
        if len(body) != body_len: raise SecurityError("unexpected AEAD body size")
        self.send_sequence += 1
        return header.pack() + body

    def open(self, frame: bytes) -> tuple[FrameHeader, bytes]:
        if len(frame) < HEADER.size or len(frame) > HEADER.size + MAX_FRAME_BYTES: raise ProtocolError("invalid frame size")
        header_blob = frame[:HEADER.size]; header = FrameHeader.unpack(header_blob)
        if header.epoch != self.epoch: raise SecurityError("unexpected epoch")
        if header.cipher != self.cipher: raise SecurityError("record cipher differs from negotiated session cipher")
        if header.compression not in {CompressionId.RAW, self.compression}:
            raise SecurityError("record compression differs from negotiated session profile")
        compressed_flag = bool(header.flags & FrameFlags.COMPRESSED)
        if compressed_flag != (header.compression != CompressionId.RAW):
            raise ProtocolError("compression flag/profile mismatch")
        if (header.flags & FrameFlags.SENSITIVE) and header.compression != CompressionId.RAW:
            raise SecurityError("sensitive record must not be compressed")
        if len(frame) != HEADER.size + header.body_len: raise ProtocolError("body length mismatch")
        aad = header_blob + self.session_id
        compressed = open_(header.cipher, self.recv_key, nonce(header.epoch, header.sequence), frame[HEADER.size:], aad)
        self.replay.check_and_mark(header.sequence)
        plain = self.compression_adapter.decompress(header.compression, compressed, header.plaintext_len)
        return header, plain

    def should_rekey(self) -> bool:
        return self.send_sequence >= REKEY_AFTER_MESSAGES or (time.monotonic() - self.created_monotonic) >= REKEY_AFTER_SECONDS

    def rekey(self, *, new_send_key: bytes, new_recv_key: bytes, new_session_id: bytes | None = None) -> None:
        if len(new_send_key) != 32 or len(new_recv_key) != 32: raise SecurityError("invalid rekey material")
        if self.epoch == 2**32 - 1: raise SecurityError("epoch exhausted")
        self.send_key = new_send_key; self.recv_key = new_recv_key
        if new_session_id is not None:
            if len(new_session_id) != 16: raise SecurityError("invalid session id")
            self.session_id = new_session_id
        self.epoch += 1; self.send_sequence = 0; self.replay = ReplayWindow(); self.created_monotonic = time.monotonic()
