from __future__ import annotations
from .envelope import Envelope
from .session import SecureSession
from .constants import FrameType

def seal_envelope(session: SecureSession, envelope: Envelope, *, stream_id: int = 0, sensitive: bool = False) -> bytes:
    return session.seal(envelope.encode(), stream_id=stream_id, frame_type=FrameType.DATA, sensitive=sensitive)

def open_envelope(session: SecureSession, frame: bytes) -> tuple[object, Envelope]:
    header, plaintext = session.open(frame)
    return header, Envelope.decode(plaintext)
