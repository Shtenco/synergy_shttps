from __future__ import annotations
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _derive(ikm: bytes, transcript_hash: bytes, info: bytes, length: int) -> bytes:
    if not ikm or not transcript_hash:
        raise ValueError("IKM and transcript hash are required")
    return HKDF(
        algorithm=hashes.SHA3_512(),
        length=length,
        salt=transcript_hash,
        info=b"SHTTPS/1/" + info,
    ).derive(ikm)


def derive_session_material(ikm: bytes, transcript_hash: bytes) -> dict[str, bytes]:
    """Derive independent, domain-separated SHTTPS traffic/session values.

    HKDF is provided by ``cryptography`` rather than by protocol-local crypto math.
    """
    return {
        "client_write": _derive(ikm, transcript_hash, b"client-write", 32),
        "server_write": _derive(ikm, transcript_hash, b"server-write", 32),
        "finished": _derive(ikm, transcript_hash, b"finished", 32),
        "session_id": _derive(ikm, transcript_hash, b"session-id", 16),
        "rekey_seed": _derive(ikm, transcript_hash, b"rekey-seed", 32),
    }
