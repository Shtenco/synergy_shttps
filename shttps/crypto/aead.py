from __future__ import annotations
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from ..constants import CipherId
from ..errors import SecurityError

def seal(cipher_id: int, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12: raise SecurityError("invalid AEAD key/nonce length")
    if cipher_id == CipherId.CHACHA20_POLY1305: return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    if cipher_id == CipherId.AES_256_GCM: return AESGCM(key).encrypt(nonce, plaintext, aad)
    raise SecurityError("unsupported cipher")

def open_(cipher_id: int, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12: raise SecurityError("invalid AEAD key/nonce length")
    try:
        if cipher_id == CipherId.CHACHA20_POLY1305: return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
        if cipher_id == CipherId.AES_256_GCM: return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise SecurityError("AEAD authentication failed") from e
    raise SecurityError("unsupported cipher")
