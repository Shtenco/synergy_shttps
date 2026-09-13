from __future__ import annotations
from .base import KeyPair
from ..errors import ProviderUnavailable

class OQSProvider:
    """Standards-conformant provider boundary backed by Open Quantum Safe/liboqs.

    This module intentionally does not implement lattice/hash-signature mathematics.
    It binds SHTTPS to a reviewed provider, matching the SYNERGY PQ security invariant.
    """
    name = "open-quantum-safe/liboqs"
    def __init__(self) -> None:
        try:
            import oqs  # type: ignore
        except Exception as e:
            raise ProviderUnavailable("liboqs-python is not available") from e
        self.oqs = oqs

    def _require_kem(self, mechanism: str) -> None:
        if mechanism not in self.oqs.get_enabled_kem_mechanisms():
            raise ProviderUnavailable(f"KEM not enabled by liboqs: {mechanism}")

    def _require_sig(self, mechanism: str) -> None:
        if mechanism not in self.oqs.get_enabled_sig_mechanisms():
            raise ProviderUnavailable(f"signature not enabled by liboqs: {mechanism}")

    def kem_generate_keypair(self, mechanism: str) -> KeyPair:
        self._require_kem(mechanism)
        with self.oqs.KeyEncapsulation(mechanism) as kem:
            public = kem.generate_keypair(); secret = kem.export_secret_key()
        return KeyPair(public, secret)

    def kem_encapsulate(self, mechanism: str, public_key: bytes) -> tuple[bytes, bytes]:
        self._require_kem(mechanism)
        with self.oqs.KeyEncapsulation(mechanism) as kem:
            return kem.encap_secret(public_key)

    def kem_decapsulate(self, mechanism: str, secret_key: bytes, ciphertext: bytes) -> bytes:
        self._require_kem(mechanism)
        with self.oqs.KeyEncapsulation(mechanism, secret_key) as kem:
            return kem.decap_secret(ciphertext)

    def sig_generate_keypair(self, mechanism: str) -> KeyPair:
        self._require_sig(mechanism)
        with self.oqs.Signature(mechanism) as sig:
            public = sig.generate_keypair(); secret = sig.export_secret_key()
        return KeyPair(public, secret)

    def sign(self, mechanism: str, secret_key: bytes, message: bytes) -> bytes:
        self._require_sig(mechanism)
        with self.oqs.Signature(mechanism, secret_key) as sig:
            return sig.sign(message)

    def verify(self, mechanism: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self._require_sig(mechanism)
        with self.oqs.Signature(mechanism) as sig:
            return bool(sig.verify(message, signature, public_key))
