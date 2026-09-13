from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..constants import SIG_ML_DSA_87
from ..errors import ProviderUnavailable, SecurityError


@dataclass(frozen=True)
class PKCS11SignerConfig:
    module: str
    token_label: str
    key_label: str
    pin_file: str

    def read_pin(self) -> str:
        p = Path(self.pin_file)
        if not p.is_file():
            raise ProviderUnavailable("PKCS#11 PIN file is unavailable")
        value = p.read_text(encoding="utf-8").strip()
        if not value:
            raise ProviderUnavailable("PKCS#11 PIN file is empty")
        return value


class PKCS11MLDSASigner:
    """Non-exportable ML-DSA-87 signing key backed by a PKCS#11 token."""

    scheme = SIG_ML_DSA_87

    def __init__(self, config: PKCS11SignerConfig) -> None:
        self.config = config
        try:
            import pkcs11  # type: ignore
            from pkcs11 import Attribute, KeyType, ObjectClass  # type: ignore
        except Exception as exc:
            raise ProviderUnavailable("python-pkcs11 is not available") from exc
        try:
            self._lib = pkcs11.lib(config.module)
            self._token = self._lib.get_token(token_label=config.token_label)
            with self._token.open(user_pin=config.read_pin()) as session:
                public = session.get_key(object_class=ObjectClass.PUBLIC_KEY, key_type=KeyType.ML_DSA, label=config.key_label)
                value = bytes(public[Attribute.VALUE])
        except Exception as exc:
            raise ProviderUnavailable(f"unable to open PKCS#11 ML-DSA signer: {exc}") from exc
        if not value:
            raise ProviderUnavailable("PKCS#11 ML-DSA public key is empty")
        self._public = value

    @property
    def public_keys(self) -> Mapping[str, bytes]:
        return {SIG_ML_DSA_87: self._public}

    def sign(self, mechanism: str, message: bytes) -> bytes:
        if mechanism != SIG_ML_DSA_87:
            raise SecurityError(f"PKCS#11 signer does not support {mechanism}")
        try:
            from pkcs11 import KeyType, ObjectClass, Mechanism  # type: ignore
            with self._token.open(user_pin=self.config.read_pin()) as session:
                private = session.get_key(object_class=ObjectClass.PRIVATE_KEY, key_type=KeyType.ML_DSA, label=self.config.key_label)
                return bytes(private.sign(message, mechanism=Mechanism.ML_DSA))
        except Exception as exc:
            raise ProviderUnavailable(f"PKCS#11 ML-DSA signing failed: {exc}") from exc

    @classmethod
    def generate(cls, config: PKCS11SignerConfig, verifier) -> "PKCS11MLDSASigner":
        try:
            import pkcs11  # type: ignore
            from pkcs11 import Attribute, KeyType, Mechanism  # type: ignore
            from pkcs11.mechanisms import MLDSAParameterSet  # type: ignore
        except Exception as exc:
            raise ProviderUnavailable("python-pkcs11 is not available") from exc
        lib = pkcs11.lib(config.module)
        token = lib.get_token(token_label=config.token_label)
        pin = config.read_pin()
        challenge = b"SHTTPS/1/pkcs11-mldsa87-interoperability\x00"
        try:
            with token.open(rw=True, user_pin=pin) as session:
                existing = list(session.get_objects({Attribute.LABEL: config.key_label}))
                if existing:
                    raise SecurityError("PKCS#11 signer key label already exists")
                public, private = session.generate_keypair(
                    KeyType.ML_DSA,
                    label=config.key_label,
                    store=True,
                    mechanism=Mechanism.ML_DSA_KEY_PAIR_GEN,
                    public_template={Attribute.PARAMETER_SET: MLDSAParameterSet.ML_DSA_87, Attribute.VERIFY: True},
                    private_template={Attribute.SIGN: True, Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False, Attribute.PRIVATE: True},
                )
                public_value = bytes(public[Attribute.VALUE])
                signature = bytes(private.sign(challenge, mechanism=Mechanism.ML_DSA))
        except SecurityError:
            raise
        except Exception as exc:
            raise ProviderUnavailable(f"PKCS#11 ML-DSA-87 key generation failed: {exc}") from exc
        if not public_value or not verifier.verify(SIG_ML_DSA_87, public_value, challenge, signature):
            raise SecurityError("PKCS#11/OQS ML-DSA-87 interoperability test failed")
        return cls(config)
