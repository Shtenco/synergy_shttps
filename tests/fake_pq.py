from __future__ import annotations
import hashlib,hmac,os
from shttps.crypto.base import KeyPair

class FakePQProvider:
    name="fake-test-provider"
    def kem_generate_keypair(self, mechanism:str)->KeyPair:
        sk=os.urandom(32); return KeyPair(hashlib.sha3_256(b"kem"+sk).digest(),sk)
    def kem_encapsulate(self, mechanism:str, public_key:bytes)->tuple[bytes,bytes]:
        r=os.urandom(32); ct=r; ss=hashlib.sha3_512(b"kemss"+public_key+r).digest(); return ct,ss
    def kem_decapsulate(self, mechanism:str, secret_key:bytes, ciphertext:bytes)->bytes:
        pk=hashlib.sha3_256(b"kem"+secret_key).digest(); return hashlib.sha3_512(b"kemss"+pk+ciphertext).digest()
    def sig_generate_keypair(self, mechanism:str)->KeyPair:
        sk=os.urandom(32); return KeyPair(sk,sk)
    def sign(self, mechanism:str, secret_key:bytes, message:bytes)->bytes:
        return hmac.new(secret_key,mechanism.encode()+message,hashlib.sha3_512).digest()
    def verify(self, mechanism:str, public_key:bytes, message:bytes, signature:bytes)->bool:
        expected=hmac.new(public_key,mechanism.encode()+message,hashlib.sha3_512).digest(); return hmac.compare_digest(expected,signature)
