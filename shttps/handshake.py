from __future__ import annotations
from dataclasses import dataclass, field
import hashlib, hmac, os
from typing import Iterable
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .canonical import b64e, b64d, canonical_json, sha3_256, sha3_512
from .constants import (
    KEM_ML_KEM_1024, SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S, CLASSICAL_X25519,
    CipherId, CompressionId, DEFAULT_PROTOCOLS, MAX_HANDSHAKE_BYTES,
)
from .crypto.base import PQProvider, KeyPair
from .errors import ProtocolError, SecurityError
from .kdf import derive_session_material

D_CH = b"SHTTPS/1/client-hello\x00"
D_SH = b"SHTTPS/1/server-hello\x00"
D_CF = b"SHTTPS/1/client-finish\x00"

@dataclass
class Identity:
    public_keys: dict[str, bytes]
    secret_keys: dict[str, bytes]

    @classmethod
    def generate(cls, provider: PQProvider, schemes: Iterable[str]) -> "Identity":
        pub={}; sec={}
        for scheme in schemes:
            kp=provider.sig_generate_keypair(scheme); pub[scheme]=kp.public_key; sec[scheme]=kp.secret_key
        return cls(pub,sec)

    @property
    def node_id(self) -> str:
        material = canonical_json({k:b64e(v) for k,v in sorted(self.public_keys.items())})
        return sha3_256(b"SHTTPS/1/node-id\x00"+material).hex()

@dataclass
class PinnedTrustStore:
    peers: dict[str, dict[str, bytes]] = field(default_factory=dict)
    def pin(self, identity: Identity) -> None: self.peers[identity.node_id] = dict(identity.public_keys)
    def verify(self, node_id: str, keys: dict[str, bytes]) -> bool:
        expected=self.peers.get(node_id); return expected is not None and expected == keys

@dataclass(frozen=True)
class HandshakeConfig:
    identity_schemes: tuple[str,...]=(SIG_ML_DSA_87,)
    kem: str=KEM_ML_KEM_1024
    use_x25519_hybrid: bool=True
    ciphers: tuple[CipherId,...]=(CipherId.CHACHA20_POLY1305,CipherId.AES_256_GCM)
    # Fail-safe default: never advertise a codec that is not locally installed.
    # Use ``with_ai_compress`` to advertise the validated local SGH1 profiles.
    compressions: tuple[CompressionId,...]=(CompressionId.RAW,)
    protocols: tuple[str,...]=DEFAULT_PROTOCOLS
    roles: tuple[str,...]=()

    @classmethod
    def with_ai_compress(cls, adapter, **kwargs) -> "HandshakeConfig":
        available = set(adapter.available_codecs())
        preferred = (
            CompressionId.AI_COMPRESS_SGH1_SPEED,
            CompressionId.AI_COMPRESS_SGH1_BALANCED,
            CompressionId.AI_COMPRESS_SGH1_MAX,
            CompressionId.RAW,
        )
        return cls(compressions=tuple(x for x in preferred if x in available), **kwargs)

@dataclass
class _ClientState:
    identity: Identity; kem: KeyPair; x_priv: X25519PrivateKey|None; hello: dict; config: HandshakeConfig
@dataclass
class _ServerState:
    identity: Identity; kem: KeyPair; x_priv: X25519PrivateKey|None; client_hello: dict; server_hello: dict; pq_s2c: bytes; config: HandshakeConfig
@dataclass(frozen=True)
class HandshakeSecrets:
    material: dict[str,bytes]; cipher: CipherId; compression: CompressionId; peer_node_id: str; transcript_hash: bytes

def _wire_keys(keys: dict[str,bytes])->dict[str,str]: return {k:b64e(v) for k,v in sorted(keys.items())}
def _read_keys(keys: dict[str,str])->dict[str,bytes]: return {str(k):b64d(str(v)) for k,v in keys.items()}
def _sign(provider:PQProvider, identity:Identity, schemes:Iterable[str], message:bytes)->dict[str,str]: return {s:b64e(provider.sign(s,identity.secret_keys[s],message)) for s in schemes}
def _verify(provider:PQProvider, keys:dict[str,bytes], signatures:dict[str,str], schemes:Iterable[str], message:bytes)->None:
    for s in schemes:
        if s not in keys or s not in signatures or not provider.verify(s,keys[s],message,b64d(signatures[s])): raise SecurityError(f"identity signature failed: {s}")
def _identity_ok(node_id:str, keys:dict[str,bytes], trust:PinnedTrustStore)->None:
    derived=sha3_256(b"SHTTPS/1/node-id\x00"+canonical_json({k:b64e(v) for k,v in sorted(keys.items())})).hex()
    if derived != node_id or not trust.verify(node_id,keys): raise SecurityError("untrusted or mismatched node identity")
def _choose(offered:list[int], preferred:tuple)->int:
    for x in preferred:
        if int(x) in offered:return int(x)
    raise ProtocolError("no mutually supported suite")
def _xpub(priv:X25519PrivateKey|None)->str|None:
    return b64e(priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)) if priv else None

def _guard_handshake(message: dict) -> None:
    if len(canonical_json(message)) > MAX_HANDSHAKE_BYTES:
        raise ProtocolError("handshake message exceeds limit")

def _require_identity_policy(peer_schemes: Iterable[str], required: tuple[str, ...]) -> tuple[str, ...]:
    schemes = tuple(str(s) for s in peer_schemes)
    # Exact set equality is deliberate: a MAX/PQ-only node must never silently
    # accept a weaker peer identity lane through subset negotiation.
    if len(schemes) != len(set(schemes)) or set(schemes) != set(required):
        raise SecurityError("identity policy mismatch or downgrade")
    return schemes

def start_client(provider:PQProvider, identity:Identity, config:HandshakeConfig)->tuple[dict,_ClientState]:
    kem=provider.kem_generate_keypair(config.kem); x=X25519PrivateKey.generate() if config.use_x25519_hybrid else None
    body={"schema":"shttps.client-hello/v1","version":1,"node_id":identity.node_id,"identity_keys":_wire_keys(identity.public_keys),"identity_schemes":list(config.identity_schemes),"random":b64e(os.urandom(32)),"kem":config.kem,"kem_public":b64e(kem.public_key),"classical_kex":CLASSICAL_X25519 if x else None,"x25519_public":_xpub(x),"ciphers":[int(x) for x in config.ciphers],"compressions":[int(x) for x in config.compressions],"protocols":list(config.protocols),"roles":list(config.roles)}
    signatures=_sign(provider,identity,config.identity_schemes,D_CH+canonical_json(body)); hello={"body":body,"signatures":signatures}
    _guard_handshake(hello)
    return hello,_ClientState(identity,kem,x,hello,config)

def accept_client(provider:PQProvider, identity:Identity, config:HandshakeConfig, trust:PinnedTrustStore, client_hello:dict)->tuple[dict,_ServerState]:
    _guard_handshake(client_hello)
    cb=client_hello.get("body") or {}; keys=_read_keys(cb.get("identity_keys") or {}); schemes=_require_identity_policy(cb.get("identity_schemes") or [], config.identity_schemes)
    if cb.get("schema")!="shttps.client-hello/v1" or cb.get("version")!=1 or cb.get("kem")!=config.kem: raise ProtocolError("invalid client hello")
    _identity_ok(str(cb.get("node_id")),keys,trust); _verify(provider,keys,client_hello.get("signatures") or {},schemes,D_CH+canonical_json(cb))
    cipher=CipherId(_choose(list(cb.get("ciphers") or []),config.ciphers)); compression=CompressionId(_choose(list(cb.get("compressions") or []),config.compressions))
    kem=provider.kem_generate_keypair(config.kem); ct_s2c,pq_s2c=provider.kem_encapsulate(config.kem,b64d(cb["kem_public"]))
    hybrid=config.use_x25519_hybrid and cb.get("classical_kex")==CLASSICAL_X25519 and cb.get("x25519_public")
    x=X25519PrivateKey.generate() if hybrid else None
    protocols=[p for p in config.protocols if p in set(cb.get("protocols") or [])]
    if not protocols: raise ProtocolError("no mutually supported application protocol")
    body={"schema":"shttps.server-hello/v1","version":1,"node_id":identity.node_id,"identity_keys":_wire_keys(identity.public_keys),"identity_schemes":list(config.identity_schemes),"random":b64e(os.urandom(32)),"kem":config.kem,"kem_public":b64e(kem.public_key),"kem_ciphertext_to_client":b64e(ct_s2c),"classical_kex":CLASSICAL_X25519 if x else None,"x25519_public":_xpub(x),"cipher":int(cipher),"compression":int(compression),"protocols":protocols,"roles":list(config.roles)}
    signed=D_SH+sha3_512(canonical_json(client_hello))+canonical_json(body); sh={"body":body,"signatures":_sign(provider,identity,config.identity_schemes,signed)}
    _guard_handshake(sh)
    return sh,_ServerState(identity,kem,x,client_hello,sh,pq_s2c,config)

def finish_client(provider:PQProvider,state:_ClientState,trust:PinnedTrustStore,server_hello:dict)->tuple[dict,HandshakeSecrets]:
    _guard_handshake(server_hello)
    sb=server_hello.get("body") or {}; keys=_read_keys(sb.get("identity_keys") or {}); schemes=_require_identity_policy(sb.get("identity_schemes") or [], state.config.identity_schemes)
    if sb.get("schema")!="shttps.server-hello/v1" or sb.get("version")!=1 or sb.get("kem")!=state.config.kem: raise ProtocolError("invalid server hello")
    try:
        chosen_cipher=CipherId(sb["cipher"]); chosen_compression=CompressionId(sb["compression"])
    except (KeyError, ValueError) as e:
        raise ProtocolError("invalid negotiated suite") from e
    if chosen_cipher not in state.config.ciphers or chosen_compression not in state.config.compressions:
        raise SecurityError("server selected an unoffered suite")
    negotiated_protocols=tuple(sb.get("protocols") or [])
    if not negotiated_protocols or any(p not in state.config.protocols for p in negotiated_protocols):
        raise SecurityError("invalid application-protocol negotiation")
    server_hybrid=sb.get("classical_kex")==CLASSICAL_X25519 and bool(sb.get("x25519_public"))
    if server_hybrid and not state.config.use_x25519_hybrid:
        raise SecurityError("unexpected classical hybrid lane")
    _identity_ok(str(sb.get("node_id")),keys,trust); _verify(provider,keys,server_hello.get("signatures") or {},schemes,D_SH+sha3_512(canonical_json(state.hello))+canonical_json(sb))
    pq_s2c=provider.kem_decapsulate(state.config.kem,state.kem.secret_key,b64d(sb["kem_ciphertext_to_client"])); ct_c2s,pq_c2s=provider.kem_encapsulate(state.config.kem,b64d(sb["kem_public"]))
    classical=b""
    if state.x_priv and sb.get("x25519_public"):
        classical=state.x_priv.exchange(X25519PublicKey.from_public_bytes(b64d(sb["x25519_public"])))
    body={"schema":"shttps.client-finish/v1","kem_ciphertext_to_server":b64e(ct_c2s)}
    pre=canonical_json(state.hello)+canonical_json(server_hello)+canonical_json(body); th=sha3_512(pre); ikm=pq_c2s+pq_s2c+classical; material=derive_session_material(ikm,th)
    body["finished_mac"]=b64e(hmac.new(material["finished"],b"client"+th,hashlib.sha3_256).digest())
    signed=D_CF+sha3_512(canonical_json(state.hello))+sha3_512(canonical_json(server_hello))+canonical_json(body)
    cf={"body":body,"signatures":_sign(provider,state.identity,state.config.identity_schemes,signed)}
    _guard_handshake(cf)
    return cf,HandshakeSecrets(material,chosen_cipher,chosen_compression,str(sb["node_id"]),th)

def finish_server(provider:PQProvider,state:_ServerState,trust:PinnedTrustStore,client_finish:dict)->tuple[dict,HandshakeSecrets]:
    _guard_handshake(client_finish)
    cb=state.client_hello["body"]; keys=_read_keys(cb["identity_keys"]); schemes=_require_identity_policy(cb["identity_schemes"], state.config.identity_schemes); fb=client_finish.get("body") or {}
    if fb.get("schema")!="shttps.client-finish/v1": raise ProtocolError("invalid client finish")
    signed=D_CF+sha3_512(canonical_json(state.client_hello))+sha3_512(canonical_json(state.server_hello))+canonical_json(fb)
    _identity_ok(str(cb["node_id"]),keys,trust); _verify(provider,keys,client_finish.get("signatures") or {},schemes,signed)
    pq_c2s=provider.kem_decapsulate(state.config.kem,state.kem.secret_key,b64d(fb["kem_ciphertext_to_server"])); classical=b""
    if state.x_priv and cb.get("x25519_public"): classical=state.x_priv.exchange(X25519PublicKey.from_public_bytes(b64d(cb["x25519_public"])))
    unsigned={"schema":"shttps.client-finish/v1","kem_ciphertext_to_server":fb["kem_ciphertext_to_server"]}; th=sha3_512(canonical_json(state.client_hello)+canonical_json(state.server_hello)+canonical_json(unsigned)); material=derive_session_material(pq_c2s+state.pq_s2c+classical,th)
    expected=hmac.new(material["finished"],b"client"+th,hashlib.sha3_256).digest()
    if not hmac.compare_digest(expected,b64d(fb["finished_mac"])): raise SecurityError("client finished MAC mismatch")
    sf={"schema":"shttps.server-finish/v1","finished_mac":b64e(hmac.new(material["finished"],b"server"+th,hashlib.sha3_256).digest())}
    sb=state.server_hello["body"]
    return sf,HandshakeSecrets(material,CipherId(sb["cipher"]),CompressionId(sb["compression"]),str(cb["node_id"]),th)

def verify_server_finish(secrets:HandshakeSecrets,server_finish:dict)->None:
    expected=hmac.new(secrets.material["finished"],b"server"+secrets.transcript_hash,hashlib.sha3_256).digest()
    if not hmac.compare_digest(expected,b64d(server_finish.get("finished_mac",""))): raise SecurityError("server finished MAC mismatch")

def make_session(secrets:HandshakeSecrets,role:str,compression_adapter=None):
    from .session import SecureSession
    if role=="client": send,recv=secrets.material["client_write"],secrets.material["server_write"]
    elif role=="server": send,recv=secrets.material["server_write"],secrets.material["client_write"]
    else: raise ValueError("role must be client or server")
    return SecureSession(secrets.material["session_id"],send,recv,secrets.cipher,secrets.compression,compression_adapter=compression_adapter)
