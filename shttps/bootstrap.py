from __future__ import annotations
import os

from .compression import AICompressAdapter
from .constants import CompressionId, SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S
from .credentials import load_identity, load_trust_store
from .crypto.oqs_provider import OQSProvider
from .errors import ProviderUnavailable
from .handshake import HandshakeConfig
from .rpc import RPCDispatcher
from .transport import SHTTPSRPCClient, SHTTPSRPCServer


def _bool(name: str, default: bool=False) -> bool:
    raw=os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1","true","yes","on"}


def production_stack(prefix: str, *, roles: tuple[str,...]=()):
    identity_path=os.getenv(f"{prefix}_SHTTPS_IDENTITY","")
    trust_path=os.getenv(f"{prefix}_SHTTPS_TRUST","")
    if not identity_path or not trust_path:
        raise ProviderUnavailable(f"{prefix}: SHTTPS identity/trust paths are required")
    provider=OQSProvider(); identity=load_identity(identity_path); trust=load_trust_store(trust_path)
    compression=AICompressAdapter(); require_compress=_bool(f"{prefix}_SHTTPS_REQUIRE_AI_COMPRESS",True)
    if require_compress and not compression.ai_compress_available:
        raise ProviderUnavailable(f"{prefix}: ai_compress/SGH1 is required but unavailable")
    max_identity=_bool(f"{prefix}_SHTTPS_MAX_IDENTITY",False)
    schemes=(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S) if max_identity else (SIG_ML_DSA_87,)
    available=set(compression.available_codecs()); preferred=(CompressionId.AI_COMPRESS_SGH1_SPEED,CompressionId.AI_COMPRESS_SGH1_BALANCED,CompressionId.RAW)
    compressions=tuple(c for c in preferred if c in available)
    if require_compress and not any(c != CompressionId.RAW for c in compressions):
        raise ProviderUnavailable(f"{prefix}: no negotiated SGH1 codec available")
    config=HandshakeConfig(identity_schemes=schemes,compressions=compressions,protocols=("shttps.rpc/v1",),roles=roles)
    return provider,identity,trust,compression,config


def rpc_client_from_env(prefix: str, *, host_default: str, port_default: int, roles: tuple[str,...]=()) -> SHTTPSRPCClient:
    provider,identity,trust,compression,config=production_stack(prefix,roles=roles)
    host=os.getenv(f"{prefix}_SHTTPS_HOST",host_default); port=int(os.getenv(f"{prefix}_SHTTPS_PORT",str(port_default))); expected=os.getenv(f"{prefix}_SHTTPS_EXPECTED_PEER","") or None; timeout=float(os.getenv(f"{prefix}_SHTTPS_TIMEOUT","15"))
    return SHTTPSRPCClient(host,port,provider,identity,trust,config,compression=compression,expected_peer_node_id=expected,timeout=timeout)


def rpc_server_from_env(prefix: str, dispatcher: RPCDispatcher, *, host_default: str, port_default: int, roles: tuple[str,...]=()) -> SHTTPSRPCServer:
    provider,identity,trust,compression,config=production_stack(prefix,roles=roles)
    host=os.getenv(f"{prefix}_SHTTPS_BIND_HOST",host_default); port=int(os.getenv(f"{prefix}_SHTTPS_BIND_PORT",str(port_default)))
    return SHTTPSRPCServer(host,port,provider,identity,trust,config,dispatcher,compression=compression)
