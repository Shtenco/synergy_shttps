from __future__ import annotations
import os
from dataclasses import dataclass

from .compression import AICompressAdapter
from .constants import CompressionId, SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S
from .credentials import load_identity, load_trust_store
from .crypto.oqs_provider import OQSProvider
from .errors import ProviderUnavailable, SecurityError
from .federation import FederationRegistry, load_verified_registry
from .handshake import HandshakeConfig, Identity, PinnedTrustStore
from .rpc import RPCDispatcher
from .transport import SHTTPSRPCClient, SHTTPSRPCServer


def _bool(name: str, default: bool=False) -> bool:
    raw=os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1","true","yes","on"}


@dataclass(frozen=True)
class ProductionContext:
    provider: OQSProvider
    identity: Identity
    trust: PinnedTrustStore
    compression: AICompressAdapter
    config: HandshakeConfig
    federation: FederationRegistry | None
    repository_name: str | None


def production_context(prefix: str, *, roles: tuple[str,...]=()) -> ProductionContext:
    identity_path=os.getenv(f"{prefix}_SHTTPS_IDENTITY","")
    if not identity_path:
        raise ProviderUnavailable(f"{prefix}: SHTTPS identity path is required")
    provider=OQSProvider(); identity=load_identity(identity_path)
    registry_path=os.getenv(f"{prefix}_SHTTPS_FEDERATION_REGISTRY",""); root_path=os.getenv(f"{prefix}_SHTTPS_FEDERATION_ROOT",""); repository_name=os.getenv(f"{prefix}_SHTTPS_REPOSITORY","") or None; state_path=os.getenv(f"{prefix}_SHTTPS_FEDERATION_STATE","") or None
    federation: FederationRegistry | None=None
    if registry_path or root_path:
        if not registry_path or not root_path or not repository_name: raise ProviderUnavailable(f"{prefix}: federation registry/root/repository must be configured together")
        federation=load_verified_registry(provider,root_path,registry_path,state_path=state_path); federation.assert_local_identity(repository_name,identity); trust=federation.trust_store()
    else:
        if not _bool(f"{prefix}_SHTTPS_ALLOW_LEGACY_TRUST",False): raise ProviderUnavailable(f"{prefix}: signed Federation Trust Registry is required")
        trust_path=os.getenv(f"{prefix}_SHTTPS_TRUST","")
        if not trust_path: raise ProviderUnavailable(f"{prefix}: legacy trust path is required only in explicit migration mode")
        trust=load_trust_store(trust_path)
    compression=AICompressAdapter(); require_compress=_bool(f"{prefix}_SHTTPS_REQUIRE_AI_COMPRESS",True)
    if require_compress and not compression.ai_compress_available: raise ProviderUnavailable(f"{prefix}: ai_compress/SGH1 is required but unavailable")
    max_identity=_bool(f"{prefix}_SHTTPS_MAX_IDENTITY",False); schemes=(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S) if max_identity else (SIG_ML_DSA_87,)
    if set(identity.public_keys)!=set(schemes): raise SecurityError(f"{prefix}: local identity schemes do not match configured identity policy")
    available=set(compression.available_codecs()); preferred=(CompressionId.AI_COMPRESS_SGH1_SPEED,CompressionId.AI_COMPRESS_SGH1_BALANCED,CompressionId.RAW); compressions=tuple(c for c in preferred if c in available)
    if require_compress and not any(c!=CompressionId.RAW for c in compressions): raise ProviderUnavailable(f"{prefix}: no negotiated SGH1 codec available")
    config=HandshakeConfig(identity_schemes=schemes,compressions=compressions,protocols=("shttps.rpc/v1",),roles=roles)
    return ProductionContext(provider,identity,trust,compression,config,federation,repository_name)


def production_stack(prefix: str, *, roles: tuple[str,...]=()):
    ctx=production_context(prefix,roles=roles); return ctx.provider,ctx.identity,ctx.trust,ctx.compression,ctx.config


def rpc_client_from_env(prefix: str, *, host_default: str, port_default: int, roles: tuple[str,...]=()) -> SHTTPSRPCClient:
    ctx=production_context(prefix,roles=roles); host=os.getenv(f"{prefix}_SHTTPS_HOST",host_default); port=int(os.getenv(f"{prefix}_SHTTPS_PORT",str(port_default))); expected_node=os.getenv(f"{prefix}_SHTTPS_EXPECTED_PEER","") or None; expected_repository=os.getenv(f"{prefix}_SHTTPS_EXPECTED_REPOSITORY","") or None; expected_ids:set[str]=set()
    if ctx.federation is not None and expected_repository:
        expected_ids={str(n["node_id"]) for n in ctx.federation.accepted_nodes(expected_repository)}
        if not expected_ids: raise ProviderUnavailable(f"{prefix}: no accepted nodes for expected repository {expected_repository}")
    if expected_node:
        if expected_ids and expected_node not in expected_ids: raise ProviderUnavailable(f"{prefix}: explicit expected peer is not an accepted node of expected repository")
        expected_ids.add(expected_node)
    return SHTTPSRPCClient(host,port,ctx.provider,ctx.identity,ctx.trust,ctx.config,compression=ctx.compression,expected_peer_node_ids=expected_ids,timeout=float(os.getenv(f"{prefix}_SHTTPS_TIMEOUT","15")))


def rpc_server_from_env(prefix: str, dispatcher: RPCDispatcher, *, host_default: str, port_default: int, roles: tuple[str,...]=()) -> SHTTPSRPCServer:
    ctx=production_context(prefix,roles=roles); host=os.getenv(f"{prefix}_SHTTPS_BIND_HOST",host_default); port=int(os.getenv(f"{prefix}_SHTTPS_BIND_PORT",str(port_default)))
    return SHTTPSRPCServer(host,port,ctx.provider,ctx.identity,ctx.trust,ctx.config,dispatcher,compression=ctx.compression,federation=ctx.federation)
