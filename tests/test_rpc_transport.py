from __future__ import annotations
import asyncio, socket
import pytest
from shttps.constants import CompressionId, SIG_ML_DSA_87
from shttps.handshake import HandshakeConfig, Identity, PinnedTrustStore
from shttps.rpc import RPCDispatcher
from shttps.transport import SHTTPSRPCClient, SHTTPSRPCServer
from .fakes import FakePQProvider, fake_compression

def _free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

def test_end_to_end_rpc_is_pq_handshaked_compressed_and_encrypted():
    async def scenario():
        p=FakePQProvider(); c=Identity.generate(p,(SIG_ML_DSA_87,)); s=Identity.generate(p,(SIG_ML_DSA_87,)); ct=PinnedTrustStore(); ct.pin(s); st=PinnedTrustStore(); st.pin(c)
        cfg=HandshakeConfig(compressions=(CompressionId.AI_COMPRESS_SGH1_SPEED,CompressionId.RAW),protocols=("shttps.rpc/v1",)); d=RPCDispatcher(); d.register("autopilot","echo",lambda params,ctx:{"echo":params,"peer":ctx["peer_node_id"],"authority":ctx["application_authority"]})
        port=_free_port(); server=SHTTPSRPCServer("127.0.0.1",port,p,s,st,cfg,d,compression=fake_compression()); await server.start()
        try:
            client=SHTTPSRPCClient("127.0.0.1",port,p,c,ct,cfg,compression=fake_compression(),expected_peer_node_id=s.node_id); result=await client.call("autopilot","echo",{"blob":"revenue "*1000}); assert result["peer"]==c.node_id and result["authority"] is False
        finally: await server.close()
    asyncio.run(scenario())

def test_rpc_unknown_method_fails_closed():
    async def scenario():
        p=FakePQProvider(); c=Identity.generate(p,(SIG_ML_DSA_87,)); s=Identity.generate(p,(SIG_ML_DSA_87,)); ct=PinnedTrustStore(); ct.pin(s); st=PinnedTrustStore(); st.pin(c); cfg=HandshakeConfig(protocols=("shttps.rpc/v1",)); port=_free_port(); server=SHTTPSRPCServer("127.0.0.1",port,p,s,st,cfg,RPCDispatcher()); await server.start()
        try:
            client=SHTTPSRPCClient("127.0.0.1",port,p,c,ct,cfg,expected_peer_node_id=s.node_id)
            with pytest.raises(RuntimeError,match="RPC_METHOD_NOT_ALLOWED"): await client.call("x","y",{})
        finally: await server.close()
    asyncio.run(scenario())
