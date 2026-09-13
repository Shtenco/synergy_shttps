from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

from .canonical import canonical_json
from .compression import AICompressAdapter
from .constants import MAX_FRAME_BYTES, MAX_HANDSHAKE_BYTES
from .crypto.base import PQProvider
from .envelope import Envelope
from .errors import ProtocolError, SecurityError
from .handshake import HandshakeConfig, Identity, PinnedTrustStore, accept_client, finish_client, finish_server, make_session, start_client, verify_server_finish
from .protocol import open_envelope, seal_envelope
from .rpc import RPC_PROTOCOL, RPCDispatcher, RPCRequest, RPCResponse

_LEN = struct.Struct(">I")
_MAX_PACKET = MAX_FRAME_BYTES + 1024 * 1024

async def _read_packet(reader: asyncio.StreamReader, *, limit: int) -> bytes:
    raw = await reader.readexactly(_LEN.size)
    size = _LEN.unpack(raw)[0]
    if size <= 0 or size > limit:
        raise ProtocolError("SHTTPS packet size outside limit")
    return await reader.readexactly(size)

async def _write_packet(writer: asyncio.StreamWriter, data: bytes, *, limit: int) -> None:
    if not data or len(data) > limit:
        raise ProtocolError("SHTTPS packet size outside limit")
    writer.write(_LEN.pack(len(data)) + data)
    await writer.drain()

def _json_packet(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError("invalid SHTTPS handshake JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("handshake packet must be object")
    return value

class SHTTPSRPCClient:
    def __init__(self, host: str, port: int, provider: PQProvider, identity: Identity, trust: PinnedTrustStore, config: HandshakeConfig, *, compression: AICompressAdapter | None = None, expected_peer_node_id: str | None = None, timeout: float = 15.0) -> None:
        self.host=host; self.port=int(port); self.provider=provider; self.identity=identity; self.trust=trust; self.config=config
        self.compression=compression or AICompressAdapter(); self.expected_peer_node_id=expected_peer_node_id; self.timeout=float(timeout)

    async def call(self, service: str, method: str, params: dict[str, Any], *, sensitive: bool=False, metadata: dict[str, Any] | None=None) -> Any:
        return await asyncio.wait_for(self._call(service, method, params, sensitive=sensitive, metadata=metadata), timeout=self.timeout)

    async def _call(self, service: str, method: str, params: dict[str, Any], *, sensitive: bool, metadata: dict[str, Any] | None) -> Any:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        try:
            ch,state=start_client(self.provider,self.identity,self.config); await _write_packet(writer,canonical_json(ch),limit=MAX_HANDSHAKE_BYTES)
            sh=_json_packet(await _read_packet(reader,limit=MAX_HANDSHAKE_BYTES)); cf,secrets=finish_client(self.provider,state,self.trust,sh)
            if self.expected_peer_node_id and secrets.peer_node_id != self.expected_peer_node_id: raise SecurityError("connected peer does not match expected node_id")
            await _write_packet(writer,canonical_json(cf),limit=MAX_HANDSHAKE_BYTES); sf=_json_packet(await _read_packet(reader,limit=MAX_HANDSHAKE_BYTES)); verify_server_finish(secrets,sf)
            session=make_session(secrets,"client",self.compression); request=RPCRequest(service=service,method=method,params=params,metadata=metadata or {})
            envelope=Envelope(protocol=RPC_PROTOCOL,source=self.identity.node_id,destination=secrets.peer_node_id,payload=request.encode(),content_type="application/json",correlation_id=request.request_id,metadata={"transport":"SHTTPS/1"})
            await _write_packet(writer,seal_envelope(session,envelope,stream_id=1,sensitive=sensitive),limit=_MAX_PACKET)
            _,response_envelope=open_envelope(session,await _read_packet(reader,limit=_MAX_PACKET))
            if response_envelope.protocol != RPC_PROTOCOL: raise ProtocolError("unexpected response protocol")
            if response_envelope.destination != self.identity.node_id or response_envelope.source != secrets.peer_node_id: raise SecurityError("RPC response endpoint binding mismatch")
            response=RPCResponse.decode(response_envelope.payload)
            if response.request_id != request.request_id or response_envelope.correlation_id != request.request_id: raise SecurityError("RPC response correlation mismatch")
            if not response.ok: raise RuntimeError(response.error or "remote RPC failed")
            return response.result
        finally:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass

    def call_sync(self, service: str, method: str, params: dict[str, Any], *, sensitive: bool=False, metadata: dict[str, Any] | None=None) -> Any:
        try: asyncio.get_running_loop()
        except RuntimeError: return asyncio.run(self.call(service,method,params,sensitive=sensitive,metadata=metadata))
        raise RuntimeError("call_sync cannot run inside an active event loop; use await call()")

class SHTTPSRPCServer:
    def __init__(self, host: str, port: int, provider: PQProvider, identity: Identity, trust: PinnedTrustStore, config: HandshakeConfig, dispatcher: RPCDispatcher, *, compression: AICompressAdapter | None=None) -> None:
        self.host=host; self.port=int(port); self.provider=provider; self.identity=identity; self.trust=trust; self.config=config; self.dispatcher=dispatcher; self.compression=compression or AICompressAdapter(); self._server=None

    async def start(self) -> None: self._server=await asyncio.start_server(self._handle,self.host,self.port)
    async def serve_forever(self) -> None:
        if self._server is None: await self.start()
        async with self._server: await self._server.serve_forever()
    async def close(self) -> None:
        if self._server is not None: self._server.close(); await self._server.wait_closed(); self._server=None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_node_id=None
        try:
            ch=_json_packet(await _read_packet(reader,limit=MAX_HANDSHAKE_BYTES)); sh,state=accept_client(self.provider,self.identity,self.config,self.trust,ch); peer_node_id=str(ch.get("body",{}).get("node_id") or "")
            await _write_packet(writer,canonical_json(sh),limit=MAX_HANDSHAKE_BYTES); cf=_json_packet(await _read_packet(reader,limit=MAX_HANDSHAKE_BYTES)); sf,secrets=finish_server(self.provider,state,self.trust,cf); peer_node_id=secrets.peer_node_id
            await _write_packet(writer,canonical_json(sf),limit=MAX_HANDSHAKE_BYTES); session=make_session(secrets,"server",self.compression)
            while True:
                try: frame=await _read_packet(reader,limit=_MAX_PACKET)
                except asyncio.IncompleteReadError: break
                header,envelope=open_envelope(session,frame)
                if envelope.protocol != RPC_PROTOCOL: raise ProtocolError("only shttps.rpc/v1 accepted on RPC server")
                if envelope.destination != self.identity.node_id or envelope.source != peer_node_id: raise SecurityError("RPC request endpoint binding mismatch")
                request=RPCRequest.decode(envelope.payload)
                if envelope.correlation_id != request.request_id: raise SecurityError("RPC request correlation mismatch")
                context={"peer_node_id":peer_node_id,"local_node_id":self.identity.node_id,"stream_id":header.stream_id,"transport":"SHTTPS/1","authenticated":True,"application_authority":False}
                response=self.dispatcher.dispatch(request,context)
                response_envelope=Envelope(protocol=RPC_PROTOCOL,source=self.identity.node_id,destination=peer_node_id,payload=response.encode(),content_type="application/json",correlation_id=request.request_id,metadata={"transport":"SHTTPS/1"})
                await _write_packet(writer,seal_envelope(session,response_envelope,stream_id=header.stream_id,sensitive=bool(header.flags & 2)),limit=_MAX_PACKET)
        except Exception:
            pass
        finally:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
