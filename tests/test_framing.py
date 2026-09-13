import pytest
from shttps.framing import FrameHeader
from shttps.constants import FrameType,FrameFlags,CompressionId,CipherId
from shttps.errors import ProtocolError

def test_frame_header_roundtrip():
    h=FrameHeader(FrameType.DATA,FrameFlags.NONE,CompressionId.RAW,CipherId.CHACHA20_POLY1305,0,2,3,10,26); assert FrameHeader.unpack(h.pack())==h

def test_reserved_flags_rejected():
    h=bytearray(FrameHeader(FrameType.DATA,FrameFlags.NONE,CompressionId.RAW,CipherId.CHACHA20_POLY1305,0,2,3,10,26).pack()); h[6]=0x80
    with pytest.raises(ProtocolError): FrameHeader.unpack(bytes(h))
