from shttps.compression import AICompressAdapter
from shttps.constants import CompressionId

def test_raw_always_available():
    c=AICompressAdapter(path="/definitely/missing"); assert CompressionId.RAW in c.available_codecs(); d=c.compress(b"abc",CompressionId.RAW); assert c.decompress(d.codec,d.data,3)==b"abc"

def test_default_handshake_can_be_raw_only():
    from shttps.handshake import HandshakeConfig
    assert HandshakeConfig().compressions==(CompressionId.RAW,)
