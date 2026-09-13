import pytest
from cryptography.exceptions import InvalidTag
from shttps.session import SecureSession
from shttps.constants import CompressionId,FrameFlags
from shttps.errors import SecurityError,ReplayError,ProtocolError


def pair():
    sid=b"s"*16; a=b"a"*32; b=b"b"*32
    return SecureSession(sid,a,b),SecureSession(sid,b,a)

def test_tamper_rejected():
    c,s=pair(); f=bytearray(c.seal(b"abc")); f[-1]^=1
    with pytest.raises(SecurityError): s.open(bytes(f))

def test_replay_rejected():
    c,s=pair(); f=c.seal(b"abc"); s.open(f)
    with pytest.raises(ReplayError): s.open(f)

def test_failed_auth_does_not_poison_replay_window():
    c,s=pair(); f=c.seal(b"first"); bad=bytearray(f); bad[-1]^=1
    with pytest.raises(SecurityError): s.open(bytes(bad))
    _,plain=s.open(f); assert plain==b"first"

def test_sensitive_is_raw():
    c,s=pair(); f=c.seal(b"secret",sensitive=True); h,p=s.open(f); assert p==b"secret" and h.compression==CompressionId.RAW and bool(h.flags&FrameFlags.SENSITIVE)
