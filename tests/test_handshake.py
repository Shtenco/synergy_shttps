import pytest
from tests.fake_pq import FakePQProvider
from shttps.handshake import Identity,PinnedTrustStore,HandshakeConfig,start_client,accept_client,finish_client,finish_server,verify_server_finish,make_session
from shttps.constants import SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S,CompressionId
from shttps.errors import SecurityError,ProtocolError


def roundtrip(cfg=None):
    p=FakePQProvider(); cfg=cfg or HandshakeConfig()
    c=Identity.generate(p,cfg.identity_schemes); s=Identity.generate(p,cfg.identity_schemes)
    trust_c=PinnedTrustStore(); trust_s=PinnedTrustStore(); trust_c.pin(s); trust_s.pin(c)
    ch,cs=start_client(p,c,cfg); sh,ss=accept_client(p,s,cfg,trust_s,ch); cf,csec=finish_client(p,cs,trust_c,sh); sf,ssec=finish_server(p,ss,trust_s,cf); verify_server_finish(csec,sf)
    return make_session(csec,"client"),make_session(ssec,"server")

def test_handshake_and_traffic():
    c,s=roundtrip(); frame=c.seal(b"hello synergy"); _,plain=s.open(frame); assert plain==b"hello synergy"

def test_max_identity_policy():
    cfg=HandshakeConfig(identity_schemes=(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S)); c,s=roundtrip(cfg); _,plain=s.open(c.seal(b"max")); assert plain==b"max"

def test_identity_downgrade_fails():
    p=FakePQProvider(); cfg=HandshakeConfig(identity_schemes=(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S)); c=Identity.generate(p,cfg.identity_schemes); s=Identity.generate(p,cfg.identity_schemes); trust=PinnedTrustStore(); trust.pin(c)
    ch,_=start_client(p,c,cfg); ch["body"]["identity_schemes"]=[SIG_ML_DSA_87]
    with pytest.raises(SecurityError): accept_client(p,s,cfg,trust,ch)

def test_no_application_protocol_fails():
    p=FakePQProvider(); cc=HandshakeConfig(protocols=("a",)); sc=HandshakeConfig(protocols=("b",)); c=Identity.generate(p,cc.identity_schemes); s=Identity.generate(p,sc.identity_schemes); trust=PinnedTrustStore(); trust.pin(c); ch,_=start_client(p,c,cc)
    with pytest.raises(ProtocolError): accept_client(p,s,sc,trust,ch)

def test_unoffered_suite_fails_client():
    p=FakePQProvider(); cfg=HandshakeConfig(compressions=(CompressionId.RAW,)); c=Identity.generate(p,cfg.identity_schemes); s=Identity.generate(p,cfg.identity_schemes); tc=PinnedTrustStore(); ts=PinnedTrustStore(); tc.pin(s); ts.pin(c); ch,cs=start_client(p,c,cfg); sh,_=accept_client(p,s,cfg,ts,ch); sh["body"]["compression"]=int(CompressionId.AI_COMPRESS_SGH1_SPEED)
    with pytest.raises(SecurityError): finish_client(p,cs,tc,sh)
