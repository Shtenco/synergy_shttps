from shttps.envelope import Envelope
from shttps.adapters.synergy import capability_envelope,decode_json_payload

def test_envelope_roundtrip():
    e=Envelope("p","a","b",b"hello"); d=Envelope.decode(e.encode()); assert d.payload==b"hello" and d.protocol=="p" and d.source=="a"

def test_capability_adapter():
    e=capability_envelope("company","autopilot",{"capability":"x"}); assert decode_json_payload(Envelope.decode(e.encode()))["capability"]=="x"
