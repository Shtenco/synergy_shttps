from __future__ import annotations
import json
from ..envelope import Envelope
from ..canonical import canonical_json

def json_envelope(protocol:str,source:str,destination:str,payload:dict,**metadata)->Envelope:
    return Envelope(protocol=protocol,source=source,destination=destination,payload=canonical_json(payload),content_type="application/json",metadata=metadata)

def capability_envelope(source:str,destination:str,capability_payload:dict)->Envelope:
    return json_envelope("synergy.capability.v1",source,destination,capability_payload,authority="application-policy-required")

def nexus_envelope(source:str,destination:str,nexus_payload:dict)->Envelope:
    return json_envelope("nexus.runtime/v3",source,destination,nexus_payload,authority="NONE")

def decode_json_payload(envelope:Envelope)->dict:
    if envelope.content_type!="application/json": raise ValueError("not a JSON envelope")
    return json.loads(envelope.payload.decode("utf-8"))
