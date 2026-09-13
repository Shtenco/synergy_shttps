from __future__ import annotations

from dataclasses import dataclass
import copy,json
from pathlib import Path
from typing import Any,Mapping,Protocol

from .canonical import b64d,b64e,canonical_json,sha3_256,sha3_512
from .constants import SIG_ML_DSA_87
from .crypto.base import PQProvider
from .errors import SecurityError
from .handshake import Identity

SIGNER_CERT_SCHEMA="shttps.federation-signer-certificate/v1"
SIGNED_SIGNER_CERT_SCHEMA="shttps.federation-signer-certificate-signed/v1"
SIGNER_REVOCATIONS_SCHEMA="shttps.federation-signer-revocations/v1"
SIGNED_SIGNER_REVOCATIONS_SCHEMA="shttps.federation-signer-revocations-signed/v1"
DELEGATED_REGISTRY_SCHEMA="shttps.federation-registry-signed/v2"
DOMAIN_CERT=b"SHTTPS/1/federation-signer-certificate\x00"
DOMAIN_REVOCATIONS=b"SHTTPS/1/federation-signer-revocations\x00"
DOMAIN_REGISTRY=b"SHTTPS/1/federation-registry-delegated\x00"


def _hash(v:dict[str,Any])->str: return sha3_512(canonical_json(v)).hex()
def _msg(domain:bytes,digest:str)->bytes: return domain+bytes.fromhex(digest)
def _signer_id(keys:Mapping[str,bytes])->str:
    return sha3_256(b"SHTTPS/1/federation-signer-id\x00"+canonical_json({k:b64e(v) for k,v in sorted(keys.items())})).hex()


def governance_projection(registry:dict[str,Any])->dict[str,Any]:
    def p(x): return {"name":str(x.get("name") or ""),"repo":str(x.get("repo") or ""),"domain":str(x.get("domain") or ""),"risk_class":str(x.get("risk_class") or ""),"role":str(x.get("role") or ""),"integration":str(x.get("integration") or ""),"enabled":bool(x.get("enabled",False)),"rpc_allow":[str(v) for v in x.get("rpc_allow") or ()]}
    return {"schema":str(registry.get("schema") or ""),"root_id":str(registry.get("root_id") or ""),"repository_count":int(registry.get("repository_count",-1)),"repositories":[p(x) for x in registry.get("repositories") or ()],"control_principals":[p(x) for x in registry.get("control_principals") or ()]}

def governance_hash(registry:dict[str,Any])->str: return _hash(governance_projection(registry))

class RegistrySigningBackend(Protocol):
    @property
    def public_keys(self)->Mapping[str,bytes]: ...
    def sign(self,mechanism:str,message:bytes)->bytes: ...

@dataclass
class IdentitySigningBackend:
    provider:PQProvider
    identity:Identity
    @property
    def public_keys(self)->Mapping[str,bytes]: return self.identity.public_keys
    def sign(self,mechanism:str,message:bytes)->bytes: return self.provider.sign(mechanism,self.identity.secret_keys[mechanism],message)


def create_signer_certificate(provider:PQProvider,root_identity:Identity,root:dict[str,Any],signer_public_keys:Mapping[str,bytes],registry_template:dict[str,Any],*,generation:int=1,not_before:int,not_after:int,max_registry_valid_seconds:int=86400*7)->dict[str,Any]:
    required=tuple(root.get("required_schemes") or ())
    if set(root_identity.public_keys)!=set(required): raise SecurityError("root private identity policy mismatch")
    if set(signer_public_keys)!={SIG_ML_DSA_87}: raise SecurityError("delegated signer must be exactly ML-DSA-87")
    if generation<=0 or not_after<=not_before or max_registry_valid_seconds<=0 or max_registry_valid_seconds>not_after-not_before: raise SecurityError("invalid delegated signer validity")
    cert={"schema":SIGNER_CERT_SCHEMA,"root_id":root["root_id"],"signer_id":_signer_id(signer_public_keys),"generation":generation,"not_before":not_before,"not_after":not_after,"required_schemes":[SIG_ML_DSA_87],"public_keys":{k:b64e(v) for k,v in signer_public_keys.items()},"governance_hash":governance_hash(registry_template),"max_registry_valid_seconds":max_registry_valid_seconds,"capabilities":["federation.registry.lifecycle.sign"]}
    digest=_hash(cert); msg=_msg(DOMAIN_CERT,digest)
    return {"schema":SIGNED_SIGNER_CERT_SCHEMA,"certificate":cert,"certificate_hash":digest,"signatures":{s:b64e(provider.sign(s,root_identity.secret_keys[s],msg)) for s in required}}


def verify_signer_certificate(provider:PQProvider,root:dict[str,Any],signed:dict[str,Any],*,now:int)->dict[str,Any]:
    if signed.get("schema")!=SIGNED_SIGNER_CERT_SCHEMA: raise SecurityError("invalid signer certificate schema")
    cert=signed.get("certificate") or {}; digest=_hash(cert)
    if cert.get("schema")!=SIGNER_CERT_SCHEMA or cert.get("root_id")!=root.get("root_id") or signed.get("certificate_hash")!=digest: raise SecurityError("invalid signer certificate")
    required=tuple(root.get("required_schemes") or ()); sigs=signed.get("signatures") or {}; msg=_msg(DOMAIN_CERT,digest)
    if set(sigs)!=set(required): raise SecurityError("signer certificate signature downgrade")
    for s in required:
        if not provider.verify(s,b64d(root["public_keys"][s]),msg,b64d(sigs[s])): raise SecurityError("signer certificate root signature failed")
    keys={k:b64d(v) for k,v in (cert.get("public_keys") or {}).items()}
    if set(keys)!={SIG_ML_DSA_87} or cert.get("required_schemes")!=[SIG_ML_DSA_87] or cert.get("signer_id")!=_signer_id(keys): raise SecurityError("signer certificate key policy mismatch")
    if cert.get("capabilities")!=["federation.registry.lifecycle.sign"]: raise SecurityError("signer capability mismatch")
    if not int(cert.get("not_before",0))<=now<int(cert.get("not_after",0)): raise SecurityError("signer certificate expired/not-yet-valid")
    return cert


def create_signer_revocations(provider:PQProvider,root_identity:Identity,root:dict[str,Any],*,sequence:int,issued_at:int,expires_at:int,revoked_signer_ids:list[str]|None=None,previous_hash:str|None=None)->dict[str,Any]:
    if sequence<=0 or expires_at<=issued_at: raise SecurityError("invalid signer revocation document")
    required=tuple(root.get("required_schemes") or ())
    body={"schema":SIGNER_REVOCATIONS_SCHEMA,"root_id":root["root_id"],"sequence":sequence,"issued_at":issued_at,"expires_at":expires_at,"previous_hash":previous_hash,"revoked_signer_ids":sorted(set(revoked_signer_ids or []))}
    digest=_hash(body); msg=_msg(DOMAIN_REVOCATIONS,digest)
    return {"schema":SIGNED_SIGNER_REVOCATIONS_SCHEMA,"revocations":body,"revocations_hash":digest,"signatures":{s:b64e(provider.sign(s,root_identity.secret_keys[s],msg)) for s in required}}


def verify_signer_revocations(provider:PQProvider,root:dict[str,Any],signed:dict[str,Any],*,now:int,last_sequence:int|None=None,last_hash:str|None=None)->dict[str,Any]:
    if signed.get("schema")!=SIGNED_SIGNER_REVOCATIONS_SCHEMA: raise SecurityError("invalid signer revocation envelope")
    body=signed.get("revocations") or {}; digest=_hash(body); required=tuple(root.get("required_schemes") or ()); sigs=signed.get("signatures") or {}
    if body.get("schema")!=SIGNER_REVOCATIONS_SCHEMA or body.get("root_id")!=root.get("root_id") or signed.get("revocations_hash")!=digest or set(sigs)!=set(required): raise SecurityError("invalid signer revocation state")
    msg=_msg(DOMAIN_REVOCATIONS,digest)
    for s in required:
        if not provider.verify(s,b64d(root["public_keys"][s]),msg,b64d(sigs[s])): raise SecurityError("signer revocation root signature failed")
    seq=int(body.get("sequence",0))
    if seq<=0 or not int(body.get("issued_at",0))<=now<int(body.get("expires_at",0)): raise SecurityError("signer revocation validity invalid")
    if last_sequence is not None:
        if seq<last_sequence: raise SecurityError("signer revocation rollback detected")
        if seq==last_sequence and last_hash and digest!=last_hash: raise SecurityError("signer revocation equivocation")
        if seq>last_sequence and last_hash and body.get("previous_hash")!=last_hash: raise SecurityError("signer revocation previous-hash mismatch")
    return body


def sign_registry_delegated(provider:PQProvider,backend:RegistrySigningBackend,root:dict[str,Any],certificate:dict[str,Any],revocations_signed:dict[str,Any],registry:dict[str,Any],*,now:int)->dict[str,Any]:
    cert=verify_signer_certificate(provider,root,certificate,now=now); rev=verify_signer_revocations(provider,root,revocations_signed,now=now)
    if cert["signer_id"] in set(rev.get("revoked_signer_ids") or ()): raise SecurityError("delegated signer is revoked")
    if governance_hash(registry)!=cert["governance_hash"]: raise SecurityError("delegated signer may not change federation governance")
    issued=int(registry.get("issued_at",0)); expires=int(registry.get("expires_at",0))
    if issued<int(cert["not_before"]) or expires>int(cert["not_after"]) or expires-issued>int(cert["max_registry_valid_seconds"]): raise SecurityError("registry validity exceeds signer certificate")
    if set(backend.public_keys)!={SIG_ML_DSA_87} or b64e(backend.public_keys[SIG_ML_DSA_87])!=cert["public_keys"][SIG_ML_DSA_87]: raise SecurityError("signing backend does not match certificate")
    digest=_hash(registry); msg=_msg(DOMAIN_REGISTRY,digest)
    return {"schema":DELEGATED_REGISTRY_SCHEMA,"registry":registry,"registry_hash":digest,"signer_certificate":certificate,"signer_revocations_sequence":int(rev["sequence"]),"signer_revocations_hash":revocations_signed["revocations_hash"],"signer_id":cert["signer_id"],"signatures":{SIG_ML_DSA_87:b64e(backend.sign(SIG_ML_DSA_87,msg))}}


def verify_delegated_registry(provider:PQProvider,root:dict[str,Any],signed:dict[str,Any],revocations_signed:dict[str,Any],*,now:int,last_sequence:int|None=None,last_hash:str|None=None,last_revocation_sequence:int|None=None,last_revocation_hash:str|None=None)->dict[str,Any]:
    if signed.get("schema")!=DELEGATED_REGISTRY_SCHEMA: raise SecurityError("invalid delegated registry schema")
    body=signed.get("registry") or {}; digest=_hash(body)
    if body.get("root_id")!=root.get("root_id") or signed.get("registry_hash")!=digest: raise SecurityError("invalid delegated registry body/hash")
    rev=verify_signer_revocations(provider,root,revocations_signed,now=now,last_sequence=last_revocation_sequence,last_hash=last_revocation_hash)
    referenced=int(signed.get("signer_revocations_sequence",0)); current=int(rev["sequence"])
    if current<referenced: raise SecurityError("delegated registry signer revocation state rollback")
    if current==referenced and signed.get("signer_revocations_hash")!=revocations_signed.get("revocations_hash"): raise SecurityError("delegated registry references wrong signer revocation state")
    cert=verify_signer_certificate(provider,root,signed.get("signer_certificate") or {},now=now)
    if signed.get("signer_id")!=cert["signer_id"] or cert["signer_id"] in set(rev.get("revoked_signer_ids") or ()): raise SecurityError("delegated registry signer revoked/mismatched")
    if governance_hash(body)!=cert["governance_hash"]: raise SecurityError("delegated registry governance hash mismatch")
    issued=int(body.get("issued_at",0)); expires=int(body.get("expires_at",0)); seq=int(body.get("sequence",0))
    if issued<=0 or expires<=issued or now<issued-300 or now>=expires or seq<=0 or issued<int(cert["not_before"]) or expires>int(cert["not_after"]) or expires-issued>int(cert["max_registry_valid_seconds"]): raise SecurityError("delegated registry validity invalid")
    if last_sequence is not None:
        if seq<last_sequence: raise SecurityError("registry rollback detected")
        if seq==last_sequence and last_hash and digest!=last_hash: raise SecurityError("registry equivocation at same sequence")
        if seq>last_sequence and last_hash and body.get("previous_registry_hash")!=last_hash: raise SecurityError("registry previous-hash chain mismatch")
    sigs=signed.get("signatures") or {}; msg=_msg(DOMAIN_REGISTRY,digest)
    if set(sigs)!={SIG_ML_DSA_87} or not provider.verify(SIG_ML_DSA_87,b64d(cert["public_keys"][SIG_ML_DSA_87]),msg,b64d(sigs[SIG_ML_DSA_87])): raise SecurityError("delegated registry signature failed")
    repos=body.get("repositories"); controls=body.get("control_principals") or []
    if not isinstance(repos,list) or not repos or int(body.get("repository_count",-1))!=len(repos): raise SecurityError("registry principal/count invalid")
    names=set(); nodes=set()
    for item in [*repos,*controls]:
        name=str(item.get("name") or "")
        if not name or name in names: raise SecurityError("duplicate/empty federation principal")
        names.add(name)
        for n in item.get("nodes") or []:
            schemes=tuple(n.get("identity_schemes") or ()); keys=n.get("public_keys") or {}; pub={str(k):b64d(str(v)) for k,v in keys.items()}; ident=Identity(pub,{k:b"" for k in pub}); nid=str(n.get("node_id") or "")
            if not nid or nid in nodes or set(schemes)!=set(keys) or ident.node_id!=nid or n.get("status") not in {"active","retiring","revoked"} or int(n.get("generation",0))<=0 or int(n.get("not_after",0))<=int(n.get("not_before",0)): raise SecurityError("invalid delegated registry node")
            nodes.add(nid)
    return body


def load_verified_delegated_registry(provider:PQProvider,root_path:str|Path,registry_path:str|Path,revocations_path:str|Path,*,state_path:str|Path|None=None,now:int)->Any:
    from .federation import FederationRegistry
    root=json.loads(Path(root_path).read_text()); signed=json.loads(Path(registry_path).read_text()); rev=json.loads(Path(revocations_path).read_text()); ls=lh=lrs=lrh=None; state=Path(state_path) if state_path else None
    if state and state.exists():
        old=json.loads(state.read_text()); ls=int(old.get("sequence",0)) or None; lh=old.get("registry_hash") or None; lrs=int(old.get("signer_revocation_sequence",0)) or None; lrh=old.get("signer_revocation_hash") or None
    body=verify_delegated_registry(provider,root,signed,rev,now=now,last_sequence=ls,last_hash=lh,last_revocation_sequence=lrs,last_revocation_hash=lrh); reg=FederationRegistry(body,now=now)
    if state:
        state.parent.mkdir(parents=True,exist_ok=True); state.write_text(json.dumps({"schema":"shttps.federation-registry-state/v1","sequence":reg.sequence,"registry_hash":reg.registry_hash,"signer_revocation_sequence":int(rev["revocations"]["sequence"]),"signer_revocation_hash":rev["revocations_hash"]},sort_keys=True))
    return reg


def build_revoke_node_body(signed:dict[str,Any],node_id:str,*,now:int,registry_valid_seconds:int=86400*7)->dict[str,Any]:
    body=copy.deepcopy(signed["registry"]); found=False
    for x in [*body.get("repositories",[]),*(body.get("control_principals") or [])]:
        for n in x.get("nodes") or []:
            if n.get("node_id")==node_id: n["status"]="revoked"; n["not_after"]=min(int(n["not_after"]),now); found=True
    if not found: raise SecurityError("node not present")
    body.update(sequence=int(body["sequence"])+1,issued_at=now,expires_at=now+registry_valid_seconds,previous_registry_hash=signed["registry_hash"])
    return body
