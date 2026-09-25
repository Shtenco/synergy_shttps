from __future__ import annotations
from dataclasses import dataclass
import copy, json, time
from pathlib import Path
from typing import Any, Iterable
from .canonical import b64d,b64e,canonical_json,sha3_256,sha3_512
from .constants import SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S
from .credentials import identity_document,write_json_private
from .crypto.base import PQProvider
from .errors import SecurityError
from .handshake import Identity,PinnedTrustStore

REGISTRY_SCHEMA="shttps.federation-registry/v1"; SIGNED_SCHEMA="shttps.federation-registry-signed/v1"; ROOT_SCHEMA="shttps.federation-root/v1"; ROOT_TRANSITION_SCHEMA="shttps.federation-root-transition/v1"
ACTIVE="active"; RETIRING="retiring"; REVOKED="revoked"
DOMAIN_REGISTRY=b"SHTTPS/1/federation-registry\x00"; DOMAIN_ROOT=b"SHTTPS/1/federation-root-rotation\x00"
def _now(): return int(time.time())
def _hash(d): return sha3_512(canonical_json(d)).hex()
def _msg(domain,h):
    try: return domain+bytes.fromhex(h)
    except ValueError as e: raise SecurityError("invalid digest encoding") from e

def node_record(identity:Identity,*,generation:int,not_before:int,not_after:int,status:str=ACTIVE)->dict[str,Any]:
    if generation<=0 or not_after<=not_before or status not in {ACTIVE,RETIRING,REVOKED}: raise ValueError("invalid node lifecycle")
    return {"node_id":identity.node_id,"generation":generation,"status":status,"not_before":int(not_before),"not_after":int(not_after),"identity_schemes":sorted(identity.public_keys),"public_keys":{k:b64e(v) for k,v in sorted(identity.public_keys.items())}}

def root_document(identity:Identity,*,generation:int=1,created_at:int|None=None,required_schemes:Iterable[str]|None=None)->dict[str,Any]:
    schemes=tuple(required_schemes or (SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S))
    if set(identity.public_keys)!=set(schemes): raise SecurityError("root identity must exactly match required schemes")
    pub={k:b64e(v) for k,v in sorted(identity.public_keys.items())}; rid=sha3_256(b"SHTTPS/1/federation-root-id\x00"+canonical_json(pub)).hex()
    return {"schema":ROOT_SCHEMA,"root_id":rid,"generation":int(generation),"created_at":int(created_at or _now()),"required_schemes":list(schemes),"public_keys":pub}

def verify_root_document(root:dict[str,Any])->None:
    if root.get("schema")!=ROOT_SCHEMA: raise SecurityError("invalid federation root schema")
    schemes=tuple(root.get("required_schemes") or ()); keys=root.get("public_keys") or {}
    if not schemes or set(keys)!=set(schemes): raise SecurityError("federation root key/scheme mismatch")
    pub={str(k):str(v) for k,v in sorted(keys.items())}; expected=sha3_256(b"SHTTPS/1/federation-root-id\x00"+canonical_json(pub)).hex()
    if root.get("root_id")!=expected: raise SecurityError("federation root_id mismatch")

def sign_registry(provider:PQProvider,root_identity:Identity,root:dict[str,Any],registry:dict[str,Any])->dict[str,Any]:
    verify_root_document(root)
    if registry.get("schema")!=REGISTRY_SCHEMA or registry.get("root_id")!=root.get("root_id"): raise SecurityError("registry/root mismatch")
    required=tuple(root["required_schemes"])
    if set(root_identity.public_keys)!=set(required): raise SecurityError("root private identity policy mismatch")
    for s in required:
        if b64e(root_identity.public_keys[s])!=root["public_keys"][s]: raise SecurityError("root private identity mismatch")
    digest=_hash(registry); msg=_msg(DOMAIN_REGISTRY,digest)
    return {"schema":SIGNED_SCHEMA,"registry":registry,"registry_hash":digest,"signatures":{s:b64e(provider.sign(s,root_identity.secret_keys[s],msg)) for s in required}}

def _verify_node(n:dict[str,Any])->None:
    if n.get("status") not in {ACTIVE,RETIRING,REVOKED}: raise SecurityError("invalid node status")
    schemes=tuple(n.get("identity_schemes") or ()); keys=n.get("public_keys") or {}
    if not schemes or set(schemes)!=set(keys): raise SecurityError("node key/scheme mismatch")
    pub={str(k):b64d(str(v)) for k,v in keys.items()}; ident=Identity(pub,{k:b"" for k in pub})
    if ident.node_id!=n.get("node_id"): raise SecurityError("node_id/public-key mismatch")
    if int(n.get("generation",0))<=0 or int(n.get("not_after",0))<=int(n.get("not_before",0)): raise SecurityError("invalid node validity")

def verify_signed_registry(provider:PQProvider,root:dict[str,Any],signed:dict[str,Any],*,now:int|None=None,last_sequence:int|None=None,last_hash:str|None=None)->dict[str,Any]:
    verify_root_document(root)
    if signed.get("schema")!=SIGNED_SCHEMA: raise SecurityError("invalid signed registry schema")
    body=signed.get("registry")
    if not isinstance(body,dict) or body.get("schema")!=REGISTRY_SCHEMA or body.get("root_id")!=root.get("root_id"): raise SecurityError("invalid registry body/root")
    digest=_hash(body)
    if signed.get("registry_hash")!=digest: raise SecurityError("registry hash mismatch")
    required=tuple(root["required_schemes"]); sigs=signed.get("signatures") or {}
    if set(sigs)!=set(required): raise SecurityError("registry signature-set downgrade")
    msg=_msg(DOMAIN_REGISTRY,digest)
    for s in required:
        if not provider.verify(s,b64d(root["public_keys"][s]),msg,b64d(sigs[s])): raise SecurityError(f"registry root signature failed: {s}")
    ts=int(now if now is not None else _now()); issued=int(body.get("issued_at",0)); expires=int(body.get("expires_at",0)); seq=int(body.get("sequence",0))
    if issued<=0 or expires<=issued or ts<issued-300 or ts>=expires or seq<=0: raise SecurityError("registry validity/sequence invalid")
    if last_sequence is not None:
        if seq<last_sequence: raise SecurityError("registry rollback detected")
        if seq==last_sequence and last_hash and digest!=last_hash: raise SecurityError("registry equivocation at same sequence")
        if seq>last_sequence and last_hash and body.get("previous_registry_hash")!=last_hash: raise SecurityError("registry previous-hash chain mismatch")
    repos=body.get("repositories"); controls=body.get("control_principals") or []
    if not isinstance(repos,list) or not repos or not isinstance(controls,list) or int(body.get("repository_count",-1))!=len(repos): raise SecurityError("registry principal/count invalid")
    names=set(); nodes=set()
    for item in [*repos,*controls]:
        name=str(item.get("name") or "")
        if not name or name in names: raise SecurityError("duplicate/empty federation principal")
        names.add(name)
        for n in item.get("nodes") or []:
            nid=str(n.get("node_id") or "")
            if not nid or nid in nodes: raise SecurityError("duplicate/empty node_id")
            nodes.add(nid); _verify_node(n)
    return body

@dataclass(frozen=True)
class FederationPrincipal:
    name:str; repo:str; domain:str; risk_class:str; role:str; integration:str; enabled:bool; rpc_allow:tuple[str,...]; nodes:tuple[dict[str,Any],...]

class FederationRegistry:
    def __init__(self,body:dict[str,Any],*,now:int|None=None):
        self.body=body; self.now=int(now if now is not None else _now()); self.sequence=int(body["sequence"]); self.registry_hash=_hash(body); self.root_id=str(body["root_id"]); self._items={}; self._node={}
        for x in [*body["repositories"],*(body.get("control_principals") or [])]:
            p=FederationPrincipal(str(x["name"]),str(x["repo"]),str(x.get("domain") or ""),str(x.get("risk_class") or ""),str(x.get("role") or ""),str(x.get("integration") or ""),bool(x.get("enabled",False)),tuple(str(v) for v in x.get("rpc_allow") or ()),tuple(x.get("nodes") or ()))
            self._items[p.name]=p
            for n in p.nodes: self._node[str(n["node_id"])]=p.name
    def repository(self,name:str)->FederationPrincipal:
        try: return self._items[name]
        except KeyError as e: raise SecurityError(f"principal not in federation registry: {name}") from e
    def repository_for_node(self,node_id:str)->FederationPrincipal:
        name=self._node.get(node_id)
        if not name: raise SecurityError("node_id not in federation registry")
        return self.repository(name)
    def accepted_nodes(self,name:str)->list[dict[str,Any]]:
        return sorted([n for n in self.repository(name).nodes if n["status"] in {ACTIVE,RETIRING} and int(n["not_before"])<=self.now<int(n["not_after"])],key=lambda n:int(n["generation"]),reverse=True)
    def preferred_node_id(self,name:str)->str:
        nodes=[n for n in self.accepted_nodes(name) if n["status"]==ACTIVE]
        if not nodes: raise SecurityError(f"no active node for {name}")
        return str(nodes[0]["node_id"])
    def trust_store(self,repositories:Iterable[str]|None=None)->PinnedTrustStore:
        peers={}
        for name in (list(repositories) if repositories is not None else list(self._items)):
            for n in self.accepted_nodes(name): peers[str(n["node_id"])]={str(k):b64d(str(v)) for k,v in n["public_keys"].items()}
        return PinnedTrustStore(peers)
    def assert_local_identity(self,name:str,identity:Identity)->None:
        nodes={str(n["node_id"]):n for n in self.accepted_nodes(name)}; n=nodes.get(identity.node_id)
        if not n: raise SecurityError("local identity is not active/retiring in federation registry")
        if {str(k):b64d(str(v)) for k,v in n["public_keys"].items()}!=identity.public_keys: raise SecurityError("local identity public key mismatch")
    def authorize_rpc(self,peer_node_id:str,service:str,method:str)->bool:
        p=self.repository_for_node(peer_node_id); route=f"{service}.{method}"
        return p.enabled and (route in p.rpc_allow or f"{service}.*" in p.rpc_allow or "*" in p.rpc_allow)
    def peer_context(self,node_id:str)->dict[str,Any]:
        p=self.repository_for_node(node_id); return {"repository":p.name,"repo":p.repo,"domain":p.domain,"risk_class":p.risk_class,"role":p.role,"integration":p.integration}

def load_verified_registry(provider:PQProvider,root_path:str|Path,registry_path:str|Path,*,state_path:str|Path|None=None,now:int|None=None)->FederationRegistry:
    root=json.loads(Path(root_path).read_text()); signed=json.loads(Path(registry_path).read_text()); ls=lh=None; state=Path(state_path) if state_path else None
    if state and state.exists():
        old=json.loads(state.read_text()); ls=int(old.get("sequence",0)) or None; lh=old.get("registry_hash") or None
    body=verify_signed_registry(provider,root,signed,now=now,last_sequence=ls,last_hash=lh); reg=FederationRegistry(body,now=now)
    if state:
        state.parent.mkdir(parents=True,exist_ok=True); state.write_text(json.dumps({"schema":"shttps.federation-registry-state/v1","sequence":reg.sequence,"registry_hash":reg.registry_hash},sort_keys=True))
    return reg

def _entry(x): return {"name":str(x["name"]),"repo":str(x["repo"]),"domain":str(x.get("domain") or ""),"risk_class":str(x.get("risk_class") or ""),"role":str(x.get("role") or ""),"integration":str(x.get("integration") or ""),"enabled":bool(x.get("enabled",False)),"rpc_allow":[str(v) for v in x.get("rpc_allow") or ()],"nodes":[]}
def federation_template_from_source(source:dict[str,Any],root:dict[str,Any],*,issued_at:int|None=None,valid_for_seconds:int=86400*30,sequence:int=1,previous_registry_hash:str|None=None)->dict[str,Any]:
    ts=int(issued_at or _now()); repos=[_entry(x) for x in source.get("repositories") or []]; controls=[_entry(x) for x in source.get("control_principals") or []]
    return {"schema":REGISTRY_SCHEMA,"sequence":int(sequence),"issued_at":ts,"expires_at":ts+int(valid_for_seconds),"previous_registry_hash":previous_registry_hash,"root_id":root["root_id"],"repository_count":len(repos),"repositories":repos,"control_principals":controls}
def node_schemes_for_repository(x): return (SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S) if x.get("risk_class") in {"financial","blockchain"} or x.get("name")=="synergy_system" else (SIG_ML_DSA_87,)
def _all(body): return [*body["repositories"],*(body.get("control_principals") or [])]
def provision_all_nodes(provider:PQProvider,registry:dict[str,Any],secrets_dir:str|Path,*,now:int|None=None,ttl_seconds:int=86400*90)->dict[str,Any]:
    ts=int(now or _now()); out=copy.deepcopy(registry); root=Path(secrets_dir); root.mkdir(parents=True,exist_ok=True)
    for x in _all(out):
        ident=Identity.generate(provider,node_schemes_for_repository(x)); write_json_private(root/f"{x['name']}.identity.json",identity_document(ident)); x["nodes"]=[node_record(ident,generation=1,not_before=ts,not_after=ts+int(ttl_seconds))]
    return out
def rotate_repository_node(provider:PQProvider,signed:dict[str,Any],root:dict[str,Any],root_identity:Identity,repository_name:str,secrets_dir:str|Path,*,now:int|None=None,ttl_seconds:int=86400*90,grace_seconds:int=3600)->dict[str,Any]:
    body=copy.deepcopy(signed["registry"]); ts=int(now or _now()); x=next((v for v in _all(body) if v["name"]==repository_name),None)
    if x is None: raise SecurityError("principal not present")
    gen=max([int(n["generation"]) for n in x.get("nodes") or []] or [0])+1
    for n in x.get("nodes") or []:
        if n["status"]==ACTIVE: n["status"]=RETIRING; n["not_after"]=min(int(n["not_after"]),ts+int(grace_seconds))
    ident=Identity.generate(provider,node_schemes_for_repository(x)); write_json_private(Path(secrets_dir)/f"{repository_name}.identity.g{gen}.json",identity_document(ident)); x.setdefault("nodes",[]).append(node_record(ident,generation=gen,not_before=ts,not_after=ts+int(ttl_seconds)))
    body.update(sequence=int(body["sequence"])+1,issued_at=ts,expires_at=max(ts+86400,min(int(body.get("expires_at",ts+86400*30)),ts+86400*30)),previous_registry_hash=signed["registry_hash"]); return sign_registry(provider,root_identity,root,body)
def revoke_node(provider:PQProvider,signed:dict[str,Any],root:dict[str,Any],root_identity:Identity,node_id:str,*,now:int|None=None)->dict[str,Any]:
    body=copy.deepcopy(signed["registry"]); ts=int(now or _now()); found=False
    for x in _all(body):
        for n in x.get("nodes") or []:
            if n.get("node_id")==node_id: n["status"]=REVOKED; n["not_after"]=min(int(n["not_after"]),ts); found=True
    if not found: raise SecurityError("node not present")
    body.update(sequence=int(body["sequence"])+1,issued_at=ts,expires_at=max(ts+86400,min(int(body.get("expires_at",ts+86400*30)),ts+86400*30)),previous_registry_hash=signed["registry_hash"]); return sign_registry(provider,root_identity,root,body)
def root_transition(provider:PQProvider,old_identity:Identity,old_root:dict[str,Any],new_root:dict[str,Any],*,created_at:int|None=None)->dict[str,Any]:
    verify_root_document(old_root); verify_root_document(new_root); body={"schema":ROOT_TRANSITION_SCHEMA,"old_root_id":old_root["root_id"],"new_root":new_root,"created_at":int(created_at or _now())}; digest=_hash(body); msg=_msg(DOMAIN_ROOT,digest); return {"body":body,"transition_hash":digest,"signatures":{s:b64e(provider.sign(s,old_identity.secret_keys[s],msg)) for s in old_root["required_schemes"]}}
def verify_root_transition(provider:PQProvider,old_root:dict[str,Any],transition:dict[str,Any])->dict[str,Any]:
    verify_root_document(old_root); body=transition.get("body") or {}; digest=_hash(body); required=tuple(old_root["required_schemes"]); sigs=transition.get("signatures") or {}
    if body.get("schema")!=ROOT_TRANSITION_SCHEMA or body.get("old_root_id")!=old_root["root_id"] or transition.get("transition_hash")!=digest or set(sigs)!=set(required): raise SecurityError("invalid root transition")
    msg=_msg(DOMAIN_ROOT,digest)
    for s in required:
        if not provider.verify(s,b64d(old_root["public_keys"][s]),msg,b64d(sigs[s])): raise SecurityError("root transition signature failed")
    new=body.get("new_root") or {}; verify_root_document(new); return new
