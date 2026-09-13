from __future__ import annotations
import copy,json,pytest
from shttps.constants import SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S
from shttps.errors import SecurityError
from shttps.federation import federation_template_from_source,provision_all_nodes,root_document
from shttps.federation_delegate import IdentitySigningBackend,create_signer_certificate,create_signer_revocations,load_verified_delegated_registry,sign_registry_delegated,verify_delegated_registry,verify_signer_revocations
from shttps.federation_rotation import build_due_registry_update
from shttps.handshake import Identity
from tests.fakes import FakePQProvider


def source():
    return {"repositories":[{"name":"agi_autopilot","repo":"https://github.com/Shtenco/agi_autopilot","domain":"execution","risk_class":"code_write","role":"executor","integration":"shttps.rpc/v1","enabled":True,"rpc_allow":[]}],"control_principals":[{"name":"synergy_ai_company","repo":"https://github.com/Shtenco/synergy_ai_company","domain":"control_plane","risk_class":"code_write","role":"orchestrator","integration":"shttps.rpc/v1","enabled":True,"rpc_allow":["autopilot.submit"]}]}


def setup_material(tmp_path,now=10_000,signer_days=35):
    provider=FakePQProvider(); root_identity=Identity.generate(provider,(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S)); root=root_document(root_identity,created_at=now-100); template=federation_template_from_source(source(),root,issued_at=now,valid_for_seconds=7*86400); signer=Identity.generate(provider,(SIG_ML_DSA_87,)); cert=create_signer_certificate(provider,root_identity,root,signer.public_keys,template,not_before=now-60,not_after=now+signer_days*86400,max_registry_valid_seconds=7*86400); rev=create_signer_revocations(provider,root_identity,root,sequence=1,issued_at=now-60,expires_at=now+90*86400); body=provision_all_nodes(provider,template,tmp_path/'nodes',now=now,ttl_seconds=90*86400); signed=sign_registry_delegated(provider,IdentitySigningBackend(provider,signer),root,cert,rev,body,now=now); return provider,root_identity,root,signer,cert,rev,signed


def test_delegated_registry_verifies_and_persists_revocation_state(tmp_path):
    now=10_000; provider,_,root,_,_,rev,signed=setup_material(tmp_path,now); assert verify_delegated_registry(provider,root,signed,rev,now=now)["sequence"]==1
    rp=tmp_path/'root.json'; gp=tmp_path/'registry.json'; vp=tmp_path/'rev.json'; sp=tmp_path/'state.json'; rp.write_text(json.dumps(root)); gp.write_text(json.dumps(signed)); vp.write_text(json.dumps(rev)); reg=load_verified_delegated_registry(provider,rp,gp,vp,state_path=sp,now=now); state=json.loads(sp.read_text()); assert reg.sequence==1 and state['signer_revocation_sequence']==1 and state['signer_revocation_hash']==rev['revocations_hash']


def test_delegated_signer_cannot_expand_acl(tmp_path):
    now=20_000; provider,_,root,signer,cert,rev,signed=setup_material(tmp_path,now); tampered=copy.deepcopy(signed['registry']); tampered['control_principals'][0]['rpc_allow'].append('autopilot.execute')
    with pytest.raises(SecurityError,match='governance'): sign_registry_delegated(provider,IdentitySigningBackend(provider,signer),root,cert,rev,tampered,now=now)


def test_root_can_revoke_online_signer_immediately(tmp_path):
    now=30_000; provider,root_identity,root,_,cert,rev,signed=setup_material(tmp_path,now); sid=cert['certificate']['signer_id']; revoked=create_signer_revocations(provider,root_identity,root,sequence=2,issued_at=now,expires_at=now+90*86400,revoked_signer_ids=[sid],previous_hash=rev['revocations_hash'])
    with pytest.raises(SecurityError,match='revoked'): verify_delegated_registry(provider,root,signed,revoked,now=now+1)


def test_signer_revocation_state_rejects_rollback(tmp_path):
    now=40_000; provider,root_identity,root,_,_,rev,_=setup_material(tmp_path,now); newer=create_signer_revocations(provider,root_identity,root,sequence=2,issued_at=now,expires_at=now+100000,previous_hash=rev['revocations_hash']); verify_signer_revocations(provider,root,newer,now=now+1,last_sequence=1,last_hash=rev['revocations_hash'])
    with pytest.raises(SecurityError,match='rollback'): verify_signer_revocations(provider,root,rev,now=now+1,last_sequence=2,last_hash=newer['revocations_hash'])


def test_lifecycle_rotation_is_delegated_without_governance_change(tmp_path):
    now=50_000; provider,root_identity,root,signer,_,_,_=setup_material(tmp_path,now,signer_days=120); template=federation_template_from_source(source(),root,issued_at=now,valid_for_seconds=7*86400); cert=create_signer_certificate(provider,root_identity,root,signer.public_keys,template,not_before=now-60,not_after=now+120*86400,max_registry_valid_seconds=7*86400); rev=create_signer_revocations(provider,root_identity,root,sequence=1,issued_at=now-60,expires_at=now+150*86400); body=provision_all_nodes(provider,template,tmp_path/'longnodes',now=now,ttl_seconds=90*86400); signed=sign_registry_delegated(provider,IdentitySigningBackend(provider,signer),root,cert,rev,body,now=now); rotate_at=now+84*86400; update,rotated=build_due_registry_update(provider,signed,tmp_path/'rotated',now=rotate_at,rotate_before_seconds=7*86400,renew_before_seconds=2*86400,registry_valid_seconds=7*86400,ttl_seconds=90*86400,grace_seconds=3600); assert update is not None and len(rotated)==2; out=sign_registry_delegated(provider,IdentitySigningBackend(provider,signer),root,cert,rev,update,now=rotate_at); assert verify_delegated_registry(provider,root,out,rev,now=rotate_at+1,last_sequence=1,last_hash=signed['registry_hash'])["sequence"]==2
