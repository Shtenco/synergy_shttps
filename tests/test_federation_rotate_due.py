from __future__ import annotations
from shttps.constants import SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S
from shttps.federation import FederationRegistry,federation_template_from_source,provision_all_nodes,root_document,sign_registry,verify_signed_registry
from shttps.federation_rotation import rotate_due_nodes
from shttps.handshake import Identity
from tests.fakes import FakePQProvider


def test_rotate_due_batches_51_repos_and_control_principal(tmp_path):
    provider=FakePQProvider(); root_identity=Identity.generate(provider,(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S)); root=root_document(root_identity,created_at=1000)
    repos=[{"name":f"repo_{i}","repo":f"https://github.com/Shtenco/repo_{i}","domain":"test","risk_class":"read_only","role":"test","integration":"shttps.rpc/v1","enabled":True,"rpc_allow":[]} for i in range(51)]
    source={"repositories":repos,"control_principals":[{"name":"synergy_ai_company","repo":"https://github.com/Shtenco/synergy_ai_company","domain":"control_plane","risk_class":"code_write","role":"orchestrator","integration":"shttps.rpc/v1","enabled":True,"rpc_allow":["nexus.runtime"]}]}
    body=federation_template_from_source(source,root,issued_at=1000,valid_for_seconds=200000,sequence=1); body=provision_all_nodes(provider,body,tmp_path/'initial',now=1000,ttl_seconds=100000); signed=sign_registry(provider,root_identity,root,body)
    out,names=rotate_due_nodes(provider,signed,root,root_identity,tmp_path/'rotated',now=99500,rotate_before_seconds=2000,ttl_seconds=100000,grace_seconds=100)
    assert len(names)==52 and out['registry']['sequence']==2 and out['registry']['previous_registry_hash']==signed['registry_hash']
    assert (tmp_path/'rotated'/'repo_0.identity.g2.json').exists() and (tmp_path/'rotated'/'repo_0.identity.json').exists()
    assert (tmp_path/'rotated'/'synergy_ai_company.identity.g2.json').exists() and (tmp_path/'rotated'/'synergy_ai_company.identity.json').exists()
    verified=verify_signed_registry(provider,root,out,now=99550,last_sequence=1,last_hash=signed['registry_hash']); reg=FederationRegistry(verified,now=99550)
    assert len(reg.accepted_nodes('repo_0'))==2 and len(reg.accepted_nodes('synergy_ai_company'))==2
