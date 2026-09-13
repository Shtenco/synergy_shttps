from __future__ import annotations
import json
import pytest

from shttps.constants import SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S
from shttps.errors import SecurityError
from shttps.federation import FederationRegistry, federation_template_from_source, provision_all_nodes, revoke_node, root_document, rotate_repository_node, sign_registry, verify_signed_registry, root_transition, verify_root_transition
from shttps.handshake import Identity
from tests.fakes import FakePQProvider


def source51():
    repos=[]
    for i in range(51):
        name=f"repo_{i}"; risk="read_only"
        if i==0: name="synergy_system"
        elif i==1: name="synergy_pay_system"; risk="financial"
        elif i==2: name="synergy_financial_os"; risk="financial"
        elif i==3: name="synergy_ai_blockchain"; risk="blockchain"
        elif i==4: name="agi_autopilot"
        elif i==5: name="agi_nexus"
        repos.append({"name":name,"repo":f"https://github.com/Shtenco/{name}","domain":"test","risk_class":risk,"role":"test","integration":"shttps.rpc/v1","enabled":True,"rpc_allow":[]})
    return {"repositories":repos,"control_principals":[{"name":"synergy_ai_company","repo":"https://github.com/Shtenco/synergy_ai_company","domain":"control_plane","risk_class":"code_write","role":"business_orchestrator","integration":"shttps.rpc/v1","enabled":True,"rpc_allow":["autopilot.submit","autopilot.status","autopilot.approve","autopilot.execute","autopilot.capabilities","nexus.runtime","nexus.memory.search","nexus.memory.upsert"]}]}


def setup_registry(tmp_path):
    p=FakePQProvider(); root_ident=Identity.generate(p,(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S)); root=root_document(root_ident,created_at=1000)
    body=federation_template_from_source(source51(),root,issued_at=1000,valid_for_seconds=100000,sequence=1)
    body=provision_all_nodes(p,body,tmp_path/'secrets',now=1000,ttl_seconds=100000)
    return p,root_ident,root,sign_registry(p,root_ident,root,body)


def test_provisions_exact_51_and_control_principal(tmp_path):
    p,_,root,signed=setup_registry(tmp_path); body=verify_signed_registry(p,root,signed,now=2000)
    assert body['repository_count']==51 and len(body['repositories'])==51 and len(body['control_principals'])==1
    reg=FederationRegistry(body,now=2000); company=reg.preferred_node_id('synergy_ai_company')
    assert reg.authorize_rpc(company,'autopilot','execute') and reg.authorize_rpc(company,'nexus','runtime')
    assert not reg.authorize_rpc(reg.preferred_node_id('agi_autopilot'),'nexus','runtime')


def test_money_chain_and_root_use_max_identity(tmp_path):
    p,_,root,signed=setup_registry(tmp_path); reg=FederationRegistry(verify_signed_registry(p,root,signed,now=2000),now=2000)
    for name in ['synergy_system','synergy_pay_system','synergy_financial_os','synergy_ai_blockchain']:
        assert set(reg.accepted_nodes(name)[0]['identity_schemes'])=={SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S}
    assert set(reg.accepted_nodes('agi_nexus')[0]['identity_schemes'])=={SIG_ML_DSA_87}


def test_signature_downgrade_and_tamper_fail(tmp_path):
    p,_,root,signed=setup_registry(tmp_path)
    broken=json.loads(json.dumps(signed)); broken['signatures'].pop(SIG_SLH_DSA_SHAKE_256S)
    with pytest.raises(SecurityError): verify_signed_registry(p,root,broken,now=2000)
    broken=json.loads(json.dumps(signed)); broken['registry']['repositories'][0]['role']='evil'
    with pytest.raises(SecurityError): verify_signed_registry(p,root,broken,now=2000)


def test_rotation_revoke_and_rollback(tmp_path):
    p,ri,root,signed=setup_registry(tmp_path); old=FederationRegistry(signed['registry'],now=2000).preferred_node_id('agi_nexus')
    rotated=rotate_repository_node(p,signed,root,ri,'agi_nexus',tmp_path/'secrets',now=3000,ttl_seconds=100000,grace_seconds=100)
    reg=FederationRegistry(verify_signed_registry(p,root,rotated,now=3050,last_sequence=1,last_hash=signed['registry_hash']),now=3050)
    assert len(reg.accepted_nodes('agi_nexus'))==2 and reg.preferred_node_id('agi_nexus')!=old
    revoked=revoke_node(p,rotated,root,ri,reg.preferred_node_id('agi_nexus'),now=3100)
    verify_signed_registry(p,root,revoked,now=3150,last_sequence=2,last_hash=rotated['registry_hash'])
    with pytest.raises(SecurityError): verify_signed_registry(p,root,signed,now=3150,last_sequence=3,last_hash=revoked['registry_hash'])


def test_root_rotation_requires_old_max_root(tmp_path):
    p,old_identity,old_root,_=setup_registry(tmp_path); new_identity=Identity.generate(p,(SIG_ML_DSA_87,SIG_SLH_DSA_SHAKE_256S)); new_root=root_document(new_identity,generation=2,created_at=4000)
    transition=root_transition(p,old_identity,old_root,new_root,created_at=4000); assert verify_root_transition(p,old_root,transition)['root_id']==new_root['root_id']
    transition['signatures'].pop(SIG_SLH_DSA_SHAKE_256S)
    with pytest.raises(SecurityError): verify_root_transition(p,old_root,transition)


def test_registry_enforces_caller_acl_over_transport(tmp_path):
    import asyncio
    async def scenario():
        from shttps.constants import CompressionId
        from shttps.credentials import load_identity
        from shttps.handshake import HandshakeConfig
        from shttps.rpc import RPCDispatcher
        from shttps.transport import SHTTPSRPCClient,SHTTPSRPCServer
        from tests.fakes import fake_compression
        p,_,root,signed=setup_registry(tmp_path); reg=FederationRegistry(verify_signed_registry(p,root,signed,now=2000),now=2000)
        company=load_identity(tmp_path/'secrets'/'synergy_ai_company.identity.json'); autopilot=load_identity(tmp_path/'secrets'/'agi_autopilot.identity.json'); nexus=load_identity(tmp_path/'secrets'/'agi_nexus.identity.json')
        trust=reg.trust_store(['synergy_ai_company','agi_autopilot','agi_nexus']); cfg=HandshakeConfig(compressions=(CompressionId.AI_COMPRESS_SGH1_SPEED,CompressionId.RAW),protocols=('shttps.rpc/v1',))
        d=RPCDispatcher(); d.register('nexus','runtime',lambda params,ctx:{'repo':ctx['repository']})
        server=SHTTPSRPCServer('127.0.0.1',0,p,nexus,trust,cfg,d,compression=fake_compression(),federation=reg); await server.start(); port=server._server.sockets[0].getsockname()[1]
        try:
            allowed=SHTTPSRPCClient('127.0.0.1',port,p,company,trust,cfg,compression=fake_compression(),expected_peer_node_ids={nexus.node_id}); assert (await allowed.call('nexus','runtime',{}))['repo']=='synergy_ai_company'
            denied=SHTTPSRPCClient('127.0.0.1',port,p,autopilot,trust,cfg,compression=fake_compression(),expected_peer_node_ids={nexus.node_id})
            with pytest.raises(RuntimeError,match='FEDERATION_RPC_NOT_AUTHORIZED'): await denied.call('nexus','runtime',{})
        finally: await server.close()
    asyncio.run(scenario())
