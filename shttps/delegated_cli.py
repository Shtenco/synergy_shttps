from __future__ import annotations
import argparse,json,os,time
from pathlib import Path
from .canonical import b64d,canonical_json
from .credentials import load_identity
from .crypto.oqs_provider import OQSProvider
from .crypto.pkcs11_signer import PKCS11MLDSASigner,PKCS11SignerConfig
from .errors import SecurityError
from .federation import federation_template_from_source,provision_all_nodes
from .federation_delegate import build_revoke_node_body,create_signer_certificate,create_signer_revocations,load_verified_delegated_registry,sign_registry_delegated,verify_delegated_registry,verify_signer_certificate,verify_signer_revocations
from .federation_rotation import build_due_registry_update,promote_pending_identities


def _read(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def _write(path,value):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); tmp=p.with_name(p.name+'.next'); tmp.write_bytes(canonical_json(value)+b'\n'); os.replace(tmp,p)
def _hsm():
    values={k:os.getenv(k,'') for k in ('SHTTPS_PKCS11_MODULE','SHTTPS_PKCS11_TOKEN_LABEL','SHTTPS_PKCS11_KEY_LABEL','SHTTPS_PKCS11_PIN_FILE')}; missing=[k for k,v in values.items() if not v]
    if missing: raise SecurityError('missing PKCS#11 configuration: '+','.join(missing))
    return PKCS11MLDSASigner(PKCS11SignerConfig(values['SHTTPS_PKCS11_MODULE'],values['SHTTPS_PKCS11_TOKEN_LABEL'],values['SHTTPS_PKCS11_KEY_LABEL'],values['SHTTPS_PKCS11_PIN_FILE']))
def _descriptor(path):
    d=_read(path); keys=d.get('public_keys') or {}
    if d.get('schema')!='shttps.pkcs11-delegated-signer-public/v1' or set(keys)!={'ML-DSA-87'}: raise SecurityError('invalid HSM signer descriptor')
    return {'ML-DSA-87':b64d(keys['ML-DSA-87'])}

def main():
    parser=argparse.ArgumentParser(prog='shttps-federation-delegated'); sub=parser.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('issue-signer-cert'); p.add_argument('--root-secret',required=True); p.add_argument('--root-public',required=True); p.add_argument('--signer-public',required=True); p.add_argument('--source',required=True); p.add_argument('--out',required=True); p.add_argument('--generation',type=int,default=1); p.add_argument('--valid-days',type=int,default=35); p.add_argument('--max-registry-valid-days',type=int,default=7)
    p=sub.add_parser('revocations-init'); p.add_argument('--root-secret',required=True); p.add_argument('--root-public',required=True); p.add_argument('--out',required=True); p.add_argument('--valid-days',type=int,default=90)
    p=sub.add_parser('revoke-signer'); p.add_argument('--root-secret',required=True); p.add_argument('--root-public',required=True); p.add_argument('--revocations',required=True); p.add_argument('--signer-id',required=True); p.add_argument('--out',required=True); p.add_argument('--valid-days',type=int,default=90)
    p=sub.add_parser('provision-initial'); p.add_argument('--root-public',required=True); p.add_argument('--signer-cert',required=True); p.add_argument('--signer-revocations',required=True); p.add_argument('--source',required=True); p.add_argument('--secrets-dir',required=True); p.add_argument('--registry-out',required=True); p.add_argument('--registry-valid-days',type=int,default=7); p.add_argument('--node-valid-days',type=int,default=90)
    p=sub.add_parser('verify'); p.add_argument('--root-public',required=True); p.add_argument('--signer-revocations',required=True); p.add_argument('--registry',required=True); p.add_argument('--state')
    p=sub.add_parser('maintain'); p.add_argument('--root-public',required=True); p.add_argument('--signer-cert',required=True); p.add_argument('--signer-revocations',required=True); p.add_argument('--registry',required=True); p.add_argument('--secrets-dir',required=True); p.add_argument('--state'); p.add_argument('--rotate-before-seconds',type=int,default=604800); p.add_argument('--renew-before-seconds',type=int,default=172800); p.add_argument('--registry-valid-days',type=int,default=7); p.add_argument('--node-valid-days',type=int,default=90); p.add_argument('--grace-seconds',type=int,default=3600)
    p=sub.add_parser('revoke-node'); p.add_argument('--root-public',required=True); p.add_argument('--signer-cert',required=True); p.add_argument('--signer-revocations',required=True); p.add_argument('--registry',required=True); p.add_argument('--node-id',required=True); p.add_argument('--registry-valid-days',type=int,default=7)
    a=parser.parse_args(); provider=OQSProvider(); now=int(time.time())
    if a.cmd=='issue-signer-cert':
        root=_read(a.root_public); root_id=load_identity(a.root_secret); template=federation_template_from_source(_read(a.source),root,issued_at=now,valid_for_seconds=a.max_registry_valid_days*86400); cert=create_signer_certificate(provider,root_id,root,_descriptor(a.signer_public),template,generation=a.generation,not_before=now-300,not_after=now+a.valid_days*86400,max_registry_valid_seconds=a.max_registry_valid_days*86400); _write(a.out,cert); print(json.dumps({'signer_id':cert['certificate']['signer_id'],'generation':a.generation})); return
    if a.cmd=='revocations-init':
        root=_read(a.root_public); root_id=load_identity(a.root_secret); out=create_signer_revocations(provider,root_id,root,sequence=1,issued_at=now,expires_at=now+a.valid_days*86400); _write(a.out,out); print(json.dumps({'sequence':1,'revocations_hash':out['revocations_hash']})); return
    if a.cmd=='revoke-signer':
        root=_read(a.root_public); root_id=load_identity(a.root_secret); old=_read(a.revocations); body=verify_signer_revocations(provider,root,old,now=now); revoked=sorted(set([*(body.get('revoked_signer_ids') or []),a.signer_id])); out=create_signer_revocations(provider,root_id,root,sequence=int(body['sequence'])+1,issued_at=now,expires_at=now+a.valid_days*86400,revoked_signer_ids=revoked,previous_hash=old['revocations_hash']); _write(a.out,out); print(json.dumps({'sequence':out['revocations']['sequence'],'revoked':len(revoked)})); return
    root=_read(a.root_public); rev=_read(a.signer_revocations)
    if a.cmd=='provision-initial':
        cert=_read(a.signer_cert); signer=_hsm(); source=_read(a.source); verify_signer_certificate(provider,root,cert,now=now); verify_signer_revocations(provider,root,rev,now=now); body=federation_template_from_source(source,root,issued_at=now,valid_for_seconds=a.registry_valid_days*86400); body=provision_all_nodes(provider,body,a.secrets_dir,now=now,ttl_seconds=a.node_valid_days*86400); out=sign_registry_delegated(provider,signer,root,cert,rev,body,now=now); verify_delegated_registry(provider,root,out,rev,now=now); _write(a.registry_out,out); print(json.dumps({'sequence':1,'registry_hash':out['registry_hash'],'repositories':len(body['repositories']),'controls':len(body.get('control_principals') or [])})); return
    if a.cmd=='verify':
        reg=load_verified_delegated_registry(provider,a.root_public,a.registry,a.signer_revocations,state_path=a.state,now=now); print(json.dumps({'sequence':reg.sequence,'registry_hash':reg.registry_hash,'root_id':reg.root_id})); return
    cert=_read(a.signer_cert); signer=_hsm(); signed=_read(a.registry); verify_delegated_registry(provider,root,signed,rev,now=now)
    if a.cmd=='maintain':
        body,rotated=build_due_registry_update(provider,signed,a.secrets_dir,now=now,rotate_before_seconds=a.rotate_before_seconds,renew_before_seconds=a.renew_before_seconds,registry_valid_seconds=a.registry_valid_days*86400,ttl_seconds=a.node_valid_days*86400,grace_seconds=a.grace_seconds)
        if body is None: print(json.dumps({'changed':False,'sequence':signed['registry']['sequence'],'rotated':[]})); return
        out=sign_registry_delegated(provider,signer,root,cert,rev,body,now=now); verify_delegated_registry(provider,root,out,rev,now=now,last_sequence=int(signed['registry']['sequence']),last_hash=signed['registry_hash']); _write(a.registry,out); promote_pending_identities(a.secrets_dir,rotated); print(json.dumps({'changed':True,'sequence':body['sequence'],'registry_hash':out['registry_hash'],'rotated':rotated})); return
    if a.cmd=='revoke-node':
        body=build_revoke_node_body(signed,a.node_id,now=now,registry_valid_seconds=a.registry_valid_days*86400); out=sign_registry_delegated(provider,signer,root,cert,rev,body,now=now); verify_delegated_registry(provider,root,out,rev,now=now,last_sequence=int(signed['registry']['sequence']),last_hash=signed['registry_hash']); _write(a.registry,out); print(json.dumps({'sequence':body['sequence'],'registry_hash':out['registry_hash'],'revoked_node':a.node_id})); return

if __name__=='__main__': main()
