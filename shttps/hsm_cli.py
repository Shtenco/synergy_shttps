from __future__ import annotations
import argparse,json,os
from pathlib import Path
from .canonical import canonical_json,b64e
from .crypto.oqs_provider import OQSProvider
from .crypto.pkcs11_signer import PKCS11MLDSASigner,PKCS11SignerConfig
from .federation_delegate import _signer_id


def _cfg(a): return PKCS11SignerConfig(a.module,a.token_label,a.key_label,a.pin_file)
def _write(path,value):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); tmp=p.with_name(p.name+'.next'); tmp.write_bytes(canonical_json(value)+b'\n'); os.replace(tmp,p)

def main():
    parser=argparse.ArgumentParser(prog='shttps-hsm-signer'); sub=parser.add_subparsers(dest='cmd',required=True)
    for name in ('init','describe','check'):
        p=sub.add_parser(name); p.add_argument('--module',required=True); p.add_argument('--token-label',required=True); p.add_argument('--key-label',required=True); p.add_argument('--pin-file',required=True)
        if name=='init': p.add_argument('--public-out',required=True)
    a=parser.parse_args(); verifier=OQSProvider(); signer=PKCS11MLDSASigner.generate(_cfg(a),verifier) if a.cmd=='init' else PKCS11MLDSASigner(_cfg(a))
    challenge=b'SHTTPS/1/pkcs11-mldsa87-runtime-check\x00'; signature=signer.sign('ML-DSA-87',challenge); public=dict(signer.public_keys)
    if not verifier.verify('ML-DSA-87',public['ML-DSA-87'],challenge,signature): raise SystemExit('PKCS11_INTEROP_FAILED')
    descriptor={'schema':'shttps.pkcs11-delegated-signer-public/v1','signer_id':_signer_id(public),'required_schemes':['ML-DSA-87'],'public_keys':{k:b64e(v) for k,v in public.items()},'key_label':a.key_label,'non_exportable_private_key_required':True}
    if a.cmd=='init': _write(a.public_out,descriptor)
    print(json.dumps({'ok':True,'signer_id':descriptor['signer_id'],'scheme':'ML-DSA-87','private_key_exported':False},sort_keys=True))

if __name__=='__main__': main()
