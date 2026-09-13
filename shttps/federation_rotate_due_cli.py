from __future__ import annotations
import argparse,json,os
from pathlib import Path
from .canonical import canonical_json
from .credentials import load_identity
from .crypto.oqs_provider import OQSProvider
from .federation import verify_signed_registry
from .federation_rotation import rotate_due_nodes,promote_pending_identities


def _read(path:str)->dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main()->None:
    p=argparse.ArgumentParser(prog="shttps-federation-rotate-due",description="Crash-safe batched federation identity rotation")
    p.add_argument("--root-secret",required=True); p.add_argument("--root-public",required=True); p.add_argument("--registry",required=True); p.add_argument("--secrets-dir",required=True)
    p.add_argument("--out"); p.add_argument("--commit-live",action="store_true")
    p.add_argument("--rotate-before-seconds",type=int,default=604800); p.add_argument("--grace-seconds",type=int,default=3600); p.add_argument("--node-valid-days",type=int,default=90)
    a=p.parse_args()
    if not a.commit_live and not a.out:
        p.error("--out is required unless --commit-live is used")
    provider=OQSProvider(); root=_read(a.root_public); root_identity=load_identity(a.root_secret); signed=_read(a.registry); verify_signed_registry(provider,root,signed)
    out,rotated=rotate_due_nodes(provider,signed,root,root_identity,a.secrets_dir,rotate_before_seconds=a.rotate_before_seconds,grace_seconds=a.grace_seconds,ttl_seconds=a.node_valid_days*86400)
    if a.commit_live:
        target=Path(a.registry); tmp=target.with_name(target.name+".next"); tmp.write_bytes(canonical_json(out)+b"\n")
        os.replace(tmp,target)
        promote_pending_identities(a.secrets_dir,rotated)
    else:
        target=Path(a.out); target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(canonical_json(out)+b"\n")
    print(json.dumps({"registry_hash":out["registry_hash"],"sequence":out["registry"]["sequence"],"rotated":rotated,"committed_live":bool(a.commit_live)}))


if __name__=="__main__": main()
