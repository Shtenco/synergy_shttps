from __future__ import annotations
import copy
from pathlib import Path
from typing import Any

from .credentials import identity_document, write_json_private
from .crypto.base import PQProvider
from .federation import ACTIVE, RETIRING, _all, _now, node_record, node_schemes_for_repository, sign_registry
from .handshake import Identity


def rotate_due_nodes(provider:PQProvider,signed:dict[str,Any],root:dict[str,Any],root_identity:Identity,secrets_dir:str|Path,*,now:int|None=None,rotate_before_seconds:int=86400*7,ttl_seconds:int=86400*90,grace_seconds:int=3600)->tuple[dict[str,Any],list[str]]:
    """Build one signed registry update for every identity entering its rotation horizon.

    New private material is written only as immutable generation files plus `.next`
    candidates. The stable identity path is deliberately NOT changed here; callers
    must publish the new signed registry first, then call promote_pending_identities.
    This makes rotation crash-safe across the registry/secret publication boundary.
    """
    body=copy.deepcopy(signed["registry"]); ts=int(now or _now()); rotated=[]; secret_root=Path(secrets_dir); secret_root.mkdir(parents=True,exist_ok=True)
    for principal in _all(body):
        active=[n for n in principal.get("nodes") or [] if n.get("status")==ACTIVE and int(n.get("not_before",0))<=ts<int(n.get("not_after",0))]
        if not active or min(int(n["not_after"]) for n in active)>ts+int(rotate_before_seconds):
            continue
        generation=max([int(n["generation"]) for n in principal.get("nodes") or []] or [0])+1
        for node in active:
            node["status"]=RETIRING; node["not_after"]=min(int(node["not_after"]),ts+int(grace_seconds))
        identity=Identity.generate(provider,node_schemes_for_repository(principal)); document=identity_document(identity)
        write_json_private(secret_root/f"{principal['name']}.identity.g{generation}.json",document)
        write_json_private(secret_root/f"{principal['name']}.identity.next.json",document)
        principal.setdefault("nodes",[]).append(node_record(identity,generation=generation,not_before=ts,not_after=ts+int(ttl_seconds)))
        rotated.append(str(principal["name"]))
    if not rotated:
        return signed,[]
    body.update(sequence=int(body["sequence"])+1,issued_at=ts,expires_at=max(ts+86400,min(int(body.get("expires_at",ts+86400*30)),ts+86400*30)),previous_registry_hash=signed["registry_hash"])
    return sign_registry(provider,root_identity,root,body),rotated


def promote_pending_identities(secrets_dir:str|Path,names:list[str])->None:
    """Atomically promote pending identities only after the new registry is live."""
    root=Path(secrets_dir)
    for name in names:
        pending=root/f"{name}.identity.next.json"; stable=root/f"{name}.identity.json"
        if not pending.exists():
            raise FileNotFoundError(f"missing pending identity for {name}")
        pending.replace(stable)
