from __future__ import annotations
import copy
from pathlib import Path
from typing import Any

from .credentials import identity_document, write_json_private
from .crypto.base import PQProvider
from .federation import ACTIVE, RETIRING, _all, _now, node_record, node_schemes_for_repository, sign_registry
from .handshake import Identity


def build_due_registry_update(
    provider:PQProvider,
    signed:dict[str,Any],
    secrets_dir:str|Path,
    *,
    now:int|None=None,
    rotate_before_seconds:int=86400*7,
    renew_before_seconds:int=86400*7,
    registry_valid_seconds:int=86400*30,
    ttl_seconds:int=86400*90,
    grace_seconds:int=3600,
)->tuple[dict[str,Any]|None,list[str]]:
    """Build an unsigned lifecycle-only registry update and pending node secrets.

    The caller chooses the signing authority: legacy root signing or delegated HSM
    signing. Static governance metadata is copied unchanged; only node lifecycle,
    timestamps, sequence, validity and hash-chain fields can change here.
    """
    body=copy.deepcopy(signed["registry"])
    ts=int(now or _now())
    rotated=[]
    secret_root=Path(secrets_dir)
    secret_root.mkdir(parents=True,exist_ok=True)
    for principal in _all(body):
        active=[n for n in principal.get("nodes") or [] if n.get("status")==ACTIVE and int(n.get("not_before",0))<=ts<int(n.get("not_after",0))]
        if not active or min(int(n["not_after"]) for n in active)>ts+int(rotate_before_seconds):
            continue
        generation=max([int(n["generation"]) for n in principal.get("nodes") or []] or [0])+1
        for node in active:
            node["status"]=RETIRING
            node["not_after"]=min(int(node["not_after"]),ts+int(grace_seconds))
        identity=Identity.generate(provider,node_schemes_for_repository(principal))
        document=identity_document(identity)
        write_json_private(secret_root/f"{principal['name']}.identity.g{generation}.json",document)
        write_json_private(secret_root/f"{principal['name']}.identity.next.json",document)
        principal.setdefault("nodes",[]).append(node_record(identity,generation=generation,not_before=ts,not_after=ts+int(ttl_seconds)))
        rotated.append(str(principal["name"]))

    renewal_due=int(body.get("expires_at",0))<=ts+int(renew_before_seconds)
    if not rotated and not renewal_due:
        return None,[]

    body.update(
        sequence=int(body["sequence"])+1,
        issued_at=ts,
        expires_at=ts+int(registry_valid_seconds),
        previous_registry_hash=signed["registry_hash"],
    )
    return body,rotated


def rotate_due_nodes(
    provider:PQProvider,
    signed:dict[str,Any],
    root:dict[str,Any],
    root_identity:Identity,
    secrets_dir:str|Path,
    *,
    now:int|None=None,
    rotate_before_seconds:int=86400*7,
    renew_before_seconds:int=86400*7,
    registry_valid_seconds:int=86400*30,
    ttl_seconds:int=86400*90,
    grace_seconds:int=3600,
)->tuple[dict[str,Any],list[str]]:
    body,rotated=build_due_registry_update(
        provider,signed,secrets_dir,now=now,
        rotate_before_seconds=rotate_before_seconds,
        renew_before_seconds=renew_before_seconds,
        registry_valid_seconds=registry_valid_seconds,
        ttl_seconds=ttl_seconds,
        grace_seconds=grace_seconds,
    )
    if body is None:
        return signed,[]
    return sign_registry(provider,root_identity,root,body),rotated


def promote_pending_identities(secrets_dir:str|Path,names:list[str])->None:
    """Atomically promote pending identities only after the new registry is live."""
    root=Path(secrets_dir)
    for name in names:
        pending=root/f"{name}.identity.next.json"
        stable=root/f"{name}.identity.json"
        if not pending.exists():
            raise FileNotFoundError(f"missing pending identity for {name}")
        pending.replace(stable)
