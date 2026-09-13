from __future__ import annotations

import json
from pathlib import Path

from .canonical import b64d, b64e, canonical_json
from .errors import SecurityError
from .handshake import Identity, PinnedTrustStore


def load_identity(path: str | Path) -> Identity:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != "shttps.identity/v1":
        raise SecurityError("invalid SHTTPS identity file")
    public = {str(k): b64d(str(v)) for k, v in (data.get("public_keys") or {}).items()}
    secret = {str(k): b64d(str(v)) for k, v in (data.get("secret_keys") or {}).items()}
    if not public or set(public) != set(secret):
        raise SecurityError("identity requires matching public/secret schemes")
    ident = Identity(public, secret)
    declared = data.get("node_id")
    if declared and declared != ident.node_id:
        raise SecurityError("identity node_id mismatch")
    return ident


def identity_document(identity: Identity, *, include_secret: bool = True) -> dict:
    data = {"schema": "shttps.identity/v1", "node_id": identity.node_id, "public_keys": {k: b64e(v) for k, v in sorted(identity.public_keys.items())}}
    if include_secret:
        data["secret_keys"] = {k: b64e(v) for k, v in sorted(identity.secret_keys.items())}
    return data


def load_trust_store(path: str | Path) -> PinnedTrustStore:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != "shttps.trust/v1":
        raise SecurityError("invalid SHTTPS trust file")
    peers: dict[str, dict[str, bytes]] = {}
    for node_id, item in (data.get("peers") or {}).items():
        keys = item.get("public_keys") if isinstance(item, dict) else None
        if not isinstance(keys, dict) or not keys:
            raise SecurityError("trust entry missing public_keys")
        peers[str(node_id)] = {str(k): b64d(str(v)) for k, v in keys.items()}
    return PinnedTrustStore(peers)


def trust_document(identities: list[Identity]) -> dict:
    return {"schema": "shttps.trust/v1", "peers": {i.node_id: {"public_keys": {k: b64e(v) for k, v in sorted(i.public_keys.items())}} for i in identities}}


def write_json_private(path: str | Path, document: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_json(document) + b"\n")
    try:
        target.chmod(0o600)
    except OSError:
        pass
