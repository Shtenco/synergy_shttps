from __future__ import annotations

from dataclasses import dataclass
import copy
import json
import time
from pathlib import Path
from typing import Any, Iterable

from .canonical import b64d, b64e, canonical_json, sha3_256, sha3_512
from .crypto.base import PQProvider
from .errors import SecurityError
from .handshake import Identity, PinnedTrustStore
from .constants import SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S
from .credentials import identity_document, write_json_private

REGISTRY_SCHEMA = "shttps.federation-registry/v1"
SIGNED_SCHEMA = "shttps.federation-registry-signed/v1"
ROOT_SCHEMA = "shttps.federation-root/v1"
ROOT_TRANSITION_SCHEMA = "shttps.federation-root-transition/v1"
NODE_STATUS_ACTIVE = "active"
NODE_STATUS_RETIRING = "retiring"
NODE_STATUS_REVOKED = "revoked"
DOMAIN_REGISTRY = b"SHTTPS/1/federation-registry\x00"
DOMAIN_ROOT_ROTATION = b"SHTTPS/1/federation-root-rotation\x00"


def _now() -> int:
    return int(time.time())


def _hash_doc(doc: dict[str, Any]) -> str:
    return sha3_512(canonical_json(doc)).hex()


def _signed_message(domain: bytes, digest_hex: str) -> bytes:
    try:
        digest = bytes.fromhex(digest_hex)
    except ValueError as exc:
        raise SecurityError("invalid digest encoding") from exc
    return domain + digest


def node_record(identity: Identity, *, generation: int, not_before: int, not_after: int, status: str = NODE_STATUS_ACTIVE) -> dict[str, Any]:
    if generation <= 0 or not_after <= not_before:
        raise ValueError("invalid node generation/validity")
    if status not in {NODE_STATUS_ACTIVE, NODE_STATUS_RETIRING, NODE_STATUS_REVOKED}:
        raise ValueError("invalid node status")
    return {
        "node_id": identity.node_id,
        "generation": generation,
        "status": status,
        "not_before": int(not_before),
        "not_after": int(not_after),
        "identity_schemes": sorted(identity.public_keys),
        "public_keys": {k: b64e(v) for k, v in sorted(identity.public_keys.items())},
    }


def root_document(identity: Identity, *, generation: int = 1, created_at: int | None = None, required_schemes: Iterable[str] | None = None) -> dict[str, Any]:
    schemes = tuple(required_schemes or (SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S))
    if set(identity.public_keys) != set(schemes):
        raise SecurityError("root identity must exactly match required schemes")
    public = {k: b64e(v) for k, v in sorted(identity.public_keys.items())}
    root_id = sha3_256(b"SHTTPS/1/federation-root-id\x00" + canonical_json(public)).hex()
    return {
        "schema": ROOT_SCHEMA,
        "root_id": root_id,
        "generation": int(generation),
        "created_at": int(created_at or _now()),
        "required_schemes": list(schemes),
        "public_keys": public,
    }


def verify_root_document(root: dict[str, Any]) -> None:
    if root.get("schema") != ROOT_SCHEMA:
        raise SecurityError("invalid federation root schema")
    schemes = tuple(root.get("required_schemes") or ())
    keys = root.get("public_keys") or {}
    if not schemes or set(keys) != set(schemes):
        raise SecurityError("federation root key/scheme mismatch")
    public = {str(k): str(v) for k, v in sorted(keys.items())}
    expected = sha3_256(b"SHTTPS/1/federation-root-id\x00" + canonical_json(public)).hex()
    if root.get("root_id") != expected:
        raise SecurityError("federation root_id mismatch")


def sign_registry(provider: PQProvider, root_identity: Identity, root: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    verify_root_document(root)
    if registry.get("schema") != REGISTRY_SCHEMA:
        raise SecurityError("invalid federation registry schema")
    if registry.get("root_id") != root.get("root_id"):
        raise SecurityError("registry root_id mismatch")
    required = tuple(root["required_schemes"])
    if set(root_identity.public_keys) != set(required):
        raise SecurityError("root private identity does not match root policy")
    for scheme in required:
        if b64e(root_identity.public_keys[scheme]) != root["public_keys"][scheme]:
            raise SecurityError("root private identity does not match pinned public root")
    digest = _hash_doc(registry)
    message = _signed_message(DOMAIN_REGISTRY, digest)
    signatures = {scheme: b64e(provider.sign(scheme, root_identity.secret_keys[scheme], message)) for scheme in required}
    return {"schema": SIGNED_SCHEMA, "registry": registry, "registry_hash": digest, "signatures": signatures}


def verify_signed_registry(provider: PQProvider, root: dict[str, Any], signed: dict[str, Any], *, now: int | None = None, last_sequence: int | None = None, last_hash: str | None = None) -> dict[str, Any]:
    verify_root_document(root)
    if signed.get("schema") != SIGNED_SCHEMA:
        raise SecurityError("invalid signed registry schema")
    registry = signed.get("registry")
    if not isinstance(registry, dict) or registry.get("schema") != REGISTRY_SCHEMA:
        raise SecurityError("invalid registry body")
    if registry.get("root_id") != root.get("root_id"):
        raise SecurityError("registry signed by unexpected root")
    digest = _hash_doc(registry)
    if signed.get("registry_hash") != digest:
        raise SecurityError("registry hash mismatch")
    required = tuple(root["required_schemes"])
    signatures = signed.get("signatures") or {}
    if set(signatures) != set(required):
        raise SecurityError("registry signature-set downgrade")
    message = _signed_message(DOMAIN_REGISTRY, digest)
    for scheme in required:
        if not provider.verify(scheme, b64d(root["public_keys"][scheme]), message, b64d(signatures[scheme])):
            raise SecurityError(f"registry root signature failed: {scheme}")
    ts = int(now if now is not None else _now())
    issued = int(registry.get("issued_at", 0)); expires = int(registry.get("expires_at", 0))
    if issued <= 0 or expires <= issued or ts < issued - 300 or ts >= expires:
        raise SecurityError("registry outside validity interval")
    sequence = int(registry.get("sequence", 0))
    if sequence <= 0:
        raise SecurityError("registry sequence must be positive")
    if last_sequence is not None:
        if sequence < last_sequence:
            raise SecurityError("registry rollback detected")
        if sequence == last_sequence and last_hash and digest != last_hash:
            raise SecurityError("registry equivocation at same sequence")
        if sequence > last_sequence and last_hash and registry.get("previous_registry_hash") != last_hash:
            raise SecurityError("registry previous-hash chain mismatch")
    repos = registry.get("repositories")
    if not isinstance(repos, list) or not repos:
        raise SecurityError("registry has no repositories")
    if int(registry.get("repository_count", -1)) != len(repos):
        raise SecurityError("repository_count mismatch")
    names: set[str] = set(); node_ids: set[str] = set()
    for item in repos:
        name = str(item.get("name") or "")
        if not name or name in names:
            raise SecurityError("duplicate/empty repository name")
        names.add(name)
        for node in item.get("nodes") or []:
            nid = str(node.get("node_id") or "")
            if not nid or nid in node_ids:
                raise SecurityError("duplicate/empty node_id")
            node_ids.add(nid); _verify_node_record(node)
    return registry


def _verify_node_record(node: dict[str, Any]) -> None:
    status = node.get("status")
    if status not in {NODE_STATUS_ACTIVE, NODE_STATUS_RETIRING, NODE_STATUS_REVOKED}:
        raise SecurityError("invalid node status")
    schemes = tuple(node.get("identity_schemes") or ()); keys = node.get("public_keys") or {}
    if not schemes or set(schemes) != set(keys):
        raise SecurityError("node identity scheme/key mismatch")
    public = {str(k): b64d(str(v)) for k, v in keys.items()}
    ident = Identity(public, {k: b"" for k in public})
    if ident.node_id != node.get("node_id"):
        raise SecurityError("node_id/public-key mismatch")
    if int(node.get("generation", 0)) <= 0 or int(node.get("not_after", 0)) <= int(node.get("not_before", 0)):
        raise SecurityError("invalid node generation/validity")


@dataclass(frozen=True)
class FederationRepository:
    name: str
    repo: str
    domain: str
    risk_class: str
    role: str
    integration: str
    enabled: bool
    rpc_allow: tuple[str, ...]
    nodes: tuple[dict[str, Any], ...]


class FederationRegistry:
    def __init__(self, body: dict[str, Any], *, now: int | None = None) -> None:
        self.body = body; self.now = int(now if now is not None else _now())
        self.sequence = int(body["sequence"]); self.registry_hash = _hash_doc(body); self.root_id = str(body["root_id"])
        self._repos: dict[str, FederationRepository] = {}; self._node_to_repo: dict[str, str] = {}
        for item in body["repositories"]:
            repo = FederationRepository(name=str(item["name"]), repo=str(item["repo"]), domain=str(item.get("domain") or ""), risk_class=str(item.get("risk_class") or ""), role=str(item.get("role") or ""), integration=str(item.get("integration") or ""), enabled=bool(item.get("enabled", False)), rpc_allow=tuple(str(x) for x in item.get("rpc_allow") or ()), nodes=tuple(item.get("nodes") or ()))
            self._repos[repo.name] = repo
            for node in repo.nodes:
                self._node_to_repo[str(node["node_id"])] = repo.name

    def repository(self, name: str) -> FederationRepository:
        try:
            return self._repos[name]
        except KeyError as exc:
            raise SecurityError(f"repository not in federation registry: {name}") from exc

    def repository_for_node(self, node_id: str) -> FederationRepository:
        name = self._node_to_repo.get(node_id)
        if not name:
            raise SecurityError("node_id not in federation registry")
        return self.repository(name)

    def accepted_nodes(self, name: str) -> list[dict[str, Any]]:
        repo = self.repository(name); result = []
        for node in repo.nodes:
            if node["status"] not in {NODE_STATUS_ACTIVE, NODE_STATUS_RETIRING}:
                continue
            if int(node["not_before"]) <= self.now < int(node["not_after"]):
                result.append(node)
        return sorted(result, key=lambda x: int(x["generation"]), reverse=True)

    def preferred_node_id(self, name: str) -> str:
        nodes = [x for x in self.accepted_nodes(name) if x["status"] == NODE_STATUS_ACTIVE]
        if not nodes:
            raise SecurityError(f"no active node for {name}")
        return str(nodes[0]["node_id"])

    def trust_store(self, repositories: Iterable[str] | None = None) -> PinnedTrustStore:
        selected = list(repositories) if repositories is not None else list(self._repos); peers: dict[str, dict[str, bytes]] = {}
        for name in selected:
            for node in self.accepted_nodes(name):
                peers[str(node["node_id"])] = {str(k): b64d(str(v)) for k, v in node["public_keys"].items()}
        return PinnedTrustStore(peers)

    def assert_local_identity(self, repository_name: str, identity: Identity) -> None:
        accepted = {str(n["node_id"]): n for n in self.accepted_nodes(repository_name)}; node = accepted.get(identity.node_id)
        if not node:
            raise SecurityError("local identity is not active/retiring in federation registry")
        expected = {str(k): b64d(str(v)) for k, v in node["public_keys"].items()}
        if expected != identity.public_keys:
            raise SecurityError("local identity public key mismatch")

    def authorize_rpc(self, peer_node_id: str, service: str, method: str) -> bool:
        repo = self.repository_for_node(peer_node_id)
        if not repo.enabled:
            return False
        route = f"{service}.{method}"
        return route in repo.rpc_allow or f"{service}.*" in repo.rpc_allow or "*" in repo.rpc_allow

    def peer_context(self, node_id: str) -> dict[str, Any]:
        repo = self.repository_for_node(node_id)
        return {"repository": repo.name, "repo": repo.repo, "domain": repo.domain, "risk_class": repo.risk_class, "role": repo.role, "integration": repo.integration}


def load_verified_registry(provider: PQProvider, root_path: str | Path, registry_path: str | Path, *, state_path: str | Path | None = None, now: int | None = None) -> FederationRegistry:
    root = json.loads(Path(root_path).read_text(encoding="utf-8")); signed = json.loads(Path(registry_path).read_text(encoding="utf-8"))
    last_sequence = last_hash = None; state_target = Path(state_path) if state_path else None
    if state_target and state_target.exists():
        state = json.loads(state_target.read_text(encoding="utf-8")); last_sequence = int(state.get("sequence", 0)) or None; last_hash = state.get("registry_hash") or None
    body = verify_signed_registry(provider, root, signed, now=now, last_sequence=last_sequence, last_hash=last_hash); registry = FederationRegistry(body, now=now)
    if state_target:
        state_target.parent.mkdir(parents=True, exist_ok=True)
        state_target.write_text(json.dumps({"schema": "shttps.federation-registry-state/v1", "sequence": registry.sequence, "registry_hash": registry.registry_hash}, sort_keys=True), encoding="utf-8")
    return registry


def federation_template_from_source(source: dict[str, Any], root: dict[str, Any], *, issued_at: int | None = None, valid_for_seconds: int = 86400 * 30, sequence: int = 1, previous_registry_hash: str | None = None) -> dict[str, Any]:
    ts = int(issued_at or _now()); repos = []
    for item in source.get("repositories") or []:
        repos.append({"name": str(item["name"]), "repo": str(item["repo"]), "domain": str(item.get("domain") or ""), "risk_class": str(item.get("risk_class") or ""), "role": str(item.get("role") or ""), "integration": str(item.get("integration") or ""), "enabled": bool(item.get("enabled", False)), "rpc_allow": [str(x) for x in item.get("rpc_allow") or ()], "nodes": []})
    return {"schema": REGISTRY_SCHEMA, "sequence": int(sequence), "issued_at": ts, "expires_at": ts + int(valid_for_seconds), "previous_registry_hash": previous_registry_hash, "root_id": root["root_id"], "repository_count": len(repos), "repositories": repos}


def node_schemes_for_repository(repo: dict[str, Any]) -> tuple[str, ...]:
    if repo.get("risk_class") in {"financial", "blockchain"} or repo.get("name") == "synergy_system":
        return (SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S)
    return (SIG_ML_DSA_87,)


def provision_all_nodes(provider: PQProvider, registry: dict[str, Any], secrets_dir: str | Path, *, now: int | None = None, ttl_seconds: int = 86400 * 90) -> dict[str, Any]:
    ts = int(now or _now()); out = copy.deepcopy(registry); secret_root = Path(secrets_dir); secret_root.mkdir(parents=True, exist_ok=True)
    for repo in out["repositories"]:
        schemes = node_schemes_for_repository(repo); identity = Identity.generate(provider, schemes)
        write_json_private(secret_root / f"{repo['name']}.identity.json", identity_document(identity))
        repo["nodes"] = [node_record(identity, generation=1, not_before=ts, not_after=ts + int(ttl_seconds))]
    return out


def rotate_repository_node(provider: PQProvider, signed: dict[str, Any], root: dict[str, Any], root_identity: Identity, repository_name: str, secrets_dir: str | Path, *, now: int | None = None, ttl_seconds: int = 86400 * 90, grace_seconds: int = 3600) -> dict[str, Any]:
    body = copy.deepcopy(signed["registry"]); ts = int(now or _now()); target = next((x for x in body["repositories"] if x["name"] == repository_name), None)
    if target is None:
        raise SecurityError("repository not present")
    generations = [int(n["generation"]) for n in target.get("nodes") or []]; generation = max(generations or [0]) + 1
    for node in target.get("nodes") or []:
        if node["status"] == NODE_STATUS_ACTIVE:
            node["status"] = NODE_STATUS_RETIRING; node["not_after"] = min(int(node["not_after"]), ts + int(grace_seconds))
    schemes = node_schemes_for_repository(target); identity = Identity.generate(provider, schemes)
    write_json_private(Path(secrets_dir) / f"{repository_name}.identity.g{generation}.json", identity_document(identity))
    target.setdefault("nodes", []).append(node_record(identity, generation=generation, not_before=ts, not_after=ts + int(ttl_seconds)))
    body["sequence"] = int(body["sequence"]) + 1; body["issued_at"] = ts; body["expires_at"] = max(ts + 86400, min(int(body.get("expires_at", ts + 86400 * 30)), ts + 86400 * 30)); body["previous_registry_hash"] = signed["registry_hash"]
    return sign_registry(provider, root_identity, root, body)


def revoke_node(provider: PQProvider, signed: dict[str, Any], root: dict[str, Any], root_identity: Identity, node_id: str, *, now: int | None = None) -> dict[str, Any]:
    body = copy.deepcopy(signed["registry"]); found = False; ts = int(now or _now())
    for repo in body["repositories"]:
        for node in repo.get("nodes") or []:
            if node.get("node_id") == node_id:
                node["status"] = NODE_STATUS_REVOKED; node["not_after"] = min(int(node["not_after"]), ts); found = True
    if not found:
        raise SecurityError("node not present")
    body["sequence"] = int(body["sequence"]) + 1; body["issued_at"] = ts; body["expires_at"] = max(ts + 86400, min(int(body.get("expires_at", ts + 86400 * 30)), ts + 86400 * 30)); body["previous_registry_hash"] = signed["registry_hash"]
    return sign_registry(provider, root_identity, root, body)


def root_transition(provider: PQProvider, old_root_identity: Identity, old_root: dict[str, Any], new_root: dict[str, Any], *, created_at: int | None = None) -> dict[str, Any]:
    verify_root_document(old_root); verify_root_document(new_root)
    body = {"schema": ROOT_TRANSITION_SCHEMA, "old_root_id": old_root["root_id"], "new_root": new_root, "created_at": int(created_at or _now())}; digest = _hash_doc(body); message = _signed_message(DOMAIN_ROOT_ROTATION, digest)
    signatures = {s: b64e(provider.sign(s, old_root_identity.secret_keys[s], message)) for s in old_root["required_schemes"]}
    return {"body": body, "transition_hash": digest, "signatures": signatures}


def verify_root_transition(provider: PQProvider, old_root: dict[str, Any], transition: dict[str, Any]) -> dict[str, Any]:
    verify_root_document(old_root); body = transition.get("body") or {}
    if body.get("schema") != ROOT_TRANSITION_SCHEMA or body.get("old_root_id") != old_root["root_id"]:
        raise SecurityError("invalid root transition")
    digest = _hash_doc(body)
    if transition.get("transition_hash") != digest:
        raise SecurityError("root transition hash mismatch")
    sigs = transition.get("signatures") or {}; required = tuple(old_root["required_schemes"])
    if set(sigs) != set(required):
        raise SecurityError("root transition signature downgrade")
    msg = _signed_message(DOMAIN_ROOT_ROTATION, digest)
    for scheme in required:
        if not provider.verify(scheme, b64d(old_root["public_keys"][scheme]), msg, b64d(sigs[scheme])):
            raise SecurityError("root transition signature failed")
    new_root = body.get("new_root") or {}; verify_root_document(new_root); return new_root
