from __future__ import annotations

import argparse
import json
from pathlib import Path

from .canonical import canonical_json
from .constants import SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S
from .credentials import identity_document, load_identity, write_json_private
from .crypto.oqs_provider import OQSProvider
from .federation import federation_template_from_source, load_verified_registry, provision_all_nodes, root_document, rotate_repository_node, revoke_node, sign_registry, verify_signed_registry
from .handshake import Identity


def _read(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str, value: dict, private: bool = False) -> None:
    if private:
        write_json_private(path, value)
    else:
        p = Path(path); p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(canonical_json(value) + b"\n")


def main() -> None:
    parser = argparse.ArgumentParser(prog="shttps-federation", description="PQ federation identity/registry provisioning")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("root-init")
    p.add_argument("--secret", required=True); p.add_argument("--public", required=True)

    p = sub.add_parser("provision-all")
    p.add_argument("--source", required=True); p.add_argument("--root-secret", required=True); p.add_argument("--root-public", required=True)
    p.add_argument("--secrets-dir", required=True); p.add_argument("--registry-out", required=True); p.add_argument("--valid-days", type=int, default=30); p.add_argument("--node-valid-days", type=int, default=90)

    p = sub.add_parser("verify")
    p.add_argument("--root-public", required=True); p.add_argument("--registry", required=True); p.add_argument("--state")

    p = sub.add_parser("rotate")
    p.add_argument("--root-secret", required=True); p.add_argument("--root-public", required=True); p.add_argument("--registry", required=True)
    p.add_argument("--repository", required=True); p.add_argument("--secrets-dir", required=True); p.add_argument("--out", required=True); p.add_argument("--grace-seconds", type=int, default=3600)

    p = sub.add_parser("revoke")
    p.add_argument("--root-secret", required=True); p.add_argument("--root-public", required=True); p.add_argument("--registry", required=True)
    p.add_argument("--node-id", required=True); p.add_argument("--out", required=True)

    args = parser.parse_args(); provider = OQSProvider()
    if args.cmd == "root-init":
        ident = Identity.generate(provider, (SIG_ML_DSA_87, SIG_SLH_DSA_SHAKE_256S)); root = root_document(ident)
        _write(args.secret, identity_document(ident), private=True); _write(args.public, root)
        print(json.dumps({"root_id": root["root_id"], "generation": root["generation"]})); return
    if args.cmd == "provision-all":
        root = _read(args.root_public); root_ident = load_identity(args.root_secret); source = _read(args.source)
        body = federation_template_from_source(source, root, valid_for_seconds=args.valid_days * 86400)
        body = provision_all_nodes(provider, body, args.secrets_dir, ttl_seconds=args.node_valid_days * 86400)
        signed = sign_registry(provider, root_ident, root, body); _write(args.registry_out, signed)
        print(json.dumps({"registry_hash": signed["registry_hash"], "sequence": body["sequence"], "repositories": len(body["repositories"])})); return
    if args.cmd == "verify":
        registry = load_verified_registry(provider, args.root_public, args.registry, state_path=args.state)
        print(json.dumps({"registry_hash": registry.registry_hash, "sequence": registry.sequence, "repositories": len(registry.body["repositories"])})); return
    if args.cmd == "rotate":
        root = _read(args.root_public); root_ident = load_identity(args.root_secret); signed = _read(args.registry)
        verify_signed_registry(provider, root, signed)
        out = rotate_repository_node(provider, signed, root, root_ident, args.repository, args.secrets_dir, grace_seconds=args.grace_seconds)
        _write(args.out, out); print(json.dumps({"registry_hash": out["registry_hash"], "sequence": out["registry"]["sequence"]})); return
    if args.cmd == "revoke":
        root = _read(args.root_public); root_ident = load_identity(args.root_secret); signed = _read(args.registry)
        verify_signed_registry(provider, root, signed)
        out = revoke_node(provider, signed, root, root_ident, args.node_id); _write(args.out, out)
        print(json.dumps({"registry_hash": out["registry_hash"], "sequence": out["registry"]["sequence"]}))


if __name__ == "__main__": main()
