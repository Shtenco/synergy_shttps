from __future__ import annotations
import base64, hashlib, json
from typing import Any

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()
