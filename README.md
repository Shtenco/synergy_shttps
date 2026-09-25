# SHTTPS

**SYNERGY Hyper Transport Security — post-quantum authenticated, compressed common communication protocol.**

SHTTPS is the secure session/record layer shared by the SYNERGY federation. It combines the existing SYNERGY PQ policy with the actual `ai_compress` Gabriel Horn lossless codec while preserving domain authority boundaries.

## Security profile

- mandatory **ML-KEM-1024** fresh session KEM;
- **ML-DSA-87** node identity;
- optional MAX identity: **ML-DSA-87 AND SLH-DSA-SHAKE-256s**;
- optional **X25519** classical lane only as an additional hybrid contribution, never a downgrade replacement;
- **HKDF-SHA3-512** transcript-bound key schedule;
- **ChaCha20-Poly1305** default AEAD, AES-256-GCM alternative;
- bounded framing, authenticated headers, anti-replay and explicit rekey epochs;
- pinned peer identities in v1 (no accidental TOFU).

The PQ policy is sourced from `Shtenco/synergy_ai_blockchain`, branch `feat/pq-evm-nexus-v1`, commit `01dbc0fa901c8195bc37c646fa6617ada2b97a99`. That lineage requires reviewed standards-conformant cryptographic providers rather than home-grown ML-KEM/ML-DSA mathematics.

## Compression

SHTTPS integrates **the real `Shtenco/synegy_ai_compress` implementation**, pinned to commit `551fae36eacb5713aa503fc9da2fbc44fe8f2e84`:

- `SGH1-speed`
- `SGH1-balanced`
- `SGH1-max`
- `RAW`

The adapter imports `compression_lab.gabriel_horn_engine.GabrielHornEngine`; it does not copy/fork the codec. Compression is used only if it actually reduces bytes. Sensitive messages default to RAW to reduce compression-oracle exposure.

## System position

```text
application protocols
(Auto-Company / Autopilot / NEXUS / finance / apps)
        |
        v
      SHTTPS       <- identity + session + records + envelopes
        |
        +---- ai_compress / SGH1
        |
        v
    SynergyNet     <- P2P routing / relay / cache / dedup / multipath
        |
        v
 physical network
```

SHTTPS always has `TRANSPORT_NONE` application authority. Receiving an authenticated frame does **not** authorize payment, accounting, trading, blockchain signing or agent execution.

## Install

```bash
python -m pip install -e '.[test]'
pytest -q
```

For local compression integration:

```bash
./scripts/bootstrap_ai_compress.sh
export SHTTPS_AI_COMPRESS_PATH="$PWD/vendor/ai_compress"
```

For production PQ operations install a reviewed `liboqs`/`liboqs-python` build that exposes ML-KEM-1024, ML-DSA-87 and (for MAX) SLH-DSA-SHAKE-256s, then use `shttps.crypto.OQSProvider`.

```bash
shttps-diagnose
```

## Status

Protocol v1 implementation includes mutual PQ handshake, hybrid combiner, AEAD record framing, replay defense, envelope adapters and `ai_compress` integration. It is a reviewable implementation candidate, **not a claim of completed external cryptographic audit or production deployment**.

See `docs/PROTOCOL_V1.md`, `docs/SECURITY.md`, `docs/THREAT_MODEL.md` and `docs/INTEGRATION_MAP.md`.
