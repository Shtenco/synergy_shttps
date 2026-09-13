# SHTTPS/1 wire protocol

SHTTPS is the common secure session/record layer for the SYNERGY federation. It deliberately does not own P2P routing, business authority, accounting, blockchain finality or AI inference.

## Layer ownership

- `Shtenco/synergynet`: peer discovery, direct/relay/multipath routing, cache/dedup and store-and-forward.
- `Shtenco/shttps`: authenticated session establishment, algorithm negotiation, encrypted records, replay defense and common envelopes.
- `Shtenco/ai_compress`: lossless codecs. SHTTPS uses Gabriel Horn `SGH1` through a pinned external adapter instead of forking codec math.
- `Shtenco/synergy_ai_blockchain`: source of the SYNERGY PQ policy and domain-separated trust commitments.
- application domains (`synergy_ai_company`, `agi_autopilot`, `agi_nexus`, finance, payments, trading): own their facts/permissions. Transport never grants them.

## Handshake

The v1 handshake is mutually authenticated:

1. ClientHello: node identity, ML-KEM-1024 ephemeral public key, optional X25519 public key, ciphers, compression profiles and application protocols; signed by every required identity lane.
2. ServerHello: same identity evidence, a fresh server KEM public key, a KEM ciphertext to the client, selected suite and protocol list; transcript-bound signatures.
3. ClientFinish: KEM ciphertext to the server, transcript-bound identity signatures and a finished MAC.
4. ServerFinish: finished MAC.

Both sides therefore contribute a fresh ML-KEM-1024 secret. If hybrid transition mode is enabled, X25519 contributes an additional independent shared secret. HKDF-SHA3-512 combines all lanes and the full transcript into independent traffic keys/session-id/rekey seed.

### Identity policies

`ONLINE`: ML-DSA-87 for SHTTPS node identity. Classical compatibility signatures are not required by this transport profile because networking identity is independent from EVM account authorization.

`MAX`: ML-DSA-87 **AND** SLH-DSA-SHAKE-256s. SHTTPS rejects identity-set downgrade rather than accepting any one available signature.

A peer is accepted only when its node ID/public-key set is pinned in the trust store (the v1 implementation deliberately avoids accidental trust-on-first-use). A future federation directory may distribute signed trust records without changing the wire transcript.

## Record protection

Record header fields are authenticated as AEAD AAD together with the 128-bit session ID. Default AEAD is ChaCha20-Poly1305; AES-256-GCM is negotiable. Nonces are deterministic `(epoch, sequence)` values and keys must never be reused across epochs.

Replay state is committed only **after** successful AEAD authentication, preventing unauthenticated sequence-window poisoning.

Rekey is required after 1,000,000 messages or 3600 seconds by default. The transport exposes explicit rekey state; production orchestration should establish fresh ML-KEM material for every new epoch rather than deriving indefinite future epochs only from old traffic keys.

## Compression

Network profiles:

- `RAW`
- `SGH1-speed`
- `SGH1-balanced`
- `SGH1-max` (available but not the default network preference)

The adapter calls the actual `GabrielHornEngine` from `ai_compress`. A compression result is used only when it beats RAW by configured byte/ratio thresholds; otherwise RAW is sent.

### Security rule: secrets are not compressed by default

Per-message `SENSITIVE` records force RAW before encryption. This reduces compression-oracle risk when attacker-controlled and secret material might otherwise share a compression context. SHTTPS compression is message-local, not a cross-origin adaptive dictionary.

## Envelope

`SHTTPS` can carry any versioned application protocol. Built-in adapters include:

- `synergy.capability.v1` — Auto-Company/Autopilot capability traffic;
- `nexus.runtime/v3` / `nexus.memory/v1`;
- `synergy.event/v1`;
- `synergy.evidence/v1`.

Every envelope states `authority=TRANSPORT_NONE`: successful transport proves authenticated delivery of bytes, not permission to spend money, book accounting entries, sign blockchain transactions or execute a capability.

## Content/hash pipeline

For large SynergyNet objects the intended order is:

`application bytes -> content-defined chunking/dedup (SynergyNet) -> ai_compress per selected chunk/object -> SHTTPS AEAD records -> route`

On receive:

`route -> SHTTPS authenticate/decrypt -> ai_compress exact reconstruction -> content hash verification -> application policy`

Encryption is intentionally after compression/dedup; encrypted bytes would destroy those redundancies. Private/salted content IDs are a SynergyNet privacy concern and must be selected before exposing cache-presence metadata.
