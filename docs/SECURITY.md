# SHTTPS security invariants

1. No home-grown ML-KEM/ML-DSA/SLH-DSA math in SHTTPS. Production binds to a reviewed standards-conformant provider and known-answer tests.
2. Session KEM: ML-KEM-1024 is mandatory. X25519, when enabled, is an additional hybrid lane and never an OR-downgrade replacement.
3. Node identity: ML-DSA-87; MAX adds SLH-DSA-SHAKE-256s with AND semantics.
4. Identity, networking, financial, validator, treasury and payment keys are independent domains. A SHTTPS node key grants no economic authority.
5. Trust is explicit. V1 uses pinned public-key sets; unknown identity is rejected.
6. Full negotiation is transcript-bound. The client additionally verifies the server did not select an unoffered cipher/compression/application protocol.
7. AEAD authenticates the fixed frame header and session ID. Replay state advances only after AEAD success.
8. `(key, epoch, sequence)` nonce tuples must be unique. Epoch/key exhaustion fails closed.
9. `SENSITIVE` payloads are RAW by policy; never compress secrets together with attacker-controlled data.
10. Decompression is bounded by the authenticated expected plaintext size; frame/handshake maximums are enforced before expensive processing.
11. No serialization format may grant application authority. Envelope authority is always `TRANSPORT_NONE`.
12. Production key material must come from a secret manager/HSM/secure host service, never Git or config examples.

## Explicit non-claims

This PR defines and tests the transport architecture but is not a third-party cryptographic audit. The OQS provider wrapper must be tested against the production environment/library versions. The `FakePQProvider` exists only in tests and provides no cryptographic security.
