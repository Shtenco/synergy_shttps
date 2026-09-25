# Threat model

SHTTPS is designed against passive capture (including harvest-now-decrypt-later), active MITM, frame modification, replay/reordering abuse, algorithm downgrade, decompression bombs within the stated framing model, accidental authority escalation and common compression-oracle patterns.

Assumptions outside SHTTPS include endpoint compromise, malicious authorized application code, stolen HSM/secret-manager credentials, compromised trust-directory governance, traffic analysis and denial-of-service above bounded parsing/resource limits. SynergyNet must separately address Sybil/routing/cache-probing concerns.

Compromise of a current traffic key exposes that epoch. Fresh ML-KEM re-handshake is the intended post-compromise recovery mechanism; SHTTPS does not claim perfect forward secrecy solely from long-lived PQ identity keys.
