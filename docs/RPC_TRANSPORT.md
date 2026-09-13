# SHTTPS RPC transport

`SHTTPSRPCClient` and `SHTTPSRPCServer` replace plaintext internal HTTP/JSON federation calls.

Wire sequence:

```text
TCP / SynergyNet stream
  -> signed mutual SHTTPS ClientHello/ServerHello
  -> mutual ML-KEM-1024 contribution (+ optional X25519)
  -> transcript-bound Finished MACs
  -> SHTTPS encrypted record
  -> optional ai_compress SGH1
  -> shttps.envelope/v1
  -> shttps.rpc/v1 request/response
  -> explicit application dispatcher / policy
```

The four-byte stream length prefix is routing/framing metadata only. Application bytes are never sent before the authenticated SHTTPS session exists. Record headers are AEAD-authenticated.

RPC routes are explicit `(service, method)` allowlists. An authenticated peer has `application_authority=false`; each runtime keeps its own policy/approval logic. Unknown RPC methods fail closed.

For production federation, configure an OQS-backed provider, pinned identity/trust files, and a local `ai_compress` checkout. If any mandatory dependency is absent, application adapters must refuse federation traffic rather than downgrade to plaintext HTTP.
