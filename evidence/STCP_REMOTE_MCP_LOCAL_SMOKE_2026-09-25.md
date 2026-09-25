# Transport T1 local smoke evidence

Date: 2026-09-25

Scope: newly added STCP framing and SYNERGY Remote MCP safety surface.

Local isolated Python smoke:
- STCP frame roundtrip: PASS
- ordered sequence tracking: PASS
- replay of same frame: REJECTED
- Remote MCP jailed read under configured root: PASS
- path escape `../outside`: REJECTED
- non-allowlisted shell command: REJECTED

Important limitation:
This was an isolated smoke of the new modules with the required RPC/error interfaces.
It is not a substitute for the full historical SHTTPS pytest suite or production
post-quantum provider tests.

GitHub Actions run 36104970736 failed before executing any job step
(`steps=[]`), so it is recorded as runner/provisioning failure rather than a
test failure.
