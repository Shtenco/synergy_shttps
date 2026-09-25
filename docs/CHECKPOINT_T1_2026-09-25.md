# TRANSPORT CONVERGENCE CHECKPOINT T1

Branch: `feat/stcp-shttps-remote-mcp-v2-20260925`

## Completed
- recovered SHTTPS v1 implementation lineage;
- retained ML-KEM/ML-DSA/SLH-DSA security profile;
- defined STCP/1 stream framing;
- defined MCP/RPC/AI/EVM/Storage/Bridge stream classes;
- added project-owned Remote MCP Gateway;
- filesystem jail, command allowlist, no shell execution, bounded output;
- added replay/order test and MCP sandbox test.

## Next gate T2
- QUIC carrier implementation;
- TCP carrier adapter wrapping the same STCP frames;
- SHTTPS session binding to STCP stream class;
- MCP federation ACL examples;
- benchmark harness TCP vs QUIC/STCP;
- local executable test evidence.

Claim boundary: protocol/code checkpoint only; QUIC performance is not yet claimed.
