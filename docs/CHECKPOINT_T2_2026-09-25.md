# TRANSPORT CONVERGENCE CHECKPOINT T2

Branch: `feat/stcp-shttps-remote-mcp-v2-20260925`

Status: LIVE-LAUNCH READY / PHYSICAL EXECUTION PENDING

## Implemented
- project-owned Remote MCP RPC service;
- MCP stdio frontend with initialize / tools/list / tools/call;
- authenticated HTTP MCP frontend at POST /mcp;
- bearer auth required for non-loopback HTTP binding;
- SHTTPS records carried through STCP/1 stream frames;
- MCP traffic bound to STCP MCP stream class;
- signed federation identity and RPC authorization path;
- jailed filesystem operations;
- no shell=True execution;
- executable allowlist;
- bounded read/output/time;
- end-to-end Remote MCP-over-STCP test added;
- end-to-end smoke command added;
- Windows/Linux pair provisioning scripts;
- Windows/Linux ai_compress bootstrap;
- exact two-host deployment procedure.

## Canonical runtime repositories
1. Shtenco/synergy_shttps
2. Shtenco/synegy_ai_compress

Recommended full-network integration:
3. Shtenco/synergynet
4. Shtenco/synergy_ai_blockchain
5. Shtenco/synergy_system

## Current evidence
- earlier isolated STCP / jail / allowlist smoke: PASS;
- newest GitHub Actions run 36106599800: runner failure before first step (steps=[]);
- DESKTOP-C8GUE41: offline at checkpoint time.

## Physical GREEN gate
On two actual hosts:
1. install PQ provider + SGH1;
2. verify signed federation;
3. start synergy-remote-mcp-node with STCP enabled;
4. run synergy-remote-mcp-smoke from controller;
5. exercise MCP initialize -> tools/list -> tools/call;
6. verify path escape and non-allowlisted command rejection;
7. run full pytest;
8. capture logs and hashes.

No GREEN claim until that gate is executed.
