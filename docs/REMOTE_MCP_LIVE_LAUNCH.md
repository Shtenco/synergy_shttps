# SYNERGY Remote MCP — live launch

The runtime uses one repository as the mandatory transport/control package:

- `Shtenco/synergy_shttps` — SHTTPS, STCP framing, federation identities, Remote MCP node, MCP stdio bridge.

Recommended integration repositories:

- `Shtenco/synergynet` — P2P routing/relay/multipath beneath SHTTPS/STCP;
- `Shtenco/synergy_ai_blockchain` — canonical PQ policy, node/inference/checkpoint/SYNA authority;
- `Shtenco/synergy_system` — federation/architecture inventory.

Do **not** copy consensus or SYNA mint logic into `synergy_shttps`.

## Process model

Machine B (remote worker):
```
synergy-remote-mcp-node
  -> SHTTPS authenticated server
  -> synergy.remote.mcp.v1
  -> jailed filesystem / allowlisted subprocess
```

Machine A (MCP client host):
```
ChatGPT/Codex/Claude/IDE
  -> synergy-mcp-gateway (stdio MCP)
  -> SHTTPS authenticated client
  -> Machine B
```

## Security boundary

The node never exposes an arbitrary shell. The default command set is:
`git, python, python3, cargo, rustc`.

Use a dedicated filesystem root. Do not point `--root` at the whole disk.

Production requires a signed federation registry and reviewed liboqs provider.
Legacy trust mode exists only for migration and is intentionally not used in
the production commands in this document.
