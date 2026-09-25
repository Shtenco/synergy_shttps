# STCP/1 + SHTTPS/2 Transport Convergence

SYNERGY uses two layers:

```text
MCP / RPC / AI / EVM / Storage / Bridge
                 ↓
              SHTTPS
     authenticated semantic envelopes
                 ↓
               STCP
 multiplexed ordered stream classes
                 ↓
      QUIC/UDP primary carrier
         TCP fallback carrier
                 ↓
            SynergyNet
```

STCP is the SYNERGY Transport Convergence Protocol. It does not reinvent
congestion control. QUIC is the preferred high-performance carrier; existing
TCP remains the compatibility/fallback carrier.

SHTTPS keeps the project-owned PQ security profile above the carrier:
ML-KEM-1024, ML-DSA-87, optional MAX SLH-DSA-SHAKE-256s, transcript-bound
HKDF-SHA3-512, ChaCha20-Poly1305, anti-replay and rekey epochs.

Stream classes: CONTROL, RPC, INFERENCE, MODEL, STORAGE, EVM, BRIDGE, MCP.

The outer STCP header never grants authority. Application authorization remains
inside the authenticated SHTTPS envelope and federation ACL.

## Remote MCP

`synergy.remote.mcp.v1` is the project-owned replacement surface for remote
node administration. Defaults: filesystem jail, command allowlist, no
`shell=True`, bounded reads/output, timeout, SHTTPS authentication and
federation RPC ACL.

Third-party remote-desktop/MCP services are bootstrap tools only and are not a
canonical dependency of the SYNERGY protocol.

## Performance gate

No "faster than TCP/QUIC" claim without matched benchmarks for latency,
throughput, goodput, CPU, memory, loss recovery and reconnect/failover.
