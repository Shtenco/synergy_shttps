# SYNERGY integration map

```text
Auto-Company / Autopilot / NEXUS / Finance / Apps
                      |
              application envelope
                      v
                  SHTTPS/1
         PQ handshake + AEAD records
                      |
       SGH1 adapter <-> Shtenco/ai_compress
                      |
                  SynergyNet
       direct / relay / multipath / cache
                      |
              physical transport
```

PQC policy provenance is pinned to `Shtenco/synergy_ai_blockchain@01dbc0fa901c8195bc37c646fa6617ada2b97a99` (`feat/pq-evm-nexus-v1`). Compression provenance is pinned to `Shtenco/ai_compress@551fae36eacb5713aa503fc9da2fbc44fe8f2e84`.

Application adapters are intentionally tiny. `synergy.capability.v1` remains the authority contract between company and Autopilot; SHTTPS only protects its bytes in transit.
