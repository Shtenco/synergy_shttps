# SYNERGY Remote MCP — live launch

## Canonical repositories

Mandatory for the Remote MCP service itself:

1. `Shtenco/synergy_shttps`
   - SHTTPS PQ handshake/session/records
   - STCP stream framing
   - signed federation registry
   - Remote MCP node
   - MCP stdio frontend
   - MCP HTTP frontend

2. `Shtenco/synegy_ai_compress`
   - Gabriel Horn / SGH1 lossless compression
   - pin: `551fae36eacb5713aa503fc9da2fbc44fe8f2e84`

Recommended for the networked SYNERGY deployment:

3. `Shtenco/synergynet`
   - P2P routing / relay / cache / dedup / multipath beneath SHTTPS/STCP.

4. `Shtenco/synergy_ai_blockchain`
   - canonical PQ policy;
   - inference/checkpoint/verification/slashing;
   - SYNA reward and protocol convergence authority.

5. `Shtenco/synergy_system`
   - federation and repository architecture map; not required in the data path.

Do not copy consensus or SYNA mint authority into `synergy_shttps`.

## Live path

```text
MCP client
  -> synergy-mcp-gateway (stdio)
     OR synergy-mcp-http-gateway (POST /mcp)
  -> SHTTPS authenticated RPC
  -> encrypted SHTTPS record
  -> STCP/1 MCP stream
  -> TCP carrier for first live deployment
  -> Remote node
  -> synergy.remote.mcp.v1
  -> jailed filesystem / allowlisted subprocess
```

QUIC is a planned lower carrier. The first live gate deliberately uses the
already implemented TCP carrier under STCP so application/session semantics
do not depend on QUIC readiness.

## 1. Clone and install

On both controller and worker machines:

```bash
git clone https://github.com/Shtenco/synergy_shttps.git
cd synergy_shttps
git checkout feat/stcp-shttps-remote-mcp-v2-20260925

python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[pq,test]'
```

Windows PowerShell activation:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[pq,test]"
```

Install the pinned compression repository:

Linux/macOS:

```bash
./scripts/bootstrap_ai_compress.sh
export SHTTPS_AI_COMPRESS_PATH="$PWD/vendor/ai_compress"
```

Windows:

```powershell
.\scripts\bootstrap_ai_compress.ps1
$env:SHTTPS_AI_COMPRESS_PATH=(Resolve-Path ".\vendor\ai_compress").Path
```

Validate the PQ provider:

```bash
shttps-diagnose
```

Do not proceed to a production-exposed endpoint unless the diagnostic confirms
the expected ML-KEM / ML-DSA / SLH-DSA provider set.

## 2. Provision identities and signed federation registry

Run this on one trusted provisioning machine:

Linux:

```bash
./scripts/provision_remote_mcp_pair.sh
```

Windows:

```powershell
.\scripts\provision_remote_mcp_pair.ps1
```

Generated layout:

```text
deploy/remote_mcp/
  root.identity.json                 KEEP OFFLINE
  root.json                          public federation root
  federation.json                    signed registry
  secrets/
    synergy_shttps.identity.json     worker/server identity
    synergy_remote_mcp_controller.identity.json
                                      controller identity
```

Never copy `root.identity.json` to either network node.

Copy only:
- `root.json` to both machines;
- `federation.json` to both machines;
- server identity only to the worker;
- controller identity only to the controller.

## 3. Worker machine

Create a dedicated root, for example:

Linux:
```bash
mkdir -p /srv/synergy-workspace /etc/synergy-mcp
```

Windows:
```powershell
New-Item -ItemType Directory -Force C:\SYNERGY\workspace
New-Item -ItemType Directory -Force C:\SYNERGY\mcp
```

Set the worker environment.

Linux example:

```bash
export SHTTPS_AI_COMPRESS_PATH=/opt/synergy/synegy_ai_compress

export SYNERGY_NODE_SHTTPS_IDENTITY=/etc/synergy-mcp/synergy_shttps.identity.json
export SYNERGY_NODE_SHTTPS_FEDERATION_ROOT=/etc/synergy-mcp/root.json
export SYNERGY_NODE_SHTTPS_FEDERATION_REGISTRY=/etc/synergy-mcp/federation.json
export SYNERGY_NODE_SHTTPS_FEDERATION_STATE=/etc/synergy-mcp/node_registry_state.json
export SYNERGY_NODE_SHTTPS_REPOSITORY=synergy_shttps
export SYNERGY_NODE_SHTTPS_STCP=1
export SYNERGY_NODE_SHTTPS_MAX_IDENTITY=1
export SYNERGY_NODE_SHTTPS_REQUIRE_AI_COMPRESS=1

synergy-remote-mcp-node \
  --bind 0.0.0.0 \
  --port 9443 \
  --root /srv/synergy-workspace \
  --allow-commands git,python,python3,cargo,rustc
```

Windows PowerShell example:

```powershell
$env:SHTTPS_AI_COMPRESS_PATH="C:\SYNERGY\synegy_ai_compress"

$env:SYNERGY_NODE_SHTTPS_IDENTITY="C:\SYNERGY\mcp\synergy_shttps.identity.json"
$env:SYNERGY_NODE_SHTTPS_FEDERATION_ROOT="C:\SYNERGY\mcp\root.json"
$env:SYNERGY_NODE_SHTTPS_FEDERATION_REGISTRY="C:\SYNERGY\mcp\federation.json"
$env:SYNERGY_NODE_SHTTPS_FEDERATION_STATE="C:\SYNERGY\mcp\node_registry_state.json"
$env:SYNERGY_NODE_SHTTPS_REPOSITORY="synergy_shttps"
$env:SYNERGY_NODE_SHTTPS_STCP="1"
$env:SYNERGY_NODE_SHTTPS_MAX_IDENTITY="1"
$env:SYNERGY_NODE_SHTTPS_REQUIRE_AI_COMPRESS="1"

synergy-remote-mcp-node --bind 0.0.0.0 --port 9443 --root C:\SYNERGY\workspace --allow-commands "git,python,python3,cargo,rustc"
```

Open only TCP port 9443 between controller and worker IPs. Do not expose the
filesystem itself through SMB/NFS for this purpose.

## 4. Controller machine

Linux:

```bash
export SHTTPS_AI_COMPRESS_PATH=/opt/synergy/synegy_ai_compress

export SYNERGY_MCP_SHTTPS_IDENTITY=/etc/synergy-mcp/synergy_remote_mcp_controller.identity.json
export SYNERGY_MCP_SHTTPS_FEDERATION_ROOT=/etc/synergy-mcp/root.json
export SYNERGY_MCP_SHTTPS_FEDERATION_REGISTRY=/etc/synergy-mcp/federation.json
export SYNERGY_MCP_SHTTPS_FEDERATION_STATE=/etc/synergy-mcp/controller_registry_state.json
export SYNERGY_MCP_SHTTPS_REPOSITORY=synergy_remote_mcp_controller
export SYNERGY_MCP_SHTTPS_EXPECTED_REPOSITORY=synergy_shttps
export SYNERGY_MCP_SHTTPS_HOST=WORKER_IP
export SYNERGY_MCP_SHTTPS_PORT=9443
export SYNERGY_MCP_SHTTPS_STCP=1
export SYNERGY_MCP_SHTTPS_MAX_IDENTITY=1
export SYNERGY_MCP_SHTTPS_REQUIRE_AI_COMPRESS=1
```

Windows:

```powershell
$env:SHTTPS_AI_COMPRESS_PATH="C:\SYNERGY\synegy_ai_compress"

$env:SYNERGY_MCP_SHTTPS_IDENTITY="C:\SYNERGY\mcp\synergy_remote_mcp_controller.identity.json"
$env:SYNERGY_MCP_SHTTPS_FEDERATION_ROOT="C:\SYNERGY\mcp\root.json"
$env:SYNERGY_MCP_SHTTPS_FEDERATION_REGISTRY="C:\SYNERGY\mcp\federation.json"
$env:SYNERGY_MCP_SHTTPS_FEDERATION_STATE="C:\SYNERGY\mcp\controller_registry_state.json"
$env:SYNERGY_MCP_SHTTPS_REPOSITORY="synergy_remote_mcp_controller"
$env:SYNERGY_MCP_SHTTPS_EXPECTED_REPOSITORY="synergy_shttps"
$env:SYNERGY_MCP_SHTTPS_HOST="WORKER_IP"
$env:SYNERGY_MCP_SHTTPS_PORT="9443"
$env:SYNERGY_MCP_SHTTPS_STCP="1"
$env:SYNERGY_MCP_SHTTPS_MAX_IDENTITY="1"
$env:SYNERGY_MCP_SHTTPS_REQUIRE_AI_COMPRESS="1"
```

Now run the full remote smoke:

```bash
synergy-remote-mcp-smoke
```

Expected status:

```json
{
  "status": "PASS",
  "health": {
    "authenticated": true,
    "transport": "SHTTPS/2+STCP/1"
  }
}
```

## 5. MCP stdio frontend

Start:

```bash
synergy-mcp-gateway
```

Generic MCP client configuration:

```json
{
  "mcpServers": {
    "synergy-remote": {
      "command": "synergy-mcp-gateway",
      "env": {
        "SYNERGY_MCP_SHTTPS_HOST": "WORKER_IP",
        "SYNERGY_MCP_SHTTPS_PORT": "9443",
        "SYNERGY_MCP_SHTTPS_STCP": "1"
      }
    }
  }
}
```

The complete federation/identity environment must also be available to the
gateway process.

## 6. Own HTTP MCP service

For a local-only HTTP endpoint:

```bash
export SYNERGY_MCP_HTTP_BIND=127.0.0.1
export SYNERGY_MCP_HTTP_PORT=8765
synergy-mcp-http-gateway
```

Endpoint:

```text
POST http://127.0.0.1:8765/mcp
```

For a non-loopback bind, bearer authentication is mandatory:

```bash
export SYNERGY_MCP_HTTP_BIND=0.0.0.0
export SYNERGY_MCP_HTTP_PORT=8765
export SYNERGY_MCP_HTTP_BEARER='GENERATE_A_LONG_RANDOM_SECRET'
synergy-mcp-http-gateway
```

For Internet exposure, terminate ordinary HTTPS in a hardened reverse proxy and
forward only to `127.0.0.1:8765`. The inter-node leg remains SHTTPS/STCP PQ.

Do not expose port 8765 directly to the public Internet without TLS.

## 7. Allowed MCP tools

The current externally advertised tools are:

- `synergy_health`
- `synergy_list_dir`
- `synergy_read_file`
- `synergy_run`

`synergy_run` does not invoke a shell. The remote worker checks the executable
basename against its allowlist.

## 8. Minimum acceptance gate

A live deployment is accepted only after all of:

1. `shttps-diagnose` confirms the intended PQ provider;
2. signed federation registry verifies;
3. `synergy-remote-mcp-smoke` returns PASS;
4. health reports `SHTTPS/2+STCP/1`;
5. path escape is rejected;
6. a non-allowlisted command is rejected;
7. MCP `initialize -> tools/list -> tools/call` works;
8. worker port is reachable only from intended controller peers.

Until those pass on the target machines, call the deployment a candidate, not GREEN.
