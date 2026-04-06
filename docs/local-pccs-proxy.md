# Local PCCS Proxy

A drop-in replacement for Phala's TDX collateral endpoint (`cloud-api.phala.network`) that fetches Intel attestation collateral directly from a local Intel PCCS (Provisioning Certificate Caching Service).

## Background

MPC nodes running in TDX CVMs need Intel attestation collateral (certificates, CRLs, TCB info) to prove they are running on genuine Intel hardware. Previously, this collateral was fetched from Phala's centralized endpoint, which introduced an external dependency that has proven unreliable (see [#467](https://github.com/near/mpc/issues/467), [#1545](https://github.com/near/mpc/issues/1545)).

The local PCCS proxy eliminates this dependency by querying the Intel PCCS service running on the host machine, which in turn fetches collateral directly from Intel.

## Architecture

```
MPC Node (inside CVM)
    │
    │  POST /api/v1/attestations/verify  (TDX quote as hex)
    ▼
Local PCCS Proxy (host, port 8082)
    │
    │  1. Parse TDX quote → extract FMSPC + CA type from PCK cert
    │  2. Query local Intel PCCS for collateral:
    │     - /tdx/certification/v4/tcb?fmspc=...
    │     - /tdx/certification/v4/qe/identity
    │     - /sgx/certification/v4/pckcrl?ca=...
    │     - /sgx/certification/v4/rootcacrl
    ▼
Intel PCCS (host, port 8081)
    │
    │  Fetches/caches from Intel PCS
    ▼
Intel Provisioning Certification Service (api.trustedservices.intel.com)
```

## Prerequisites

- **Intel PCCS** installed and running on the host (package `sgx-dcap-pccs`, typically listening on `https://localhost:8081`)
- **Python 3** (no external dependencies -- uses stdlib only)
- **OpenSSL** CLI (for parsing PCK certificates)

### Verify Intel PCCS is running

```bash
systemctl status pccs
# Should show: active (running)

# Test PCCS is responding
curl -sk https://localhost:8081/sgx/certification/v4/qe/identity | head -c 100
# Should return JSON with QE identity data
```

If PCCS is not installed, follow the [Intel PCCS setup guide](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/#provisioning-certificate-caching-service-pccs) or install via:

```bash
sudo apt install sgx-dcap-pccs
```

## Installation

The proxy is a single Python script at `scripts/local-pccs-proxy.py`. No build step or dependencies required.

```bash
# Make executable (optional)
chmod +x scripts/local-pccs-proxy.py
```

## Usage

### Start manually

```bash
# Default: listen on 0.0.0.0:8082, upstream PCCS at https://localhost:8081
python3 -u scripts/local-pccs-proxy.py

# Custom port and PCCS URL
python3 -u scripts/local-pccs-proxy.py --port 9090 --pccs-url https://localhost:8081

# Bind to specific address
python3 -u scripts/local-pccs-proxy.py --bind 127.0.0.1 --port 8082
```

> **Note:** Use `python3 -u` (unbuffered) to see log output in real time when redirecting to a file.

### Install as a systemd service

Create `/etc/systemd/system/local-pccs-proxy.service`:

```ini
[Unit]
Description=Local PCCS Proxy for TDX Attestation Collateral
After=pccs.service network.target
Wants=pccs.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /opt/mpc/scripts/local-pccs-proxy.py --port 8082
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable local-pccs-proxy
sudo systemctl start local-pccs-proxy
sudo systemctl status local-pccs-proxy
```

### Verify it's working

```bash
# Health check
curl http://localhost:8082/health
# {"status": "ok"}
```

## Configuring the MPC node

The MPC node's `quote_upload_url` must point to the proxy. Since the node runs inside a CVM, it cannot reach `localhost` on the host -- use the host's external IP instead.

### Via node TOML config (recommended)

Add `quote_upload_url` to the `[mpc_node_config]` section of the dstack user config:

```toml
[mpc_node_config]
home_dir = "/data"
quote_upload_url = "http://<HOST_IP>:8082/api/v1/attestations/verify"
```

If `quote_upload_url` is omitted, the node falls back to Phala's endpoint (set by the launcher in the `[tee]` section).

### Via localnet test template

The localnet config template at `localnet/tee/scripts/rust-launcher/node.conf.localnet.toml.tpl` has a commented-out example:

```toml
[mpc_node_config]
# quote_upload_url = "http://${MACHINE_IP}:8082/api/v1/attestations/verify"
```

Uncomment and set `MACHINE_IP` to enable the local proxy.

## API

### `POST /api/v1/attestations/verify`

Accepts a TDX quote and returns Intel attestation collateral. API-compatible with Phala's endpoint.

**Request:**
- Content-Type: `multipart/form-data`
- Field: `hex` -- the TDX quote as a hex-encoded string

**Response (200):**
```json
{
  "quote_collateral": {
    "tcb_info_issuer_chain": "<PEM certificate chain>",
    "tcb_info": "<JSON string>",
    "tcb_info_signature": "<hex-encoded signature>",
    "qe_identity_issuer_chain": "<PEM certificate chain>",
    "qe_identity": "<JSON string>",
    "qe_identity_signature": "<hex-encoded signature>",
    "pck_crl_issuer_chain": "<PEM certificate chain>",
    "root_ca_crl": "<hex-encoded DER CRL>",
    "pck_crl": "<hex-encoded DER CRL>",
    "pck_certificate_chain": "<PEM certificate chain>"
  }
}
```

**Error (500):**
```json
{
  "error": "<error message>"
}
```

### `GET /health`

Returns `{"status": "ok"}` if the proxy is running.

## Testing

### Unit test (Rust)

Run the dedicated test that validates the proxy returns correct collateral:

```bash
# Start the proxy first
python3 -u scripts/local-pccs-proxy.py --port 8082 &

# Run the test
cargo test -p tee-authority --features external-services-tests \
  --profile test-release test_upload_quote_for_collateral_with_local_pccs_proxy
```

Override the URL via environment variable:

```bash
LOCAL_PCCS_PROXY_URL=http://localhost:9090/api/v1/attestations/verify \
  cargo test -p tee-authority --features external-services-tests \
  --profile test-release test_upload_quote_for_collateral_with_local_pccs_proxy
```

### Manual test with curl

```bash
# Using the test quote from the repo
QUOTE_HEX=$(python3 -c "
import json
with open('crates/test-utils/assets/quote.json') as f:
    print(bytes(json.load(f)).hex())
")

curl -s -X POST http://localhost:8082/api/v1/attestations/verify \
  -F "hex=$QUOTE_HEX" | python3 -m json.tool | head -20
```

### E2E test (2-node CVM cluster)

See the [TEE testing guide](../localnet/tee/scripts/rust-launcher/how-to-run-localnet-tee-setup-script.md) for deploying a full 2-node cluster. The proxy logs will show collateral requests from each CVM:

```
Received quote (10012 hex chars)
  FMSPC: b0c06f000000, CA type: platform
[06/Apr/2026 12:14:12] "POST /api/v1/attestations/verify HTTP/1.1" 200 -
  Collateral returned successfully
```

## Troubleshooting

### Proxy starts but CVM can't reach it

The proxy must be reachable from inside the CVM. Common issues:
- **Binding**: Ensure the proxy listens on `0.0.0.0` (default), not `127.0.0.1`
- **Firewall**: Port 8082 must be open for inbound connections
- **URL**: Use the host's external IP (e.g. `http://51.68.219.1:8082`), not `localhost`

### PCCS returns errors

```bash
# Check PCCS is running
systemctl status pccs

# Test PCCS directly
curl -sk https://localhost:8081/sgx/certification/v4/qe/identity

# Check PCCS logs
journalctl -u pccs --tail 20
```

### Quote parsing fails

The proxy only supports TDX v4 quotes (TEE type 0x81). SGX quotes are not supported. Check the error message in the proxy logs for details.

## Related issues

- [#467](https://github.com/near/mpc/issues/467) -- Remove dependency on Phala PCS endpoint
- [#1545](https://github.com/near/mpc/issues/1545) -- Introduce independent CRL endpoint and remove dependency on Phala's CRL endpoint
