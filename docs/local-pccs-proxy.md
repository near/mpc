# Local PCCS Proxy

A drop-in replacement for Phala's TDX collateral endpoint (`cloud-api.phala.network`) that fetches Intel attestation collateral directly from a local Intel PCCS (Provisioning Certificate Caching Service).

## Background

MPC nodes running in TDX CVMs need Intel attestation collateral (certificates, CRLs, TCB info) to prove they are running on genuine Intel hardware. Previously, this collateral was fetched from Phala's centralized endpoint, which introduced an external dependency that has proven unreliable.

The local PCCS proxy eliminates this dependency by querying the Intel PCCS service running on the host machine, which in turn fetches collateral directly from Intel.

## Architecture

```
MPC Node (inside CVM)
    |
    |  POST /api/v1/attestations/verify  (TDX quote as hex)
    v
Local PCCS Proxy (host, port 8082)
    |
    |  1. Parse TDX quote -> extract FMSPC + CA type from PCK cert
    |  2. Query local Intel PCCS for collateral:
    |     - /tdx/certification/v4/tcb?fmspc=...
    |     - /tdx/certification/v4/qe/identity
    |     - /sgx/certification/v4/pckcrl?ca=...
    |     - /sgx/certification/v4/rootcacrl
    v
Intel PCCS (host, port 8081)
    |
    |  Fetches/caches from Intel PCS
    v
Intel Provisioning Certification Service (api.trustedservices.intel.com)
```

## Prerequisites

- **Intel PCCS** installed and running on the host (package `sgx-dcap-pccs`, typically listening on `https://localhost:8081`). For installation and configuration, follow the [Intel PCCS setup guide](https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/#provisioning-certificate-caching-service-pccs).
- **Python 3** (for the Python proxy -- no external dependencies, uses stdlib only)
- **OpenSSL** CLI (for the Python proxy -- used for PCK certificate parsing)

The Rust proxy (`pccs-proxy` crate) has no runtime dependencies beyond the binary itself.

### Verify Intel PCCS is running

```bash
systemctl status pccs
# Should show: active (running)

# Test PCCS is responding
curl -sk https://localhost:8081/sgx/certification/v4/qe/identity | head -c 100
# Should return JSON with QE identity data
```

## Installation

Two implementations are provided:

### Rust (recommended for production)

```bash
cargo build -p pccs-proxy --release
# Binary at: target/release/pccs-proxy
```

### Python (zero-dependency fallback)

No build step required. The script is at `scripts/local-pccs-proxy.py`.

## Usage

### Rust proxy

```bash
# Default: listen on 0.0.0.0:8082, upstream PCCS at https://localhost:8081
./target/release/pccs-proxy

# Custom listen address and PCCS URL
./target/release/pccs-proxy --listen 0.0.0.0:9090 --pccs-url https://localhost:8081
```

### Python proxy

```bash
# Default: listen on 0.0.0.0:8082, upstream PCCS at https://localhost:8081
python3 -u scripts/local-pccs-proxy.py

# Custom port and PCCS URL
python3 -u scripts/local-pccs-proxy.py --port 9090 --pccs-url https://localhost:8081
```

> **Note:** Use `python3 -u` (unbuffered) to see log output in real time when redirecting to a file.

### Run as a systemd service

See `deployment/local-pccs-proxy.service` for a sample systemd unit file.

### Verify it's working

```bash
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

See the [TEE testing guide](../localnet/tee/scripts/rust-launcher/how-to-run-localnet-tee-setup-script.md) for deploying a full 2-node cluster with the local proxy.

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
