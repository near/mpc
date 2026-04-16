# pccs-proxy

Local PCCS proxy for TDX attestation collateral. Drop-in replacement for Phala's collateral endpoint, backed by a local Intel PCCS.

See [docs/local-pccs-proxy.md](../../docs/local-pccs-proxy.md) for full documentation.

## Quick start

```bash
cargo build -p pccs-proxy --release
./target/release/pccs-proxy --listen 0.0.0.0:8082 --pccs-url https://localhost:8081
```
