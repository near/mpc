# Test fixtures

Vendored from the `Phala-Network/dcap-qvl` sample corpus at release
[`v0.4.0`](https://github.com/Phala-Network/dcap-qvl/releases/tag/v0.4.0)
— the same release the workspace `Cargo.toml` pins the `dcap-qvl`
dependency to, so the conformance suite runs against fixtures produced
by the same upstream code it's testing against.

Source URLs:

- `sgx_quote` — `sample/sgx_quote`
- `tdx_quote` — `sample/tdx_quote`
- `tdx_quote_collateral.json` — `sample/tdx_quote_collateral.json`

These are used by `tests/conformance.rs` to prove `Asn1DerConfig` is a
byte-for-byte drop-in replacement for `DefaultConfig` on real Intel SGX
and TDX quotes.

When upgrading the `dcap-qvl` pin, re-vendor these files from the
matching upstream release and update the version here.
