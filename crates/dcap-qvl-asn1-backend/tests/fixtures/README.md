# Test fixtures

Vendored from the `Phala-Network/dcap-qvl` sample corpus at commit
`8a533f5d7ef3e231fc4a0c864fde8129737dbc90` — the same revision the
workspace `Cargo.toml` pins the `dcap-qvl` git dependency to, so the
conformance suite runs against fixtures produced by the same upstream
code it's testing against.

Source URLs:

- `sgx_quote` — `sample/sgx_quote`
- `tdx_quote` — `sample/tdx_quote`
- `tdx_quote_collateral.json` — `sample/tdx_quote_collateral.json`

These are used by `tests/conformance.rs` to prove `Asn1DerConfig` is a
byte-for-byte drop-in replacement for `DefaultConfig` on real Intel SGX
and TDX quotes.

When upgrading the `dcap-qvl` pin, re-vendor these files from the matching
upstream commit and update the SHA here.
