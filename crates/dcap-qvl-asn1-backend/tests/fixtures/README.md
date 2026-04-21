# Test fixtures

Vendored from the `Phala-Network/dcap-qvl` sample corpus at commit
`68de626c37f3ff89447236e3529e4475979fd3fd` (the HEAD of PR #144 at the
time this crate was imported).

Source URLs:

- `sgx_quote` — `sample/sgx_quote`
- `tdx_quote` — `sample/tdx_quote`
- `tdx_quote_collateral.json` — `sample/tdx_quote_collateral.json`

These are used by `tests/conformance.rs` to prove `Asn1DerConfig` is a
byte-for-byte drop-in replacement for `DefaultConfig` on real Intel SGX
and TDX quotes.

When upgrading the `dcap-qvl` pin, re-vendor these files from the matching
upstream commit and update the SHA here.
