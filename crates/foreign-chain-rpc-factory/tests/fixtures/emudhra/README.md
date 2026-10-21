# Compromised eMudhra RPC TLS regression test

These public CA chains come from the `chains.zip` archive published at
<https://emudhra.we-have-a-problem.com/> on 20 October 2026. The archive's
server certificates are omitted. Each PEM contains an affected TLS intermediate
and, for the emSign path, its cross-signed parent. Both the emSign and Sectigo
trust paths are covered for all six affected TLS intermediates.

The two affected code-signing intermediates are outside this TLS test's scope.

The test requires the original compromised CA private keys in a local directory;
they are not copied into this repository. It creates fresh one-day certificates
for `localhost`, starts an HTTPS Ethereum JSON-RPC endpoint on loopback, and uses
the production `build_http_client` with Alchemy-style path authentication. No real
Alchemy endpoint, API key, DNS override, or trust-store change is involved.

First, a client explicitly trusting the issuing intermediate must successfully call
`eth_chainId`. The production client must then reject the certificate for a CA
trust error, before sending an RPC request. A timeout, invalid hostname, expired
leaf, or malformed certificate does not count as a passing rejection.

Run from the repository root:

```sh
EMUDHRA_CERTS_DIR=/path/to/certs cargo nextest run \
  --cargo-profile=test-release \
  -p foreign-chain-rpc-factory --test emudhra_tls --run-ignored only
```

The directory must contain `EM_{DV,OV,EV}_TLS_CA_{G3B,G3C}.key.pem`. Each key is
checked against the public key of the corresponding original CA certificate.

These are manual tests because private-key inputs are external and the production
RPC client delegates trust decisions to the operating system. A passing run
establishes rejection on that host, not on every deployment. Run the same tests
against the production OS/container image to check its trust configuration.
