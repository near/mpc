# Proposal generator

This tool is meant for the MPC team to generate proposals for foreign chain whitelist
voting and share the generated payload with operators. It builds the
`vote_update_foreign_chain_providers` argument from a TOML config file.

## Usage

```bash
cargo run -p proposal-generator -- crates/proposal-generator/proposals/testnet-rpc-whitelist.toml
```

Prints the `vote_update_foreign_chain_providers` call argument, so the transaction
that lands can be read back against the proposal you generated.

## Config format

Keys and values use the contract's serde shapes verbatim: chain keys are
`ForeignChain` variant names, chain tables are `ChainEntry`:

```toml
[chains.Aptos]
quorum = 3  # RPC response quorum nodes apply when querying this chain

[chains.Aptos.providers.alchemy]
base_url = "https://aptos-testnet.g.alchemy.com/v2/"
auth_scheme = { Path = { placeholder = "{API_KEY}" } }
chain_routing = "Embedded"
```

- `base_url` — may carry a single `{}` standing for one operator-chosen host
  label (QuickNode-style per-operator slugs).
- `auth_scheme` — `"None"`, `{ Header = { name = "...", scheme = "..." } }`
  (`scheme` optional), `{ Path = { placeholder = "..." } }`, or
  `{ Query = { name = "..." } }`.
- `chain_routing` — `"Embedded"`, `{ PathSegment = { segment = "..." } }`, or
  `{ QueryParam = { name = "...", value = "..." } }`.

## Voting

Paste the printed JSON into a `vote_update_foreign_chain_providers` call
(`$SIGNER` is the MPC signer contract account, `$VOTER` the participant account
casting the vote, `$NETWORK` the network config):

```bash
near contract call-function as-transaction "$SIGNER" \
  vote_update_foreign_chain_providers \
  json-args '<GENERATOR_OUTPUT>' \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$VOTER" network-config "$NETWORK" sign-with-keychain send
```

A chain's entry is applied once the protocol signing threshold of participants
submits byte-identical proposals for it.
