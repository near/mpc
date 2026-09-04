# Proposal generator

This tool is meant for MPC team to generate proposals for foreign chain whitelist
voting and share generated payload with operators. It the argument for
foreign chain whitelist voting from TOML config file.

## Usage

```bash
cargo run -p proposal-generator -- crates/proposal-generator/proposals/testnet-rpc-whitelist.toml
```

Prints the borsh-encoded `NonEmptyBTreeMap<ForeignChain, ChainEntry>` as base64,
along with the sha256 of the borsh encoding that the contract logs,
so the transaction that landed can be checked against the bytes you generated.

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

Paste the printed base64 into a `vote_update_foreign_chain_providers` call
(`$SIGNER` is the MPC signer contract account, `$VOTER` the participant account
casting the vote, `$NETWORK` the network config):

```bash
near contract call-function as-transaction "$SIGNER" \
  vote_update_foreign_chain_providers \
  base64-args '<GENERATOR_OUTPUT>' \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$VOTER" network-config "$NETWORK" sign-with-keychain send
```

A chain's entry is applied once the protocol signing threshold of participants
submits byte-identical proposals for it.
