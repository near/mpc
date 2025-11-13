# Historic MPC contracts

This crate stores binaries of historic contracts, which we can use for compatibility tests.

Additionally, to support our pytests we have a binary in `bin/copy_contracts.rs` that
takes the latest mainnet and testnet contracts and writes them to the appropriate pytest folder.
