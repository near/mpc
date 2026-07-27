#!/usr/bin/env bash
set -euo pipefail

# Lint contract crates under the real build config via `cargo near check`.
#
# The wasm32 + `--cfg near` counterpart of plain `cargo clippy`: it lints the
# contract crates in the build config they actually deploy under, which the host
# target (no `--cfg near`) can't reach. `RUSTFLAGS=-Dwarnings` makes it a gate;
# Cargo caps lints on non-workspace deps, so only our crates can fail.
#
# Contract crates are exactly the workspace cdylibs; ask Cargo so the list self-maintains.
cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(any(.targets[].crate_types[]; . == "cdylib")) | .manifest_path' \
  | while read -r manifest; do
      cargo near check --clippy --locked --env 'RUSTFLAGS=-Dwarnings' --manifest-path "$manifest"
    done
