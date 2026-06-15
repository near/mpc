#! /usr/bin/env bash
#
# Builds the Rust launcher reproducibly and prints its manifest digest.
# No assertion — the previous strict check was removed in #3199; see
# https://github.com/near/mpc/issues/2662 for context and the
# preconditions for restoring it.

set -euo pipefail

# The `*-manifest-digest` derivation hashes the manifest of the pushed
# `dir:` layout (built by skopeo inside the Nix sandbox), so the digest is
# deterministic across builders and the only output is a `sha256:HEX` line.
nix build .#rust-launcher-image-manifest-digest --out-link result-rust-launcher-digest -L
echo "Built launcher image hash: $(cat result-rust-launcher-digest)"
