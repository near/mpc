#! /usr/bin/env bash
#
# Builds the Rust launcher reproducibly and prints its manifest digest.
# No assertion — the previous strict check was removed in #3199; see
# https://github.com/near/mpc/issues/2662 for context and the
# preconditions for restoring it.

set -euo pipefail

./deployment/build-images.sh --rust-launcher
