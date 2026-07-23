#!/usr/bin/env bash
#
# upgrade-prepare.sh — Build the local artifacts a contract/node upgrade needs.
#
# Downloads the release contract WASM, builds serialized.bin (the borsh
# ProposeUpdateArgs blob propose_update expects), prints the wasm sha256, and
# prints the node manifest digest in both forms. Deterministic; no on-chain state
# is touched. See how-to/contract-upgrade.md and node-hash-vote.md.
#
# Usage:  ./scripts/ops/upgrade-prepare.sh <VERSION>
# Example: ./scripts/ops/upgrade-prepare.sh 3.13.0

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ops/lib.sh
source "$HERE/lib.sh"

[[ $# -eq 1 ]] || die "Usage: $SCRIPT_NAME <VERSION>  (e.g. 3.13.0)"
version="$1"
validate_version "$version"
require_cmds gh tar python3 skopeo

tarball="mpc-contract-v${version}.tar.gz"
wasm="mpc-contract-v${version}.wasm"

if [[ ! -f "$wasm" ]]; then
    echo "==> Downloading contract WASM for v${version}..."
    run gh release download "$version" --repo near/mpc --pattern "$tarball" --clobber
    run tar xzf "$tarball"
    [[ -f "$wasm" ]] || die "expected ${wasm} inside ${tarball} but it was not found."
else
    echo "==> Using existing ${wasm} (delete it to re-download)."
fi

echo "==> Building serialized.bin (borsh ProposeUpdateArgs { code: Some, config: None })..."
# Byte layout must match how-to/contract-upgrade.md: Some(code) tag + u32 len + wasm + None(config) tag.
export WASM_PATH="$wasm"
run python3 - <<'PY'
import hashlib, os, struct
wasm = open(os.environ['WASM_PATH'], 'rb').read()
blob = b'\x01' + struct.pack('<I', len(wasm)) + wasm + b'\x00'
open('serialized.bin', 'wb').write(blob)
print(f"    wasm bytes:   {len(wasm)}")
print(f"    wasm sha256:  {hashlib.sha256(wasm).hexdigest()}")
print(f"    serialized:   serialized.bin ({len(blob)} bytes)")
PY

echo "==> Node manifest digest (nearone/mpc-node:${version}):"
prefixed="$(node_digest "$version")"
bare="${prefixed#sha256:}"
printf '    vote_code_hash (bare hex):       %s\n' "$bare"
printf '    mpc_hash_override (sha256: ...):  %s\n' "$prefixed"

echo
echo "Done. Next: ./scripts/ops/upgrade-commands.sh ${version} <net>"
