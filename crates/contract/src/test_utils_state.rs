//! Host-side editing of raw contract state for sandbox tests.

use crate::MpcContract;
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash};
use near_sdk::borsh::{self, BorshDeserialize};

/// Adds `compose_hash` to `launcher_hash`'s allowlist entry in a raw `STATE` blob, for
/// sandbox tests to patch back in. The attestation fixture's compose hash is not
/// derivable from the compiled-in template, so no vote can allow it.
pub fn allow_launcher_compose_hash_in_state(
    state: &[u8],
    launcher_hash: &LauncherImageHash,
    compose_hash: LauncherDockerComposeHash,
) -> Vec<u8> {
    let mut contract = MpcContract::try_from_slice(state).expect("STATE deserializes");
    let roundtrip = borsh::to_vec(&contract).expect("STATE serializes");
    assert!(
        roundtrip == state,
        "STATE must round-trip byte-identically; the host-side layout has drifted"
    );
    contract
        .tee_state
        .allowed_launcher_images
        .allow_compose_hash(launcher_hash, compose_hash);
    borsh::to_vec(&contract).expect("STATE serializes")
}
