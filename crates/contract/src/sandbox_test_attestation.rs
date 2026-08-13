//! Sandbox-only whitelisting of the attestation fixture's launcher compose hash.
//!
//! Compose hashes otherwise enter the allowlist only by derivation from the compiled-in template,
//! and the fixture's compose carries the service that exported its signer key, so no vote can
//! allow it. Gated so no released artifact carries this.

use crate::{MpcContract, MpcContractExt};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash};
use near_sdk::near;

#[near]
impl MpcContract {
    /// Panics if `launcher_hash` is not allowed yet, so callers vote it in first.
    pub fn sandbox_allow_launcher_compose_hash(
        &mut self,
        launcher_hash: LauncherImageHash,
        compose_hash: LauncherDockerComposeHash,
    ) {
        self.tee_state
            .allowed_launcher_images
            .allow_compose_hash(&launcher_hash, compose_hash);
    }
}
