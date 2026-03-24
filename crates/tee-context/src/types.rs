use mpc_primitives::hash::{DockerImageHash, LauncherDockerComposeHash};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::Ed25519PublicKey;

/// Allowed TEE hashes fetched from the governance contract.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowedTeeHashes {
    pub allowed_docker_image_hashes: Vec<DockerImageHash>,
    pub allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
}

/// Identity of the service using this context.
#[derive(Clone, Debug)]
pub struct TeeNodeIdentity {
    pub node_account_id: AccountId,
    pub account_public_key: Ed25519PublicKey,
}
