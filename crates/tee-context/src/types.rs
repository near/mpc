use mpc_primitives::hash::{DockerImageHash, LauncherDockerComposeHash};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::{Attestation, Ed25519PublicKey};
use serde::{Deserialize, Serialize};

/// Allowed TEE hashes fetched from the governance contract.
#[derive(Clone, Debug, Default)]
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

/// Arguments for the `submit_participant_info` contract call.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitParticipantInfoArgs {
    pub proposed_participant_attestation: Attestation,
    pub tls_public_key: Ed25519PublicKey,
}
