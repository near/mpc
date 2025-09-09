use crate::{
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    tee::proposal::{AllowedDockerImageHashes, CodeHashesVotes, MpcDockerImageHash},
};
use attestation::{
    attestation::Attestation,
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{env, near, PublicKey};

pub enum TeeValidationResult {
    Full,
    Partial {
        participants_with_valid_attestation: Participants,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TeeQuoteStatus {
    /// TEE quote and Docker image verification both passed successfully.
    /// The participant is considered to have a valid, verified TEE status.
    Valid,

    /// TEE verification failed - either the quote verification failed,
    /// the Docker image verification failed, or both validations failed.
    /// The participant should not be trusted for TEE-dependent operations.
    Invalid,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
    pub(crate) votes: CodeHashesVotes,
}

impl Default for TeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: AllowedDockerImageHashes::default(),
            allowed_launcher_compose_hashes: vec![],
            votes: CodeHashesVotes::default(),
        }
    }
}

impl TeeState {
    pub(crate) fn verify_attestation(
        &mut self,
        attestation: &Attestation,
        tls_public_key: PublicKey,
        tee_upgrade_period_blocks: u64,
    ) -> TeeQuoteStatus {
        let expected_report_data = ReportData::V1(ReportDataV1::new(tls_public_key));
        let current_time_milliseconds = env::block_timestamp_ms();
        let current_time_seconds = current_time_milliseconds / 1_000;

        let is_valid = attestation.verify(
            expected_report_data,
            current_time_seconds,
            &self.get_allowed_hashes(tee_upgrade_period_blocks),
            &self.allowed_launcher_compose_hashes,
        );

        if is_valid {
            TeeQuoteStatus::Valid
        } else {
            TeeQuoteStatus::Invalid
        }
    }

    pub fn vote(
        &mut self,
        code_hash: MpcDockerImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.votes.vote(code_hash.clone(), participant)
    }

    /// Retrieves the current allowed hashes, cleaning up any expired entries.
    pub fn get_allowed_hashes(
        &mut self,
        tee_upgrade_period_blocks: u64,
    ) -> Vec<MpcDockerImageHash> {
        // Clean up expired entries and return the current allowed hashes. Don't remove the get
        // call, as it ensures we only get hashes valid for the current block height.
        self.allowed_docker_image_hashes
            .get(env::block_height(), tee_upgrade_period_blocks)
            .iter()
            .map(|entry| entry.image_hash.clone())
            .collect()
    }

    pub fn whitelist_tee_proposal(
        &mut self,
        tee_proposal: MpcDockerImageHash,
        tee_upgrade_period_blocks: u64,
    ) {
        self.votes.clear_votes();
        self.allowed_launcher_compose_hashes.push(
            AllowedDockerImageHashes::get_docker_compose_hash(tee_proposal.clone()),
        );
        self.allowed_docker_image_hashes.insert(
            tee_proposal,
            env::block_height(),
            tee_upgrade_period_blocks,
        );
    }
}
