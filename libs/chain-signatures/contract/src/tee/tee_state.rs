use crate::{
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    storage_keys::StorageKey,
    tee::{
        proposal::{AllowedDockerImageHashes, CodeHashesVotes, MpcDockerImageHash},
        quote::TeeQuoteStatus,
        tee_participant::TeeParticipantInfo,
    },
};
use attestation::{
    attestation::Attestation,
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{env, near, store::IterableMap, AccountId};

pub enum TeeValidationResult {
    Full,
    Partial(Participants),
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) historical_docker_image_hashes: Vec<LauncherDockerComposeHash>,
    pub(crate) votes: CodeHashesVotes,
    pub(crate) tee_participant_info: IterableMap<AccountId, Attestation>,
}

impl Default for TeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: Default::default(),
            historical_docker_image_hashes: Default::default(),
            votes: Default::default(),
            tee_participant_info: IterableMap::new(StorageKey::TeeParticipantInfo),
        }
    }
}

impl TeeState {
    /// Performs TEE validation on the given participants.
    ///
    /// Returns `TeeValidationResult::Full` if all participants are valid,
    /// or `TeeValidationResult::Partial` with the subset of valid participants otherwise.
    ///
    /// Participants with `TeeQuoteStatus::Valid` or `TeeQuoteStatus::None` are considered valid.
    /// The returned `Participants` preserves participant data and `next_id()`.
    pub fn validate_tee(&self, participants: &Participants) -> TeeValidationResult {
        let new_participants: Vec<_> = participants
            .participants()
            .iter()
            .filter(|(account_id, _, _)| {
                matches!(
                    self.tee_status(account_id),
                    TeeQuoteStatus::Valid | TeeQuoteStatus::None
                )
            })
            .cloned()
            .collect();
        if new_participants.len() != participants.len() {
            TeeValidationResult::Partial(Participants::init(
                participants.next_id(),
                new_participants,
            ))
        } else {
            TeeValidationResult::Full
        }
    }

    /// Maps `account_id` to its `TeeQuoteStatus`. If `account_id` has no TEE information associated to it, then it is mapped to
    /// `TeeQuoteStatus::None`.
    pub fn tee_status(&self, account_id: &AccountId) -> TeeQuoteStatus {
        let current_block_timestamp = env::block_timestamp_ms() / 1_000;
        let account_public_key = env::signer_account_pk();
        let tls_public_key = env::signer_account_pk(); // TODO: Get the TLS key, not account key.

        let report_data = ReportData::V1(ReportDataV1::new(tls_public_key, account_public_key));
        // let expected_report_data = todo!();
        self.tee_participant_info
            .get(account_id)
            .map(|tee_participant_info| {
                TeeQuoteStatus::from(tee_participant_info.verify(
                    expected_report_data,
                    current_block_timestamp,
                    &allowed_mpc_docker_image_hashes,
                    &self.allowed_docker_image_hashes,
                ))
            })
            .unwrap_or(TeeQuoteStatus::None)
    }

    pub fn add_participant(
        &mut self,
        account_id: AccountId,
        proposed_tee_participant: TeeParticipantInfo,
    ) {
        self.tee_participant_info
            .insert(account_id.clone(), proposed_tee_participant.clone());
    }

    pub fn vote(
        &mut self,
        code_hash: MpcDockerImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.votes.vote(code_hash.clone(), participant)
    }

    pub fn get_allowed_hashes(&mut self) -> Vec<MpcDockerImageHash> {
        self.allowed_docker_image_hashes
            .get(env::block_height())
            .into_iter()
            .map(|entry| entry.image_hash)
            .collect()
    }

    pub fn get_historical_hashes(&mut self) -> Vec<LauncherDockerComposeHash> {
        self.historical_docker_image_hashes.clone()
    }

    pub fn whitelist_tee_proposal(&mut self, tee_proposal: MpcDockerImageHash) {
        self.votes.clear_votes();
        self.historical_docker_image_hashes.push(
            AllowedDockerImageHashes::get_docker_compose_hash(tee_proposal.clone()),
        );
        self.allowed_docker_image_hashes
            .insert(tee_proposal, env::block_height());
    }
}
