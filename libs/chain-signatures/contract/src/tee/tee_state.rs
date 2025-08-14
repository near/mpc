use crate::{
    errors::Error,
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    storage_keys::StorageKey,
    tee::{
        proposal::{AllowedDockerImageHashes, CodeHashesVotes, MpcDockerImageHash},
        quote::TeeQuoteStatus,
    },
};
use attestation::{
    attestation::{Attestation, DstackAttestation},
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{env, near, store::IterableMap, AccountId, PublicKey};

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
    pub(crate) participants_attestations: IterableMap<AccountId, DstackAttestation>,
}

impl Default for TeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: Default::default(),
            historical_docker_image_hashes: Default::default(),
            votes: Default::default(),
            participants_attestations: IterableMap::new(StorageKey::TeeParticipantAttestation),
        }
    }
}
impl TeeState {
    /// Verifies the TEE quote and Docker image.
    pub(crate) fn verify_tee_participant(
        &mut self,
        account_id: &AccountId,
        sign_pk: &PublicKey,
        timestamp_s: u64,
    ) -> Result<TeeQuoteStatus, Error> {
        let participant_attestation = self.participants_attestations.get(account_id);
        let Some(participant_attestation) = participant_attestation else {
            return Ok(TeeQuoteStatus::None);
        };
        let attestation = Attestation::Dstack(DstackAttestation::new(
            participant_attestation.quote,
            participant_attestation.collateral,
            participant_attestation.tcb_info,
            participant_attestation.expected_measurements,
        ));
        let allowed = self.get_allowed_hashes();
        let historical = self.get_historical_hashes();
        let account_key = env::signer_account_pk();
        let expected_report_data = ReportData::V1(ReportDataV1::new(sign_pk, account_key));
        let quote_result =
            attestation.verify(expected_report_data, timestamp_s, &allowed, historical);

        Ok(if quote_result {
            TeeQuoteStatus::Valid
        } else {
            TeeQuoteStatus::Invalid
        })
    }

    /// Performs TEE validation on the given participants.
    ///
    /// Returns `TeeValidationResult::Full` if all participants are valid,
    /// or `TeeValidationResult::Partial` with the subset of valid participants otherwise.
    ///
    /// Participants with `TeeQuoteStatus::Valid` or `TeeQuoteStatus::None` are considered valid.
    /// The returned `Participants` preserves participant data and `next_id()`.
    pub fn validate_tee(&mut self, participants: &Participants) -> TeeValidationResult {
        let new_participants: Vec<_> = participants
            .participants()
            .iter()
            .filter(|(account_id, _, participant_info)| {
                matches!(
                    self.tee_status(account_id, &participant_info.sign_pk),
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

    /// Retrieves and validates the TEE status for a participant, combining both the TEE quote
    /// verification and the Docker image verification. If both validations pass, the participant
    /// is considered to have a valid TEE status. Otherwise, the participant is marked as invalid.
    /// If no TEE information is found, the participant is marked with `TeeQuoteStatus::None`.
    pub fn tee_status(&mut self, account_id: &AccountId, sign_pk: &PublicKey) -> TeeQuoteStatus {
        let now_sec = env::block_timestamp_ms() / 1_000;
        match self.verify_tee_participant(account_id, sign_pk, now_sec) {
            Ok(status) => status,
            Err(_) => TeeQuoteStatus::Invalid,
        }
    }

    pub fn add_participant(
        &mut self,
        account_id: AccountId,
        proposed_tee_participant: DstackAttestation,
    ) {
        self.participants_attestations
            .insert(account_id.clone(), proposed_tee_participant.clone());
    }

    pub fn vote(
        &mut self,
        code_hash: MpcDockerImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.votes.vote(code_hash.clone(), participant)
    }
    /// Retrieves the current allowed hashes, cleaning up any expired entries.
    pub fn get_allowed_hashes(&mut self) -> Vec<MpcDockerImageHash> {
        // Clean up expired entries and return the current allowed hashes.
        // don't remove the get call, as it ensures we only get hashes valid for the current block height
        self.allowed_docker_image_hashes
            .get(env::block_height())
            .into_iter()
            .map(|entry| entry.image_hash)
            .collect()
    }

    pub fn get_historical_hashes(&self) -> &Vec<LauncherDockerComposeHash> {
        &self.historical_docker_image_hashes
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
