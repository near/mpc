use crate::{
    errors::Error,
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    storage_keys::StorageKey,
    tee::{
        proposal::{AllowedDockerImageHashes, CodeHashesVotes, MpcDockerImageHash},
        quote::TeeQuoteStatus,
        tee_participant::TeeParticipantInfo,
    },
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
    pub(crate) tee_participant_info: IterableMap<AccountId, TeeParticipantInfo>,
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
    /// Returns either `Valid` or `Invalid`.
    /// May return an error
    pub(crate) fn verify_tee_participant_info(
        &mut self,
        tee_participant_info: &TeeParticipantInfo,
        sign_pk: &PublicKey,
    ) -> Result<TeeQuoteStatus, Error> {
        let allowed_mpc_docker_image_hashes = self.get_allowed_hashes();
        let allowed_launcher_hashes = self.get_allowed_launcher_hashes();
        tee_participant_info.verify(
            allowed_mpc_docker_image_hashes.as_slice(),
            allowed_launcher_hashes.as_slice(),
            sign_pk,
        )
    }

    /// Verifies the TEE quote and Docker image
    pub(crate) fn verify_tee_participant(
        &mut self,
        account_id: &AccountId,
        sign_pk: &PublicKey,
    ) -> Result<TeeQuoteStatus, Error> {
        let allowed_mpc_docker_image_hashes = self.get_allowed_hashes();
        let allowed_launcher_hashes = self.get_allowed_launcher_hashes();
        let tee_participant_info = self.tee_participant_info.get(account_id);
        if let Some(tee_participant_info) = tee_participant_info {
            tee_participant_info.verify(
                allowed_mpc_docker_image_hashes.as_slice(),
                allowed_launcher_hashes.as_slice(),
                sign_pk,
            )
        } else {
            Ok(TeeQuoteStatus::None)
        }
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
        match self.verify_tee_participant(account_id, sign_pk) {
            Ok(status) => status,
            Err(_) => TeeQuoteStatus::Invalid,
        }
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

    pub fn get_allowed_launcher_hashes(&self) -> &Vec<LauncherDockerComposeHash> {
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
