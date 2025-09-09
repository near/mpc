use crate::{
    errors::Error,
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    storage_keys::StorageKey,
    tee::proposal::{AllowedDockerImageHashes, CodeHashesVotes, MpcDockerImageHash},
};
use attestation::{
    attestation::Attestation,
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{env, near, store::IterableMap, AccountId, PublicKey};
use std::collections::HashSet;

pub(crate) enum TeeValidationResult {
    /// All participants have a valid attestation.
    Full,
    /// Only a subset of the participants had a valid attestation.
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
    pub(crate) participants_attestations: IterableMap<AccountId, Attestation>,
}

impl Default for TeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: AllowedDockerImageHashes::default(),
            allowed_launcher_compose_hashes: vec![],
            votes: CodeHashesVotes::default(),
            participants_attestations: IterableMap::new(StorageKey::TeeParticipantAttestation),
        }
    }
}

impl TeeState {
    fn current_time_seconds() -> u64 {
        let current_time_milliseconds = env::block_timestamp_ms();
        current_time_milliseconds / 1_000
    }

    pub(crate) fn verify_proposed_participant_attestation(
        &mut self,
        attestation: &Attestation,
        tls_public_key: PublicKey,
        tee_upgrade_period_blocks: u64,
    ) -> TeeQuoteStatus {
        let expected_report_data = ReportData::V1(ReportDataV1::new(tls_public_key));
        let is_valid = attestation.verify(
            expected_report_data,
            Self::current_time_seconds(),
            &self.get_allowed_hashes(tee_upgrade_period_blocks),
            &self.allowed_launcher_compose_hashes,
        );

        if is_valid {
            TeeQuoteStatus::Valid
        } else {
            TeeQuoteStatus::Invalid
        }
    }

    /// Verifies the TEE quote and Docker image
    pub(crate) fn verify_tee_participant(
        &mut self,
        account_id: &AccountId,
        tls_public_key: PublicKey,
        tee_upgrade_period_blocks: u64,
    ) -> Result<TeeQuoteStatus, Error> {
        let allowed_mpc_docker_image_hashes = self.get_allowed_hashes(tee_upgrade_period_blocks);
        let allowed_launcher_compose_hashes = &self.allowed_launcher_compose_hashes;

        let participant_attestation = self.participants_attestations.get(account_id);
        let Some(participant_attestation) = participant_attestation else {
            return Ok(TeeQuoteStatus::Invalid);
        };

        let expected_report_data = ReportData::V1(ReportDataV1::new(tls_public_key));
        let time_stamp_seconds = Self::current_time_seconds();

        let quote_result = participant_attestation.verify(
            expected_report_data,
            time_stamp_seconds,
            &allowed_mpc_docker_image_hashes,
            allowed_launcher_compose_hashes,
        );

        let quote_result = if quote_result {
            TeeQuoteStatus::Valid
        } else {
            TeeQuoteStatus::Invalid
        };

        Ok(quote_result)
    }

    /// Performs TEE validation on the given participants.
    pub(crate) fn validate_participants_tee_attestation(
        &mut self,
        participants: &Participants,
        tee_upgrade_period_blocks: u64,
    ) -> TeeValidationResult {
        let participants_with_valid_attestation: Vec<_> = participants
            .participants()
            .iter()
            .filter(|(account_id, _, participant_info)| {
                let tls_public_key = participant_info.sign_pk.clone();
                let tee_status = self.verify_tee_participant(
                    account_id,
                    tls_public_key,
                    tee_upgrade_period_blocks,
                );

                matches!(tee_status, Ok(TeeQuoteStatus::Valid))
            })
            .cloned()
            .collect();

        let all_participants_passed_attestation =
            participants_with_valid_attestation.len() == participants.len();

        if all_participants_passed_attestation {
            TeeValidationResult::Full
        } else {
            let new_participant_set =
                Participants::init(participants.next_id(), participants_with_valid_attestation);

            TeeValidationResult::Partial {
                participants_with_valid_attestation: new_participant_set,
            }
        }
    }

    pub fn add_participant(
        &mut self,
        account_id: AccountId,
        proposed_tee_participant: Attestation,
    ) {
        self.participants_attestations
            .insert(account_id, proposed_tee_participant);
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

    /// Removes TEE information for accounts that are not in the provided participants list.
    /// This is used to clean up storage after a resharing concludes.
    pub fn clean_non_participants(&mut self, participants: &Participants) {
        let participant_accounts: HashSet<&AccountId> = participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id)
            .collect();

        // Collect accounts to remove (can't remove while iterating)
        let accounts_to_remove: Vec<AccountId> = self
            .participants_attestations
            .keys()
            .filter(|account_id| !participant_accounts.contains(account_id))
            .cloned()
            .collect();

        // Remove non-participant TEE information
        for account_id in &accounts_to_remove {
            self.participants_attestations.remove(account_id);
        }
    }

    /// Returns the list of accounts that currently have TEE attestations stored.
    /// Note: This may include accounts that are no longer active protocol participants.
    pub fn get_tee_accounts(&self) -> Vec<AccountId> {
        self.participants_attestations.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::attestation::{Attestation, MockAttestation};
    use near_sdk::AccountId;

    #[test]
    fn test_clean_non_participants() {
        let mut tee_state = TeeState::default();

        // Create some test participants using test utils
        let participants = crate::primitives::test_utils::gen_participants(3);
        let non_participant: AccountId = "dave.near".parse().unwrap();

        // Get participant account IDs for verification
        let participant_accounts: Vec<AccountId> = participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();

        // Add TEE information for all participants and non-participant
        let local_attestation = Attestation::Mock(MockAttestation::Valid);

        for account_id in &participant_accounts {
            tee_state.add_participant(account_id.clone(), local_attestation.clone());
        }
        tee_state.add_participant(non_participant.clone(), local_attestation.clone());

        // Verify all 4 accounts have TEE info initially
        assert_eq!(tee_state.participants_attestations.len(), 4);
        for account_id in &participant_accounts {
            assert!(tee_state.participants_attestations.contains_key(account_id));
        }
        assert!(tee_state
            .participants_attestations
            .contains_key(&non_participant));

        // Clean non-participants
        tee_state.clean_non_participants(&participants);

        // Verify only participants remain
        assert_eq!(tee_state.participants_attestations.len(), 3);
        for account_id in &participant_accounts {
            assert!(tee_state.participants_attestations.contains_key(account_id));
        }
        assert!(!tee_state
            .participants_attestations
            .contains_key(&non_participant));
    }
}
