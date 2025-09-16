use crate::{
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    storage_keys::StorageKey,
    tee::{
        proposal::{AllowedDockerImageHashes, CodeHashesVotes, MpcDockerImageHash},
        quote::TeeQuoteStatus,
    },
};
use attestation::{
    attestation::Attestation,
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{env, near, store::IterableMap, AccountId, PublicKey};
use std::collections::HashSet;

#[near(serializers=[borsh, json])]
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Clone, Hash)]
pub struct NodeUid {
    /// Operator account
    pub account_id: AccountId,
    /// TLS public key
    pub tls_public_key: PublicKey,
}

pub enum TeeValidationResult {
    /// All participants are valid
    Full,
    /// Only a subset of the participants have a valid attestation.
    Partial {
        participants_with_valid_attestation: Participants,
    },
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
    pub(crate) votes: CodeHashesVotes,
    pub(crate) participants_attestations: IterableMap<NodeUid, Attestation>,
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
        node_uid: &NodeUid,
        tee_upgrade_period_blocks: u64,
    ) -> TeeQuoteStatus {
        let allowed_mpc_docker_image_hashes = self.get_allowed_hashes(tee_upgrade_period_blocks);
        let allowed_launcher_compose_hashes = &self.allowed_launcher_compose_hashes;

        let participant_attestation = self.participants_attestations.get(node_uid);
        let Some(participant_attestation) = participant_attestation else {
            return TeeQuoteStatus::None;
        };

        let expected_report_data =
            ReportData::V1(ReportDataV1::new(node_uid.tls_public_key.clone()));
        let time_stamp_seconds = Self::current_time_seconds();

        let quote_result = participant_attestation.verify(
            expected_report_data,
            time_stamp_seconds,
            &allowed_mpc_docker_image_hashes,
            allowed_launcher_compose_hashes,
        );

        if quote_result {
            TeeQuoteStatus::Valid
        } else {
            TeeQuoteStatus::Invalid
        }
    }

    /// Performs TEE validation on the given participants.
    ///
    /// Participants with [`TeeQuoteStatus::Valid`] or [`TeeQuoteStatus::None`] are considered
    /// valid. The returned [`Participants`] preserves participant data and
    /// [`Participants::next_id()`].
    pub fn validate_tee(
        &mut self,
        participants: &Participants,
        tee_upgrade_period_blocks: u64,
    ) -> TeeValidationResult {
        let new_participants: Vec<_> = participants
            .participants()
            .iter()
            .filter(|(account_id, _, participant_info)| {
                let tls_public_key = participant_info.sign_pk.clone();

                matches!(
                    self.verify_tee_participant(
                        &NodeUid {
                            account_id: account_id.clone(),
                            tls_public_key
                        },
                        tee_upgrade_period_blocks
                    ),
                    TeeQuoteStatus::Valid | TeeQuoteStatus::None
                )
            })
            .cloned()
            .collect();

        if new_participants.len() != participants.len() {
            let participants_with_valid_attestation =
                Participants::init(participants.next_id(), new_participants);

            TeeValidationResult::Partial {
                participants_with_valid_attestation,
            }
        } else {
            TeeValidationResult::Full
        }
    }

    pub fn add_participant(&mut self, node_uid: NodeUid, proposed_tee_participant: Attestation) {
        self.participants_attestations
            .insert(node_uid, proposed_tee_participant);
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
        let participant_accounts: HashSet<NodeUid> = participants
            .participants()
            .iter()
            .map(|(account_id, _, p_info)| NodeUid {
                account_id: account_id.clone(),
                tls_public_key: p_info.sign_pk.clone(),
            })
            .collect();

        // Collect accounts to remove (can't remove while iterating)
        let nodes_to_remove: Vec<NodeUid> = self
            .participants_attestations
            .keys()
            .filter(|node_uid| !participant_accounts.contains(node_uid))
            .cloned()
            .collect();

        // Remove non-participant TEE information
        for node_uid in &nodes_to_remove {
            self.participants_attestations.remove(node_uid);
        }
    }

    /// Returns the list of accounts that currently have TEE attestations stored.
    /// Note: This may include accounts that are no longer active protocol participants.
    pub fn get_tee_accounts(&self) -> Vec<NodeUid> {
        self.participants_attestations.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::primitives::test_utils::bogus_ed25519_near_public_key;

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
        let participant_nodes: Vec<NodeUid> = participants
            .participants()
            .iter()
            .map(|(account_id, _, p_info)| NodeUid {
                account_id: account_id.clone(),
                tls_public_key: p_info.sign_pk.clone(),
            })
            .collect();

        // Add TEE information for all participants and non-participant
        let local_attestation = Attestation::Mock(MockAttestation::Valid);

        let non_participant_uid = NodeUid {
            account_id: non_participant.clone(),
            tls_public_key: bogus_ed25519_near_public_key(),
        };
        for node_id in &participant_nodes {
            tee_state.add_participant(node_id.clone(), local_attestation.clone());
        }
        tee_state.add_participant(non_participant_uid.clone(), local_attestation.clone());

        // Verify all 4 accounts have TEE info initially
        assert_eq!(tee_state.participants_attestations.len(), 4);
        for node_id in &participant_nodes {
            assert!(tee_state.participants_attestations.contains_key(node_id));
        }
        assert!(tee_state
            .participants_attestations
            .contains_key(&non_participant_uid));

        // Clean non-participants
        tee_state.clean_non_participants(&participants);

        // Verify only participants remain
        assert_eq!(tee_state.participants_attestations.len(), 3);
        for node_id in &participant_nodes {
            assert!(tee_state.participants_attestations.contains_key(node_id));
        }
        assert!(!tee_state
            .participants_attestations
            .contains_key(&non_participant_uid));
    }
}
