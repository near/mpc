use crate::{
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    storage_keys::StorageKey,
    tee::proposal::{
        AllowedDockerImageHashes, AllowedMpcDockerImage, CodeHashesVotes, MpcDockerImageHash,
    },
    TryIntoInterfaceType,
};
use attestation::{
    attestation::{Attestation, MockAttestation},
    report_data::{ReportData, ReportDataV1},
};
use borsh::{BorshDeserialize, BorshSerialize};
use contract_interface::types::Ed25519PublicKey;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_sdk::{env, near, store::IterableMap, AccountId};
use std::hash::{Hash, Hasher};
use std::{collections::HashSet, time::Duration};

#[near(serializers=[borsh, json])]
#[derive(Debug, Ord, PartialOrd, Clone)]
pub struct NodeId {
    /// Operator account
    pub account_id: AccountId,
    /// TLS public key, MUST BE of type Ed25519
    pub tls_public_key: near_sdk::PublicKey,
    pub account_public_key: Option<near_sdk::PublicKey>,
}

// Implement Eq + Hash ignoring account_public_key
impl PartialEq for NodeId {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id && self.tls_public_key == other.tls_public_key
    }
}

impl Eq for NodeId {}

impl Hash for NodeId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.account_id.hash(state);
        self.tls_public_key.hash(state);
        // intentionally ignoring account_public_key
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeQuoteStatus {
    /// TEE quote and Docker image verification both passed successfully.
    /// The participant is considered to have a valid, verified TEE status.
    Valid,

    /// TEE verification failed - either the quote verification failed,
    /// the Docker image verification failed, or both validations failed.
    /// The participant should not be trusted for TEE-dependent operations.
    Invalid(String),
}
#[derive(Debug)]
pub enum TeeValidationResult {
    /// All participants are valid
    Full,
    /// Only a subset of the participants have a valid attestation.
    Partial {
        participants_with_valid_attestation: Participants,
    },
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
    pub(crate) votes: CodeHashesVotes,
    pub participants_attestations: IterableMap<near_sdk::PublicKey, (NodeId, Attestation)>,
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
    /// Creates a [`TeeState`] with an initial set of participants that will receive a valid mocked attestation.
    pub(crate) fn with_mocked_participant_attestations(participants: &Participants) -> Self {
        let mut participants_attestations = IterableMap::new(StorageKey::TeeParticipantAttestation);

        participants
            .participants()
            .iter()
            .for_each(|(account_id, _, participant_info)| {
                let node_id = NodeId {
                    account_id: account_id.clone(),
                    tls_public_key: participant_info.sign_pk.clone(),
                    account_public_key: None,
                };

                participants_attestations.insert(
                    participant_info.sign_pk.clone(),
                    (node_id, Attestation::Mock(MockAttestation::Valid)),
                );
            });

        Self {
            participants_attestations,
            ..Default::default()
        }
    }
    fn current_time_seconds() -> u64 {
        let current_time_milliseconds = env::block_timestamp_ms();
        current_time_milliseconds / 1_000
    }

    pub(crate) fn verify_proposed_participant_attestation(
        &mut self,
        attestation: &Attestation,
        tls_public_key: Ed25519PublicKey,
        account_public_key: Ed25519PublicKey,
        tee_upgrade_deadline_duration: Duration,
    ) -> TeeQuoteStatus {
        let expected_report_data = ReportData::V1(ReportDataV1::new(
            *tls_public_key.as_bytes(),
            *account_public_key.as_bytes(),
        ));

        match attestation.verify(
            expected_report_data,
            Self::current_time_seconds(),
            &self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration),
            &self.allowed_launcher_compose_hashes,
        ) {
            Ok(()) => TeeQuoteStatus::Valid,
            Err(err) => TeeQuoteStatus::Invalid(err.to_string()),
        }
    }

    /// Verifies the TEE quote and Docker image
    pub(crate) fn verify_tee_participant(
        &mut self,
        node_id: &NodeId,
        tee_upgrade_deadline_duration: Duration,
    ) -> TeeQuoteStatus {
        let allowed_mpc_docker_image_hashes =
            self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration);
        let allowed_launcher_compose_hashes = &self.allowed_launcher_compose_hashes;

        let participant_attestation = self.participants_attestations.get(&node_id.tls_public_key);
        let Some(participant_attestation) = participant_attestation else {
            return TeeQuoteStatus::Invalid("participant has no attestation".to_string());
        };

        // Convert TLS public key
        let tls_public_key = match node_id.tls_public_key.clone().try_into_dto_type() {
            Ok(value) => value,
            Err(err) => {
                return TeeQuoteStatus::Invalid(format!(
                    "could not convert TLS pub key to DTO type: {err}"
                ))
            }
        };

        // Convert account public key if available
        //
        // WARNING:
        // Some legacy/mock nodes may not have an account_public_key set yet.
        // In that case, we allow `None` temporarily to avoid breaking existing tests or flows.
        //
        // TODO(#823): Remove this fallback once all MPC nodes are required
        //             to run inside a TEE and provide a valid account_public_key.
        let account_public_key = match node_id.account_public_key.clone() {
            Some(pk) => pk.try_into_dto_type().ok(),
            None => None,
        };

        let account_key_bytes = match account_public_key {
            Some(ref pk) => *pk.as_bytes(),
            None => [0u8; 32], // TODO(#823): remove this fallback once all nodes must have account_public_key
        };

        let expected_report_data = ReportData::new(*tls_public_key.as_bytes(), account_key_bytes);

        // Verify the attestation quote
        let time_stamp_seconds = Self::current_time_seconds();
        match participant_attestation.1.verify(
            expected_report_data,
            time_stamp_seconds,
            &allowed_mpc_docker_image_hashes,
            allowed_launcher_compose_hashes,
        ) {
            Ok(()) => TeeQuoteStatus::Valid,
            Err(err) => TeeQuoteStatus::Invalid(err.to_string()),
        }
    }

    pub fn validate_tee(
        &mut self,
        participants: &Participants,
        tee_upgrade_deadline_duration: Duration,
    ) -> TeeValidationResult {
        self.allowed_docker_image_hashes
            .cleanup_expired_hashes(tee_upgrade_deadline_duration);

        let participants_with_valid_attestation: Vec<_> = participants
            .participants()
            .iter()
            .filter(|(account_id, _, participant_info)| {
                let tls_public_key = participant_info.sign_pk.clone();

                // Try to find an existing NodeId with account_public_key filled
                let maybe_node = self.find_node_id_by_tls_key(&tls_public_key);

                let node_id = NodeId {
                    account_id: account_id.clone(),
                    tls_public_key: tls_public_key.clone(),

                    // In transition (mock attestation) mode — try to reuse known key, else None.
                    // TODO(#823): remove this fallback once all MPC nodes have a valid TEE key.
                    account_public_key: maybe_node.and_then(|n| n.account_public_key.clone()),
                };

                let tee_status =
                    self.verify_tee_participant(&node_id, tee_upgrade_deadline_duration);

                matches!(tee_status, TeeQuoteStatus::Valid)
            })
            .cloned()
            .collect();

        if participants_with_valid_attestation.len() != participants.len() {
            let participants_with_valid_attestation =
                Participants::init(participants.next_id(), participants_with_valid_attestation);

            TeeValidationResult::Partial {
                participants_with_valid_attestation,
            }
        } else {
            TeeValidationResult::Full
        }
    }

    /// Adds a participant attestation for the given node.
    ///
    /// Returns:
    /// - `true` if this is the first attestation for the node (i.e., a new participant was added).
    /// - `false` if the node already had an attestation (the existing one was replaced).
    pub fn add_participant(&mut self, node_id: NodeId, attestation: Attestation) -> bool {
        let tls_pk = node_id.tls_public_key.clone();

        let is_new = !self.participants_attestations.contains_key(&tls_pk);

        // Must pass owned values, not references
        self.participants_attestations
            .insert(tls_pk, (node_id, attestation));

        is_new
    }

    pub fn vote(
        &mut self,
        code_hash: MpcDockerImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.votes.vote(code_hash.clone(), participant)
    }

    pub fn get_allowed_mpc_docker_image_hashes(
        &self,
        tee_upgrade_deadline_duration: Duration,
    ) -> Vec<MpcDockerImageHash> {
        self.get_allowed_mpc_docker_images(tee_upgrade_deadline_duration)
            .into_iter()
            .map(|entry| entry.image_hash)
            .collect()
    }

    pub fn get_allowed_mpc_docker_images(
        &self,
        tee_upgrade_deadline_duration: Duration,
    ) -> Vec<AllowedMpcDockerImage> {
        self.allowed_docker_image_hashes
            .get(tee_upgrade_deadline_duration)
    }

    pub fn whitelist_tee_proposal(
        &mut self,
        tee_proposal: MpcDockerImageHash,
        tee_upgrade_deadline_duration: Duration,
    ) {
        self.votes.clear_votes();
        self.allowed_launcher_compose_hashes.push(
            AllowedDockerImageHashes::get_docker_compose_hash(tee_proposal.clone()),
        );
        self.allowed_docker_image_hashes
            .insert(tee_proposal, tee_upgrade_deadline_duration);
    }

    /// Removes TEE information for nodes that are not in the provided participants list.
    /// Used to clean up storage after a resharing concludes.
    pub fn clean_non_participants(&mut self, participants: &Participants) {
        // Collect all allowed TLS public keys from current participants
        let active_tls_keys: HashSet<&near_sdk::PublicKey> = participants
            .participants()
            .iter()
            .map(|(_, _, p_info)| &p_info.sign_pk)
            .collect();

        // Collect TLS keys that are *not* in the active participants list
        let stale_keys: Vec<near_sdk::PublicKey> = self
            .participants_attestations
            .keys()
            .filter(|tls_pk| !active_tls_keys.contains(*tls_pk))
            .cloned()
            .collect();

        // Remove all stale TEE entries
        for tls_pk in stale_keys {
            self.participants_attestations.remove(&tls_pk);
        }
    }

    /// Returns the list of accounts that currently have TEE attestations stored.
    /// Note: This may include accounts that are no longer active protocol participants.
    pub fn get_tee_accounts(&self) -> Vec<NodeId> {
        self.participants_attestations
            .values()
            .map(|(node_id, _)| node_id.clone())
            .collect()
    }

    /// Find a NodeId by its TLS public key.
    pub fn find_node_id_by_tls_key(&self, tls_public_key: &near_sdk::PublicKey) -> Option<NodeId> {
        self.participants_attestations
            .get(tls_public_key)
            .map(|(node_id, _)| node_id.clone())
    }
    /// Returns true if the caller has at least one participant entry
    /// whose TLS key matches an attested node belonging to the caller account.
    ///
    /// Handles multiple participants per account and supports legacy mock nodes.
    pub fn is_caller_an_attested_participant(&self, participants: &Participants) -> bool {
        let signer_pk = env::signer_account_pk();
        let signer_id = env::signer_account_id();

        match participants.info(&signer_id) {
            None => false,
            Some(info) => {
                match self.participants_attestations.get(&info.sign_pk) {
                    None => false,
                    Some((node_id, _attestation)) => {
                        node_id.account_id == signer_id
                            && node_id
                                .account_public_key
                                .as_ref()
                                .map(|pk| pk == &signer_pk)
                                .unwrap_or(true) // TODO (#823) Legacy fallback for mock nodes
                    }
                }
            }
        }
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
        let participant_nodes: Vec<NodeId> = participants
            .participants()
            .iter()
            .map(|(account_id, _, p_info)| NodeId {
                account_id: account_id.clone(),
                tls_public_key: p_info.sign_pk.clone(),
                account_public_key: Some(bogus_ed25519_near_public_key()),
            })
            .collect();

        // Add TEE information for all participants and non-participant
        let local_attestation = Attestation::Mock(MockAttestation::Valid);

        let non_participant_uid = NodeId {
            account_id: non_participant.clone(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
            tls_public_key: bogus_ed25519_near_public_key(),
        };

        for node_id in &participant_nodes {
            tee_state.add_participant(node_id.clone(), local_attestation.clone());
        }
        tee_state.add_participant(non_participant_uid.clone(), local_attestation.clone());

        // Verify all 4 accounts have TEE info initially
        assert_eq!(tee_state.participants_attestations.len(), 4);
        for node_id in &participant_nodes {
            assert!(tee_state
                .participants_attestations
                .contains_key(&node_id.tls_public_key));
        }
        assert!(tee_state
            .participants_attestations
            .contains_key(&non_participant_uid.tls_public_key));

        // Clean non-participants
        tee_state.clean_non_participants(&participants);

        // Verify only participants remain
        assert_eq!(tee_state.participants_attestations.len(), 3);
        for node_id in &participant_nodes {
            assert!(tee_state
                .participants_attestations
                .contains_key(&node_id.tls_public_key));
        }
        assert!(!tee_state
            .participants_attestations
            .contains_key(&non_participant_uid.tls_public_key));
    }
}
