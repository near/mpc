use crate::{
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    tee::proposal::{
        AllowedDockerImageHashes, AllowedMpcDockerImage, CodeHashesVotes, MpcDockerImageHash,
    },
    TryIntoInterfaceType,
};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::{
    attestation::{self, Attestation, VerifiedAttestation},
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_account_id::AccountId;
use near_sdk::{env, near};
use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};
use std::{collections::HashSet, time::Duration};
use utilities::AccountIdExtV1;

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

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum AttestationSubmissionError {
    #[error("the submitted attestation failed verification, reason: {:?}", .0)]
    InvalidAttestation(#[from] attestation::VerificationError),
    #[error("the submitted attestation's TLS key is not a valid ED25519 key")]
    InvalidTlsKey,
}

#[derive(Debug)]
pub(crate) enum ParticipantInsertion {
    NewlyInsertedParticipant,
    UpdatedExistingParticipant,
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
pub(crate) struct NodeAttestation {
    pub(crate) node_id: NodeId,
    pub(crate) verified_attestation: VerifiedAttestation,
}

#[derive(Default, Debug, BorshSerialize, BorshDeserialize)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) allowed_launcher_compose_hashes: Vec<LauncherDockerComposeHash>,
    pub(crate) votes: CodeHashesVotes,
    /// Mapping of TLS public key of a participant to its [`NodeAttestation`].
    /// Attestations are stored for any valid participant that has submitted one, not
    /// just for the currently active participants.
    pub(crate) stored_attestations: BTreeMap<near_sdk::PublicKey, NodeAttestation>,
}

impl TeeState {
    /// Creates a [`TeeState`] with an initial set of participants that will receive a valid mocked attestation.
    pub(crate) fn with_mocked_participant_attestations(participants: &Participants) -> Self {
        let mut participants_attestations = BTreeMap::new();

        participants
            .participants()
            .for_each(|(account_id, _, participant_info)| {
                let node_id = NodeId {
                    account_id: account_id.clone(),
                    tls_public_key: participant_info.sign_pk.clone(),
                    account_public_key: None,
                };

                participants_attestations.insert(
                    participant_info.sign_pk.clone(),
                    NodeAttestation {
                        node_id,
                        verified_attestation: VerifiedAttestation::Mock(
                            attestation::MockAttestation::Valid,
                        ),
                    },
                );
            });

        Self {
            stored_attestations: participants_attestations,
            ..Default::default()
        }
    }

    fn current_time_seconds() -> u64 {
        let current_time_milliseconds = env::block_timestamp_ms();
        current_time_milliseconds / 1_000
    }

    /// Adds a participant attestation for the given node iff the attestation succeeds verification.
    pub(crate) fn add_participant(
        &mut self,
        node_id: NodeId,
        attestation: Attestation,
        tee_upgrade_deadline_duration: Duration,
    ) -> Result<ParticipantInsertion, AttestationSubmissionError> {
        // Convert TLS public key
        let tls_public_key = node_id
            .tls_public_key
            .clone()
            .try_into_dto_type()
            .map_err(|_| AttestationSubmissionError::InvalidTlsKey)?;

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

        let expected_report_data: ReportData =
            ReportDataV1::new(*tls_public_key.as_bytes(), account_key_bytes).into();

        let verified_attestation = attestation.verify(
            expected_report_data.into(),
            Self::current_time_seconds(),
            &self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration),
            &self.allowed_launcher_compose_hashes,
        )?;

        let tls_pk = node_id.tls_public_key.clone();

        let insertion = self.stored_attestations.insert(
            tls_pk,
            NodeAttestation {
                node_id,
                verified_attestation,
            },
        );

        Ok(match insertion {
            Some(_previous_attestation) => ParticipantInsertion::UpdatedExistingParticipant,
            None => ParticipantInsertion::NewlyInsertedParticipant,
        })
    }

    /// reverifies stored participant attestations.
    pub(crate) fn reverify_participants(
        &self,
        node_id: &NodeId,
        tee_upgrade_deadline_duration: Duration,
    ) -> TeeQuoteStatus {
        let allowed_mpc_docker_image_hashes =
            self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration);
        let allowed_launcher_compose_hashes = &self.allowed_launcher_compose_hashes;

        let participant_attestation = self.stored_attestations.get(&node_id.tls_public_key);
        let Some(participant_attestation) = participant_attestation else {
            return TeeQuoteStatus::Invalid("participant has no attestation".to_string());
        };

        // Verify the attestation quote
        let time_stamp_seconds = Self::current_time_seconds();
        match participant_attestation.verified_attestation.re_verify(
            time_stamp_seconds,
            &allowed_mpc_docker_image_hashes,
            allowed_launcher_compose_hashes,
        ) {
            Ok(()) => TeeQuoteStatus::Valid,
            Err(err) => TeeQuoteStatus::Invalid(err.to_string()),
        }
    }

    /// reverifies stored participant attestations and removes any participant attestation
    /// from the internal state that fails reverifications. Reverification can fail, for example,
    /// the MPC image hash the attestation was tied to is no longer allowed, or due to certificate
    /// expiries.
    pub fn reverify_and_cleanup_participants(
        &mut self,
        participants: &Participants,
        tee_upgrade_deadline_duration: Duration,
    ) -> TeeValidationResult {
        self.allowed_docker_image_hashes
            .cleanup_expired_hashes(tee_upgrade_deadline_duration);

        let participants_with_valid_attestation: Vec<_> = participants
            .participants()
            .filter(|(account_id, _, participant_info)| {
                let tls_public_key = participant_info.sign_pk.clone();

                // Try to find an existing NodeId with account_public_key filled
                let maybe_node = self.find_node_id_by_tls_key(&tls_public_key);

                let node_id = NodeId {
                    account_id: (*account_id).clone(),
                    tls_public_key: tls_public_key.clone(),

                    // In transition (mock attestation) mode — try to reuse known key, else None.
                    // TODO(#823): remove this fallback once all MPC nodes have a valid TEE key.
                    account_public_key: maybe_node.and_then(|n| n.account_public_key.clone()),
                };

                let tee_status =
                    self.reverify_participants(&node_id, tee_upgrade_deadline_duration);

                matches!(tee_status, TeeQuoteStatus::Valid)
            })
            .map(|(a, p, i)| (a.clone(), *p, i.clone()))
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
            .map(|(_, _, p_info)| &p_info.sign_pk)
            .collect();

        // Collect TLS keys that are *not* in the active participants list
        let stale_keys: Vec<near_sdk::PublicKey> = self
            .stored_attestations
            .keys()
            .filter(|tls_pk| !active_tls_keys.contains(*tls_pk))
            .cloned()
            .collect();

        // Remove all stale TEE entries
        for tls_pk in stale_keys {
            self.stored_attestations.remove(&tls_pk);
        }
    }

    /// Returns the list of accounts that currently have TEE attestations stored.
    /// Note: This may include accounts that are no longer active protocol participants.
    pub fn get_tee_accounts(&self) -> Vec<NodeId> {
        self.stored_attestations
            .values()
            .map(|node_attestation| node_attestation.node_id.clone())
            .collect()
    }

    /// Find a NodeId by its TLS public key.
    pub fn find_node_id_by_tls_key(&self, tls_public_key: &near_sdk::PublicKey) -> Option<NodeId> {
        self.stored_attestations
            .get(tls_public_key)
            .map(|node_attestation| node_attestation.node_id.clone())
    }

    /// Returns Ok(()) if the caller has at least one participant entry
    /// whose TLS key matches an attested node belonging to the caller account.
    ///
    /// Handles multiple participants per account and supports legacy mock nodes.
    pub(crate) fn is_caller_an_attested_participant(
        &self,
        participants: &Participants,
    ) -> Result<(), AttestationCheckError> {
        let signer_pk = env::signer_account_pk();
        let signer_id = env::signer_account_id().as_v2_account_id();

        let info = participants
            .info(&signer_id)
            .ok_or(AttestationCheckError::CallerNotParticipant)?;

        let attestation = self
            .stored_attestations
            .get(&info.sign_pk)
            .ok_or(AttestationCheckError::AttestationNotFound)?;

        if attestation.node_id.account_id != signer_id {
            return Err(AttestationCheckError::AttestationOwnerMismatch);
        }

        if let Some(node_pk) = &attestation.node_id.account_public_key {
            if node_pk != &signer_pk {
                return Err(AttestationCheckError::AttestationKeyMismatch);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum AttestationCheckError {
    CallerNotParticipant,
    AttestationNotFound,
    AttestationOwnerMismatch,
    AttestationKeyMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::bogus_ed25519_near_public_key;
    use crate::primitives::test_utils::gen_participants;
    use crate::tee::test_utils::set_block_timestamp;
    use assert_matches::assert_matches;
    use mpc_attestation::attestation::{Attestation, MockAttestation};
    use near_account_id::AccountId;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::time::Duration;
    use utilities::AccountIdExtV2;

    /// Helper to set up the testing environment with a specific signer
    fn set_signer(account_id: &AccountId, public_key: &near_sdk::PublicKey) {
        let mut builder = VMContextBuilder::new();
        builder
            .signer_account_id(account_id.as_v1_account_id())
            .signer_account_pk(public_key.clone());
        testing_env!(builder.build());
    }

    #[test]
    fn test_clean_non_participants() {
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10000);

        let mut tee_state = TeeState::default();

        // Create some test participants using test utils
        let participants = crate::primitives::test_utils::gen_participants(3);
        let non_participant: AccountId = "dave.near".parse().unwrap();

        // Get participant account IDs for verification
        let participant_nodes: Vec<NodeId> = participants
            .participants()
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
            let insertion_result = tee_state.add_participant(
                node_id.clone(),
                local_attestation.clone(),
                TEE_UPGRADE_DURATION,
            );

            assert_matches!(
                insertion_result,
                Ok(ParticipantInsertion::NewlyInsertedParticipant)
            );
        }
        let insertion_result = tee_state.add_participant(
            non_participant_uid.clone(),
            local_attestation.clone(),
            TEE_UPGRADE_DURATION,
        );
        assert_matches!(
            insertion_result,
            Ok(ParticipantInsertion::NewlyInsertedParticipant)
        );

        // Verify all 4 accounts have TEE info initially
        assert_eq!(tee_state.stored_attestations.len(), 4);
        for node_id in &participant_nodes {
            assert!(tee_state
                .stored_attestations
                .contains_key(&node_id.tls_public_key));
        }
        assert!(tee_state
            .stored_attestations
            .contains_key(&non_participant_uid.tls_public_key));

        // Clean non-participants
        tee_state.clean_non_participants(&participants);

        // Verify only participants remain
        assert_eq!(tee_state.stored_attestations.len(), 3);
        for node_id in &participant_nodes {
            assert!(tee_state
                .stored_attestations
                .contains_key(&node_id.tls_public_key));
        }
        assert!(!tee_state
            .stored_attestations
            .contains_key(&non_participant_uid.tls_public_key));
    }

    #[test]
    fn updating_existing_participant_returns_existing_participant() {
        // given
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10000);
        let mut tee_state = TeeState::default();

        let participant: AccountId = "dave.near".parse().unwrap();
        let local_attestation = Attestation::Mock(MockAttestation::Valid);

        let participant_id = NodeId {
            account_id: participant.clone(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
            tls_public_key: bogus_ed25519_near_public_key(),
        };

        let insertion_result = tee_state.add_participant(
            participant_id.clone(),
            local_attestation.clone(),
            TEE_UPGRADE_DURATION,
        );
        assert_matches!(
            insertion_result,
            Ok(ParticipantInsertion::NewlyInsertedParticipant)
        );

        // when
        let re_insertion_result = tee_state.add_participant(
            participant_id.clone(),
            local_attestation.clone(),
            TEE_UPGRADE_DURATION,
        );

        // then
        assert_matches!(
            re_insertion_result,
            Ok(ParticipantInsertion::UpdatedExistingParticipant)
        );
    }

    #[test]
    fn add_participant_increases_storage_size() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };
        let attestation = Attestation::Mock(MockAttestation::Valid);

        // when
        tee_state
            .add_participant(node_id, attestation, Duration::from_secs(0))
            .unwrap();

        // then
        assert_eq!(
            tee_state.stored_attestations.len(),
            1,
            "Internal storage count should increase by exactly one"
        );
    }

    #[test]
    fn add_participant_indexes_by_tls_key() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };
        let attestation = Attestation::Mock(MockAttestation::Valid);

        // when
        tee_state
            .add_participant(node_id.clone(), attestation, Duration::from_secs(0))
            .unwrap();

        // then
        assert!(
            tee_state
                .stored_attestations
                .contains_key(&node_id.tls_public_key),
            "Entry should be strictly retrievable using the TLS public key"
        );
    }

    #[test]
    fn add_participant_preserves_node_id_integrity() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };
        let attestation = Attestation::Mock(MockAttestation::Valid);

        // when
        tee_state
            .add_participant(node_id.clone(), attestation, Duration::from_secs(0))
            .unwrap();

        // then
        let stored_entry = tee_state
            .stored_attestations
            .get(&node_id.tls_public_key)
            .unwrap();

        assert_eq!(
            stored_entry.node_id, node_id,
            "The stored NodeId struct must exactly match the inserted one"
        );
    }

    #[test]
    fn internal_storage_distinguishes_participants_by_tls_key() {
        // given
        let mut tee_state = TeeState::default();

        let node_1 = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };

        let node_2 = NodeId {
            account_id: "bob.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };

        // when
        tee_state
            .add_participant(
                node_1.clone(),
                Attestation::Mock(MockAttestation::Valid),
                Duration::from_secs(0),
            )
            .unwrap();
        tee_state
            .add_participant(
                node_2.clone(),
                Attestation::Mock(MockAttestation::Valid),
                Duration::from_secs(0),
            )
            .unwrap();

        // then
        assert_eq!(tee_state.stored_attestations.len(), 2);
        assert!(tee_state
            .stored_attestations
            .contains_key(&node_1.tls_public_key));
        assert!(tee_state
            .stored_attestations
            .contains_key(&node_2.tls_public_key));
    }

    #[test]
    fn re_verify_validates_fresh_attestation() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "fresh.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };

        const NOW_SECONDS: u64 = 1000;

        testing_env!(VMContextBuilder::new().block_timestamp(NOW_SECONDS).build());

        let attestation = Attestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(NOW_SECONDS),
        });

        tee_state
            .add_participant(node_id.clone(), attestation, Duration::from_secs(0))
            .unwrap();

        // when
        let status = tee_state.reverify_participants(&node_id, Duration::from_secs(0));

        // then
        assert_eq!(status, TeeQuoteStatus::Valid);
    }

    #[test]
    fn test_re_verify_rejects_expired_attestation() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "about_to_be_expired.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };

        const EXPIRY_TIMESTAMP_SECONDS: u64 = 1000;
        const ELAPSED_SECONDS: u64 = 200;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let attestation = Attestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(EXPIRY_TIMESTAMP_SECONDS),
        });

        tee_state
            .add_participant(node_id.clone(), attestation, Duration::from_secs(0))
            .unwrap();

        // when
        testing_env!(VMContextBuilder::new()
            .block_timestamp(
                Duration::from_secs(EXPIRY_TIMESTAMP_SECONDS + ELAPSED_SECONDS).as_nanos() as u64
            )
            .build());

        let status = tee_state.reverify_participants(&node_id, Duration::from_secs(0));

        // then
        assert_matches!(status, TeeQuoteStatus::Invalid(_));
    }

    #[test]
    fn re_verify_succeeds_within_expiry_time() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "valid_check.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };

        const EXPIRY_TIMESTAMP_SECONDS: u64 = 1000;

        testing_env!(VMContextBuilder::new()
            .block_timestamp(Duration::from_secs(0).as_nanos() as u64)
            .build());

        let attestation = Attestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(EXPIRY_TIMESTAMP_SECONDS),
        });

        tee_state
            .add_participant(node_id.clone(), attestation, Duration::from_secs(0))
            .unwrap();

        // when
        testing_env!(VMContextBuilder::new()
            .block_timestamp(Duration::from_secs(EXPIRY_TIMESTAMP_SECONDS - 1).as_nanos() as u64)
            .build());

        let status = tee_state.reverify_participants(&node_id, Duration::from_secs(0));

        // then
        assert_eq!(status, TeeQuoteStatus::Valid);
    }

    #[test]
    fn test_re_verify_returns_invalid_for_missing_node() {
        // given
        let tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "ghost.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_near_public_key(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        };

        // when
        let status = tee_state.reverify_participants(&node_id, Duration::from_secs(0));

        // then
        assert_matches!(status, TeeQuoteStatus::Invalid(msg) if msg.contains("participant has no attestation"));
    }

    #[test]
    fn test_is_caller_attested_success() {
        let mut tee_state = TeeState::default();
        let tee_upgrade_duration = Duration::MAX;
        // Generate 1 participant
        let participants = gen_participants(1);
        let (account_id, _, participant_info) = participants.participants().next().unwrap();

        // 1. Define the Signer's NEAR Public Key (Wallet Key)
        let signer_pk = bogus_ed25519_near_public_key();

        // 2. Set the environment so the caller is the participant
        set_signer(account_id, &signer_pk);

        // 3. Register the attestation in TeeState
        // The TLS key comes from participant_info, the Account Key must match the signer_pk
        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key: participant_info.sign_pk.clone(),
            account_public_key: Some(signer_pk),
        };
        tee_state
            .add_participant(
                node_id,
                Attestation::Mock(MockAttestation::Valid),
                tee_upgrade_duration,
            )
            .expect("Attestation is valid on insertion");

        // 4. Verify check passes
        let result = tee_state.is_caller_an_attested_participant(&participants);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_caller_attested_success_legacy_no_account_key() {
        // Tests the case where account_public_key is None (legacy/mock nodes)
        let tee_upgrade_duration = Duration::MAX;
        let mut tee_state = TeeState::default();
        let participants = gen_participants(1);
        let (account_id, _, participant_info) = participants.participants().next().unwrap();

        let signer_pk = bogus_ed25519_near_public_key();
        set_signer(account_id, &signer_pk);

        // Register attestation with None for account_public_key
        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key: participant_info.sign_pk.clone(),
            account_public_key: None,
        };
        tee_state
            .add_participant(
                node_id,
                Attestation::Mock(MockAttestation::Valid),
                tee_upgrade_duration,
            )
            .expect("Attestation is valid on insertion");

        let result = tee_state.is_caller_an_attested_participant(&participants);
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn test_err_caller_not_participant() {
        let tee_state = TeeState::default();
        let participants = gen_participants(1);

        // Caller is NOT in the participants list
        let random_account: AccountId = "random_guy.near".parse().unwrap();
        let random_pk = bogus_ed25519_near_public_key();
        set_signer(&random_account, &random_pk);

        let result = tee_state.is_caller_an_attested_participant(&participants);

        assert_matches!(result, Err(AttestationCheckError::CallerNotParticipant));
    }

    #[test]
    fn test_err_attestation_not_found() {
        let tee_state = TeeState::default();
        let participants = gen_participants(1);
        let (account_id, _, _) = participants.participants().next().unwrap();

        let signer_pk = bogus_ed25519_near_public_key();
        set_signer(account_id, &signer_pk);

        // We do NOT add the participant to tee_state.stored_attestations

        let result = tee_state.is_caller_an_attested_participant(&participants);

        assert_matches!(result, Err(AttestationCheckError::AttestationNotFound));
    }

    #[test]
    fn test_err_attestation_owner_mismatch() {
        let mut tee_state = TeeState::default();
        let participants = gen_participants(1);
        let (account_id, _, participant_info) = participants.participants().next().unwrap();
        let tee_upgrade_duration = Duration::MAX;

        let signer_pk = bogus_ed25519_near_public_key();
        set_signer(account_id, &signer_pk);

        // Create a data integrity issue:
        // The TLS key in `participants` points to an entry in `tee_state`...
        // ...but that entry claims it belongs to a different AccountId.
        let other_account: AccountId = "imposter.near".parse().unwrap();

        let node_id = NodeId {
            account_id: other_account, // Mismatch here
            tls_public_key: participant_info.sign_pk.clone(),
            account_public_key: Some(signer_pk),
        };
        tee_state
            .add_participant(
                node_id,
                Attestation::Mock(MockAttestation::Valid),
                tee_upgrade_duration,
            )
            .expect("Attestation is valid on insertion");

        let result = tee_state.is_caller_an_attested_participant(&participants);

        assert_matches!(result, Err(AttestationCheckError::AttestationOwnerMismatch));
    }

    #[test]
    fn test_err_attestation_key_mismatch() {
        // given
        let mut tee_state = TeeState::default();
        let participants = gen_participants(1);
        let (account_id, _, participant_info) = participants.participants().next().unwrap();
        let tee_upgrade_duration = Duration::MAX;

        let signer_pk = bogus_ed25519_near_public_key();
        set_signer(account_id, &signer_pk);

        // Generate a different key for the stored attestation
        // (e.g., The user rotated their wallet key, but hasn't updated the TEE registry)
        let old_signer_pk: near_sdk::PublicKey =
            "ed25519:3t4M1gXg2Qd5g6X8z1g2X3t4M1gXg2Qd5g6X8z1g2X3t"
                .parse()
                .unwrap();

        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key: participant_info.sign_pk.clone(),
            account_public_key: Some(old_signer_pk), // Mismatch here
        };
        tee_state
            .add_participant(
                node_id,
                Attestation::Mock(MockAttestation::Valid),
                tee_upgrade_duration,
            )
            .expect("Attestation is valid on insertion");

        // when
        let result = tee_state.is_caller_an_attested_participant(&participants);

        // then
        assert_matches!(result, Err(AttestationCheckError::AttestationKeyMismatch));
    }

    // validate_tee() unit tests

    /// Grace period for TEE upgrade deadline used in validate_tee() tests
    const TEST_GRACE_PERIOD: Duration = Duration::from_secs(10);

    /// Helper to create a NodeId from participant data
    fn create_node_id(account_id: &AccountId, sign_pk: &near_sdk::PublicKey) -> NodeId {
        NodeId {
            account_id: account_id.clone(),
            tls_public_key: sign_pk.clone(),
            account_public_key: Some(bogus_ed25519_near_public_key()),
        }
    }

    /// Helper to extract account IDs from participants for assertion comparisons
    fn account_ids(participants: &Participants) -> Vec<AccountId> {
        participants
            .participants()
            .map(|(acc, _, _)| acc.clone())
            .collect()
    }

    #[test]
    fn validate_tee_returns_full_when_all_participants_have_valid_attestations() {
        let mut tee_state = TeeState::default();
        let participants = gen_participants(3);
        let tee_upgrade_duration = Duration::MAX;

        // Add valid attestations for all participants
        for (account_id, _, participant_info) in participants.participants() {
            let node_id = create_node_id(account_id, &participant_info.sign_pk);
            tee_state
                .add_participant(
                    node_id,
                    Attestation::Mock(MockAttestation::Valid),
                    tee_upgrade_duration,
                )
                .expect("mock attestation is valid");
        }

        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        assert_matches!(validation_result, TeeValidationResult::Full);
    }

    #[test]
    fn validate_tee_returns_partial_when_participant_has_no_attestation() {
        let mut tee_state = TeeState::default();
        let participants = gen_participants(3);
        let participant_list = participants.participants_vec();
        let tee_upgrade_duration = Duration::MAX;

        // Add valid attestations for only first 2 participants
        for (account_id, _, participant_info) in participant_list.iter().take(2) {
            let node_id = create_node_id(account_id, &participant_info.sign_pk);
            tee_state
                .add_participant(
                    node_id,
                    Attestation::Mock(MockAttestation::Valid),
                    tee_upgrade_duration,
                )
                .expect("mock attestation is valid");
        }
        // Third participant has no attestation

        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        let expected_valid_account_ids = account_ids(&participants)[..2].to_vec();
        assert_matches!(
            validation_result,
            TeeValidationResult::Partial { participants_with_valid_attestation }
                if account_ids(&participants_with_valid_attestation) == expected_valid_account_ids
        );
    }

    #[test]
    fn validate_tee_returns_partial_when_attestation_is_expired() {
        let current_time_secs = env::block_timestamp() / 1_000_000_000;
        let expiry_time_secs = current_time_secs + TEST_GRACE_PERIOD.as_secs();
        let tee_upgrade_duration = Duration::MAX;

        let mut tee_state = TeeState::default();
        let participants = gen_participants(3);
        let participant_list = participants.participants_vec();

        // Add valid attestations for first 2 participants
        for (account_id, _, participant_info) in participant_list.iter().take(2) {
            let node_id = create_node_id(account_id, &participant_info.sign_pk);
            tee_state
                .add_participant(
                    node_id,
                    Attestation::Mock(MockAttestation::Valid),
                    tee_upgrade_duration,
                )
                .expect("mock attestation is valid");
        }

        // Add expiring attestation for third participant
        let (account_id, _, participant_info) = &participant_list[2];
        let node_id = create_node_id(account_id, &participant_info.sign_pk);
        let expiring_attestation = Attestation::Mock(MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(expiry_time_secs),
        });
        tee_state
            .add_participant(node_id, expiring_attestation, tee_upgrade_duration)
            .expect("mock attestation is valid");

        // Advance time to exact expiry boundary
        set_block_timestamp(expiry_time_secs * 1_000_000_000);

        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        let expected_valid_account_ids = account_ids(&participants)[..2].to_vec();
        assert_matches!(
            validation_result,
            TeeValidationResult::Partial { participants_with_valid_attestation }
                if account_ids(&participants_with_valid_attestation) == expected_valid_account_ids
        );
    }

    #[test]
    fn validate_tee_returns_full_when_attestation_not_yet_expired() {
        let current_time_secs = env::block_timestamp() / 1_000_000_000;
        let expiry_time_secs = current_time_secs + 2 * TEST_GRACE_PERIOD.as_secs();
        let before_expiry_time_secs = current_time_secs + TEST_GRACE_PERIOD.as_secs();
        let tee_upgrade_duration = Duration::MAX;

        let mut tee_state = TeeState::default();
        let participants = gen_participants(3);

        // Add attestations for all participants, third one with future expiry
        let participant_list = participants.participants_vec();

        for (i, (account_id, _, participant_info)) in participant_list.iter().enumerate() {
            let node_id = create_node_id(account_id, &participant_info.sign_pk);
            let attestation = if i == 2 {
                Attestation::Mock(MockAttestation::WithConstraints {
                    mpc_docker_image_hash: None,
                    launcher_docker_compose_hash: None,
                    expiry_timestamp_seconds: Some(expiry_time_secs),
                })
            } else {
                Attestation::Mock(MockAttestation::Valid)
            };
            tee_state
                .add_participant(node_id, attestation, tee_upgrade_duration)
                .expect("mock attestation is valid");
        }

        // Advance time, but still before expiry
        set_block_timestamp(before_expiry_time_secs * 1_000_000_000);

        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        assert_matches!(
            validation_result,
            TeeValidationResult::Full,
            "All participants should be valid before expiry"
        );
    }

    #[test]
    fn add_participant_rejects_invalid_attesations() {
        let mut tee_state = TeeState::default();
        let participants = gen_participants(3);
        let participant_list = participants.participants_vec();
        let tee_upgrade_duration = Duration::MAX;

        // Add valid attestations for first 2 participants
        for (account_id, _, participant_info) in participant_list.iter().take(2) {
            let node_id = create_node_id(account_id, &participant_info.sign_pk);
            tee_state
                .add_participant(
                    node_id,
                    Attestation::Mock(MockAttestation::Valid),
                    tee_upgrade_duration,
                )
                .expect("mock attestation is valid");
        }

        // Add invalid attestation for third participant
        let (account_id, _, participant_info) = &participant_list[2];
        let node_id = create_node_id(account_id, &participant_info.sign_pk);
        let add_participant_result = tee_state.add_participant(
            node_id,
            Attestation::Mock(MockAttestation::Invalid),
            tee_upgrade_duration,
        );

        assert_matches!(
            add_participant_result,
            Err(AttestationSubmissionError::InvalidAttestation(_))
        )
    }
}
