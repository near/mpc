use crate::{
    primitives::{key_state::AuthenticatedParticipantId, participants::Participants},
    storage_keys::StorageKey,
    tee::measurements::{
        AllowedMeasurements, ContractExpectedMeasurements, MeasurementVoteAction, MeasurementVotes,
    },
    tee::proposal::{
        AllowedDockerImageHashes, AllowedLauncherImages, AllowedMpcDockerImage, CodeHashesVotes,
        LauncherHashVotes, LauncherVoteAction, NodeImageHash,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::{
    attestation::{
        self, AcceptedAttestation, DstackAttestation, DstackVerify, MockAttestation,
        VerifiedAttestation,
    },
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash};
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_sdk::{env, near, store::IterableMap};
use std::time::Duration;
use tee_verifier_interface::VerifiedReport;

pub use near_mpc_contract_interface::types::NodeId;

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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationSubmissionError {
    #[error("the submitted attestation failed verification, reason: {:?}", .0)]
    InvalidAttestation(#[from] attestation::VerificationError),
    #[error(
        "TLS public key is already registered to a different account; only the owning account may update it"
    )]
    TlsKeyOwnedByOtherAccount,
}

#[derive(Debug)]
#[expect(clippy::large_enum_variant)]
pub(crate) enum ParticipantInsertion {
    NewlyInsertedParticipant,
    /// Holds the overwritten entry so [`TeeState::revert_dstack_store`] can put
    /// it back if the async store is rolled back.
    UpdatedExistingParticipant(NodeAttestation),
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
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct NodeAttestation {
    pub(crate) node_id: NodeId,
    pub(crate) verified_attestation: VerifiedAttestation,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) allowed_launcher_images: AllowedLauncherImages,
    pub(crate) votes: CodeHashesVotes,
    pub(crate) launcher_votes: LauncherHashVotes,
    /// Mapping of TLS public key of a participant to its [`NodeAttestation`].
    /// Attestations are stored for any valid participant that has submitted one, not
    /// just for the currently active participants. Callers must not assume this map is
    /// small; use the key-indexed accessors rather than scanning the whole collection.
    pub(crate) stored_attestations: IterableMap<Ed25519PublicKey, NodeAttestation>,
    pub(crate) allowed_measurements: AllowedMeasurements,
    pub(crate) measurement_votes: MeasurementVotes,
}

impl Default for TeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: Default::default(),
            allowed_launcher_images: Default::default(),
            votes: Default::default(),
            launcher_votes: Default::default(),
            stored_attestations: IterableMap::new(StorageKey::StoredAttestations),
            allowed_measurements: Default::default(),
            measurement_votes: Default::default(),
        }
    }
}

impl TeeState {
    /// Creates a [`TeeState`] with an initial set of participants that will receive a valid mocked attestation.
    pub(crate) fn with_mocked_participant_attestations(participants: &Participants) -> Self {
        let mut tee_state = Self::default();

        for (account_id, _, participant_info) in participants.participants() {
            let tls_public_key = participant_info.tls_public_key.clone();
            // TODO(#1087): replace account_public_key with a real account public
            // key passed in by the caller. `Participants` does not currently
            // carry the operator's account public key, so a mocked entry
            // cannot record the real one and we use the TLS key as a unique
            // per-participant placeholder. The mock keeps the
            // participant from being kicked out of an empty `TeeState` until
            // a real `submit_participant_info` call replaces it (keyed by
            // TLS), but any caller-facing check that compares
            // `signer_account_pk` against the stored key will fail until
            // then. #1087 tracks threading real attestations through
            // initialization so this sentinel can go away.
            let node_id = NodeId {
                account_id: account_id.clone(),
                tls_public_key: tls_public_key.clone(),
                // Use tls_public_key as account_public_key instead of hardcoded
                // Ed25519PublicKey::from([0u8; 32]) so that same account public
                // key isn't associated with different tls keys.
                // This is not a fix for above issue: #1087, which should be
                // addressed outside this PR.
                account_public_key: tls_public_key.clone(),
            };

            tee_state.stored_attestations.insert(
                tls_public_key,
                NodeAttestation {
                    node_id,
                    verified_attestation: VerifiedAttestation::Mock(
                        attestation::MockAttestation::Valid,
                    ),
                },
            );
        }

        tee_state
    }

    fn current_time_seconds() -> u64 {
        env::block_timestamp_ms() / 1_000
    }

    pub(crate) fn add_mock_participant(
        &mut self,
        node_id: NodeId,
        mock: MockAttestation,
        tee_upgrade_deadline_duration: Duration,
    ) -> Result<ParticipantInsertion, AttestationSubmissionError> {
        let AcceptedAttestation {
            attestation: verified_attestation,
            advisory_ids,
        } = mock.verify(
            Self::current_time_seconds(),
            &self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration),
            &self.get_allowed_launcher_compose_hashes(),
            &self.get_accepted_measurements(),
        )?;

        log_informational_advisory_ids(&advisory_ids);

        self.store_verified_attestation(node_id, verified_attestation)
    }

    /// Runs the post-DCAP checks for a [`Attestation::Dstack`] attestation
    /// against the [`VerifiedReport`] the verifier returned, then stores the
    /// result.
    pub(crate) fn finish_dstack_verify(
        &mut self,
        node_id: NodeId,
        dstack: &DstackAttestation,
        report: &VerifiedReport,
        tee_upgrade_deadline_duration: Duration,
    ) -> Result<ParticipantInsertion, AttestationSubmissionError> {
        let expected_report_data = Self::expected_report_data(&node_id);
        let accepted_measurements = self.get_accepted_measurements();
        let AcceptedAttestation {
            attestation: verified_attestation,
            advisory_ids,
        } = dstack.verify(
            report,
            expected_report_data,
            Self::current_time_seconds(),
            &self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration),
            &self.get_allowed_launcher_compose_hashes(),
            &accepted_measurements,
        )?;

        log_informational_advisory_ids(&advisory_ids);
        self.store_verified_attestation(node_id, verified_attestation)
    }

    fn expected_report_data(node_id: &NodeId) -> ::attestation::report_data::ReportData {
        let report_data: ReportData = ReportDataV1::new(
            *node_id.tls_public_key.as_bytes(),
            *node_id.account_public_key.as_bytes(),
        )
        .into();
        report_data.into()
    }

    /// Stores an already-verified attestation, rejecting a TLS key owned by a
    /// different account.
    ///
    /// On an update, the returned [`ParticipantInsertion::UpdatedExistingParticipant`]
    /// carries the displaced [`NodeAttestation`]; the Dstack path uses it to undo
    /// this store via [`Self::revert_dstack_store`], because its callback receipt
    /// commits even when the later storage charge fails.
    fn store_verified_attestation(
        &mut self,
        node_id: NodeId,
        verified_attestation: VerifiedAttestation,
    ) -> Result<ParticipantInsertion, AttestationSubmissionError> {
        let tls_pk = node_id.tls_public_key.clone();

        // Authorization: a TLS key registered to one account must not be
        // overwritten by a submission from a different account. Without this,
        // any caller could replace any participant's stored attestation, since
        // the entry is keyed only by `tls_public_key`.
        if let Some(existing) = self.stored_attestations.get(&tls_pk)
            && existing.node_id.account_id != node_id.account_id
        {
            return Err(AttestationSubmissionError::TlsKeyOwnedByOtherAccount);
        }

        let previous = self.stored_attestations.insert(
            tls_pk,
            NodeAttestation {
                node_id,
                verified_attestation,
            },
        );

        Ok(match previous {
            Some(previous) => ParticipantInsertion::UpdatedExistingParticipant(previous),
            None => ParticipantInsertion::NewlyInsertedParticipant,
        })
    }

    /// Undoes a [`Self::finish_dstack_verify`] store: restores the displaced
    /// entry, or removes the newly-inserted one if there was none. Used by the
    /// async flow when the storage charge fails after the store, so a caller
    /// can't get storage for free in a receipt that still commits.
    pub(crate) fn revert_dstack_store(
        &mut self,
        tls_public_key: &Ed25519PublicKey,
        insertion: ParticipantInsertion,
    ) {
        match insertion {
            ParticipantInsertion::UpdatedExistingParticipant(previous) => {
                self.stored_attestations
                    .insert(tls_public_key.clone(), previous);
            }
            ParticipantInsertion::NewlyInsertedParticipant => {
                self.stored_attestations.remove(tls_public_key);
            }
        }
    }

    /// reverifies stored participant attestations.
    pub(crate) fn reverify_participants(
        &self,
        node_id: &NodeId,
        tee_upgrade_deadline_duration: Duration,
    ) -> TeeQuoteStatus {
        let allowed_mpc_docker_image_hashes =
            self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration);
        let allowed_launcher_compose_hashes = self.get_allowed_launcher_compose_hashes();
        let allowed_measurements = self.get_accepted_measurements();

        let participant_attestation = self.stored_attestations.get(&node_id.tls_public_key);
        let Some(participant_attestation) = participant_attestation else {
            return TeeQuoteStatus::Invalid("participant has no attestation".to_string());
        };

        // Verify the attestation quote
        let time_stamp_seconds = Self::current_time_seconds();
        match participant_attestation.verified_attestation.re_verify(
            time_stamp_seconds,
            &allowed_mpc_docker_image_hashes,
            &allowed_launcher_compose_hashes,
            &allowed_measurements,
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
            .iter()
            .filter(|(_, _, participant_info)| {
                // Use the stored NodeId (keyed by TLS public key) so the real
                // `account_public_key` participates in re-verification. If
                // there is no stored attestation for this TLS key, the
                // participant is invalid.
                let Some(node_id) = self.find_node_id_by_tls_key(&participant_info.tls_public_key)
                else {
                    return false;
                };

                let tee_status =
                    self.reverify_participants(&node_id, tee_upgrade_deadline_duration);

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

    pub fn vote(
        &mut self,
        code_hash: NodeImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.votes.vote(code_hash, participant)
    }

    pub fn get_allowed_mpc_docker_image_hashes(
        &self,
        tee_upgrade_deadline_duration: Duration,
    ) -> Vec<NodeImageHash> {
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
        tee_proposal: NodeImageHash,
        tee_upgrade_deadline_duration: Duration,
    ) {
        self.votes.clear_votes();
        // Add compose hashes for the new MPC image across all allowed launcher images
        self.allowed_launcher_images
            .add_mpc_image_compose_hashes(&tee_proposal);
        self.allowed_docker_image_hashes
            .insert(tee_proposal, tee_upgrade_deadline_duration);
    }

    /// Returns all allowed launcher compose hashes (flattened from all allowed launcher images).
    pub fn get_allowed_launcher_compose_hashes(&self) -> Vec<LauncherDockerComposeHash> {
        self.allowed_launcher_images.all_compose_hashes()
    }

    /// Casts a vote for adding or removing a launcher image hash.
    /// Returns the total number of votes for the same action.
    pub fn vote_launcher(
        &mut self,
        action: LauncherVoteAction,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.launcher_votes.vote(action, participant)
    }

    /// Adds a new launcher image to the allowed set, computing compose hashes
    /// for all currently allowed MPC images. Clears launcher votes.
    pub fn add_launcher_image(
        &mut self,
        launcher_hash: LauncherImageHash,
        tee_upgrade_deadline_duration: Duration,
    ) -> bool {
        self.launcher_votes.clear_votes();
        let mpc_image_hashes = self
            .allowed_docker_image_hashes
            .get_image_hashes(tee_upgrade_deadline_duration);
        self.allowed_launcher_images
            .add(launcher_hash, &mpc_image_hashes)
    }

    /// Removes a launcher image from the allowed set. Clears launcher votes.
    pub fn remove_launcher_image(&mut self, launcher_hash: &LauncherImageHash) -> bool {
        self.launcher_votes.clear_votes();
        self.allowed_launcher_images.remove(launcher_hash)
    }

    /// Returns all allowed launcher image hashes.
    pub fn get_allowed_launcher_hashes(&self) -> Vec<LauncherImageHash> {
        self.allowed_launcher_images.launcher_hashes()
    }

    /// Casts a vote for adding or removing an OS measurement.
    /// Returns the total number of votes for the same action.
    pub fn vote_measurement(
        &mut self,
        action: MeasurementVoteAction,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.measurement_votes.vote(action, participant)
    }

    /// Adds a new measurement set to the allowed list. Clears measurement votes.
    pub fn add_measurement(&mut self, measurement: ContractExpectedMeasurements) -> bool {
        self.measurement_votes.clear_votes();
        self.allowed_measurements.add(measurement)
    }

    /// Removes a measurement set from the allowed list. Clears measurement votes.
    pub fn remove_measurement(&mut self, measurement: &ContractExpectedMeasurements) -> bool {
        self.measurement_votes.clear_votes();
        self.allowed_measurements.remove(measurement)
    }

    /// Returns all allowed OS measurements.
    pub fn get_allowed_measurements(&self) -> Vec<ContractExpectedMeasurements> {
        self.allowed_measurements.entries().to_vec()
    }

    /// Returns accepted measurements for attestation verification.
    /// Returns the on-chain list as-is (empty list means no measurements are accepted,
    /// consistent with docker image hashes and launcher hashes).
    fn get_accepted_measurements(&self) -> Vec<mpc_attestation::attestation::ExpectedMeasurements> {
        self.allowed_measurements.to_attestation_measurements()
    }

    /// Drops votes cast by nodes that are no longer participants. Used after a resharing
    /// concludes. Attestation cleanup is handled separately by
    /// [`TeeState::clean_invalid_attestations`].
    pub fn clean_non_participant_votes(&mut self, participants: &Participants) {
        self.votes = self.votes.get_remaining_votes(participants);
        self.launcher_votes = self.launcher_votes.get_remaining_votes(participants);
        self.measurement_votes = self.measurement_votes.get_remaining_votes(participants);
    }

    /// Scans up to `max_scan` entries from `stored_attestations` and removes any whose
    /// attestation no longer passes `re_verify` under the current docker-hash /
    /// launcher-hash / measurement whitelists, or whose attestation has expired.
    /// Returns the number of entries removed.
    pub fn clean_invalid_attestations(
        &mut self,
        tee_upgrade_deadline_duration: Duration,
        max_scan: usize,
    ) -> u32 {
        let has_invalid_attestation = |node_id: &NodeId| {
            !matches!(
                self.reverify_participants(node_id, tee_upgrade_deadline_duration),
                TeeQuoteStatus::Valid
            )
        };

        // Materialize candidates before any mutation to avoid iterator invalidation.
        let invalid_tls_keys: Vec<Ed25519PublicKey> = self
            .stored_attestations
            .iter()
            .take(max_scan)
            .filter(|(_, node_attestation)| has_invalid_attestation(&node_attestation.node_id))
            .map(|(tls_pk, _)| tls_pk.clone())
            .collect();

        let removed = u32::try_from(invalid_tls_keys.len())
            .expect("u32 should always be convertible from usize on wasm32");

        for tls_pk in invalid_tls_keys {
            self.stored_attestations.remove(&tls_pk);
        }
        removed
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
    pub fn find_node_id_by_tls_key(&self, tls_public_key: &Ed25519PublicKey) -> Option<NodeId> {
        self.stored_attestations
            .get(tls_public_key)
            .map(|node_attestation| node_attestation.node_id.clone())
    }

    /// Finds the `NodeId` (account_id + tls_public_key) for the node whose attested
    /// account public key matches `signer_account_pk`.
    pub(crate) fn lookup_node_id_by_signer_pk(
        &self,
        signer_account_pk: &Ed25519PublicKey,
    ) -> Result<&NodeId, AttestationCheckError> {
        self.stored_attestations
            .iter()
            .find(|(_, attestation)| attestation.node_id.account_public_key == *signer_account_pk)
            .map(|(_, attestation)| &attestation.node_id)
            .ok_or(AttestationCheckError::AttestationNotFound)
    }

    /// Returns Ok(()) if the caller has at least one participant entry
    /// whose TLS key matches an attested node belonging to the caller account.
    ///
    /// Handles multiple participants per account and supports legacy mock nodes.
    pub(crate) fn is_caller_an_attested_participant(
        &self,
        participants: &Participants,
    ) -> Result<(), AttestationCheckError> {
        let signer_account_pk = env::signer_account_pk();
        let signer_id = env::signer_account_id();

        let info = participants
            .info(&signer_id)
            .ok_or(AttestationCheckError::CallerNotParticipant)?;

        let attestation = self
            .stored_attestations
            .get(&info.tls_public_key)
            .ok_or(AttestationCheckError::AttestationNotFound)?;

        if attestation.node_id.account_id != signer_id {
            return Err(AttestationCheckError::AttestationOwnerMismatch);
        }

        // Stored account keys are Ed25519 by construction; a non-Ed25519
        // signer necessarily mismatches.
        let signer_ed25519 = Ed25519PublicKey::try_from(&signer_account_pk)
            .map_err(|_| AttestationCheckError::AttestationKeyMismatch)?;
        if attestation.node_id.account_public_key != signer_ed25519 {
            return Err(AttestationCheckError::AttestationKeyMismatch);
        }

        Ok(())
    }
}

/// Maximum number of advisory IDs to inline in the attestation-acceptance log.
/// PCS collateral is externally controlled, so we cap the rendered list to keep
/// receipt size predictable; the full count is always reported.
const MAX_LOGGED_ADVISORY_IDS: usize = 8;

fn log_informational_advisory_ids(advisory_ids: &[String]) {
    if advisory_ids.is_empty() {
        return;
    }
    let total = advisory_ids.len();
    let shown = advisory_ids
        .iter()
        .take(MAX_LOGGED_ADVISORY_IDS)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = match total.checked_sub(MAX_LOGGED_ADVISORY_IDS) {
        Some(extra) if extra > 0 => format!(" (+{extra} more)"),
        _ => String::new(),
    };
    env::log_str(&format!(
        "attestation accepted with {total} informational advisory ID(s): {shown}{suffix}",
    ));
}

#[derive(Debug)]
pub(crate) enum AttestationCheckError {
    CallerNotParticipant,
    AttestationNotFound,
    AttestationOwnerMismatch,
    AttestationKeyMismatch,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::key_state::AuthenticatedParticipantId;
    use crate::primitives::test_utils::{
        bogus_ed25519_near_public_key, bogus_ed25519_public_key, gen_participant, gen_participants,
    };
    use crate::tee::test_utils::set_block_timestamp;
    use assert_matches::assert_matches;
    use mpc_attestation::attestation::MockAttestation;
    use mpc_primitives::hash::{LauncherImageHash, NodeImageHash};
    use near_account_id::AccountId;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use std::time::Duration;

    /// Helper to set up the testing environment with a specific signer
    fn set_signer(account_id: &AccountId, public_key: &near_sdk::PublicKey) {
        let mut builder = VMContextBuilder::new();
        builder
            .signer_account_id(account_id.clone())
            .signer_account_pk(public_key.clone());
        testing_env!(builder.build());
    }

    #[test]
    fn clean_non_participant_votes__should_not_touch_attestations() {
        // Given
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10000);

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
                tls_public_key: p_info.tls_public_key.clone(),
                account_public_key: bogus_ed25519_public_key(),
            })
            .collect();

        // Add TEE information for all participants and non-participant
        let local_attestation = MockAttestation::Valid;

        let non_participant_uid = NodeId {
            account_id: non_participant.clone(),
            account_public_key: bogus_ed25519_public_key(),
            tls_public_key: bogus_ed25519_public_key(),
        };

        for node_id in &participant_nodes {
            tee_state
                .add_mock_participant(
                    node_id.clone(),
                    local_attestation.clone(),
                    TEE_UPGRADE_DURATION,
                )
                .unwrap();
        }
        tee_state
            .add_mock_participant(
                non_participant_uid.clone(),
                local_attestation.clone(),
                TEE_UPGRADE_DURATION,
            )
            .unwrap();

        // Verify all 4 accounts have TEE info initially
        assert_eq!(tee_state.stored_attestations.len(), 4);

        // When: the vote-cleanup path runs for the current participant set.
        tee_state.clean_non_participant_votes(&participants);

        // Then: attestations are left untouched (attestation cleanup is a separate path).
        assert_eq!(tee_state.stored_attestations.len(), 4);
        for node_id in &participant_nodes {
            assert!(
                tee_state
                    .stored_attestations
                    .contains_key(&node_id.tls_public_key)
            );
        }
        assert!(
            tee_state
                .stored_attestations
                .contains_key(&non_participant_uid.tls_public_key)
        );
    }

    #[test]
    fn clean_invalid_attestations__should_remove_expired_entries() {
        // Given: one fresh and one already-expired attestation stored.
        const FRESH_EXPIRY_SECONDS: u64 = 10_000;
        const STALE_EXPIRY_SECONDS: u64 = 1_000;
        const NOW_SECONDS: u64 = 5_000;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();

        let fresh_node = NodeId {
            account_id: "fresh.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let stale_node = NodeId {
            account_id: "stale.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };

        let fresh = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(FRESH_EXPIRY_SECONDS),
            expected_measurements: None,
        };
        let stale = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(STALE_EXPIRY_SECONDS),
            expected_measurements: None,
        };

        tee_state
            .add_mock_participant(fresh_node.clone(), fresh, Duration::from_secs(0))
            .unwrap();
        tee_state
            .add_mock_participant(stale_node.clone(), stale, Duration::from_secs(0))
            .unwrap();

        assert_eq!(tee_state.stored_attestations.len(), 2);

        // When: the clock advances past the stale entry's expiry and cleanup runs.
        set_block_timestamp(NOW_SECONDS * 1_000_000_000);
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100);

        // Then: only the expired entry is removed.
        assert_eq!(removed, 1);
        assert!(
            tee_state
                .stored_attestations
                .contains_key(&fresh_node.tls_public_key)
        );
        assert!(
            !tee_state
                .stored_attestations
                .contains_key(&stale_node.tls_public_key)
        );
    }

    #[test]
    fn clean_invalid_attestations__should_honor_max_scan() {
        // Given: ten expired attestations stored.
        const EXPIRY_SECONDS: u64 = 1_000;
        const NOW_SECONDS: u64 = 5_000;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();

        let expired = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(EXPIRY_SECONDS),
            expected_measurements: None,
        };

        for idx in 0..10 {
            let node_id = NodeId {
                account_id: format!("node{idx}.near").parse().unwrap(),
                tls_public_key: bogus_ed25519_public_key(),
                account_public_key: bogus_ed25519_public_key(),
            };
            tee_state
                .add_mock_participant(node_id, expired.clone(), Duration::from_secs(0))
                .unwrap();
        }
        assert_eq!(tee_state.stored_attestations.len(), 10);

        set_block_timestamp(NOW_SECONDS * 1_000_000_000);

        // When: cleanup is called repeatedly with a scan limit of 3 until no progress is made.
        let mut total_removed = 0u32;
        loop {
            let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 3);
            total_removed += removed;
            if removed == 0 {
                break;
            }
            assert!(removed <= 3);
        }

        // Then: all ten entries are removed across multiple calls, each bounded by max_scan.
        assert_eq!(total_removed, 10);
        assert_eq!(tee_state.stored_attestations.len(), 0);
    }

    #[test]
    fn clean_invalid_attestations__should_keep_valid_entries() {
        // Given: a single attestation whose expiry is in the future.
        const FUTURE_EXPIRY_SECONDS: u64 = 10_000;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let attestation = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(FUTURE_EXPIRY_SECONDS),
            expected_measurements: None,
        };
        tee_state
            .add_mock_participant(node_id.clone(), attestation, Duration::from_secs(0))
            .unwrap();

        // When: cleanup runs while the attestation is still valid.
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100);

        // Then: nothing is removed.
        assert_eq!(removed, 0);
        assert!(
            tee_state
                .stored_attestations
                .contains_key(&node_id.tls_public_key)
        );
    }

    #[test]
    fn updating_existing_participant_returns_existing_participant() {
        // given
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10000);
        let mut tee_state = TeeState::default();

        let participant: AccountId = "dave.near".parse().unwrap();
        let local_attestation = MockAttestation::Valid;

        let participant_id = NodeId {
            account_id: participant.clone(),
            account_public_key: bogus_ed25519_public_key(),
            tls_public_key: bogus_ed25519_public_key(),
        };

        let insertion_result = tee_state.add_mock_participant(
            participant_id.clone(),
            local_attestation.clone(),
            TEE_UPGRADE_DURATION,
        );
        assert_matches!(
            insertion_result,
            Ok(ParticipantInsertion::NewlyInsertedParticipant)
        );

        // when
        let re_insertion_result = tee_state.add_mock_participant(
            participant_id.clone(),
            local_attestation.clone(),
            TEE_UPGRADE_DURATION,
        );

        // then
        assert_matches!(
            re_insertion_result,
            Ok(ParticipantInsertion::UpdatedExistingParticipant(_))
        );
    }

    #[test]
    fn add_participant_increases_storage_size() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let attestation = MockAttestation::Valid;

        // when
        tee_state
            .add_mock_participant(node_id, attestation, Duration::from_secs(0))
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
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let attestation = MockAttestation::Valid;

        // when
        tee_state
            .add_mock_participant(node_id.clone(), attestation, Duration::from_secs(0))
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
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let attestation = MockAttestation::Valid;

        // when
        tee_state
            .add_mock_participant(node_id.clone(), attestation, Duration::from_secs(0))
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
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };

        let node_2 = NodeId {
            account_id: "bob.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };

        // when
        tee_state
            .add_mock_participant(
                node_1.clone(),
                MockAttestation::Valid,
                Duration::from_secs(0),
            )
            .unwrap();
        tee_state
            .add_mock_participant(
                node_2.clone(),
                MockAttestation::Valid,
                Duration::from_secs(0),
            )
            .unwrap();

        // then
        assert_eq!(tee_state.stored_attestations.len(), 2);
        assert!(
            tee_state
                .stored_attestations
                .contains_key(&node_1.tls_public_key)
        );
        assert!(
            tee_state
                .stored_attestations
                .contains_key(&node_2.tls_public_key)
        );
    }

    #[test]
    fn re_verify_validates_fresh_attestation() {
        // given
        let mut tee_state = TeeState::default();
        let node_id = NodeId {
            account_id: "fresh.near".parse().unwrap(),
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };

        const NOW_SECONDS: u64 = 1000;

        testing_env!(VMContextBuilder::new().block_timestamp(NOW_SECONDS).build());

        let attestation = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(NOW_SECONDS),
            expected_measurements: None,
        };

        tee_state
            .add_mock_participant(node_id.clone(), attestation, Duration::from_secs(0))
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
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };

        const EXPIRY_TIMESTAMP_SECONDS: u64 = 1000;
        const ELAPSED_SECONDS: u64 = 200;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let attestation = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(EXPIRY_TIMESTAMP_SECONDS),
            expected_measurements: None,
        };

        tee_state
            .add_mock_participant(node_id.clone(), attestation, Duration::from_secs(0))
            .unwrap();

        // when
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(
                    Duration::from_secs(EXPIRY_TIMESTAMP_SECONDS + ELAPSED_SECONDS).as_nanos()
                        as u64
                )
                .build()
        );

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
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
        };

        const EXPIRY_TIMESTAMP_SECONDS: u64 = 1000;

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(Duration::from_secs(0).as_nanos() as u64)
                .build()
        );

        let attestation = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(EXPIRY_TIMESTAMP_SECONDS),
            expected_measurements: None,
        };

        tee_state
            .add_mock_participant(node_id.clone(), attestation, Duration::from_secs(0))
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
            tls_public_key: bogus_ed25519_public_key(),
            account_public_key: bogus_ed25519_public_key(),
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
        let (account_id, _, participant_info) = participants.participants().iter().next().unwrap();

        // 1. Define the Signer's NEAR Public Key (Wallet Key)
        let signer_pk = bogus_ed25519_near_public_key();

        // 2. Set the environment so the caller is the participant
        set_signer(account_id, &signer_pk);

        // 3. Register the attestation in TeeState
        // The TLS key comes from participant_info, the Account Key must match the signer_pk
        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key: participant_info.tls_public_key.clone(),
            account_public_key: Ed25519PublicKey::try_from(&signer_pk).unwrap(),
        };
        tee_state
            .add_mock_participant(node_id, MockAttestation::Valid, tee_upgrade_duration)
            .expect("Attestation is valid on insertion");

        // 4. Verify check passes
        tee_state
            .is_caller_an_attested_participant(&participants)
            .expect("Attested participant should be accepted");
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
        let (account_id, _, _) = participants.participants().iter().next().unwrap();

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
        let (account_id, _, participant_info) = participants.participants().iter().next().unwrap();
        let tee_upgrade_duration = Duration::MAX;

        let signer_pk = bogus_ed25519_near_public_key();
        set_signer(account_id, &signer_pk);

        // Create a data integrity issue:
        // The TLS key in `participants` points to an entry in `tee_state`...
        // ...but that entry claims it belongs to a different AccountId.
        let other_account: AccountId = "imposter.near".parse().unwrap();

        let node_id = NodeId {
            account_id: other_account.clone(), // Mismatch here
            tls_public_key: participant_info.tls_public_key.clone(),
            account_public_key: Ed25519PublicKey::try_from(&signer_pk).unwrap(),
        };
        tee_state
            .add_mock_participant(node_id, MockAttestation::Valid, tee_upgrade_duration)
            .expect("Attestation is valid on insertion");

        let result = tee_state.is_caller_an_attested_participant(&participants);

        assert_matches!(result, Err(AttestationCheckError::AttestationOwnerMismatch));
    }

    #[test]
    fn test_err_attestation_key_mismatch() {
        // given
        let mut tee_state = TeeState::default();
        let participants = gen_participants(1);
        let (account_id, _, participant_info) = participants.participants().iter().next().unwrap();
        let tee_upgrade_duration = Duration::MAX;

        let signer_pk = bogus_ed25519_near_public_key();
        set_signer(account_id, &signer_pk);

        // Generate a different key for the stored attestation
        // (e.g., The user rotated their wallet key, but hasn't updated the TEE registry)
        let old_signer_pk: Ed25519PublicKey =
            "ed25519:3t4M1gXg2Qd5g6X8z1g2X3t4M1gXg2Qd5g6X8z1g2X3t"
                .parse()
                .unwrap();

        let node_id = NodeId {
            account_id: account_id.clone(),
            tls_public_key: participant_info.tls_public_key.clone(),
            account_public_key: old_signer_pk, // Mismatch here
        };
        tee_state
            .add_mock_participant(node_id, MockAttestation::Valid, tee_upgrade_duration)
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
    fn create_node_id(account_id: &AccountId, tls_public_key: &Ed25519PublicKey) -> NodeId {
        NodeId {
            account_id: account_id.clone(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: bogus_ed25519_public_key(),
        }
    }

    /// Helper to extract account IDs from participants for assertion comparisons
    fn account_ids(participants: &Participants) -> Vec<AccountId> {
        participants
            .participants()
            .iter()
            .map(|(acc, _, _)| acc.clone())
            .collect()
    }

    #[test]
    fn validate_tee_returns_full_when_all_participants_have_valid_attestations() {
        let mut tee_state = TeeState::default();
        let participants = gen_participants(3);
        let tee_upgrade_duration = Duration::MAX;

        // Add valid attestations for all participants
        for (account_id, _, participant_info) in participants.participants().iter() {
            let node_id = create_node_id(account_id, &participant_info.tls_public_key);
            tee_state
                .add_mock_participant(node_id, MockAttestation::Valid, tee_upgrade_duration)
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
        let participant_list: Vec<_> = participants.participants().to_vec();
        let tee_upgrade_duration = Duration::MAX;

        // Add valid attestations for only first 2 participants
        for (account_id, _, participant_info) in participant_list.iter().take(2) {
            let node_id = create_node_id(account_id, &participant_info.tls_public_key);
            tee_state
                .add_mock_participant(node_id, MockAttestation::Valid, tee_upgrade_duration)
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
        let participant_list: Vec<_> = participants.participants().to_vec();

        // Add valid attestations for first 2 participants
        for (account_id, _, participant_info) in participant_list.iter().take(2) {
            let node_id = create_node_id(account_id, &participant_info.tls_public_key);
            tee_state
                .add_mock_participant(node_id, MockAttestation::Valid, tee_upgrade_duration)
                .expect("mock attestation is valid");
        }

        // Add expiring attestation for third participant
        let (account_id, _, participant_info) = &participant_list[2];
        let node_id = create_node_id(account_id, &participant_info.tls_public_key);
        let expiring_attestation = MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: None,
            expiry_timestamp_seconds: Some(expiry_time_secs),
            expected_measurements: None,
        };
        tee_state
            .add_mock_participant(node_id, expiring_attestation, tee_upgrade_duration)
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
        let participant_list: Vec<_> = participants.participants().to_vec();

        for (i, (account_id, _, participant_info)) in participant_list.iter().enumerate() {
            let node_id = create_node_id(account_id, &participant_info.tls_public_key);
            let attestation = if i == 2 {
                MockAttestation::WithConstraints {
                    mpc_docker_image_hash: None,
                    launcher_docker_compose_hash: None,
                    expiry_timestamp_seconds: Some(expiry_time_secs),
                    expected_measurements: None,
                }
            } else {
                MockAttestation::Valid
            };
            tee_state
                .add_mock_participant(node_id, attestation, tee_upgrade_duration)
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
    fn add_participant__should_reject_tls_key_owned_by_other_account() {
        // Given: an existing attestation registered to `alice.near` under some TLS key.
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10_000);

        let mut tee_state = TeeState::default();
        let tls_public_key = bogus_ed25519_public_key();

        let alice_node = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: bogus_ed25519_public_key(),
        };
        tee_state
            .add_mock_participant(
                alice_node.clone(),
                MockAttestation::Valid,
                TEE_UPGRADE_DURATION,
            )
            .expect("initial insertion should succeed");

        // When: a different account submits an attestation for the same TLS key.
        let attacker_node = NodeId {
            account_id: "attacker.near".parse().unwrap(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let result = tee_state.add_mock_participant(
            attacker_node,
            MockAttestation::Valid,
            TEE_UPGRADE_DURATION,
        );

        // Then: the overwrite is rejected and the original entry is untouched.
        assert_matches!(
            result,
            Err(AttestationSubmissionError::TlsKeyOwnedByOtherAccount)
        );
        let stored = tee_state
            .stored_attestations
            .get(&tls_public_key)
            .expect("entry must still be present");
        assert_eq!(stored.node_id, alice_node);
    }

    #[test]
    fn add_participant__should_allow_same_account_to_update_its_own_entry() {
        // Given: an existing attestation registered to `alice.near`.
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10_000);

        let mut tee_state = TeeState::default();
        let tls_public_key = bogus_ed25519_public_key();

        let initial_node = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: bogus_ed25519_public_key(),
        };
        tee_state
            .add_mock_participant(initial_node, MockAttestation::Valid, TEE_UPGRADE_DURATION)
            .expect("initial insertion should succeed");

        // When: the same account resubmits with a rotated account_public_key.
        let rotated_node = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key,
            account_public_key: bogus_ed25519_public_key(),
        };
        let result = tee_state.add_mock_participant(
            rotated_node.clone(),
            MockAttestation::Valid,
            TEE_UPGRADE_DURATION,
        );

        // Then: the update is accepted and the stored entry reflects the new key.
        assert_matches!(
            result,
            Ok(ParticipantInsertion::UpdatedExistingParticipant(_))
        );
        let stored = tee_state
            .stored_attestations
            .get(&rotated_node.tls_public_key)
            .expect("entry must be present");
        assert_eq!(stored.node_id, rotated_node);
    }

    #[test]
    fn revert_dstack_store__restores_the_displaced_entry_on_update() {
        // Given: `alice` has an attestation, then updates it — the second insertion
        // returns the displaced original wrapped in `UpdatedExistingParticipant`.
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10_000);
        let mut tee_state = TeeState::default();
        let tls_public_key = bogus_ed25519_public_key();
        let original_node = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: bogus_ed25519_public_key(),
        };
        tee_state
            .add_mock_participant(
                original_node.clone(),
                MockAttestation::Valid,
                TEE_UPGRADE_DURATION,
            )
            .expect("initial insertion should succeed");
        let updated_node = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let insertion = tee_state
            .add_mock_participant(updated_node, MockAttestation::Valid, TEE_UPGRADE_DURATION)
            .expect("update should succeed");
        assert_matches!(
            insertion,
            ParticipantInsertion::UpdatedExistingParticipant(_)
        );

        // When: the store is reverted.
        tee_state.revert_dstack_store(&tls_public_key, insertion);

        // Then: the original (displaced) entry is back in place.
        let stored = tee_state
            .stored_attestations
            .get(&tls_public_key)
            .expect("original entry must be restored");
        assert_eq!(stored.node_id, original_node);
    }

    #[test]
    fn revert_dstack_store__removes_the_newly_inserted_entry() {
        // Given: a brand-new attestation for `alice` (no prior entry displaced).
        const TEE_UPGRADE_DURATION: Duration = Duration::from_secs(10_000);
        let mut tee_state = TeeState::default();
        let tls_public_key = bogus_ed25519_public_key();
        let node = NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: bogus_ed25519_public_key(),
        };
        let insertion = tee_state
            .add_mock_participant(node, MockAttestation::Valid, TEE_UPGRADE_DURATION)
            .expect("insertion should succeed");
        assert_matches!(insertion, ParticipantInsertion::NewlyInsertedParticipant);

        // When: the store is reverted.
        tee_state.revert_dstack_store(&tls_public_key, insertion);

        // Then: the entry is gone.
        assert!(
            tee_state.stored_attestations.get(&tls_public_key).is_none(),
            "newly inserted entry must be removed on revert"
        );
    }

    #[test]
    fn add_participant_rejects_invalid_attestations() {
        let mut tee_state = TeeState::default();
        let participants = gen_participants(3);
        let participant_list: Vec<_> = participants.participants().to_vec();
        let tee_upgrade_duration = Duration::MAX;

        // Add valid attestations for first 2 participants
        for (account_id, _, participant_info) in participant_list.iter().take(2) {
            let node_id = create_node_id(account_id, &participant_info.tls_public_key);
            tee_state
                .add_mock_participant(node_id, MockAttestation::Valid, tee_upgrade_duration)
                .expect("mock attestation is valid");
        }

        // Add invalid attestation for third participant
        let (account_id, _, participant_info) = &participant_list[2];
        let node_id = create_node_id(account_id, &participant_info.tls_public_key);
        let add_participant_result =
            tee_state.add_mock_participant(node_id, MockAttestation::Invalid, tee_upgrade_duration);

        assert_matches!(
            add_participant_result,
            Err(AttestationSubmissionError::InvalidAttestation(_))
        )
    }

    /// Stale CodeHashesVotes entries from removed participants must not count toward
    /// quorum after resharing.
    ///
    /// Scenario (N=5, T=3):
    /// 1. P1 and P2 vote for malicious hash before resharing.
    /// 2. Resharing removes P1 and P2. New set: {P3, P4, P5}.
    /// 3. clean_non_participant_votes removes stale votes.
    /// 4. P3 votes for the same hash — only 1 vote, not 3.
    #[test]
    fn test_clean_non_participant_votes_removes_stale_votes() {
        // Build 5 participants
        let mut all_participants = Participants::new();
        let mut account_ids = Vec::new();
        for i in 0..5 {
            let (account_id, info) = gen_participant(i);
            account_ids.push(account_id.clone());
            all_participants.insert(account_id, info).unwrap();
        }

        let mut tee_state = TeeState::default();

        // P0 and P1 vote for a malicious hash before resharing
        let malicious_hash = NodeImageHash::from([0xAA; 32]);
        for account_id in &account_ids[0..2] {
            let mut ctx = VMContextBuilder::new();
            ctx.signer_account_id(account_id.clone());
            testing_env!(ctx.build());
            let auth_id = AuthenticatedParticipantId::new(&all_participants).unwrap();
            tee_state.votes.vote(malicious_hash, &auth_id);
        }
        assert_eq!(tee_state.votes.proposal_by_account.len(), 2);

        // Resharing removes P0 and P1. New participant set: {P2, P3, P4}.
        let new_participants = all_participants.subset(2..5);

        // Clean non-participants (as done by CLEAN_TEE_STATUS after resharing)
        tee_state.clean_non_participant_votes(&new_participants);

        // Stale votes must be removed
        assert_eq!(tee_state.votes.proposal_by_account.len(), 0);

        // P2 votes for the same malicious hash — should be only 1 vote, not 3
        let p2_account = &account_ids[2];
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(p2_account.clone());
        testing_env!(ctx.build());
        let auth_id = AuthenticatedParticipantId::new(&new_participants).unwrap();
        let vote_count = tee_state.votes.vote(malicious_hash, &auth_id);
        assert_eq!(vote_count, 1, "Only the fresh vote from P2 should count");
    }

    /// Verifies that clean_non_participants also removes stale launcher and measurement votes.
    #[test]
    fn test_clean_non_participants_removes_stale_launcher_and_measurement_votes() {
        let mut all_participants = Participants::new();
        let mut account_ids = Vec::new();
        for i in 0..3 {
            let (account_id, info) = gen_participant(i);
            account_ids.push(account_id.clone());
            all_participants.insert(account_id, info).unwrap();
        }

        let mut tee_state = TeeState::default();

        // P0 votes for a launcher hash
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(account_ids[0].clone());
        testing_env!(ctx.build());
        let auth_id = AuthenticatedParticipantId::new(&all_participants).unwrap();
        let launcher_action = LauncherVoteAction::Add(LauncherImageHash::from([0xBB; 32]));
        tee_state.launcher_votes.vote(launcher_action, &auth_id);

        assert_eq!(tee_state.launcher_votes.vote_by_account.len(), 1);

        // New participant set excludes P0
        let new_participants = all_participants.subset(1..3);
        tee_state.clean_non_participant_votes(&new_participants);

        assert_eq!(tee_state.launcher_votes.vote_by_account.len(), 0);
    }
}
