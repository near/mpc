#[cfg(test)]
use crate::primitives::test_utils::bogus_ed25519_public_key;
use crate::{
    dto_mapping::IntoInterfaceType,
    primitives::{
        key_state::AuthenticatedAccountId,
        participants::Participants,
        proposal_hash::ToProposalHash,
        time::Timestamp,
        votes::{VoterSet, Votes},
    },
    storage_keys::StorageKey,
    tee::measurements::AllowedMeasurements,
    tee::proposal::{
        AllowedLauncherImageInsertion, AllowedLauncherImages, NodeImageHash,
        StoredDockerImageHashes,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::{
    TcbInfo,
    attestation::{self, AcceptedAttestation, DstackVerify, MockAttestation, VerifiedAttestation},
    report_data::{ReportData, ReportDataV1},
};
use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash};
use near_mpc_contract_interface::types::{
    self as dtos, AccountId, Ed25519PublicKey, ExpectedMeasurements, LauncherVoteAction,
    MeasurementVoteAction,
};
use near_sdk::{log, near, store::IterableMap};
use std::time::Duration;
use tee_verifier_interface::{CollateralDates, VerifiedReport};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationSubmissionError {
    #[error("the submitted attestation failed verification, reason: {0}")]
    InvalidAttestation(#[from] attestation::VerificationError),
    #[error(
        "TLS public key is already registered to a different account; only the owning account may update it"
    )]
    TlsKeyOwnedByOtherAccount,
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

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: StoredDockerImageHashes,
    pub(crate) allowed_launcher_images: AllowedLauncherImages,
    pub(crate) votes: Votes<AuthenticatedAccountId>,
    pub(crate) launcher_votes: Votes<AuthenticatedAccountId>,
    /// Invariant: each TLS key a participant uses (its current one and, during a node migration,
    /// the destination one) maps to a node owned by that participant, except that an initial
    /// participant has no node until its first attestation. Joining the participant set
    /// and migrating require such a node, and [`crate::MpcContract::clean_invalid_attestations`]
    /// never removes it. This lets [`Self::assert_tls_key_claimable`] decide whether an account
    /// may store a node under a TLS key by looking only at this map, so code that changes how
    /// participants get TLS keys or how nodes are removed must preserve the invariant.
    ///
    /// Callers must not assume this map is small; use the key-indexed accessors rather than
    /// scanning the whole collection.
    pub(crate) nodes: IterableMap<Ed25519PublicKey, Node>,
    pub(crate) allowed_measurements: AllowedMeasurements,
    pub(crate) measurement_votes: Votes<AuthenticatedAccountId>,
}

impl Default for TeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: Default::default(),
            allowed_launcher_images: Default::default(),
            votes: Votes::new(
                StorageKey::CodeHashVotesByVoter,
                StorageKey::CodeHashVotesByProposal,
            ),
            launcher_votes: Votes::new(
                StorageKey::LauncherHashVotesByVoter,
                StorageKey::LauncherHashVotesByProposal,
            ),
            nodes: IterableMap::new(StorageKey::Nodes),
            allowed_measurements: Default::default(),
            measurement_votes: Votes::new(
                StorageKey::MeasurementVotesByVoter,
                StorageKey::MeasurementVotesByProposal,
            ),
        }
    }
}

impl TeeState {
    /// Creates a [`TeeState`] in which every participant has a valid mock attestation, signed
    /// with a random signer public key.
    #[cfg(test)]
    pub(crate) fn with_mocked_participant_attestations(participants: &Participants) -> Self {
        let mut tee_state = Self::default();

        for (account_id, _, participant_info) in participants.participants() {
            let tls_public_key = participant_info.tls_public_key.clone();
            let signer_public_key = bogus_ed25519_public_key();
            tee_state.nodes.insert(
                tls_public_key.clone(),
                Node {
                    owner: account_id.clone(),
                    tls_public_key,
                    signer_public_key,
                    attestation: VerifiedAttestation::Mock(MockAttestation::Valid),
                    attestation_accepted_at_seconds: Self::current_time_seconds(),
                },
            );
        }

        tee_state
    }

    pub(crate) fn current_time_seconds() -> u64 {
        Timestamp::now().as_secs()
    }

    /// Returns whether the node is new.
    pub(crate) fn verify_and_store_mock(
        &mut self,
        node: dtos::NodeInfo,
        mock: MockAttestation,
        tee_upgrade_deadline_duration: Duration,
    ) -> Result<bool, AttestationSubmissionError> {
        let accepted = mock.verify(
            Self::current_time_seconds(),
            &self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration),
            &self.get_allowed_launcher_compose_hashes(),
            &self.get_accepted_measurements(),
        )?;
        self.store_verified_attestation(node, accepted)
    }

    /// Runs the post-DCAP checks for a dstack [`TcbInfo`] against the
    /// [`VerifiedReport`] the verifier returned, then stores the result. Returns whether the
    /// node is new.
    pub(crate) fn verify_and_store_dstack(
        &mut self,
        node: dtos::NodeInfo,
        tcb_info: &TcbInfo,
        report: &VerifiedReport,
        collateral_dates: &CollateralDates,
        tee_upgrade_deadline_duration: Duration,
    ) -> Result<bool, AttestationSubmissionError> {
        let accepted = tcb_info.verify(
            report,
            collateral_dates,
            Self::expected_report_data(&node),
            &self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration),
            &self.get_allowed_launcher_compose_hashes(),
            &self.get_accepted_measurements(),
        )?;
        self.store_verified_attestation(node, accepted)
    }

    fn expected_report_data(node: &dtos::NodeInfo) -> ::attestation_types::ReportData {
        let report_data: ReportData = ReportDataV1::new(
            *node.tls_public_key.as_bytes(),
            *node.account_public_key.as_bytes(),
        )
        .into();
        report_data.into()
    }

    fn store_verified_attestation(
        &mut self,
        node: dtos::NodeInfo,
        accepted: AcceptedAttestation,
    ) -> Result<bool, AttestationSubmissionError> {
        log_informational_advisory_ids(&accepted.advisory_ids);
        let tls_pk = node.tls_public_key.clone();

        self.assert_tls_key_claimable(&node.account_id, &tls_pk)?;

        let previous = self.nodes.insert(
            tls_pk,
            Node {
                owner: node.account_id,
                tls_public_key: node.tls_public_key,
                signer_public_key: node.account_public_key,
                attestation: accepted.attestation,
                attestation_accepted_at_seconds: Self::current_time_seconds(),
            },
        );

        Ok(previous.is_none())
    }

    pub(crate) fn has_valid_attestation(
        &self,
        node: &Node,
        tee_upgrade_deadline_duration: Duration,
    ) -> bool {
        node.attestation
            .re_verify(
                Self::current_time_seconds(),
                &self.get_allowed_mpc_docker_image_hashes(tee_upgrade_deadline_duration),
                &self.get_allowed_launcher_compose_hashes(),
                &self.get_accepted_measurements(),
            )
            .is_ok()
    }

    /// Evicts expired entries from the allowed docker-image set, then reverifies stored
    /// participant attestations, reporting whether all still pass or, if not, which subset
    /// does (an attestation fails when e.g. its MPC image hash is no longer allowed, or a
    /// certificate expired).
    ///
    /// The attestations themselves are not pruned here; reclaiming them is
    /// [`crate::MpcContract::clean_invalid_attestations`]'s job.
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
            .filter(|(account_id, _, participant_info)| {
                self.node_of(account_id, &participant_info.tls_public_key)
                    .is_some_and(|node| {
                        self.has_valid_attestation(node, tee_upgrade_deadline_duration)
                    })
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

    pub fn vote_mpc_node_manifest_digest(
        &mut self,
        code_hash: NodeImageHash,
        voter: AuthenticatedAccountId,
    ) -> &VoterSet<AuthenticatedAccountId> {
        self.votes.vote(voter, code_hash.to_proposal_hash())
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
    ) -> Vec<dtos::AllowedMpcDockerImageHash> {
        self.allowed_docker_image_hashes
            .allowed_images(tee_upgrade_deadline_duration)
    }

    pub fn whitelist_tee_proposal(
        &mut self,
        tee_proposal: NodeImageHash,
        tee_upgrade_deadline_duration: Duration,
    ) {
        self.votes.clear();
        // Add compose hashes for the new MPC image across all allowed launcher images
        self.allowed_launcher_images
            .add_mpc_image_compose_hashes(&tee_proposal);
        self.allowed_docker_image_hashes
            .insert(tee_proposal, tee_upgrade_deadline_duration);
    }

    pub fn get_allowed_launcher_compose_hashes(&self) -> Vec<LauncherDockerComposeHash> {
        self.allowed_launcher_images.all_compose_hashes()
    }

    /// Removes the launchers no participant in `current_participants` uses once their TTL has
    /// passed, after restamping the ones they do use. Pass the running participants: a launcher
    /// used only by a participant missing here can be removed, which invalidates that
    /// participant's attestation.
    pub(crate) fn remove_unused_launchers(
        &mut self,
        current_participants: &Participants,
        ttl: Duration,
    ) {
        let in_use: Vec<LauncherDockerComposeHash> = current_participants
            .participants()
            .iter()
            .filter_map(|(account_id, _, participant_info)| {
                self.node_of(account_id, &participant_info.tls_public_key)
            })
            .filter_map(|node| node.attestation.launcher_compose_hash())
            .collect();
        self.allowed_launcher_images.remove_unused(&in_use, ttl);
    }

    /// Casts a vote for adding or removing a launcher image hash.
    pub fn vote_launcher(
        &mut self,
        action: LauncherVoteAction,
        voter: AuthenticatedAccountId,
    ) -> &VoterSet<AuthenticatedAccountId> {
        self.launcher_votes.vote(voter, action.to_proposal_hash())
    }

    /// Adds a launcher image to the allowed set, computing compose hashes for all currently
    /// allowed MPC images. If already present, refreshes it instead. Clears launcher votes.
    pub fn add_launcher_image(
        &mut self,
        launcher_hash: LauncherImageHash,
        tee_upgrade_deadline_duration: Duration,
        ttl: Duration,
    ) -> AllowedLauncherImageInsertion {
        self.launcher_votes.clear();
        let mpc_image_hashes = self
            .allowed_docker_image_hashes
            .get_image_hashes(tee_upgrade_deadline_duration);
        self.allowed_launcher_images
            .add_or_refresh(launcher_hash, &mpc_image_hashes, ttl)
    }

    /// Removes a launcher image from the allowed set. Clears launcher votes.
    pub fn remove_launcher_image(&mut self, launcher_hash: &LauncherImageHash) -> bool {
        self.launcher_votes.clear();
        self.allowed_launcher_images.remove(launcher_hash)
    }

    /// Returns all allowed launcher image hashes.
    pub fn get_allowed_launcher_hashes(&self) -> Vec<LauncherImageHash> {
        self.allowed_launcher_images.launcher_hashes()
    }

    /// Casts a vote for adding or removing an OS measurement.
    pub fn vote_measurement(
        &mut self,
        action: MeasurementVoteAction,
        voter: AuthenticatedAccountId,
    ) -> &VoterSet<AuthenticatedAccountId> {
        self.measurement_votes
            .vote(voter, action.to_proposal_hash())
    }

    /// Adds a new measurement set to the allowed list. Clears measurement votes.
    pub fn add_measurement(&mut self, measurement: ExpectedMeasurements) -> bool {
        self.measurement_votes.clear();
        self.allowed_measurements.add(measurement)
    }

    /// Removes a measurement set from the allowed list. Clears measurement votes.
    pub fn remove_measurement(&mut self, measurement: &ExpectedMeasurements) -> bool {
        self.measurement_votes.clear();
        self.allowed_measurements.remove(measurement)
    }

    /// Returns all allowed OS measurements.
    pub fn get_allowed_measurements(&self) -> Vec<ExpectedMeasurements> {
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
    /// [`crate::MpcContract::clean_invalid_attestations`].
    pub fn clean_non_participant_votes(&mut self, participants: &Participants) {
        self.votes
            .retain_votes(|voter: &AuthenticatedAccountId| participants.is_participant(voter));
        self.launcher_votes
            .retain_votes(|voter: &AuthenticatedAccountId| participants.is_participant(voter));
        self.measurement_votes
            .retain_votes(|voter: &AuthenticatedAccountId| participants.is_participant(voter));
    }

    /// Returns the owner of each removed node, so the caller can give back the attestation-storage
    /// grant it consumed.
    pub(crate) fn clean_invalid_attestations(
        &mut self,
        tee_upgrade_deadline_duration: Duration,
        max_scan: usize,
        is_in_use: impl Fn(&Node) -> bool,
    ) -> Vec<AccountId> {
        // Materialize candidates before any mutation to avoid iterator invalidation.
        let removable_tls_keys: Vec<Ed25519PublicKey> = self
            .nodes
            .iter()
            .take(max_scan)
            .filter(|(_, node)| {
                !self.has_valid_attestation(node, tee_upgrade_deadline_duration) && !is_in_use(node)
            })
            .map(|(tls_pk, _)| tls_pk.clone())
            .collect();

        removable_tls_keys
            .into_iter()
            .filter_map(|tls_pk| self.nodes.remove(&tls_pk))
            .map(|node| node.owner)
            .collect()
    }

    /// Fails if another account's node is stored under the TLS key. Checking only the stored node
    /// is enough because of the invariant on [`Self::nodes`]; attestation submission covers its
    /// exception for initial participants by also checking the participant set.
    pub(crate) fn assert_tls_key_claimable(
        &self,
        account_id: &AccountId,
        tls_public_key: &Ed25519PublicKey,
    ) -> Result<(), AttestationSubmissionError> {
        if self
            .nodes
            .get(tls_public_key)
            .is_some_and(|node| node.owner != *account_id)
        {
            return Err(AttestationSubmissionError::TlsKeyOwnedByOtherAccount);
        }
        Ok(())
    }

    pub fn get_tee_accounts(&self) -> Vec<dtos::NodeInfo> {
        self.nodes
            .values()
            .map(IntoInterfaceType::into_dto_type)
            .collect()
    }

    pub(crate) fn node_of(
        &self,
        account_id: &AccountId,
        tls_public_key: &Ed25519PublicKey,
    ) -> Option<&Node> {
        self.nodes
            .get(tls_public_key)
            .filter(|node| node.owner == *account_id)
    }

    pub(crate) fn node_signed_by(
        &self,
        account_id: &AccountId,
        tls_public_key: &Ed25519PublicKey,
        signer_public_key: &near_sdk::PublicKey,
    ) -> Option<&Node> {
        let signer_public_key = Ed25519PublicKey::try_from(signer_public_key).ok()?;
        self.node_of(account_id, tls_public_key)
            .filter(|node| node.signer_public_key == signer_public_key)
    }
}

/// An MPC node, stored under its TLS key. An account can own many nodes; as a participant it
/// uses its current node and, while migrating, the node it migrates to.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct Node {
    pub(crate) owner: AccountId,
    pub(crate) tls_public_key: Ed25519PublicKey,
    pub(crate) signer_public_key: Ed25519PublicKey,
    pub(crate) attestation: VerifiedAttestation,
    /// Block time at which this entry was last stored, restamped by every accepted submission.
    pub(crate) attestation_accepted_at_seconds: u64,
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
    log!("attestation accepted with {total} informational advisory ID(s): {shown}{suffix}");
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::dto_mapping::IntoContractType;
    use crate::primitives::test_utils::{
        authenticate_account_as, bogus_ed25519_public_key, create_node, gen_account_id,
        gen_participant, gen_participants, node_for,
    };
    use crate::tee::{
        proposal::get_docker_compose_hash,
        test_utils::{
            dstack_fixture_node, set_block_secs, set_block_timestamp, whitelist_dstack_measurements,
        },
    };
    use mpc_attestation::attestation::MockAttestation;
    use mpc_primitives::hash::{
        KeyProviderEventDigest, LauncherImageHash, MrtdHash, NodeImageHash, Rtmr0Hash, Rtmr1Hash,
        Rtmr2Hash,
    };
    use near_sdk::{env, test_utils::VMContextBuilder, testing_env};
    use rstest::rstest;
    use std::time::Duration;
    use std::{
        assert_matches,
        collections::{BTreeMap, BTreeSet},
    };
    use test_utils::attestation::{
        VALID_ATTESTATION_TIMESTAMP, collateral_dates, image_digest, launcher_compose_digest,
        launcher_image_hash, mock_expiring_at, mock_tcb_info, verified_report,
    };

    #[test]
    fn clean_non_participant_votes__should_not_touch_attestations() {
        // Given
        let mut tee_state = TeeState::default();
        let non_participant = node_for(&gen_account_id());
        submit_mock(&mut tee_state, &non_participant, MockAttestation::Valid).unwrap();

        // When
        tee_state.clean_non_participant_votes(&gen_participants(3));

        // Then
        assert_eq!(tee_state.get_tee_accounts(), vec![non_participant]);
    }

    #[test]
    fn clean_invalid_attestations__should_remove_expired_entries() {
        // Given: one fresh and one already-expired attestation stored.
        const FRESH_EXPIRY_SECONDS: u64 = 10_000;
        const STALE_EXPIRY_SECONDS: u64 = 1_000;
        const NOW_SECONDS: u64 = 5_000;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();

        let fresh_node = node_for(&"fresh.near".parse().unwrap());
        let stale_node = node_for(&"stale.near".parse().unwrap());

        let fresh = mock_expiring_at(FRESH_EXPIRY_SECONDS).into_contract_type();
        let stale = mock_expiring_at(STALE_EXPIRY_SECONDS).into_contract_type();
        submit_mock(&mut tee_state, &fresh_node, fresh).unwrap();
        submit_mock(&mut tee_state, &stale_node, stale).unwrap();

        // When: the clock advances past the stale entry's expiry and cleanup runs.
        set_block_timestamp(NOW_SECONDS * 1_000_000_000);
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100, |_| false);

        // Then: only the expired entry is removed.
        assert_eq!(removed, vec![stale_node.account_id]);
        assert_eq!(tee_state.get_tee_accounts(), vec![fresh_node]);
    }

    #[test]
    fn clean_invalid_attestations__should_remove_accepted_mock_valid_after_expiry() {
        // Given: a `MockAttestation::Valid` accepted via the normal submission path.
        // It must be stamped with an expiry so it can eventually be cleaned up.
        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());
        submit_mock(&mut tee_state, &node, MockAttestation::Valid).unwrap();

        // Before expiry: cleanup keeps the entry.
        assert!(
            tee_state
                .clean_invalid_attestations(Duration::from_secs(0), 100, |_| false)
                .is_empty()
        );

        // When: the clock advances past the stamped expiry window and cleanup runs.
        set_block_timestamp((attestation::MOCK_EXPIRATION_DURATION_SECONDS + 1) * 1_000_000_000);
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100, |_| false);

        // Then: the previously uncleanable mock entry is removed.
        assert_eq!(removed, vec![node.account_id]);
        assert!(tee_state.nodes.is_empty());
    }

    #[test]
    fn verify_and_store_mock__should_cap_a_submitter_supplied_expiry_beyond_the_default() {
        // Given: a mock submitted with an expiry far beyond the contract's default
        // window. A submitter must not be able to extend its lifetime past the cap.
        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());
        let oversized = mock_expiring_at(attestation::MOCK_EXPIRATION_DURATION_SECONDS * 10)
            .into_contract_type();
        submit_mock(&mut tee_state, &node, oversized).unwrap();

        // When: the clock advances just past the contract's default window, well before the
        // submitter's requested expiry.
        set_block_timestamp((attestation::MOCK_EXPIRATION_DURATION_SECONDS + 1) * 1_000_000_000);
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100, |_| false);

        // Then: the entry is cleaned, so the submitted expiry was capped at the default.
        assert_eq!(removed, vec![node.account_id]);
        assert!(tee_state.nodes.is_empty());
    }

    #[test]
    fn clean_invalid_attestations__should_honor_max_scan() {
        // Given: ten expired attestations stored.
        const EXPIRY_SECONDS: u64 = 1_000;
        const NOW_SECONDS: u64 = 5_000;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();

        let expired = mock_expiring_at(EXPIRY_SECONDS).into_contract_type();

        for idx in 0..10 {
            let node = node_for(&format!("node{idx}.near").parse().unwrap());
            submit_mock(&mut tee_state, &node, expired.clone()).unwrap();
        }
        assert_eq!(tee_state.nodes.len(), 10);

        set_block_timestamp(NOW_SECONDS * 1_000_000_000);

        // When: cleanup is called repeatedly with a scan limit of 3 until no progress is made.
        let mut total_removed = 0;
        loop {
            let removed =
                tee_state.clean_invalid_attestations(Duration::from_secs(0), 3, |_| false);
            total_removed += removed.len();
            if removed.is_empty() {
                break;
            }
            assert!(removed.len() <= 3);
        }

        // Then: all ten entries are removed across multiple calls, each bounded by max_scan.
        assert_eq!(total_removed, 10);
        assert_eq!(tee_state.nodes.len(), 0);
    }

    #[test]
    fn clean_invalid_attestations__should_keep_valid_entries() {
        // Given: a single attestation whose expiry is in the future.
        const FUTURE_EXPIRY_SECONDS: u64 = 10_000;

        testing_env!(VMContextBuilder::new().block_timestamp(0).build());

        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());
        let attestation = mock_expiring_at(FUTURE_EXPIRY_SECONDS).into_contract_type();
        submit_mock(&mut tee_state, &node, attestation).unwrap();

        // When: cleanup runs while the attestation is still valid.
        let removed = tee_state.clean_invalid_attestations(Duration::from_secs(0), 100, |_| false);

        // Then: nothing is removed.
        assert!(removed.is_empty());
        assert_eq!(tee_state.get_tee_accounts(), vec![node]);
    }

    #[test]
    fn clean_invalid_attestations__should_keep_an_invalid_node_in_use() {
        // Given
        set_block_secs(0);
        let mut tee_state = TeeState::default();
        let in_use = node_for(&"alice.near".parse().unwrap());
        let unused = node_for(&"bob.near".parse().unwrap());
        for node in [&in_use, &unused] {
            submit_mock(&mut tee_state, node, MockAttestation::Valid).unwrap();
        }
        set_block_secs(attestation::MOCK_EXPIRATION_DURATION_SECONDS + 1);

        // When
        let removed = tee_state.clean_invalid_attestations(Duration::ZERO, 100, |node| {
            node.tls_public_key == in_use.tls_public_key
        });

        // Then
        assert_eq!(removed, vec![unused.account_id]);
        assert_eq!(tee_state.get_tee_accounts(), vec![in_use]);
    }

    #[test]
    fn verify_and_store_mock__should_report_only_the_first_submission_as_a_new_node() {
        // Given
        let mut tee_state = TeeState::default();
        let node = node_for(&"dave.near".parse().unwrap());
        let first_submission = submit_mock(&mut tee_state, &node, MockAttestation::Valid);

        // When
        let resubmission = submit_mock(&mut tee_state, &node, MockAttestation::Valid);

        // Then
        assert_eq!(first_submission, Ok(true));
        assert_eq!(resubmission, Ok(false));
    }

    #[test]
    fn verify_and_store_mock__should_store_the_submitted_node() {
        // Given
        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());

        // When
        submit_mock(&mut tee_state, &node, MockAttestation::Valid).unwrap();

        // Then
        assert_eq!(tee_state.get_tee_accounts(), vec![node]);
    }

    #[rstest]
    #[case::before_expiry(attestation::MOCK_EXPIRATION_DURATION_SECONDS - 1, true)]
    #[case::after_expiry(attestation::MOCK_EXPIRATION_DURATION_SECONDS + 1, false)]
    fn has_valid_attestation__should_hold_until_the_attestation_expires(
        #[case] now_seconds: u64,
        #[case] expected: bool,
    ) {
        // Given
        set_block_secs(0);
        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());
        submit_mock(&mut tee_state, &node, MockAttestation::Valid).unwrap();
        let stored = tee_state.nodes.get(&node.tls_public_key).unwrap();

        // When
        set_block_secs(now_seconds);
        let is_valid = tee_state.has_valid_attestation(stored, Duration::ZERO);

        // Then
        assert_eq!(is_valid, expected);
    }

    const TEST_GRACE_PERIOD: Duration = Duration::from_secs(10);

    #[test]
    fn validate_tee_returns_full_when_all_participants_have_valid_attestations() {
        // Given
        let participants = gen_participants(3);
        let mut tee_state = TeeState::with_mocked_participant_attestations(&participants);

        // When
        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        // Then
        assert_matches!(validation_result, TeeValidationResult::Full);
    }

    const LAUNCHER_TTL: Duration = Duration::from_secs(100);
    const OLD_LAUNCHER_ADDED_AT_SECS: u64 = 1;
    const NEWEST_LAUNCHER_ADDED_AT_SECS: u64 = OLD_LAUNCHER_ADDED_AT_SECS + 1;
    const VERY_FAR_IN_FUTURE_SECS: u64 = 1_000_000;

    fn after_retention(added_at_secs: u64) -> u64 {
        added_at_secs + LAUNCHER_TTL.as_secs() + 1
    }

    fn launcher_mock(launcher: &LauncherImageHash, mpc_hash: &NodeImageHash) -> MockAttestation {
        MockAttestation::WithConstraints {
            mpc_docker_image_hash: None,
            launcher_docker_compose_hash: Some(get_docker_compose_hash(launcher, mpc_hash)),
            expiry_timestamp_seconds: Some(VERY_FAR_IN_FUTURE_SECS),
            expected_measurements: None,
        }
    }

    #[test]
    fn remove_unused_launchers__should_keep_launcher_in_use_past_its_retention() {
        // Given
        let participants = gen_participants(1);
        let (account_id, _, participant_info) = participants.participants()[0].clone();
        set_block_secs(OLD_LAUNCHER_ADDED_AT_SECS);
        let mut tee_state = TeeState::default();
        let mpc_hash = NodeImageHash::from([10u8; 32]);
        let adopted = LauncherImageHash::from([1u8; 32]);
        let unused = LauncherImageHash::from([2u8; 32]);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(adopted, &[mpc_hash], LAUNCHER_TTL);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(unused, &[mpc_hash], LAUNCHER_TTL);
        submit_mock(
            &mut tee_state,
            &create_node(&account_id, &participant_info.tls_public_key),
            launcher_mock(&adopted, &mpc_hash),
        )
        .unwrap();

        // When
        set_block_secs(after_retention(OLD_LAUNCHER_ADDED_AT_SECS));
        tee_state.remove_unused_launchers(&participants, LAUNCHER_TTL);

        // Then
        assert_eq!(tee_state.get_allowed_launcher_hashes(), vec![adopted]);
        assert_matches!(
            tee_state.reverify_and_cleanup_participants(&participants, Duration::MAX),
            TeeValidationResult::Full
        );
    }

    #[test]
    fn remove_unused_launchers__should_keep_every_participants_launcher() {
        // Given
        let participants = gen_participants(2);
        set_block_secs(OLD_LAUNCHER_ADDED_AT_SECS);
        let mut tee_state = TeeState::default();
        let mpc_hash = NodeImageHash::from([10u8; 32]);
        let used = vec![
            LauncherImageHash::from([1u8; 32]),
            LauncherImageHash::from([2u8; 32]),
        ];
        let unused = LauncherImageHash::from([3u8; 32]);
        for ((account_id, _, participant_info), launcher) in
            participants.participants().iter().zip(&used)
        {
            tee_state
                .allowed_launcher_images
                .add_or_refresh(*launcher, &[mpc_hash], LAUNCHER_TTL);
            submit_mock(
                &mut tee_state,
                &create_node(account_id, &participant_info.tls_public_key),
                launcher_mock(launcher, &mpc_hash),
            )
            .unwrap();
        }
        tee_state
            .allowed_launcher_images
            .add_or_refresh(unused, &[mpc_hash], LAUNCHER_TTL);

        // When
        set_block_secs(after_retention(OLD_LAUNCHER_ADDED_AT_SECS));
        tee_state.remove_unused_launchers(&participants, LAUNCHER_TTL);

        // Then
        assert_eq!(tee_state.get_allowed_launcher_hashes(), used);
    }

    /// An older launcher attested by the given node, and a newer unused one.
    fn tee_state_with_old_launcher_attested_by(
        node: dtos::NodeInfo,
    ) -> (TeeState, LauncherImageHash) {
        let mut tee_state = TeeState::default();
        let mpc_hash = NodeImageHash::from([10u8; 32]);
        let old = LauncherImageHash::from([1u8; 32]);
        let newest = LauncherImageHash::from([2u8; 32]);
        set_block_secs(OLD_LAUNCHER_ADDED_AT_SECS);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(old, &[mpc_hash], LAUNCHER_TTL);
        submit_mock(&mut tee_state, &node, launcher_mock(&old, &mpc_hash)).unwrap();
        set_block_secs(NEWEST_LAUNCHER_ADDED_AT_SECS);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(newest, &[mpc_hash], LAUNCHER_TTL);
        (tee_state, newest)
    }

    #[test]
    fn remove_unused_launchers__should_not_count_attestation_of_non_participant() {
        // Given
        let participants = gen_participants(1);
        let (mut tee_state, newest) =
            tee_state_with_old_launcher_attested_by(node_for(&gen_account_id()));

        // When
        set_block_secs(after_retention(NEWEST_LAUNCHER_ADDED_AT_SECS));
        tee_state.remove_unused_launchers(&participants, LAUNCHER_TTL);

        // Then
        assert_eq!(tee_state.get_allowed_launcher_hashes(), vec![newest]);
    }

    #[test]
    fn remove_unused_launchers__should_not_count_attestation_of_another_account() {
        // Given
        let participants = gen_participants(1);
        let (_, _, participant_info) = participants.participants()[0].clone();
        let (mut tee_state, newest) = tee_state_with_old_launcher_attested_by(create_node(
            &gen_account_id(),
            &participant_info.tls_public_key,
        ));

        // When
        set_block_secs(after_retention(NEWEST_LAUNCHER_ADDED_AT_SECS));
        tee_state.remove_unused_launchers(&participants, LAUNCHER_TTL);

        // Then
        assert_eq!(tee_state.get_allowed_launcher_hashes(), vec![newest]);
    }

    #[test]
    fn reverify_and_cleanup_participants__should_not_remove_lapsed_launchers() {
        // Given
        let mut tee_state = TeeState::default();
        let mpc_hash = NodeImageHash::from([10u8; 32]);
        let launchers = vec![
            LauncherImageHash::from([1u8; 32]),
            LauncherImageHash::from([2u8; 32]),
        ];
        set_block_secs(OLD_LAUNCHER_ADDED_AT_SECS);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(launchers[0], &[mpc_hash], LAUNCHER_TTL);
        set_block_secs(NEWEST_LAUNCHER_ADDED_AT_SECS);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(launchers[1], &[mpc_hash], LAUNCHER_TTL);

        // When
        set_block_secs(after_retention(NEWEST_LAUNCHER_ADDED_AT_SECS));
        let _ = tee_state.reverify_and_cleanup_participants(&gen_participants(1), Duration::MAX);

        // Then
        assert_eq!(tee_state.get_allowed_launcher_hashes(), launchers);
    }

    #[test]
    fn validate_tee_returns_partial_when_participant_has_no_attestation() {
        // Given
        let participants = gen_participants(3);
        let attested = participants.subset(0..2);
        let mut tee_state = TeeState::with_mocked_participant_attestations(&attested);

        // When
        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        // Then
        assert_matches!(
            validation_result,
            TeeValidationResult::Partial { participants_with_valid_attestation }
                if participants_with_valid_attestation == attested
        );
    }

    #[test]
    fn validate_tee_returns_partial_when_attestation_is_expired() {
        // Given
        let current_time_secs = env::block_timestamp() / 1_000_000_000;
        let expiry_time_secs = current_time_secs + TEST_GRACE_PERIOD.as_secs();
        let participants = gen_participants(3);
        let attested = participants.subset(0..2);
        let mut tee_state = TeeState::with_mocked_participant_attestations(&attested);
        let (account_id, _, participant_info) = &participants.participants()[2];
        let node = create_node(account_id, &participant_info.tls_public_key);
        let expiring_attestation = mock_expiring_at(expiry_time_secs).into_contract_type();
        submit_mock(&mut tee_state, &node, expiring_attestation).unwrap();
        set_block_timestamp((expiry_time_secs + 1) * 1_000_000_000);

        // When
        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        // Then
        assert_matches!(
            validation_result,
            TeeValidationResult::Partial { participants_with_valid_attestation }
                if participants_with_valid_attestation == attested
        );
    }

    #[test]
    fn reverify_and_cleanup_participants__should_reject_a_participant_whose_tls_key_is_attested_to_another_account()
     {
        // Given
        let participants = gen_participants(3);
        let attested = participants.subset(0..2);
        let mut tee_state = TeeState::with_mocked_participant_attestations(&attested);
        let impersonated_tls_key = &participants.participants()[2].2.tls_public_key;
        let imposter = create_node(&"imposter.near".parse().unwrap(), impersonated_tls_key);
        submit_mock(&mut tee_state, &imposter, MockAttestation::Valid).unwrap();

        // When
        let validation_result =
            tee_state.reverify_and_cleanup_participants(&participants, TEST_GRACE_PERIOD);

        // Then
        assert_matches!(
            validation_result,
            TeeValidationResult::Partial { participants_with_valid_attestation }
                if participants_with_valid_attestation == attested
        );
    }

    #[test]
    fn verify_and_store_mock__should_reject_tls_key_owned_by_other_account() {
        // Given
        let mut tee_state = TeeState::default();
        let alice_node = node_for(&"alice.near".parse().unwrap());
        submit_mock(&mut tee_state, &alice_node, MockAttestation::Valid).unwrap();
        let attacker_node = create_node(&"bob.near".parse().unwrap(), &alice_node.tls_public_key);

        // When
        let result = submit_mock(&mut tee_state, &attacker_node, MockAttestation::Valid);

        // Then
        assert_matches!(
            result,
            Err(AttestationSubmissionError::TlsKeyOwnedByOtherAccount)
        );
        assert_eq!(tee_state.get_tee_accounts(), vec![alice_node]);
    }

    #[test]
    fn verify_and_store_mock__should_allow_same_account_to_update_its_own_entry() {
        // Given
        let mut tee_state = TeeState::default();
        let initial_node = node_for(&"alice.near".parse().unwrap());
        submit_mock(&mut tee_state, &initial_node, MockAttestation::Valid).unwrap();
        let rotated_node = dtos::NodeInfo {
            account_public_key: bogus_ed25519_public_key(),
            ..initial_node
        };

        // When
        let result = submit_mock(&mut tee_state, &rotated_node, MockAttestation::Valid);

        // Then
        assert_eq!(result, Ok(false));
        assert_eq!(tee_state.get_tee_accounts(), vec![rotated_node]);
    }

    #[test]
    fn verify_and_store_mock__should_reject_invalid_attestations() {
        // Given
        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());

        // When
        let result = submit_mock(&mut tee_state, &node, MockAttestation::Invalid);

        // Then
        assert_matches!(
            result,
            Err(AttestationSubmissionError::InvalidAttestation(_))
        );
        assert!(tee_state.nodes.is_empty());
    }

    #[test]
    fn verify_and_store_dstack__should_reject_and_store_nothing_when_post_dcap_checks_fail() {
        // Given
        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());

        // When
        let result = tee_state.verify_and_store_dstack(
            node,
            &mock_tcb_info(),
            &verified_report(),
            &collateral_dates(),
            Duration::MAX,
        );

        // Then
        assert_matches!(
            result,
            Err(AttestationSubmissionError::InvalidAttestation(_))
        );
        assert!(tee_state.nodes.is_empty());
    }

    /// A [`TeeState`] that accepts the fixture attestation, and the node it attests.
    fn tee_state_accepting_the_fixture() -> (TeeState, dtos::NodeInfo) {
        set_block_timestamp(VALID_ATTESTATION_TIMESTAMP * 1_000_000_000);
        let mut tee_state = TeeState::default();
        whitelist_dstack_measurements(
            &mut tee_state,
            image_digest(),
            launcher_image_hash(),
            Some(launcher_compose_digest()),
        );
        (tee_state, dstack_fixture_node())
    }

    #[test]
    fn verify_and_store_dstack__should_store_when_all_post_dcap_checks_pass() {
        // Given
        let (mut tee_state, node) = tee_state_accepting_the_fixture();

        // When
        let result = tee_state.verify_and_store_dstack(
            node.clone(),
            &mock_tcb_info(),
            &verified_report(),
            &collateral_dates(),
            Duration::MAX,
        );

        // Then
        assert_eq!(result, Ok(true));
        let stored = tee_state
            .nodes
            .get(&node.tls_public_key)
            .expect("attestation must be stored");
        assert_eq!(
            stored.attestation_accepted_at_seconds,
            VALID_ATTESTATION_TIMESTAMP
        );
        assert_matches!(
            &stored.attestation,
            VerifiedAttestation::Dstack(attestation)
                if attestation.expiry_timestamp_seconds == collateral_dates().earliest_expiration_date
        );
        assert_eq!(tee_state.get_tee_accounts(), vec![node]);
    }

    #[test]
    fn verify_and_store_dstack__should_overwrite_the_expiry_with_an_earlier_one() {
        // Given
        let (mut tee_state, node) = tee_state_accepting_the_fixture();
        tee_state
            .verify_and_store_dstack(
                node.clone(),
                &mock_tcb_info(),
                &verified_report(),
                &collateral_dates(),
                Duration::MAX,
            )
            .unwrap();
        let earlier_expiry = collateral_dates().earliest_expiration_date - 1;
        let older_collateral_dates = CollateralDates {
            earliest_expiration_date: earlier_expiry,
            ..collateral_dates()
        };

        // When
        let result = tee_state.verify_and_store_dstack(
            node.clone(),
            &mock_tcb_info(),
            &verified_report(),
            &older_collateral_dates,
            Duration::MAX,
        );

        // Then
        assert_eq!(result, Ok(false));
        let stored = tee_state
            .nodes
            .get(&node.tls_public_key)
            .expect("attestation must be stored");
        assert_matches!(
            &stored.attestation,
            VerifiedAttestation::Dstack(attestation)
                if attestation.expiry_timestamp_seconds == earlier_expiry
        );
    }

    /// Stale code-hash votes from removed participants must not count toward
    /// quorum after resharing.
    ///
    /// Scenario (N=5, T=3):
    /// 1. P0, P1 and P2 vote for a node image hash before resharing.
    /// 2. Resharing removes P0 and P1. New set: {P2, P3, P4}.
    /// 3. clean_non_participant_votes keeps only P2's vote — 1 vote toward quorum, not 3.
    #[test]
    fn clean_non_participant_votes__should_keep_only_votes_of_current_participants() {
        // Given
        let mut all_participants = Participants::new();
        let mut account_ids = Vec::new();
        for i in 0..5 {
            let (account_id, info) = gen_participant(i);
            account_ids.push(account_id.clone());
            all_participants.insert(account_id, info).unwrap();
        }
        let voters: Vec<_> = account_ids[..3]
            .iter()
            .map(|account_id| authenticate_account_as(account_id, &all_participants))
            .collect();
        let node_image_hash = NodeImageHash::from([0xAA; 32]);
        let mut tee_state = TeeState::default();
        for voter in &voters {
            tee_state.vote_mpc_node_manifest_digest(node_image_hash, voter.clone());
        }
        assert_eq!(
            tee_state.votes.all(),
            BTreeMap::from([(
                node_image_hash.to_proposal_hash(),
                voters.iter().cloned().collect::<BTreeSet<_>>(),
            )])
        );
        let new_participants = all_participants.subset(2..5);

        // When
        tee_state.clean_non_participant_votes(&new_participants);

        // Then
        assert_eq!(
            tee_state.votes.all(),
            BTreeMap::from([(
                node_image_hash.to_proposal_hash(),
                BTreeSet::from([voters[2].clone()]),
            )])
        );
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

        // P0 votes for a launcher hash and an OS measurement
        let voter = authenticate_account_as(&account_ids[0], &all_participants);
        let launcher_action = LauncherVoteAction::Add(LauncherImageHash::from([0xBB; 32]));
        tee_state.vote_launcher(launcher_action, voter.clone());
        let measurement_action = MeasurementVoteAction::Add(ExpectedMeasurements {
            mrtd: MrtdHash::from([0xCC; 48]),
            rtmr0: Rtmr0Hash::from([0xCC; 48]),
            rtmr1: Rtmr1Hash::from([0xCC; 48]),
            rtmr2: Rtmr2Hash::from([0xCC; 48]),
            key_provider_event_digest: KeyProviderEventDigest::from([0xCC; 48]),
        });
        tee_state.vote_measurement(measurement_action, voter);

        assert_eq!(tee_state.launcher_votes.all().len(), 1);
        assert_eq!(tee_state.measurement_votes.all().len(), 1);

        // New participant set excludes P0
        let new_participants = all_participants.subset(1..3);
        tee_state.clean_non_participant_votes(&new_participants);

        assert!(tee_state.launcher_votes.all().is_empty());
        assert!(tee_state.measurement_votes.all().is_empty());
    }

    #[test]
    fn verify_and_store_mock__should_reject_removed_launcher_hash() {
        // Given
        let participants = gen_participants(1);
        let (account_id, _, participant_info) = participants.participants()[0].clone();
        let node = create_node(&account_id, &participant_info.tls_public_key);
        let mpc_hash = NodeImageHash::from([10u8; 32]);
        let removed = LauncherImageHash::from([1u8; 32]);
        let newest = LauncherImageHash::from([2u8; 32]);
        let mut tee_state = TeeState::default();
        set_block_secs(OLD_LAUNCHER_ADDED_AT_SECS);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(removed, &[mpc_hash], LAUNCHER_TTL);
        set_block_secs(NEWEST_LAUNCHER_ADDED_AT_SECS);
        tee_state
            .allowed_launcher_images
            .add_or_refresh(newest, &[mpc_hash], LAUNCHER_TTL);
        set_block_secs(after_retention(OLD_LAUNCHER_ADDED_AT_SECS));
        tee_state.remove_unused_launchers(&participants, LAUNCHER_TTL);

        // When
        let result = submit_mock(&mut tee_state, &node, launcher_mock(&removed, &mpc_hash));

        // Then
        assert_matches!(
            result,
            Err(AttestationSubmissionError::InvalidAttestation(_))
        );
    }

    const ACCEPTED_AT_SECONDS: u64 = 1_800_000_000;
    const RESUBMITTED_AT_SECONDS: u64 = ACCEPTED_AT_SECONDS + 3600;

    fn stamped_accepted_at(tee_state: &TeeState, node: &dtos::NodeInfo) -> u64 {
        tee_state
            .nodes
            .get(&node.tls_public_key)
            .expect("the attestation was stored")
            .attestation_accepted_at_seconds
    }

    fn submit_mock(
        tee_state: &mut TeeState,
        node: &dtos::NodeInfo,
        mock: MockAttestation,
    ) -> Result<bool, AttestationSubmissionError> {
        tee_state.verify_and_store_mock(node.clone(), mock, Duration::from_secs(0))
    }

    #[test]
    fn verify_and_store_mock__should_stamp_the_block_time() {
        // Given
        set_block_secs(ACCEPTED_AT_SECONDS);
        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());

        // When
        submit_mock(&mut tee_state, &node, MockAttestation::Valid).unwrap();

        // Then
        assert_eq!(stamped_accepted_at(&tee_state, &node), ACCEPTED_AT_SECONDS);
    }

    #[rstest]
    #[case::rejected(MockAttestation::Invalid, ACCEPTED_AT_SECONDS)]
    #[case::accepted_again(MockAttestation::Valid, RESUBMITTED_AT_SECONDS)]
    fn verify_and_store_mock__should_restamp_only_an_accepted_resubmission(
        #[case] resubmitted: MockAttestation,
        #[case] expected_stamp: u64,
    ) {
        // Given: an entry stored by an accepted submission
        set_block_secs(ACCEPTED_AT_SECONDS);
        let mut tee_state = TeeState::default();
        let node = node_for(&"alice.near".parse().unwrap());
        submit_mock(&mut tee_state, &node, MockAttestation::Valid).unwrap();

        // When: the same node submits again an hour later
        set_block_secs(RESUBMITTED_AT_SECONDS);
        let _ = submit_mock(&mut tee_state, &node, resubmitted);

        // Then
        assert_eq!(stamped_accepted_at(&tee_state, &node), expected_stamp);
    }
}
