use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types as dtos;
use near_sdk::{env::sha256, log, near};
use std::{collections::BTreeMap, time::Duration};

use crate::primitives::{
    key_state::AuthenticatedParticipantId, participants::Participants, time::Timestamp,
};

pub use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash, NodeImageHash};

/// Docker Compose YAML template for the launcher. Compose hashes are derived on-chain as
/// `sha256(template(launcher_hash, mpc_hash))`. Placeholders:
/// - `{{LAUNCHER_IMAGE_HASH}}`: the launcher Docker image hash
/// - `{{DEFAULT_IMAGE_DIGEST_HASH}}`: the MPC node Docker image hash
const LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE: &str =
    include_str!("../../assets/launcher_docker_compose.yaml.template");

/// Tracks votes to add whitelisted TEE code hashes. Each participant can at any given time vote for
/// a code hash to add.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeHashesVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, NodeImageHash>,
}

impl CodeHashesVotes {
    /// Casts a vote for the proposal and returns the total number of participants who have voted
    /// for the same code hash. If the participant already voted, their previous vote is replaced.
    pub fn vote(
        &mut self,
        proposal: NodeImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant.clone(), proposal)
            .is_some()
        {
            log!("removed old vote for signer");
        }
        let total = self.count_votes(&proposal);
        log!("total votes for proposal: {}", total);
        total
    }

    /// Counts the total number of participants who have voted for the given code hash.
    fn count_votes(&self, proposal: &NodeImageHash) -> u64 {
        self.proposal_by_account
            .values()
            .filter(|&prop| prop == proposal)
            .count() as u64
    }

    /// Clears all proposals.
    pub fn clear_votes(&mut self) {
        self.proposal_by_account.clear();
    }

    /// Returns a new `CodeHashesVotes` containing only votes from current participants.
    pub fn get_remaining_votes(&self, participants: &Participants) -> Self {
        let remaining = self
            .proposal_by_account
            .iter()
            .filter(|(participant_id, _)| {
                participants.is_participant_given_participant_id(&participant_id.get())
            })
            .map(|(participant_id, vote)| (participant_id.clone(), *vote))
            .collect();
        CodeHashesVotes {
            proposal_by_account: remaining,
        }
    }
}

/// The action a participant is voting for on a launcher image hash.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LauncherVoteAction {
    Add(LauncherImageHash),
    Remove(LauncherImageHash),
}

/// Tracks votes for adding or removing launcher image hashes.
/// Each participant can have at most one active vote at a time.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LauncherHashVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, LauncherVoteAction>,
}

impl LauncherHashVotes {
    /// Casts a vote for the given action and returns the total number of participants
    /// who have voted for the same action. Replaces any previous vote by this participant.
    pub fn vote(
        &mut self,
        action: LauncherVoteAction,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        if self
            .vote_by_account
            .insert(participant.clone(), action.clone())
            .is_some()
        {
            log!("removed old launcher vote for signer");
        }
        let total = self.count_votes(&action);
        log!("total launcher votes for action: {}", total);
        total
    }

    /// Counts the total number of participants who have voted for the given action.
    fn count_votes(&self, action: &LauncherVoteAction) -> u64 {
        u64::try_from(
            self.vote_by_account
                .values()
                .filter(|a| *a == action)
                .count(),
        )
        .expect("participant count should not overflow u64")
    }

    /// Clears all launcher votes.
    pub fn clear_votes(&mut self) {
        self.vote_by_account.clear();
    }

    /// Returns a new `LauncherHashVotes` containing only votes from current participants.
    pub fn get_remaining_votes(&self, participants: &Participants) -> Self {
        let remaining = self
            .vote_by_account
            .iter()
            .filter(|(participant_id, _)| {
                participants.is_participant_given_participant_id(&participant_id.get())
            })
            .map(|(participant_id, vote)| (participant_id.clone(), vote.clone()))
            .collect();
        LauncherHashVotes {
            vote_by_account: remaining,
        }
    }
}

/// An allowed Docker image configuration entry containing the MPC image hash
/// and when it was added to the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
struct WhitelistedMpcDockerImageHash {
    image_hash: NodeImageHash,
    added: Timestamp,
}

fn make_dtos_docker_image_hash(
    prev: &WhitelistedMpcDockerImageHash,
    next: &WhitelistedMpcDockerImageHash,
    tee_upgrade_deadline_duration: Duration,
) -> dtos::AllowedMpcDockerImageHash {
    dtos::AllowedMpcDockerImageHash {
        image_hash: prev.image_hash,
        // A timestamp overflow means the grace period never ends, so the entry
        // never expires.
        expiry_timestamp_seconds: next
            .added
            .checked_add(tee_upgrade_deadline_duration)
            .map(Timestamp::as_secs),
    }
}

/// Collection of whitelisted Docker code hashes that are the only ones MPC nodes are allowed to
/// run.
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(super) struct StoredDockerImageHashes {
    /// Whitelisted code hashes, sorted by when they were added (oldest first). Expired entries are
    /// lazily cleaned up during insertions and TEE validation.
    allowed_tee_proposals: Vec<WhitelistedMpcDockerImageHash>,
}

impl StoredDockerImageHashes {
    /// Returns the list of currently allowed docker image hashes, oldest first; the newest entry
    /// has no expiry.
    pub fn allowed_images(
        &self,
        tee_upgrade_deadline_duration: Duration,
    ) -> Vec<dtos::AllowedMpcDockerImageHash> {
        let valid = self
            .allowed_tee_proposals
            .get(self.cutoff_index(tee_upgrade_deadline_duration)..)
            .unwrap_or(&[]);

        let Some(latest) = valid.last() else {
            return Vec::new();
        };

        let mut res: Vec<dtos::AllowedMpcDockerImageHash> = valid
            .windows(2)
            .map(|window| {
                let [prev, next] = window else {
                    unreachable!("windows(2) always yields two-element slices")
                };
                make_dtos_docker_image_hash(prev, next, tee_upgrade_deadline_duration)
            })
            .collect();
        res.push(dtos::AllowedMpcDockerImageHash {
            image_hash: latest.image_hash,
            expiry_timestamp_seconds: None,
        });
        res
    }

    /// Index of the oldest still-valid entry, as of the current block time.
    fn cutoff_index(&self, tee_upgrade_deadline_duration: Duration) -> usize {
        let current_time = Timestamp::now();
        self.allowed_tee_proposals
            .iter()
            .rposition(|allowed_docker_image| {
                let Some(grace_period_deadline) = allowed_docker_image
                    .added
                    .checked_add(tee_upgrade_deadline_duration)
                else {
                    log!("Error: timestamp overflowed when calculating grace_period_deadline.");
                    return true;
                };
                // if the grace period for this docker hash is in the past, then older hashes are no longer accepted
                grace_period_deadline < current_time
            })
            .unwrap_or(0)
    }

    /// Removes all expired code hashes and returns the number of removed entries.
    /// Ensures that at least one (the latest) proposal always remains in the whitelist.
    pub fn cleanup_expired_hashes(&mut self, tee_upgrade_deadline_duration: Duration) {
        let cutoff_index = self.cutoff_index(tee_upgrade_deadline_duration);
        self.allowed_tee_proposals.drain(..cutoff_index);
    }

    /// Inserts a new code hash into the list after cleaning expired entries. Maintains the sorted
    /// order by `added` (ascending).
    pub fn insert(&mut self, code_hash: NodeImageHash, tee_upgrade_deadline_duration: Duration) {
        self.cleanup_expired_hashes(tee_upgrade_deadline_duration);

        // Remove the old entry if it exists
        if let Some(pos) = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| entry.image_hash == code_hash)
        {
            self.allowed_tee_proposals.remove(pos);
        }

        let new_entry = WhitelistedMpcDockerImageHash {
            image_hash: code_hash,
            added: Timestamp::now(),
        };

        // Find the correct position to maintain sorted order by `added`
        let insert_index = self
            .allowed_tee_proposals
            .iter()
            // strictly less, `<`, such that new entries take higher precedence
            // if two entries have the exact same time stamp.
            .rposition(|entry| new_entry.added < entry.added)
            .unwrap_or(self.allowed_tee_proposals.len());

        self.allowed_tee_proposals.insert(insert_index, new_entry);
    }

    /// Returns only the image hashes of valid entries.
    pub fn get_image_hashes(&self, tee_upgrade_deadline_duration: Duration) -> Vec<NodeImageHash> {
        self.allowed_images(tee_upgrade_deadline_duration)
            .into_iter()
            .map(|entry| entry.image_hash)
            .collect()
    }
}

/// An allowed launcher image entry containing the launcher image hash and all
/// derived compose hashes (one per allowed MPC image at the time of addition,
/// plus any added later via MPC image votes).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct AllowedLauncherImage {
    pub(crate) launcher_hash: LauncherImageHash,
    pub(crate) compose_hashes: Vec<LauncherDockerComposeHash>,
}

/// Collection of allowed launcher images. Managed via voting (add requires threshold,
/// remove requires unanimity).
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct AllowedLauncherImages {
    entries: Vec<AllowedLauncherImage>,
}

impl AllowedLauncherImages {
    /// Adds a new launcher image hash. Computes compose hashes for the given
    /// set of currently allowed MPC image hashes.
    /// Returns `false` if the launcher hash is already in the allowed list.
    pub fn add(
        &mut self,
        launcher_hash: LauncherImageHash,
        current_mpc_image_hashes: &[NodeImageHash],
    ) -> bool {
        if self
            .entries
            .iter()
            .any(|e| e.launcher_hash == launcher_hash)
        {
            log!("launcher hash already in allowed list");
            return false;
        }

        let compose_hashes: Vec<LauncherDockerComposeHash> = current_mpc_image_hashes
            .iter()
            .map(|mpc_hash| get_docker_compose_hash(&launcher_hash, mpc_hash))
            .collect();

        self.entries.push(AllowedLauncherImage {
            launcher_hash,
            compose_hashes,
        });

        true
    }

    /// Removes a launcher image hash and all its associated compose hashes.
    /// Returns `false` if the launcher hash was not found or if removal would leave the list empty.
    pub fn remove(&mut self, launcher_hash: &LauncherImageHash) -> bool {
        let would_remain = self
            .entries
            .iter()
            .filter(|e| &e.launcher_hash != launcher_hash)
            .count();
        if would_remain == 0 {
            return false;
        }
        let len_before = self.entries.len();
        self.entries.retain(|e| &e.launcher_hash != launcher_hash);
        self.entries.len() < len_before
    }

    /// Adds a compose hash for a new MPC image to all existing launcher entries.
    /// Called when a new MPC image hash is voted in.
    pub fn add_mpc_image_compose_hashes(&mut self, mpc_image_hash: &NodeImageHash) {
        for entry in &mut self.entries {
            let compose_hash = get_docker_compose_hash(&entry.launcher_hash, mpc_image_hash);
            if !entry.compose_hashes.contains(&compose_hash) {
                entry.compose_hashes.push(compose_hash);
            }
        }
    }

    /// Returns all compose hashes across all allowed launcher images (flattened).
    pub fn all_compose_hashes(&self) -> Vec<LauncherDockerComposeHash> {
        self.entries
            .iter()
            .flat_map(|e| e.compose_hashes.iter().cloned())
            .collect()
    }

    /// Returns all allowed launcher image hashes.
    pub fn launcher_hashes(&self) -> Vec<LauncherImageHash> {
        self.entries.iter().map(|e| e.launcher_hash).collect()
    }
}

/// Given a launcher image hash and MPC docker image hash, compute the launcher docker compose hash
/// by filling the template and taking SHA-256.
pub fn get_docker_compose_hash(
    launcher_image_hash: &LauncherImageHash,
    mpc_docker_image_hash: &NodeImageHash,
) -> LauncherDockerComposeHash {
    let filled_yaml = LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE
        .replace("{{LAUNCHER_IMAGE_HASH}}", &launcher_image_hash.as_hex())
        .replace(
            "{{DEFAULT_IMAGE_DIGEST_HASH}}",
            &mpc_docker_image_hash.as_hex(),
        );
    let hash = sha256(filled_yaml.as_bytes());
    assert!(
        hash.len() == 32,
        "Docker compose hash must be 32 bytes long"
    );

    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(&hash);

    LauncherDockerComposeHash::from(hash_arr)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    use super::*;
    const TEST_TEE_UPGRADE_DEADLINE_DURATION: Duration = Duration::from_secs(10 * 24 * 60 * 60); // 10 days
    const SECOND: Duration = Duration::from_secs(1);
    const NANOS_IN_SECOND: u64 = SECOND.as_nanos() as u64;

    fn dummy_code_hash(val: u8) -> NodeImageHash {
        NodeImageHash::from([val; 32])
    }

    fn dummy_launcher_hash(val: u8) -> LauncherImageHash {
        LauncherImageHash::from([val; 32])
    }

    #[test]
    fn test_insert_and_get() {
        let mut allowed = StoredDockerImageHashes::default();
        let mut current_time_nano_seconds = 0;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(current_time_nano_seconds)
                .build()
        );

        // Insert a new proposal
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        current_time_nano_seconds += NANOS_IN_SECOND;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(current_time_nano_seconds)
                .build()
        );

        // Insert the same code hash again
        allowed.insert(
            dummy_code_hash(1),
            TEST_TEE_UPGRADE_DEADLINE_DURATION + SECOND,
        );

        current_time_nano_seconds += NANOS_IN_SECOND;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(current_time_nano_seconds)
                .build()
        );

        // Insert a different code hash
        allowed.insert(
            dummy_code_hash(2),
            TEST_TEE_UPGRADE_DEADLINE_DURATION + 2 * SECOND,
        );

        current_time_nano_seconds += NANOS_IN_SECOND;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(current_time_nano_seconds)
                .build()
        );

        // Get proposals (should return both)
        allowed.cleanup_expired_hashes(TEST_TEE_UPGRADE_DEADLINE_DURATION);
        let proposals: Vec<_> = allowed.allowed_images(TEST_TEE_UPGRADE_DEADLINE_DURATION);
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(1));
        assert_eq!(proposals[1].image_hash, dummy_code_hash(2));
    }

    #[test]
    fn allowed_images__should_report_eviction_time_computed_from_next_newer_entry() {
        // Given: two entries added one second apart.
        let mut allowed = StoredDockerImageHashes::default();
        let first_entry_time = NANOS_IN_SECOND;
        let second_entry_time = 2 * NANOS_IN_SECOND;

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(first_entry_time)
                .build()
        );
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(second_entry_time)
                .build()
        );
        allowed.insert(dummy_code_hash(2), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // When
        let entries = allowed.allowed_images(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // Then: the older entry is evicted when the grace period after the newer entry ends.
        let expected_expiry_seconds =
            second_entry_time / NANOS_IN_SECOND + TEST_TEE_UPGRADE_DEADLINE_DURATION.as_secs();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].image_hash, dummy_code_hash(1));
        assert_eq!(
            entries[0].expiry_timestamp_seconds,
            Some(expected_expiry_seconds)
        );
        assert_eq!(entries[1].image_hash, dummy_code_hash(2));
        assert_eq!(entries[1].expiry_timestamp_seconds, None);
    }

    #[test]
    fn allowed_images__should_return_none_expiry_for_newest_entry() {
        // Given: a single entry.
        let mut allowed = StoredDockerImageHashes::default();
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(NANOS_IN_SECOND)
                .build()
        );
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // When: queried long after its own grace period would have ended.
        testing_env!(VMContextBuilder::new().block_timestamp(u64::MAX).build());
        let entries = allowed.allowed_images(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // Then: the newest (only) entry never expires.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].expiry_timestamp_seconds, None);
    }

    #[test]
    fn allowed_images__should_drop_expired_entries() {
        // Given: two entries where the older one's grace period has ended.
        let mut allowed = StoredDockerImageHashes::default();
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(NANOS_IN_SECOND)
                .build()
        );
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);
        let second_entry_time = 2 * NANOS_IN_SECOND;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(second_entry_time)
                .build()
        );
        allowed.insert(dummy_code_hash(2), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // When: queried past the newer entry's grace deadline.
        let past_grace_deadline = second_entry_time
            + TEST_TEE_UPGRADE_DEADLINE_DURATION.as_nanos() as u64
            + NANOS_IN_SECOND;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(past_grace_deadline)
                .build()
        );
        let entries = allowed.allowed_images(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // Then: only the newest entry remains and it never expires.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].image_hash, dummy_code_hash(2));
        assert_eq!(entries[0].expiry_timestamp_seconds, None);
    }

    #[test]
    fn test_clean_expired() {
        let mut allowed = StoredDockerImageHashes::default();
        let first_entry_time_nano_seconds = NANOS_IN_SECOND;

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(first_entry_time_nano_seconds)
                .build()
        );

        // Insert two proposals at different time intervals
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        let second_entry_time_nano_seconds = first_entry_time_nano_seconds + NANOS_IN_SECOND;
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(second_entry_time_nano_seconds)
                .build()
        );

        allowed.insert(dummy_code_hash(2), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        let first_entry_expiry_time_nanoseconds = second_entry_time_nano_seconds
            + TEST_TEE_UPGRADE_DEADLINE_DURATION.as_nanos() as u64
            + 1;

        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(first_entry_expiry_time_nanoseconds)
                .build()
        );

        allowed.cleanup_expired_hashes(TEST_TEE_UPGRADE_DEADLINE_DURATION);
        let proposals: Vec<_> = allowed.allowed_images(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // Only the second proposal should remain if the first is expired
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(2));

        // Move block time far enough to expire both proposals. We always keep at least one
        // proposal in storage
        testing_env!(VMContextBuilder::new().block_timestamp(u64::MAX).build());

        allowed.cleanup_expired_hashes(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        let proposals: Vec<_> = allowed.allowed_images(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        assert_eq!(proposals.len(), 1);
    }

    #[test]
    fn test_allowed_launcher_images_add_and_remove() {
        let mut allowed = AllowedLauncherImages::default();
        let launcher_1 = dummy_launcher_hash(1);
        let launcher_2 = dummy_launcher_hash(2);
        let mpc_hashes = vec![dummy_code_hash(10), dummy_code_hash(20)];

        // Add first launcher
        assert!(allowed.add(launcher_1, &mpc_hashes));
        assert_eq!(allowed.launcher_hashes().len(), 1);
        // Should have 2 compose hashes (one per MPC image)
        assert_eq!(allowed.all_compose_hashes().len(), 2);

        // Adding the same launcher again returns false
        assert!(!allowed.add(launcher_1, &mpc_hashes));

        // Add second launcher
        assert!(allowed.add(launcher_2, &mpc_hashes));
        assert_eq!(allowed.launcher_hashes().len(), 2);
        assert_eq!(allowed.all_compose_hashes().len(), 4);

        // Remove first launcher
        assert!(allowed.remove(&launcher_1));
        assert_eq!(allowed.launcher_hashes().len(), 1);
        assert_eq!(allowed.all_compose_hashes().len(), 2);
        assert!(!allowed.launcher_hashes().contains(&launcher_1));
        assert!(allowed.launcher_hashes().contains(&launcher_2));

        // Removing non-existent launcher returns false
        assert!(!allowed.remove(&launcher_1));
    }

    #[test]
    fn test_allowed_launcher_images_add_mpc_image() {
        let mut allowed = AllowedLauncherImages::default();
        let launcher = dummy_launcher_hash(1);
        let mpc_hash_1 = dummy_code_hash(10);

        allowed.add(launcher, &[mpc_hash_1]);
        assert_eq!(allowed.all_compose_hashes().len(), 1);

        // Add a new MPC image — should add one compose hash per launcher
        let mpc_hash_2 = dummy_code_hash(20);
        allowed.add_mpc_image_compose_hashes(&mpc_hash_2);
        assert_eq!(allowed.all_compose_hashes().len(), 2);

        // Adding the same MPC image again should not duplicate
        allowed.add_mpc_image_compose_hashes(&mpc_hash_2);
        assert_eq!(allowed.all_compose_hashes().len(), 2);
    }

    #[test]
    fn test_compose_hash_uses_both_hashes() {
        let launcher_1 = dummy_launcher_hash(1);
        let launcher_2 = dummy_launcher_hash(2);
        let mpc_hash = dummy_code_hash(10);

        let compose_1 = get_docker_compose_hash(&launcher_1, &mpc_hash);
        let compose_2 = get_docker_compose_hash(&launcher_2, &mpc_hash);

        // Different launcher hashes should produce different compose hashes
        assert_ne!(compose_1, compose_2);
    }
}
