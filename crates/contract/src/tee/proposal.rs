use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{env::sha256, log, near};
use std::time::Duration;

use crate::primitives::{key_state::AuthenticatedParticipantId, time::Timestamp, votes::Votes};

pub use mpc_primitives::hash::{LauncherDockerComposeHash, LauncherImageHash, NodeImageHash};

/// Docker Compose YAML template for the launcher. Compose hashes are derived on-chain as
/// `sha256(template(launcher_hash, mpc_hash))`. Placeholders:
/// - `{{LAUNCHER_IMAGE_HASH}}`: the launcher Docker image hash
/// - `{{DEFAULT_IMAGE_DIGEST_HASH}}`: the MPC node Docker image hash
const LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE: &str =
    include_str!("../../assets/launcher_docker_compose.yaml.template");

pub type CodeHashesVotes = Votes<AuthenticatedParticipantId, NodeImageHash>;

/// The action a participant is voting for on a launcher image hash.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LauncherVoteAction {
    Add(LauncherImageHash),
    Remove(LauncherImageHash),
}

pub type LauncherHashVotes = Votes<AuthenticatedParticipantId, LauncherVoteAction>;

/// An allowed Docker image configuration entry containing the MPC image hash
/// and when it was added to the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct AllowedMpcDockerImage {
    pub(crate) image_hash: NodeImageHash,
    pub(crate) added: Timestamp,
}

/// Collection of whitelisted Docker code hashes that are the only ones MPC nodes are allowed to
/// run.
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct AllowedDockerImageHashes {
    /// Whitelisted code hashes, sorted by when they were added (oldest first). Expired entries are
    /// lazily cleaned up during insertions and TEE validation.
    allowed_tee_proposals: Vec<AllowedMpcDockerImage>,
}

impl AllowedDockerImageHashes {
    /// Checks if a Docker image hash is still valid (not expired).
    fn valid_entries(&self, tee_upgrade_deadline_duration: Duration) -> Vec<AllowedMpcDockerImage> {
        let current_time = Timestamp::now();
        // get the index of the most recently enforced docker image
        let cutoff_index = self
            .allowed_tee_proposals
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
            .unwrap_or(0);

        self.allowed_tee_proposals
            .get(cutoff_index..)
            .unwrap_or(&[])
            .to_vec()
    }

    /// Removes all expired code hashes and returns the number of removed entries.
    /// Ensures that at least one (the latest) proposal always remains in the whitelist.
    pub fn cleanup_expired_hashes(&mut self, tee_upgrade_deadline_duration: Duration) {
        let valid_entries = self.valid_entries(tee_upgrade_deadline_duration);
        self.allowed_tee_proposals = valid_entries;
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

        let new_entry = AllowedMpcDockerImage {
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

    /// Returns valid hashes without cleaning expired entries (read-only). Ensures that at least
    /// one proposal (the latest) is always returned. Use [`Self::cleanup_expired_hashes`]
    /// explicitly when cleanup of the internal structure is needed.
    pub fn get(&self, tee_upgrade_deadline_duration: Duration) -> Vec<AllowedMpcDockerImage> {
        self.valid_entries(tee_upgrade_deadline_duration)
    }

    /// Returns only the image hashes of valid entries.
    pub fn get_image_hashes(&self, tee_upgrade_deadline_duration: Duration) -> Vec<NodeImageHash> {
        self.valid_entries(tee_upgrade_deadline_duration)
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
        let mut allowed = AllowedDockerImageHashes::default();
        let mut current_time_nano_seconds = 0;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(current_time_nano_seconds)
            .build());

        // Insert a new proposal
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        current_time_nano_seconds += NANOS_IN_SECOND;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(current_time_nano_seconds)
            .build());

        // Insert the same code hash again
        allowed.insert(
            dummy_code_hash(1),
            TEST_TEE_UPGRADE_DEADLINE_DURATION + SECOND,
        );

        current_time_nano_seconds += NANOS_IN_SECOND;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(current_time_nano_seconds)
            .build());

        // Insert a different code hash
        allowed.insert(
            dummy_code_hash(2),
            TEST_TEE_UPGRADE_DEADLINE_DURATION + 2 * SECOND,
        );

        current_time_nano_seconds += NANOS_IN_SECOND;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(current_time_nano_seconds)
            .build());

        // Get proposals (should return both)
        allowed.cleanup_expired_hashes(TEST_TEE_UPGRADE_DEADLINE_DURATION);
        let proposals: Vec<_> = allowed.get(TEST_TEE_UPGRADE_DEADLINE_DURATION);
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(1));
        assert_eq!(proposals[1].image_hash, dummy_code_hash(2));
    }

    #[test]
    fn test_clean_expired() {
        let mut allowed = AllowedDockerImageHashes::default();
        let first_entry_time_nano_seconds = NANOS_IN_SECOND;

        testing_env!(VMContextBuilder::new()
            .block_timestamp(first_entry_time_nano_seconds)
            .build());

        // Insert two proposals at different time intervals
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        let second_entry_time_nano_seconds = first_entry_time_nano_seconds + NANOS_IN_SECOND;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(second_entry_time_nano_seconds)
            .build());

        allowed.insert(dummy_code_hash(2), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        let first_entry_expiry_time_nanoseconds = second_entry_time_nano_seconds
            + TEST_TEE_UPGRADE_DEADLINE_DURATION.as_nanos() as u64
            + 1;

        testing_env!(VMContextBuilder::new()
            .block_timestamp(first_entry_expiry_time_nanoseconds)
            .build());

        allowed.cleanup_expired_hashes(TEST_TEE_UPGRADE_DEADLINE_DURATION);
        let proposals: Vec<_> = allowed.get(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // Only the second proposal should remain if the first is expired
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(2));

        // Move block time far enough to expire both proposals. We always keep at least one
        // proposal in storage
        testing_env!(VMContextBuilder::new().block_timestamp(u64::MAX).build());

        allowed.cleanup_expired_hashes(TEST_TEE_UPGRADE_DEADLINE_DURATION);

        let proposals: Vec<_> = allowed.get(TEST_TEE_UPGRADE_DEADLINE_DURATION);

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
