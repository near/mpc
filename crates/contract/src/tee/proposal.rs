use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{env::sha256, log, near};
use std::{collections::BTreeMap, time::Duration};

use crate::primitives::{key_state::AuthenticatedParticipantId, time::Timestamp};

pub use mpc_primitives::hash::{LauncherDockerComposeHash, MpcDockerImageHash};

/// TCB info JSON file containing measurement values.
const LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE: &str =
    include_str!("../../assets/launcher_docker_compose.yaml.template");

/// Tracks votes to add whitelisted TEE code hashes. Each participant can at any given time vote for
/// a code hash to add.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeHashesVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, MpcDockerImageHash>,
}

impl CodeHashesVotes {
    /// Casts a vote for the proposal and returns the total number of participants who have voted
    /// for the same code hash. If the participant already voted, their previous vote is replaced.
    pub fn vote(
        &mut self,
        proposal: MpcDockerImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant.clone(), proposal.clone())
            .is_some()
        {
            log!("removed old vote for signer");
        }
        let total = self.count_votes(&proposal);
        log!("total votes for proposal: {}", total);
        total
    }

    /// Counts the total number of participants who have voted for the given code hash.
    fn count_votes(&self, proposal: &MpcDockerImageHash) -> u64 {
        self.proposal_by_account
            .values()
            .filter(|&prop| prop == proposal)
            .count() as u64
    }

    /// Clears all proposals.
    pub fn clear_votes(&mut self) {
        self.proposal_by_account.clear();
    }
}

/// An allowed Docker image configuration entry containing both the MPC image hash and its
/// corresponding launcher compose hash, along with when it was added to the allowlist.
#[near(serializers=[json])]
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AllowedMpcDockerImage {
    pub(crate) image_hash: MpcDockerImageHash,
    pub(crate) docker_compose_hash: LauncherDockerComposeHash,
    pub(crate) added: Timestamp,
}
/// Collection of whitelisted Docker code hashes that are the only ones MPC nodes are allowed to
/// run.
#[near(serializers=[json])]
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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
    pub fn insert(
        &mut self,
        code_hash: MpcDockerImageHash,
        tee_upgrade_deadline_duration: Duration,
    ) {
        self.cleanup_expired_hashes(tee_upgrade_deadline_duration);

        // Remove the old entry if it exists
        if let Some(pos) = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| entry.image_hash == code_hash)
        {
            self.allowed_tee_proposals.remove(pos);
        }

        let docker_compose_hash = Self::get_docker_compose_hash(code_hash.clone());

        let new_entry = AllowedMpcDockerImage {
            image_hash: code_hash,
            docker_compose_hash,
            added: Timestamp::now(),
        };

        // Find the correct position to maintain sorted order by `added`
        let insert_index = self
            .allowed_tee_proposals
            .iter()
            // strictly less, `<`, such that new entries take higher precedence
            // if two entries have the exact same time stamp.
            .position(|entry| new_entry.added < entry.added)
            .unwrap_or(self.allowed_tee_proposals.len());

        self.allowed_tee_proposals.insert(insert_index, new_entry);
    }

    /// Returns valid hashes without cleaning expired entries (read-only). Ensures that at least
    /// one proposal (the latest) is always returned. Use [`Self::cleanup_expired_hashes`]
    /// explicitly when cleanup of the internal structure is needed.
    pub fn get(&self, tee_upgrade_deadline_duration: Duration) -> Vec<AllowedMpcDockerImage> {
        self.valid_entries(tee_upgrade_deadline_duration)
    }

    // Given a docker image hash obtain the launcher docker compose hash
    pub fn get_docker_compose_hash(
        mpc_docker_image_hash: MpcDockerImageHash,
    ) -> LauncherDockerComposeHash {
        let filled_yaml = LAUNCHER_DOCKER_COMPOSE_YAML_TEMPLATE.replace(
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
}

#[cfg(test)]
mod tests {
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    use super::*;
    const TEST_TEE_UPGRADE_DEADLINE_DURATION: Duration = Duration::from_secs(10 * 24 * 60 * 60); // 10 days
    const SECOND: Duration = Duration::from_secs(1);
    const NANOS_IN_SECOND: u64 = SECOND.as_nanos() as u64;

    fn dummy_code_hash(val: u8) -> MpcDockerImageHash {
        MpcDockerImageHash::from([val; 32])
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
}
