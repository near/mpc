use borsh::BorshDeserialize;
use borsh::BorshSerialize;
use near_sdk::{env::sha256, log, near};
use std::collections::BTreeMap;
use std::time::Duration;

use crate::primitives::key_state::AuthenticatedParticipantId;
use crate::primitives::time::TimeStamp;

pub use mpc_primitives::hash::LauncherDockerComposeHash;
pub use mpc_primitives::hash::MpcDockerImageHash;

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
    pub(crate) added: TimeStamp,
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
    fn is_image_hash_valid(
        entry: &AllowedMpcDockerImage,
        tee_upgrade_deadline_duration: Duration,
    ) -> bool {
        let current_time = TimeStamp::now();
        let entry_age = current_time
            .checked_sub(entry.added)
            .expect("Near system time is monotonically increasing");
        let entry_is_not_expired = entry_age <= tee_upgrade_deadline_duration;

        entry_is_not_expired
    }

    /// Removes all expired code hashes and returns the number of removed entries.
    /// Ensures that at least one (the latest) proposal always remains in the whitelist.
    pub fn cleanup_expired_hashes(&mut self, tee_upgrade_deadline_duration: Duration) -> usize {
        // Find the first non-expired entry, but never remove the last one
        let expired_count = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| Self::is_image_hash_valid(entry, tee_upgrade_deadline_duration))
            .unwrap_or(self.allowed_tee_proposals.len());

        // Never remove all proposals; always keep at least one (the latest)
        let expired_count = expired_count.min(self.allowed_tee_proposals.len().saturating_sub(1));

        self.allowed_tee_proposals.drain(0..expired_count);

        expired_count
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
            added: TimeStamp::now(),
        };

        // Find the correct position to maintain sorted order by `added`
        let insert_index = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| new_entry.added <= entry.added)
            .unwrap_or(self.allowed_tee_proposals.len());

        self.allowed_tee_proposals.insert(insert_index, new_entry);
    }

    /// Returns valid hashes without cleaning expired entries (read-only). Ensures that at least
    /// one proposal (the latest) is always returned. Use [`Self::cleanup_expired_hashes`]
    /// explicitly when cleanup of the internal structure is needed.
    pub fn get(&self, tee_upgrade_deadline_duration: Duration) -> Vec<&AllowedMpcDockerImage> {
        let valid_entries: Vec<_> = self
            .allowed_tee_proposals
            .iter()
            .filter(|entry| Self::is_image_hash_valid(entry, tee_upgrade_deadline_duration))
            .collect();

        // If no valid entries, return at least the latest entry
        if valid_entries.is_empty() {
            self.allowed_tee_proposals.last().into_iter().collect()
        } else {
            valid_entries
        }
    }

    // Given a docker image hash obtain the launcher docker compose hash
    pub fn get_docker_compose_hash(
        mpc_docker_image_hash: MpcDockerImageHash,
    ) -> LauncherDockerComposeHash {
        let filled_yaml = format!("version: '3.8'\n\nservices:\n  launcher:\n    image: barakeinavnear/launcher@sha256:1ea7571baf18bd052359abd2a1f269e7836f9bad2270eb55fc9475aa327f8d96\n\n # isuse #531: TODO (security): Replace with a specific image digest\n    container_name: launcher\n\n    environment:\n      - DOCKER_CONTENT_TRUST=1\n      - DEFAULT_IMAGE_DIGEST=sha256:{}\n\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n      - /var/run/dstack.sock:/var/run/dstack.sock\n      - /tapp:/tapp:ro\n      - shared-volume:/mnt/shared:ro\n\n    security_opt:\n      - no-new-privileges:true\n\n    read_only: true\n\n    tmpfs:\n      - /tmp\n\nvolumes:\n  shared-volume:\n    name: shared-volume",
            mpc_docker_image_hash.as_hex()
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
    const NANOS_PER_MILLI: u64 = 1_000_000;

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

        current_time_nano_seconds += NANOS_PER_MILLI;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(current_time_nano_seconds)
            .build());

        // Insert the same code hash again
        allowed.insert(
            dummy_code_hash(1),
            TEST_TEE_UPGRADE_DEADLINE_DURATION + SECOND,
        );

        current_time_nano_seconds += NANOS_PER_MILLI;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(current_time_nano_seconds)
            .build());

        // Insert a different code hash
        allowed.insert(
            dummy_code_hash(2),
            TEST_TEE_UPGRADE_DEADLINE_DURATION + 2 * SECOND,
        );

        current_time_nano_seconds += NANOS_PER_MILLI;
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
        let first_entry_time_nano_seconds = NANOS_PER_MILLI;

        testing_env!(VMContextBuilder::new()
            .block_timestamp(first_entry_time_nano_seconds)
            .build());

        // Insert two proposals at different time intervals
        allowed.insert(dummy_code_hash(1), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        let second_entry_time_nano_seconds = NANOS_PER_MILLI * 2;
        testing_env!(VMContextBuilder::new()
            .block_timestamp(second_entry_time_nano_seconds)
            .build());

        allowed.insert(dummy_code_hash(2), TEST_TEE_UPGRADE_DEADLINE_DURATION);

        // Move time far enough to expire the first proposal
        let first_entry_expiry_time_nanoseconds = first_entry_time_nano_seconds
            + TEST_TEE_UPGRADE_DEADLINE_DURATION.as_nanos() as u64
            + NANOS_PER_MILLI;

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
