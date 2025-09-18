use near_sdk::{env::sha256, log, near, BlockHeight};
use std::collections::BTreeMap;

use crate::primitives::key_state::AuthenticatedParticipantId;

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
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedMpcDockerImage {
    pub image_hash: MpcDockerImageHash,
    pub docker_compose_hash: LauncherDockerComposeHash,
    pub added: BlockHeight,
}
/// Collection of whitelisted Docker code hashes that are the only ones MPC nodes are allowed to
/// run.
#[near(serializers=[borsh, json])]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct AllowedDockerImageHashes {
    /// Whitelisted code hashes, sorted by when they were added (oldest first). Expired entries are
    /// lazily cleaned up during insertions and TEE validation.
    allowed_tee_proposals: Vec<AllowedMpcDockerImage>,
}

impl AllowedDockerImageHashes {
    /// Checks if a Docker image hash is still valid (not expired).
    fn is_image_hash_valid(
        entry: &AllowedMpcDockerImage,
        tee_upgrade_deadline_duration_blocks: u64,
        current_block_height: BlockHeight,
    ) -> bool {
        entry.added + tee_upgrade_deadline_duration_blocks >= current_block_height
    }

    /// Removes all expired code hashes and returns the number of removed entries.
    /// Ensures that at least one (the latest) proposal always remains in the whitelist.
    pub fn cleanup_expired_hashes(
        &mut self,
        current_block_height: BlockHeight,
        tee_upgrade_deadline_duration_blocks: u64,
    ) -> usize {
        // Find the first non-expired entry, but never remove the last one
        let expired_count = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| {
                Self::is_image_hash_valid(
                    entry,
                    tee_upgrade_deadline_duration_blocks,
                    current_block_height,
                )
            })
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
        current_block_height: u64,
        tee_upgrade_deadline_duration_blocks: u64,
    ) {
        self.cleanup_expired_hashes(current_block_height, tee_upgrade_deadline_duration_blocks);

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
            added: current_block_height,
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
    pub fn get(
        &self,
        current_block_height: BlockHeight,
        tee_upgrade_deadline_duration_blocks: u64,
    ) -> Vec<&AllowedMpcDockerImage> {
        let valid_entries: Vec<_> = self
            .allowed_tee_proposals
            .iter()
            .filter(|entry| {
                Self::is_image_hash_valid(
                    entry,
                    tee_upgrade_deadline_duration_blocks,
                    current_block_height,
                )
            })
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
    use super::*;
    const TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS: u64 = 100;

    fn dummy_code_hash(val: u8) -> MpcDockerImageHash {
        MpcDockerImageHash::from([val; 32])
    }

    #[test]
    fn test_insert_and_get() {
        let mut allowed = AllowedDockerImageHashes::default();
        let block_height = 1000;

        // Insert a new proposal
        allowed.insert(
            dummy_code_hash(1),
            block_height,
            TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS,
        );

        // Insert the same code hash again
        allowed.insert(
            dummy_code_hash(1),
            block_height + 1,
            TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS,
        );

        // Insert a different code hash
        allowed.insert(
            dummy_code_hash(2),
            block_height + 2,
            TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS,
        );

        // Get proposals (should return both)
        allowed.cleanup_expired_hashes(block_height + 2, TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS);
        let proposals: Vec<_> =
            allowed.get(block_height + 2, TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS);
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(1));
        assert_eq!(proposals[1].image_hash, dummy_code_hash(2));
    }

    #[test]
    fn test_clean_expired() {
        let mut allowed = AllowedDockerImageHashes::default();
        let block_height = 1000;

        // Insert two proposals at different heights
        allowed.insert(
            dummy_code_hash(1),
            block_height,
            TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS,
        );
        allowed.insert(
            dummy_code_hash(2),
            block_height + 1,
            TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS,
        );

        // Move block height far enough to expire the first proposal
        let expired_height = block_height + TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS + 1;
        allowed.cleanup_expired_hashes(expired_height, TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS);
        let proposals: Vec<_> =
            allowed.get(expired_height, TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS);

        // Only the second proposal should remain if the first is expired
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(2));

        // Move block height far enough to expire both proposals. We always keep at least one
        // proposal in storage
        let expired_height = block_height + TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS + 2;
        allowed.cleanup_expired_hashes(expired_height, TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS);
        let proposals: Vec<_> =
            allowed.get(expired_height, TEST_TEE_UPGRADE_DEADLINE_DURATION_BLOCKS);

        assert_eq!(proposals.len(), 1);
    }
}
