use derive_more::From;
use near_sdk::{env::sha256, log, near, BlockHeight};
use std::collections::BTreeMap;

use crate::primitives::key_state::AuthenticatedParticipantId;

// Maximum time after which TEE MPC nodes must be upgraded to the latest version
const TEE_UPGRADE_PERIOD: BlockHeight = 7 * 24 * 60 * 100; // ~7 days @ block time of 600 ms, e.g. 100 blocks every 60 seconds

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
/// Common functionality for 32-byte SHA256 hashes used in the TEE environment.
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    From,
)]
pub struct Hash32<T> {
    pub bytes: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T> Hash32<T> {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

// Marker types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Image;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Compose;

/// Hash of an MPC Docker image running in the TEE environment. Used as a proposal for a new TEE
/// code hash to add to the whitelist, together with the TEE quote (which includes the RTMR3
/// measurement and more).
pub type MpcDockerImageHash = Hash32<Image>;

/// Hash of the launcher's Docker Compose file used to run the MPC node in the TEE environment. It
/// is computed from the launcher's Docker Compose template populated with the MPC node's Docker
/// image hash.
pub type LauncherDockerComposeHash = Hash32<Compose>;

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

/// A proposal for a new TEE code hash to be added to the whitelist, along with the time it was
/// added.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedDockerImageHash {
    pub image_hash: MpcDockerImageHash,
    pub docker_compose_hash: LauncherDockerComposeHash,
    pub added: BlockHeight,
}
/// Collection of whitelisted Docker code hashes that are the only ones MPC nodes are allowed to
/// run.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowedDockerImageHashes {
    /// Whitelisted code hashes, sorted by when they were added (oldest first). Expired entries are
    /// lazily cleaned up during insertions and lookups.
    allowed_tee_proposals: Vec<AllowedDockerImageHash>,
}

impl AllowedDockerImageHashes {
    /// Removes all expired code hashes and returns the number of removed entries.
    /// Ensures that at least one (the latest) proposal always remains in the whitelist.
    fn clean_expired_hashes(&mut self, current_block_height: BlockHeight) -> usize {
        // Find the first non-expired entry, but never remove the last one
        let expired_count = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| entry.added + TEE_UPGRADE_PERIOD >= current_block_height)
            .unwrap_or(self.allowed_tee_proposals.len());

        // Never remove all proposals; always keep at least one (the latest)
        let expired_count = expired_count.min(self.allowed_tee_proposals.len().saturating_sub(1));

        self.allowed_tee_proposals.drain(0..expired_count);

        expired_count
    }

    /// Inserts a new code hash into the list after cleaning expired entries. Maintains the sorted
    /// order by `added` (ascending). Returns `true` if the insertion was successful, `false` if the
    /// code hash already exists.
    pub fn insert(&mut self, code_hash: MpcDockerImageHash, current_block_height: u64) -> bool {
        self.clean_expired_hashes(current_block_height);

        // Remove the old entry if it exists
        if let Some(pos) = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| entry.image_hash == code_hash)
        {
            self.allowed_tee_proposals.remove(pos);
        }

        let docker_compose_hash = Self::get_docker_compose_hash(code_hash.clone());

        let new_entry = AllowedDockerImageHash {
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

        true
    }

    pub fn get(&mut self, current_block_height: BlockHeight) -> Vec<AllowedDockerImageHash> {
        self.clean_expired_hashes(current_block_height);
        self.allowed_tee_proposals.clone()
    }

    fn get_docker_compose_hash(
        mpc_docker_image_hash: MpcDockerImageHash,
    ) -> LauncherDockerComposeHash {
        let filled_yaml = format!(
            r#"version: "3.8"

services:
web:
image: barakeinavnear/launcher:latest
container_name: launcher
environment:
  - DOCKER_CONTENT_TRUST=1
  - DEFAULT_IMAGE_DIGEST=sha256:{}
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
  - /var/run/dstack.sock:/var/run/dstack.sock
  - /tapp:/tapp:ro
  - /var/lib/docker/volumes/shared-volume/_data:/mnt/shared:ro
"#,
            mpc_docker_image_hash.as_hex()
        );

        let hash = sha256(filled_yaml.as_bytes());
        assert!(
            hash.len() == 32,
            "Docker compose hash must be 32 bytes long"
        );

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash);

        LauncherDockerComposeHash::new(hash_arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_code_hash(val: u8) -> MpcDockerImageHash {
        MpcDockerImageHash::new([val; 32])
    }

    #[test]
    fn test_insert_and_get() {
        let mut allowed = AllowedDockerImageHashes::default();
        let block_height = 1000;

        // Insert a new proposal
        let inserted = allowed.insert(dummy_code_hash(1), block_height);
        assert!(inserted);

        // Insert the same code hash again (should success)
        let inserted_again = allowed.insert(dummy_code_hash(1), block_height + 1);
        assert!(inserted_again);

        // Insert a different code hash
        let inserted2 = allowed.insert(dummy_code_hash(2), block_height + 2);
        assert!(inserted2);

        // Get proposals (should return both)
        let proposals = allowed.get(block_height + 2);
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(1));
        assert_eq!(proposals[1].image_hash, dummy_code_hash(2));
    }

    #[test]
    fn test_clean_expired() {
        let mut allowed = AllowedDockerImageHashes::default();
        let block_height = 1000;

        // Insert two proposals at different heights
        allowed.insert(dummy_code_hash(1), block_height);
        allowed.insert(dummy_code_hash(2), block_height + 1);

        // Move block height far enough to expire the first proposal
        let expired_height = block_height + TEE_UPGRADE_PERIOD + 1;
        let proposals = allowed.get(expired_height);

        // Only the second proposal should remain if the first is expired
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(2));

        // Move block height far enough to expire both proposals; we never allow all proposals in
        // the whitelist to expire, so there should still be one proposal in the whitelist
        let expired_height = block_height + TEE_UPGRADE_PERIOD + 2;
        let proposals = allowed.get(expired_height);

        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(2));
    }
}
