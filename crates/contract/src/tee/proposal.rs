use borsh::{BorshDeserialize, BorshSerialize};
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
    /// Last time this launcher was "used": stamped when it is voted in / re-voted, and
    /// refreshed on each attestation by a current participant. Drives expiry.
    pub(crate) last_used: Timestamp,
}

impl AllowedLauncherImage {
    fn is_expired(&self, ttl: Duration, now: Timestamp) -> bool {
        match self.last_used.checked_add(ttl) {
            Some(deadline) => deadline < now,
            // Overflow means the deadline is unrepresentably far in the future, so the
            // entry is not expired. Never panic here: a bogus timestamp must not evict a hash.
            None => false,
        }
    }
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
    /// set of currently allowed MPC image hashes. If the launcher hash already
    /// exists, refreshes its `last_used` timestamp (re-vote refresh) and returns `true`.
    pub fn add(
        &mut self,
        launcher_hash: LauncherImageHash,
        current_mpc_image_hashes: &[NodeImageHash],
    ) -> bool {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.launcher_hash == launcher_hash)
        {
            // Re-vote refreshes only the clock; compose hashes are maintained
            // separately via `add_mpc_image_compose_hashes`.
            log!("launcher hash already in allowed list, refreshing");
            existing.last_used = Timestamp::now();
            return true;
        }

        let compose_hashes: Vec<LauncherDockerComposeHash> = current_mpc_image_hashes
            .iter()
            .map(|mpc_hash| get_docker_compose_hash(&launcher_hash, mpc_hash))
            .collect();

        self.entries.push(AllowedLauncherImage {
            launcher_hash,
            compose_hashes,
            last_used: Timestamp::now(),
        });

        true
    }

    /// Returns indices of non-expired entries. If all are expired, keeps the most
    /// recently used one as a fallback so reads never go fully empty.
    fn live_indices(&self, ttl: Duration) -> Vec<usize> {
        let now = Timestamp::now();
        let live: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_expired(ttl, now))
            .map(|(i, _)| i)
            .collect();

        if !live.is_empty() {
            return live;
        }

        self.entries
            .iter()
            .enumerate()
            .max_by_key(|(_, e)| e.last_used)
            .map(|(i, _)| vec![i])
            .unwrap_or_default()
    }

    /// Refreshes the `last_used` timestamp of the entry whose `compose_hashes`
    /// contains `compose_hash`. Returns `true` if a matching entry was found.
    pub fn refresh_last_used(&mut self, compose_hash: &LauncherDockerComposeHash) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.compose_hashes.contains(compose_hash))
        {
            entry.last_used = Timestamp::now();
            true
        } else {
            false
        }
    }

    /// Removes expired entries, always keeping at least one (the most recently used).
    pub fn cleanup_expired(&mut self, ttl: Duration) {
        if self.entries.len() <= 1 {
            return;
        }
        let now = Timestamp::now();
        if self.entries.iter().any(|e| !e.is_expired(ttl, now)) {
            self.entries.retain(|e| !e.is_expired(ttl, now));
        } else {
            let newest = self
                .entries
                .iter()
                .enumerate()
                .max_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i)
                .expect("entries is non-empty");
            let kept = self.entries.remove(newest);
            self.entries = vec![kept];
        }
    }

    /// Migration constructor.
    pub(crate) fn from_entries(entries: Vec<AllowedLauncherImage>) -> Self {
        Self { entries }
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

    /// Returns all compose hashes across non-expired launcher images (flattened).
    pub fn all_compose_hashes(&self, ttl: Duration) -> Vec<LauncherDockerComposeHash> {
        self.live_indices(ttl)
            .into_iter()
            .flat_map(|i| self.entries[i].compose_hashes.iter().cloned())
            .collect()
    }

    /// Returns all non-expired allowed launcher image hashes.
    pub fn launcher_hashes(&self, ttl: Duration) -> Vec<LauncherImageHash> {
        self.live_indices(ttl)
            .into_iter()
            .map(|i| self.entries[i].launcher_hash)
            .collect()
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
        let proposals: Vec<_> = allowed.get(TEST_TEE_UPGRADE_DEADLINE_DURATION);
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals[0].image_hash, dummy_code_hash(1));
        assert_eq!(proposals[1].image_hash, dummy_code_hash(2));
    }

    #[test]
    fn test_clean_expired() {
        let mut allowed = AllowedDockerImageHashes::default();
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

    const BIG_TTL: Duration = Duration::from_secs(1_000_000);

    fn set_block_secs(secs: u64) {
        testing_env!(
            VMContextBuilder::new()
                .block_timestamp(secs * NANOS_IN_SECOND)
                .build()
        );
    }

    #[test]
    fn test_allowed_launcher_images_add_and_remove() {
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let launcher_1 = dummy_launcher_hash(1);
        let launcher_2 = dummy_launcher_hash(2);
        let mpc_hashes = vec![dummy_code_hash(10), dummy_code_hash(20)];

        // Add first launcher
        assert!(allowed.add(launcher_1, &mpc_hashes));
        assert_eq!(allowed.launcher_hashes(BIG_TTL).len(), 1);
        // Should have 2 compose hashes (one per MPC image)
        assert_eq!(allowed.all_compose_hashes(BIG_TTL).len(), 2);

        // Re-adding the same launcher now refreshes and returns true (no new entry)
        assert!(allowed.add(launcher_1, &mpc_hashes));
        assert_eq!(allowed.launcher_hashes(BIG_TTL).len(), 1);
        assert_eq!(allowed.all_compose_hashes(BIG_TTL).len(), 2);

        // Add second launcher
        assert!(allowed.add(launcher_2, &mpc_hashes));
        assert_eq!(allowed.launcher_hashes(BIG_TTL).len(), 2);
        assert_eq!(allowed.all_compose_hashes(BIG_TTL).len(), 4);

        // Remove first launcher
        assert!(allowed.remove(&launcher_1));
        assert_eq!(allowed.launcher_hashes(BIG_TTL).len(), 1);
        assert_eq!(allowed.all_compose_hashes(BIG_TTL).len(), 2);
        assert!(!allowed.launcher_hashes(BIG_TTL).contains(&launcher_1));
        assert!(allowed.launcher_hashes(BIG_TTL).contains(&launcher_2));

        // Removing non-existent launcher returns false
        assert!(!allowed.remove(&launcher_1));
    }

    #[test]
    fn test_allowed_launcher_images_add_mpc_image() {
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let launcher = dummy_launcher_hash(1);
        let mpc_hash_1 = dummy_code_hash(10);

        allowed.add(launcher, &[mpc_hash_1]);
        assert_eq!(allowed.all_compose_hashes(BIG_TTL).len(), 1);

        // Add a new MPC image — should add one compose hash per launcher
        let mpc_hash_2 = dummy_code_hash(20);
        allowed.add_mpc_image_compose_hashes(&mpc_hash_2);
        assert_eq!(allowed.all_compose_hashes(BIG_TTL).len(), 2);

        // Adding the same MPC image again should not duplicate
        allowed.add_mpc_image_compose_hashes(&mpc_hash_2);
        assert_eq!(allowed.all_compose_hashes(BIG_TTL).len(), 2);
    }

    #[test]
    fn refresh_last_used_keeps_entry_alive_past_ttl() {
        let ttl = Duration::from_secs(100);
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let launcher = dummy_launcher_hash(1);
        let mpc_hash = dummy_code_hash(10);
        allowed.add(launcher, &[mpc_hash]);
        let compose = get_docker_compose_hash(&launcher, &mpc_hash);

        // Just before original deadline, refresh on use.
        set_block_secs(90);
        assert!(allowed.refresh_last_used(&compose));

        // Past the original deadline (1 + 100), but within the refreshed window.
        set_block_secs(150);
        assert_eq!(allowed.launcher_hashes(ttl).len(), 1);
        assert_eq!(allowed.all_compose_hashes(ttl).len(), 1);

        // Refreshing an unknown compose hash returns false.
        assert!(
            !allowed
                .refresh_last_used(&get_docker_compose_hash(&dummy_launcher_hash(9), &mpc_hash))
        );
    }

    /// Read-time filtering only *hides* expired entries; it never deletes (only
    /// `cleanup_expired` does). So enlarging the TTL brings back an entry a smaller TTL hid.
    #[test]
    fn enlarging_ttl_unhides_previously_expired_entry() {
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let mpc_hashes = vec![dummy_code_hash(10)];
        allowed.add(dummy_launcher_hash(1), &mpc_hashes);
        // A second, newer entry so the fallback doesn't mask the first's expiry.
        set_block_secs(50);
        allowed.add(dummy_launcher_hash(2), &mpc_hashes);

        // At t=200 with a 100s TTL, launcher_1 (last_used=1) is hidden.
        set_block_secs(200);
        let small_ttl = Duration::from_secs(100);
        assert_eq!(
            allowed.launcher_hashes(small_ttl),
            vec![dummy_launcher_hash(2)]
        );

        // A larger TTL at the same instant un-hides it — the entry was never deleted.
        let large_ttl = Duration::from_secs(1_000);
        assert_eq!(
            allowed.launcher_hashes(large_ttl),
            vec![dummy_launcher_hash(1), dummy_launcher_hash(2)]
        );
    }

    #[test]
    fn expired_entries_are_filtered_from_reads() {
        let ttl = Duration::from_secs(100);
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let mpc_hashes = vec![dummy_code_hash(10)];
        allowed.add(dummy_launcher_hash(1), &mpc_hashes);

        // Add a second, newer launcher later.
        set_block_secs(200);
        allowed.add(dummy_launcher_hash(2), &mpc_hashes);

        // At t=250, launcher_1 (added t=1) is expired but launcher_2 (added t=200) is live.
        set_block_secs(250);
        let hashes = allowed.launcher_hashes(ttl);
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains(&dummy_launcher_hash(2)));
        assert_eq!(allowed.all_compose_hashes(ttl).len(), 1);
    }

    #[test]
    fn newest_fallback_when_all_expired() {
        let ttl = Duration::from_secs(100);
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let mpc_hashes = vec![dummy_code_hash(10)];
        allowed.add(dummy_launcher_hash(1), &mpc_hashes);
        set_block_secs(50);
        allowed.add(dummy_launcher_hash(2), &mpc_hashes);

        // Far in the future: both expired, fallback keeps the newest by `added`.
        set_block_secs(10_000);
        let hashes = allowed.launcher_hashes(ttl);
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains(&dummy_launcher_hash(2)));
    }

    #[test]
    fn cleanup_expired_removes_expired_but_keeps_one() {
        let ttl = Duration::from_secs(100);
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let mpc_hashes = vec![dummy_code_hash(10)];
        allowed.add(dummy_launcher_hash(1), &mpc_hashes);
        set_block_secs(200);
        allowed.add(dummy_launcher_hash(2), &mpc_hashes);

        // launcher_1 expired, launcher_2 live: only the live one remains.
        set_block_secs(250);
        allowed.cleanup_expired(ttl);
        assert_eq!(allowed.launcher_hashes(BIG_TTL).len(), 1);
        assert!(
            allowed
                .launcher_hashes(BIG_TTL)
                .contains(&dummy_launcher_hash(2))
        );

        // Both expired now: cleanup still keeps exactly one (the newest by `added`).
        set_block_secs(1_000_000);
        // Re-add an older entry to have two expired entries.
        let mut allowed2 = AllowedLauncherImages::default();
        set_block_secs(1);
        allowed2.add(dummy_launcher_hash(1), &mpc_hashes);
        set_block_secs(50);
        allowed2.add(dummy_launcher_hash(2), &mpc_hashes);
        set_block_secs(1_000_000);
        allowed2.cleanup_expired(ttl);
        let remaining = allowed2.launcher_hashes(BIG_TTL);
        assert_eq!(remaining.len(), 1);
        assert!(remaining.contains(&dummy_launcher_hash(2)));
    }

    #[test]
    fn re_add_refresh_resets_added_and_keeps_alive() {
        let ttl = Duration::from_secs(100);
        set_block_secs(1);
        let mut allowed = AllowedLauncherImages::default();
        let launcher = dummy_launcher_hash(1);
        let mpc_hashes = vec![dummy_code_hash(10)];
        allowed.add(launcher, &mpc_hashes);

        // Just before expiry, re-vote (re-add): returns true and resets `added`.
        set_block_secs(90);
        assert!(allowed.add(launcher, &mpc_hashes));

        // Past the original deadline (1 + 100) but within the refreshed window.
        set_block_secs(150);
        assert_eq!(allowed.launcher_hashes(ttl).len(), 1);
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
