use crate::{
    primitives::key_state::AuthenticatedParticipantId,
    storage_keys::StorageKey,
    tee::{
        proposal::{AllowedDockerImageHashes, CodeHashesVotes, DockerImageHash},
        quote::{verify_codehash, TeeQuoteStatus},
        tee_participant::TeeParticipantInfo,
    },
};
use near_sdk::{env, near, store::IterableMap, AccountId};
use std::collections::BTreeMap;

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct TeeState {
    pub(crate) allowed_docker_image_hashes: AllowedDockerImageHashes,
    pub(crate) historical_docker_image_hashes: Vec<DockerImageHash>,
    pub(crate) votes: CodeHashesVotes,
    pub(crate) tee_participant_info: IterableMap<AccountId, TeeParticipantInfo>,
}

impl Default for TeeState {
    fn default() -> Self {
        Self {
            allowed_docker_image_hashes: Default::default(),
            historical_docker_image_hashes: Default::default(),
            votes: Default::default(),
            tee_participant_info: IterableMap::new(StorageKey::TeeParticipantInfo),
        }
    }
}

impl TeeState {
    pub fn add_participant(
        &mut self,
        account_id: AccountId,
        proposed_tee_participant: TeeParticipantInfo,
    ) {
        self.tee_participant_info
            .insert(account_id.clone(), proposed_tee_participant.clone());
    }

    pub fn vote(
        &mut self,
        code_hash: DockerImageHash,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        self.votes.vote(code_hash.clone(), participant)
    }

    pub fn get_all_allowed_hashes(&mut self) -> Vec<DockerImageHash> {
        self.allowed_docker_image_hashes
            .get(env::block_height())
            .into_iter()
            .map(|entry| entry.image_hash)
            .collect()
    }

    /// maps every element in `participants` to its `TeeQuoteStatus`. If an element of
    /// `participants` does not have any TEE information associated to it, then it is mapped to
    /// `TeeQuoteStatus::None`.
    pub fn tee_status(&self, participants: Vec<AccountId>) -> BTreeMap<AccountId, TeeQuoteStatus> {
        let now_sec = env::block_timestamp_ms() / 1_000;
        participants
            .into_iter()
            .map(|account_id| {
                let status = self
                    .tee_participant_info
                    .get(&account_id)
                    .map(|tee_participant_info| {
                        TeeQuoteStatus::from(tee_participant_info.verify_quote(now_sec))
                    })
                    .unwrap_or(TeeQuoteStatus::None);
                (account_id, status)
            })
            .collect()
    }

    pub fn is_code_hash_allowed(
        &mut self,
        _code_hash: DockerImageHash,
        expected_rtmr3: &[u8; 48],
        raw_tcb_info: String,
    ) -> bool {
        let expected_rtmr3 = hex::encode(expected_rtmr3);
        let code_hash = verify_codehash(raw_tcb_info, expected_rtmr3);
        self.historical_docker_image_hashes
            .iter()
            .chain(
                self.allowed_docker_image_hashes
                    .get(env::block_height())
                    .iter()
                    .map(|entry| &entry.image_hash),
            )
            .any(|proposal| proposal.as_hex() == code_hash)
    }

    pub fn whitelist_tee_proposal(&mut self, tee_proposal: DockerImageHash) {
        self.votes.clear_votes();
        self.historical_docker_image_hashes
            .push(tee_proposal.clone());
        self.allowed_docker_image_hashes
            .insert(tee_proposal, env::block_height());
    }
}
