//! Contract updates: participants vote for a [`dtos::UpdateHash`], and while a governance
//! threshold of them backs it, the matching [`Update`] may be submitted and applied.

use crate::{
    config::Config,
    dto_mapping::IntoInterfaceType,
    errors::Error,
    primitives::{
        key_state::AuthenticatedAccountId,
        participants::Participants,
        proposal_hash::{Json, ProposalHash, Sha256, ToProposalHash},
        thresholds::GovernanceThresholdParameters,
        votes::Votes,
    },
    storage_keys::StorageKey,
};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types as dtos;
use near_sdk::{Gas, NearToken, Promise, env, near};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Update {
    Code(Vec<u8>),
    Config(Config),
}

impl TryFrom<dtos::Update> for Update {
    type Error = Error;

    fn try_from(value: dtos::Update) -> Result<Self, Self::Error> {
        Ok(match value {
            dtos::Update::Code(code) => Update::Code(code),
            dtos::Update::Config(config) => Update::Config(config.try_into()?),
        })
    }
}

impl Update {
    /// Code updates deploy the code and call `migrate` with `gas`; config updates call
    /// `update_config` with the gas the new config prescribes.
    pub fn into_promise(self, gas: Gas) -> Promise {
        let promise = Promise::new(env::current_account_id());
        match self {
            Update::Code(code) => promise.deploy_contract(code).function_call(
                method_names::MIGRATE,
                Vec::new(),
                NearToken::from_near(0),
                gas,
            ),
            Update::Config(config) => {
                let gas = Gas::from_tgas(config.contract_upgrade_deposit_tera_gas);
                let dto_config = config.into_dto_type();
                promise.function_call(
                    method_names::UPDATE_CONFIG,
                    serde_json::to_vec(&(&dto_config,)).expect("Config serializes to JSON"),
                    NearToken::from_near(0),
                    gas,
                )
            }
        }
    }
}

/// JSON so that participants can verify a pending-vote key off-chain from the hash they
/// submitted.
impl ToProposalHash for dtos::UpdateHash {
    type Serializer = Json;
    type Hasher = Sha256;
}

/// Approval is not latched: an update may be submitted exactly while its hash holds votes from
/// a governance threshold of *current* participants. Withdrawing a vote therefore un-approves
/// the hash, and so does a resharing that drops its backers.
///
/// A governance threshold always exceeds half the participants and each participant holds one
/// vote, so at most one hash is approved at a time.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct UpdateVotes {
    pending: Votes<AuthenticatedAccountId>,
}

impl Default for UpdateVotes {
    fn default() -> Self {
        Self {
            pending: Votes::new(
                StorageKey::UpdateVotesByVoter,
                StorageKey::UpdateVotesByProposal,
            ),
        }
    }
}

impl UpdateVotes {
    /// Records `voter`'s vote for `update_hash`, replacing any earlier vote of theirs. Returns
    /// whether the hash is now approved.
    pub fn vote(
        &mut self,
        update_hash: &dtos::UpdateHash,
        voter: AuthenticatedAccountId,
        threshold_parameters: &GovernanceThresholdParameters,
    ) -> bool {
        let count = self
            .pending
            .vote(voter, update_hash.to_proposal_hash())
            .count_participants(threshold_parameters.participants());
        count >= threshold_parameters.threshold().value()
    }

    /// Whether `update_hash` is approved, i.e. whether it holds votes from a governance
    /// threshold of current participants.
    pub fn is_approved(
        &self,
        update_hash: &dtos::UpdateHash,
        threshold_parameters: &GovernanceThresholdParameters,
    ) -> bool {
        self.pending
            .voters_for(&update_hash.to_proposal_hash())
            .is_some_and(|voters| {
                voters.count_participants(threshold_parameters.participants())
                    >= threshold_parameters.threshold().value()
            })
    }

    /// Clears every vote if `update_hash` is approved, so that the caller may apply it exactly
    /// once. Votes for other hashes go too: they were cast against the superseded contract.
    pub fn take_if_approved(
        &mut self,
        update_hash: &dtos::UpdateHash,
        threshold_parameters: &GovernanceThresholdParameters,
    ) -> bool {
        if !self.is_approved(update_hash, threshold_parameters) {
            return false;
        }
        self.pending.clear();
        true
    }

    /// Withdraws `voter`'s vote, which un-approves the hash they backed if it drops below the
    /// governance threshold.
    pub fn remove_vote(&mut self, voter: &AuthenticatedAccountId) {
        self.pending.remove_vote(voter);
    }

    /// Drops votes from accounts that are no longer participants.
    pub fn retain(&mut self, current: &Participants) {
        self.pending
            .retain_votes(|voter| current.is_participant(voter));
    }

    pub fn pending(&self) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedAccountId>> {
        self.pending.all()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use crate::primitives::key_state::AuthenticatedAccountId;
    use crate::primitives::participants::Participants;
    use crate::primitives::proposal_hash::{ProposalHash, ToProposalHash};
    use crate::primitives::test_utils::gen_participants;
    use crate::primitives::thresholds::GovernanceThresholdParameters;
    use crate::tee::test_utils::Environment;
    use crate::update::{Update, UpdateVotes};
    use mpc_primitives::GovernanceThreshold;
    use near_mpc_contract_interface::types as dtos;
    use std::collections::{BTreeMap, BTreeSet};
    use test_utils::contract_types::dummy_config;

    fn update_hash(byte: u8) -> dtos::UpdateHash {
        dtos::UpdateHash::Code(dtos::Hash256([byte; 32]))
    }

    /// Three participants with governance threshold 2.
    struct Voting {
        params: GovernanceThresholdParameters,
        voters: Vec<AuthenticatedAccountId>,
        votes: UpdateVotes,
    }

    impl Voting {
        fn new() -> Self {
            let participants = gen_participants(3);
            let voters = authenticated(&participants);
            Self {
                params: GovernanceThresholdParameters::new_unvalidated(
                    participants,
                    GovernanceThreshold::new(2),
                ),
                voters,
                votes: UpdateVotes::default(),
            }
        }

        fn vote(&mut self, voter: usize, hash: u8) -> bool {
            self.votes
                .vote(&update_hash(hash), self.voters[voter].clone(), &self.params)
        }

        fn is_approved(&self, hash: u8) -> bool {
            self.votes.is_approved(&update_hash(hash), &self.params)
        }
    }

    fn authenticated(participants: &Participants) -> Vec<AuthenticatedAccountId> {
        participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| {
                Environment::new(None, Some(account_id.clone()), None);
                AuthenticatedAccountId::new(participants).unwrap()
            })
            .collect()
    }

    fn pending(
        buckets: &[(u8, &[&AuthenticatedAccountId])],
    ) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedAccountId>> {
        buckets
            .iter()
            .map(|(hash, voters)| {
                (
                    update_hash(*hash).to_proposal_hash(),
                    voters.iter().map(|voter| (*voter).clone()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn update_try_from__should_reject_invalid_config() {
        // Given a config whose launcher TTL is below the attestation validity window.
        let mut config = dummy_config(1);
        config.launcher_hash_unused_ttl_seconds = 0;

        // When
        let result = Update::try_from(dtos::Update::Config(config));

        // Then
        let err = result.expect_err("invalid config must be rejected");
        assert!(
            format!("{err:?}").contains("launcher_hash_unused_ttl_seconds"),
            "error should point at the invalid field, got: {err:?}"
        );
    }

    #[test]
    fn vote__should_not_approve_below_threshold() {
        // Given
        let mut voting = Voting::new();

        // When
        let approved = voting.vote(0, 1);

        // Then
        assert!(!approved);
        assert!(!voting.is_approved(1));
        assert_eq!(
            voting.votes.pending(),
            pending(&[(1, &[&voting.voters[0]])])
        );
    }

    #[test]
    fn vote__should_approve_at_threshold_and_keep_the_votes() {
        // Given
        let mut voting = Voting::new();
        assert!(!voting.vote(0, 1));

        // When
        let approved = voting.vote(1, 1);

        // Then the hash is approved, and the votes backing it remain so that a later
        // withdrawal can take it back below the threshold.
        assert!(approved);
        assert!(voting.is_approved(1));
        assert_eq!(
            voting.votes.pending(),
            pending(&[(1, &[&voting.voters[0], &voting.voters[1]])])
        );
    }

    #[test]
    fn remove_vote__should_un_approve_a_hash_that_drops_below_the_threshold() {
        // Given an approved hash.
        let mut voting = Voting::new();
        voting.vote(0, 1);
        assert!(voting.vote(1, 1));

        // When one of its backers withdraws.
        voting.votes.remove_vote(&voting.voters[0].clone());

        // Then it is no longer approved, and `take_if_approved` refuses it.
        assert!(!voting.is_approved(1));
        assert!(
            !voting
                .votes
                .take_if_approved(&update_hash(1), &voting.params)
        );
    }

    #[test]
    fn retain__should_un_approve_a_hash_backed_by_departed_participants() {
        // Given an approved hash.
        let mut voting = Voting::new();
        voting.vote(0, 1);
        assert!(voting.vote(1, 1));

        // When a resharing leaves only one of its backers in the participant set.
        let current = voting.params.participants().subset(1..3);
        voting.votes.retain(&current);

        // Then the hash is no longer approved under the new parameters.
        let params =
            GovernanceThresholdParameters::new_unvalidated(current, GovernanceThreshold::new(2));
        assert!(!voting.votes.is_approved(&update_hash(1), &params));
    }

    #[test]
    fn vote__should_move_approval_to_a_newly_backed_hash() {
        // Given
        let mut voting = Voting::new();
        voting.vote(0, 1);
        assert!(voting.vote(1, 1));

        // When the two backers switch to another hash.
        voting.vote(0, 2);
        let approved = voting.vote(1, 2);

        // Then
        assert!(approved);
        assert!(voting.is_approved(2));
        assert!(!voting.is_approved(1));
    }

    #[test]
    fn vote__should_replace_the_voters_previous_vote() {
        // Given
        let mut voting = Voting::new();
        voting.vote(0, 1);

        // When
        voting.vote(0, 2);

        // Then
        assert_eq!(
            voting.votes.pending(),
            pending(&[(2, &[&voting.voters[0]])])
        );
    }

    #[test]
    fn vote__should_ignore_votes_from_dropped_participants() {
        // Given a voter from a participant set that is no longer current.
        let mut voting = Voting::new();
        let former = authenticated(&gen_participants(1)).remove(0);
        assert!(
            !voting
                .votes
                .vote(&update_hash(1), former.clone(), &voting.params)
        );

        // When a single current participant joins the vote.
        let approved = voting.vote(0, 1);

        // Then the former participant's vote is recorded but does not count.
        assert!(!approved);
        assert_eq!(
            voting.votes.pending(),
            pending(&[(1, &[&former, &voting.voters[0]])])
        );
    }

    #[test]
    fn take_if_approved__should_consume_only_an_approved_hash() {
        // Given an approved hash 1, and a hash 2 below the threshold.
        let mut voting = Voting::new();
        voting.vote(0, 1);
        voting.vote(1, 1);
        voting.vote(2, 2);

        // When / Then
        assert!(
            !voting
                .votes
                .take_if_approved(&update_hash(2), &voting.params)
        );
        assert!(
            voting
                .votes
                .take_if_approved(&update_hash(1), &voting.params)
        );
        // Taking it clears every vote, so it cannot be applied twice.
        assert_eq!(voting.votes.pending(), BTreeMap::new());
        assert!(
            !voting
                .votes
                .take_if_approved(&update_hash(1), &voting.params)
        );
    }

    #[test]
    fn remove_vote__should_drop_only_that_voters_vote() {
        // Given
        let mut voting = Voting::new();
        voting.vote(0, 1);
        voting.vote(1, 2);

        // When
        voting.votes.remove_vote(&voting.voters[0]);

        // Then
        assert_eq!(
            voting.votes.pending(),
            pending(&[(2, &[&voting.voters[1]])])
        );
    }

    #[test]
    fn retain__should_drop_votes_of_former_participants() {
        // Given
        let mut voting = Voting::new();
        voting.vote(0, 1);
        voting.vote(2, 2);
        let current = voting.params.participants().subset(2..3);

        // When
        voting.votes.retain(&current);

        // Then
        assert_eq!(
            voting.votes.pending(),
            pending(&[(2, &[&voting.voters[2]])])
        );
    }
}
