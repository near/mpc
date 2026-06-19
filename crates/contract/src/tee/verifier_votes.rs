//! Participant voting for the trusted `tee-verifier` contract account.
//!
//! `mpc-contract` verifies quotes against a single trusted verifier contract
//! account, chosen by a threshold vote of active participants, each committing
//! to the `(account_id, code_hash)` pair they audited off-chain.

use crate::{
    errors::{ConversionError, Error},
    primitives::{
        key_state::AuthenticatedParticipantId,
        participants::Participants,
        thresholds::ThresholdParameters,
        votes::{ProposalHash, ProposalHashEncoding, Votes},
    },
    storage_keys::StorageKey,
};
use mpc_primitives::hash::TeeVerifierCodeHash;
use near_sdk::{AccountId, near};
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

/// A proposal to point the trusted verifier account at a candidate account.
///
/// The expected code hash makes every yes-voter commit to the exact code they
/// audited off-chain: two voters who name the same account but disagree on its
/// code hash land in different proposal buckets and neither reaches threshold
/// on its own. The contract consumes only the candidate account once a bucket
/// crosses threshold.
#[near(serializers = [borsh])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierChangeProposal {
    pub candidate_account_id: AccountId,
    pub expected_code_hash: TeeVerifierCodeHash,
}

impl ProposalHashEncoding for VerifierChangeProposal {
    fn bytes_for_hash(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of VerifierChangeProposal must succeed")
    }
}

/// Pending votes for changing the trusted verifier account.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct TeeVerifierVotes {
    pending: Votes<AuthenticatedParticipantId>,
}

impl Default for TeeVerifierVotes {
    fn default() -> Self {
        Self {
            pending: Votes::new(
                StorageKey::TeeVerifierVotesByVoterV1,
                StorageKey::TeeVerifierVotesByProposalV1,
            ),
        }
    }
}

impl TeeVerifierVotes {
    /// Records the participant's vote for the proposal. Returns the winning
    /// candidate account once it crosses the signing threshold (votes from
    /// dropped participants don't count); on a win, all pending votes are
    /// cleared and the caller must apply the new verifier account.
    pub fn vote(
        &mut self,
        proposal: VerifierChangeProposal,
        participant: AuthenticatedParticipantId,
        threshold_parameters: &ThresholdParameters,
    ) -> Result<Option<AccountId>, Error> {
        let protocol_threshold = threshold_parameters.threshold().value();
        let participants = threshold_parameters.participants();
        let proposal_hash: ProposalHash = proposal.clone().into();

        let count_usize = {
            let voter_set = self.pending.vote(participant, proposal_hash);
            voter_set.count_for(|p| participants.is_participant_given_participant_id(&p.get()))
        };
        let count = u64::try_from(count_usize).map_err(|e| ConversionError::DataConversion {
            reason: format!("vote count {count_usize} does not fit in u64: {e}"),
        })?;

        if count >= protocol_threshold {
            self.pending.clear();
            Ok(Some(proposal.candidate_account_id))
        } else {
            Ok(None)
        }
    }

    /// Withdraws the caller's current vote, if any. No-op when the caller has
    /// not voted.
    pub fn withdraw(&mut self, participant: &AuthenticatedParticipantId) {
        self.pending.remove_vote(participant);
    }

    /// Drops votes from accounts that are no longer participants (called after
    /// a resharing changes the participant set).
    pub fn retain(&mut self, current: &Participants) {
        self.pending
            .retain_votes(|p| current.is_participant_given_participant_id(&p.get()));
    }

    #[cfg(test)]
    fn pending_votes(&self) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedParticipantId>> {
        self.pending.all()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::gen_participants;
    use mpc_primitives::Threshold;
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    fn threshold_params(participants: &Participants, threshold: u64) -> ThresholdParameters {
        ThresholdParameters::new_unvalidated(participants.clone(), Threshold::new(threshold))
    }

    /// Build `n` participants and pre-authenticate each.
    fn setup(n: usize) -> (Participants, Vec<AuthenticatedParticipantId>) {
        let participants = gen_participants(n);
        let mut auth_ids = Vec::with_capacity(n);
        for (account_id, _, _) in participants.participants() {
            let mut ctx = VMContextBuilder::new();
            ctx.signer_account_id(account_id.clone());
            testing_env!(ctx.build());
            auth_ids.push(AuthenticatedParticipantId::new(&participants).unwrap());
        }
        (participants, auth_ids)
    }

    fn proposal(account: &str, hash_byte: u8) -> VerifierChangeProposal {
        VerifierChangeProposal {
            candidate_account_id: account.parse().unwrap(),
            expected_code_hash: TeeVerifierCodeHash::new([hash_byte; 32]),
        }
    }

    /// Build 3 authenticated participants with the given signing threshold,
    /// alongside fresh, empty pending votes.
    fn setup_votes(
        threshold: u64,
    ) -> (
        Participants,
        ThresholdParameters,
        Vec<AuthenticatedParticipantId>,
        TeeVerifierVotes,
    ) {
        let (participants, voters) = setup(3);
        let params = threshold_params(&participants, threshold);
        (
            participants.clone(),
            params,
            voters,
            TeeVerifierVotes::default(),
        )
    }

    /// The expected pending-vote map: each `(proposal, voters)` pair becomes a
    /// [`ProposalHash`] bucket holding exactly those voters.
    fn expected_votes(
        buckets: impl IntoIterator<Item = (VerifierChangeProposal, Vec<AuthenticatedParticipantId>)>,
    ) -> BTreeMap<ProposalHash, BTreeSet<AuthenticatedParticipantId>> {
        let mut map = BTreeMap::new();
        for (proposal, voters) in buckets {
            let voter_count = voters.len();
            let voter_set: BTreeSet<_> = voters.into_iter().collect();
            assert_eq!(
                voter_set.len(),
                voter_count,
                "duplicate voter in expected bucket"
            );
            assert!(
                map.insert(proposal.into(), voter_set).is_none(),
                "duplicate proposal in expected votes"
            );
        }
        map
    }

    #[test]
    fn vote__should_not_cross_below_threshold() {
        // Given 3 participants, threshold 2
        let (_participants, params, voters, mut votes) = setup_votes(2);
        let proposal = proposal("v.near", 1);

        // When one participant votes
        let result = votes
            .vote(proposal.clone(), voters[0].clone(), &params)
            .unwrap();

        // Then no candidate wins yet, and the single vote is recorded
        assert_eq!(result, None);
        assert_eq!(
            votes.pending_votes(),
            expected_votes([(proposal, vec![voters[0].clone()])])
        );
    }

    #[test]
    fn vote__should_cross_threshold_and_clear_pending() {
        // Given 3 participants, threshold 2
        let (_participants, params, voters, mut votes) = setup_votes(2);
        let proposal = proposal("v.near", 1);

        // When two participants vote for the same (account, hash)
        assert_eq!(
            votes
                .vote(proposal.clone(), voters[0].clone(), &params)
                .unwrap(),
            None
        );
        let result = votes
            .vote(proposal.clone(), voters[1].clone(), &params)
            .unwrap();

        // Then the candidate wins and all pending votes are cleared
        assert_eq!(result, Some(proposal.candidate_account_id));
        assert_eq!(votes.pending_votes(), BTreeMap::new());
    }

    #[test]
    fn vote__should_not_combine_same_account_different_hashes() {
        // Given 3 participants, threshold 2
        let (_participants, params, voters, mut votes) = setup_votes(2);
        let candidate = "v.near";
        let proposal_hash_1 = proposal(candidate, 1);
        let proposal_hash_2 = proposal(candidate, 2);

        // When two participants vote for the same account but different code hashes
        assert_eq!(
            votes
                .vote(proposal_hash_1.clone(), voters[0].clone(), &params)
                .unwrap(),
            None
        );
        let result = votes
            .vote(proposal_hash_2.clone(), voters[1].clone(), &params)
            .unwrap();

        // Then neither bucket reaches threshold: the two votes land in separate
        // (account, hash) buckets.
        assert_eq!(result, None);
        assert_eq!(
            votes.pending_votes(),
            expected_votes([
                (proposal_hash_1, vec![voters[0].clone()]),
                (proposal_hash_2, vec![voters[1].clone()]),
            ])
        );
    }

    #[test]
    fn revote__should_replace_previous_vote() {
        // Given 3 participants, threshold 2
        let (_participants, params, voters, mut votes) = setup_votes(2);
        let first_proposal = proposal("a.near", 1);
        let second_proposal = proposal("b.near", 1);

        // When the same voter votes, then switches to a different candidate
        votes
            .vote(first_proposal, voters[0].clone(), &params)
            .unwrap();
        votes
            .vote(second_proposal.clone(), voters[0].clone(), &params)
            .unwrap();

        // Then only the b.near vote remains (the a.near bucket is gone); a
        // second voter on b.near then crosses.
        assert_eq!(
            votes.pending_votes(),
            expected_votes([(second_proposal.clone(), vec![voters[0].clone()])])
        );
        let result = votes
            .vote(second_proposal.clone(), voters[1].clone(), &params)
            .unwrap();
        assert_eq!(result, Some(second_proposal.candidate_account_id));
    }

    #[test]
    fn withdraw__should_remove_caller_vote() {
        // Given 3 participants, threshold 2, and one recorded vote
        let (_participants, params, voters, mut votes) = setup_votes(2);
        let proposal = proposal("v.near", 1);
        votes
            .vote(proposal.clone(), voters[0].clone(), &params)
            .unwrap();
        assert_eq!(
            votes.pending_votes(),
            expected_votes([(proposal, vec![voters[0].clone()])])
        );

        // When the caller withdraws
        votes.withdraw(&voters[0]);

        // Then their vote is removed
        assert_eq!(votes.pending_votes(), BTreeMap::new());

        // When a voter who never voted withdraws, it is a no-op
        votes.withdraw(&voters[1]);
        assert_eq!(votes.pending_votes(), BTreeMap::new());
    }

    #[test]
    fn retain__should_keep_current_participants_and_drop_the_rest() {
        // Given 3 participants, threshold 3, and two voters sharing one bucket
        let (participants, params, voters, mut votes) = setup_votes(3);
        let proposal = proposal("v.near", 1);
        votes
            .vote(proposal.clone(), voters[0].clone(), &params)
            .unwrap();
        votes
            .vote(proposal.clone(), voters[1].clone(), &params)
            .unwrap();
        let both_voters =
            expected_votes([(proposal.clone(), vec![voters[0].clone(), voters[1].clone()])]);
        assert_eq!(votes.pending_votes(), both_voters);

        // When retaining against the same participant set
        votes.retain(&participants);
        // Then it is a no-op
        assert_eq!(votes.pending_votes(), both_voters);

        // When retaining against a strict subset that excludes voter 0
        votes.retain(&participants.subset(1..3));
        // Then voter 1 is kept and voter 0 is dropped
        assert_eq!(
            votes.pending_votes(),
            expected_votes([(proposal, vec![voters[1].clone()])])
        );

        // When retaining against an empty set (no current participants)
        votes.retain(&gen_participants(0));
        // Then all votes are dropped
        assert_eq!(votes.pending_votes(), BTreeMap::new());
    }
}
