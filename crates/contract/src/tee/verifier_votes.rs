//! Participant voting for the trusted `tee-verifier` account.
//!
//! `mpc-contract` invokes `verify_quote` on a single trusted verifier account
//! (`tee_verifier_account_id`), chosen by a threshold vote of active
//! participants, each committing to the `(account_id, code_hash)` pair they
//! audited off-chain. This mirrors the foreign-chain provider voting
//! ([`crate::foreign_chain_rpc::ProviderVotes`]) on top of the generic
//! [`Votes`] primitive.

use crate::errors::{ConversionError, Error};
use crate::primitives::thresholds::ThresholdParameters;
use crate::primitives::votes::{ProposalHash, ProposalHashEncoding, Votes};
use crate::primitives::{key_state::AuthenticatedParticipantId, participants::Participants};
use crate::storage_keys::StorageKey;
use near_sdk::{AccountId, CryptoHash, near};

/// A proposal to point `tee_verifier_account_id` at `candidate_account_id`.
///
/// `expected_code_hash` makes every yes-voter commit to the exact code they
/// audited off-chain: two voters who name the same account but disagree on its
/// code hash land in different proposal buckets and neither reaches threshold
/// on its own. The contract consumes only `candidate_account_id` once a bucket
/// crosses threshold; the hash is purely a commitment device.
#[near(serializers = [borsh])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierChangeProposal {
    pub candidate_account_id: AccountId,
    pub expected_code_hash: CryptoHash,
}

impl ProposalHashEncoding for VerifierChangeProposal {
    fn bytes_for_hash(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialization of VerifierChangeProposal must succeed")
    }
}

/// Pending votes for changing `tee_verifier_account_id`. Each voter is an
/// active MPC participant authenticated via [`AuthenticatedParticipantId`].
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
    /// Records `participant`'s vote for `proposal`. Returns `Some(candidate)`
    /// when the proposal crosses the signing threshold (stale rows from dropped
    /// participants don't count); on `Some`, all pending rows for that
    /// candidate are cleared and the caller must apply the new
    /// `tee_verifier_account_id`.
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
            // Clear every pending vote — including losing-hash buckets for the
            // same account and votes for other candidates — so a stale quorum
            // can't later re-fire against the now-current verifier.
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
    fn pending_voter_count(&self) -> usize {
        self.pending.all().values().map(|s| s.len()).sum()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::gen_participants;
    use crate::primitives::thresholds::ThresholdParameters;
    use mpc_primitives::Threshold;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn tp(participants: &Participants, n: u64) -> ThresholdParameters {
        ThresholdParameters::new_unvalidated(participants.clone(), Threshold::new(n))
    }

    /// Build `n` participants and pre-authenticate each (env reset before any
    /// storage-backed state is touched, mirroring the foreign-chain vote tests).
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

    fn candidate(id: &str) -> AccountId {
        id.parse().unwrap()
    }

    fn proposal(account: &str, hash_byte: u8) -> VerifierChangeProposal {
        VerifierChangeProposal {
            candidate_account_id: candidate(account),
            expected_code_hash: [hash_byte; 32],
        }
    }

    #[test]
    fn vote__should_not_cross_below_threshold() {
        // Given 3 participants, threshold 2
        let (participants, voters) = setup(3);
        let params = tp(&participants, 2);
        let mut votes = TeeVerifierVotes::default();

        // When one participant votes
        let result = votes
            .vote(proposal("v.near", 1), voters[0].clone(), &params)
            .unwrap();

        // Then no candidate wins yet
        assert_eq!(result, None);
        assert_eq!(votes.pending_voter_count(), 1);
    }

    #[test]
    fn vote__should_cross_threshold_and_clear_pending() {
        // Given 3 participants, threshold 2
        let (participants, voters) = setup(3);
        let params = tp(&participants, 2);
        let mut votes = TeeVerifierVotes::default();

        // When two participants vote for the same (account, hash)
        assert_eq!(
            votes
                .vote(proposal("v.near", 1), voters[0].clone(), &params)
                .unwrap(),
            None
        );
        let result = votes
            .vote(proposal("v.near", 1), voters[1].clone(), &params)
            .unwrap();

        // Then the candidate wins and all pending votes are cleared
        assert_eq!(result, Some(candidate("v.near")));
        assert_eq!(votes.pending_voter_count(), 0);
    }

    #[test]
    fn vote__should_not_combine_same_account_different_hashes() {
        // Given 3 participants, threshold 2
        let (participants, voters) = setup(3);
        let params = tp(&participants, 2);
        let mut votes = TeeVerifierVotes::default();

        // When two participants vote for the same account but different code hashes
        assert_eq!(
            votes
                .vote(proposal("v.near", 1), voters[0].clone(), &params)
                .unwrap(),
            None
        );
        let result = votes
            .vote(proposal("v.near", 2), voters[1].clone(), &params)
            .unwrap();

        // Then neither bucket reaches threshold
        assert_eq!(result, None);
        assert_eq!(votes.pending_voter_count(), 2);
    }

    #[test]
    fn revote__should_replace_previous_vote() {
        let (participants, voters) = setup(3);
        let params = tp(&participants, 2);
        let mut votes = TeeVerifierVotes::default();

        votes
            .vote(proposal("a.near", 1), voters[0].clone(), &params)
            .unwrap();
        // Same voter switches to a different candidate.
        votes
            .vote(proposal("b.near", 1), voters[0].clone(), &params)
            .unwrap();

        // Still just one pending vote, now for b.near; a second voter on b.near crosses.
        assert_eq!(votes.pending_voter_count(), 1);
        let result = votes
            .vote(proposal("b.near", 1), voters[1].clone(), &params)
            .unwrap();
        assert_eq!(result, Some(candidate("b.near")));
    }

    #[test]
    fn withdraw__should_remove_caller_vote() {
        let (participants, voters) = setup(3);
        let params = tp(&participants, 2);
        let mut votes = TeeVerifierVotes::default();

        votes
            .vote(proposal("v.near", 1), voters[0].clone(), &params)
            .unwrap();
        assert_eq!(votes.pending_voter_count(), 1);

        votes.withdraw(&voters[0]);
        assert_eq!(votes.pending_voter_count(), 0);

        // No-op for a voter who never voted.
        votes.withdraw(&voters[1]);
        assert_eq!(votes.pending_voter_count(), 0);
    }

    #[test]
    fn retain__should_keep_current_participants_and_drop_the_rest() {
        let (participants, voters) = setup(3);
        let params = tp(&participants, 3);
        let mut votes = TeeVerifierVotes::default();

        votes
            .vote(proposal("v.near", 1), voters[0].clone(), &params)
            .unwrap();
        votes
            .vote(proposal("v.near", 1), voters[1].clone(), &params)
            .unwrap();
        assert_eq!(votes.pending_voter_count(), 2);

        // Retaining against the same participant set is a no-op.
        votes.retain(&participants);
        assert_eq!(votes.pending_voter_count(), 2);

        // Retaining against a strict subset that excludes voter 0 keeps voter 1
        // and drops voter 0.
        votes.retain(&participants.subset(1..3));
        assert_eq!(votes.pending_voter_count(), 1);

        // Retaining against an empty set (no current participants) drops all votes.
        votes.retain(&gen_participants(0));
        assert_eq!(votes.pending_voter_count(), 0);
    }
}
