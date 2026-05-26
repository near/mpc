//! Hash-based vote stores for governance (participants + threshold) and domain
//! changes. Lives at the top level of [`MpcContract`][crate::MpcContract] rather
//! than inside [`RunningContractState`][crate::state::running::RunningContractState]
//! because [`Votes<V>`] is `IterableMap`-backed and cannot satisfy
//! `Clone + PartialEq + JSON`, which `RunningContractState` derives.

use near_sdk::near;

use crate::primitives::{
    domain::ProposedDomains,
    key_state::{AuthenticatedAccountId, AuthenticatedParticipantId},
    participants::Participants,
    thresholds::ThresholdParameters,
    votes::{ProposalHash, Votes},
};
use crate::storage_keys::StorageKey;

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct ContractVotes {
    governance: Votes<AuthenticatedAccountId>,
    domains: Votes<AuthenticatedParticipantId>,
}

impl Default for ContractVotes {
    fn default() -> Self {
        Self {
            governance: Votes::new(
                StorageKey::GovernanceVotesByVoterV1,
                StorageKey::GovernanceVotesByProposalV1,
            ),
            domains: Votes::new(
                StorageKey::DomainsVotesByVoterV1,
                StorageKey::DomainsVotesByProposalV1,
            ),
        }
    }
}

impl ContractVotes {
    /// Records `voter`'s vote for `proposal` and returns the count of voters from
    /// `participants` who have voted for the *same* proposal.
    pub fn vote_governance(
        &mut self,
        voter: AuthenticatedAccountId,
        proposal: &ThresholdParameters,
        participants: &Participants,
    ) -> u64 {
        let hash = ProposalHash::from(proposal.clone());
        let voter_set = self.governance.vote(voter, hash);
        voter_set
            .count_for(|v| {
                participants
                    .participants()
                    .iter()
                    .any(|(acc_id, _, _)| v.get() == acc_id)
            })
            .try_into()
            .expect("usize -> u64 conversion never fails on wasm32")
    }

    /// Counts voters from `participants` who have voted for `proposal`.
    /// Does not record a new vote.
    pub fn governance_count_for(
        &self,
        proposal: &ThresholdParameters,
        participants: &Participants,
    ) -> u64 {
        let hash = ProposalHash::from(proposal.clone());
        self.governance
            .all()
            .get(&hash)
            .map(|voters| {
                voters
                    .iter()
                    .filter(|v| {
                        participants
                            .participants()
                            .iter()
                            .any(|(acc_id, _, _)| v.get() == acc_id)
                    })
                    .count()
            })
            .unwrap_or(0)
            .try_into()
            .expect("usize -> u64 conversion never fails on wasm32")
    }

    /// Records `voter`'s vote to add `proposal` (a list of domains).
    /// Returns the count of voters who have voted for the same proposal.
    pub fn vote_domains(
        &mut self,
        voter: AuthenticatedParticipantId,
        proposal: &ProposedDomains,
    ) -> u64 {
        let hash = ProposalHash::from(proposal.clone());
        let voter_set = self.domains.vote(voter, hash);
        u64::try_from(voter_set.count_for(|_| true))
            .expect("usize -> u64 conversion never fails on wasm32")
    }

    /// Drops all in-flight governance votes. Called on state transitions that
    /// produce a fresh `RunningContractState` lifetime.
    pub fn clear_governance(&mut self) {
        self.governance.clear();
    }

    /// Drops all in-flight domain votes.
    pub fn clear_domains(&mut self) {
        self.domains.clear();
    }

    /// Retains only votes cast by accounts still in `current`. Mirrors the legacy
    /// `AddDomainsVotes::get_remaining_votes` semantics used post-resharing.
    pub fn retain_domain_votes_for(&mut self, current: &Participants) {
        self.domains
            .retain_votes(|v| current.is_participant_given_participant_id(&v.get()));
    }
}
