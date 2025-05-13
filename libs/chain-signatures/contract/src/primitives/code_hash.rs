use near_sdk::{log, near};
use std::collections::BTreeMap;

use super::key_state::AuthenticatedParticipantId;

/// Hash of a Docker image running in the TEE environment.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct CodeHash([u8; 32]);

/// Remote Attestation TDX quote.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TeeQuote(Vec<u8>);

impl TeeQuote {
    pub fn new(data: Vec<u8>) -> Self {
        TeeQuote(data)
    }
}

/// Proposal for a new TEE code hash to be added to the whitelist, along with the TEE quote
/// containing the RTMR3.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TeeProposal {
    pub code_hash: CodeHash,
    pub tee_quote: TeeQuote,
}

/// Tracks votes to add whitelisted TEE code hashes. Each participant can at any given time vote for
/// a code hash to add.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeHashesVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, TeeProposal>,
}

impl CodeHashesVotes {
    /// Casts a vote for the proposal and returns the total number of participants who have voted
    /// for the same code hash. If the participant already voted, their previous vote is replaced.
    pub fn vote(&mut self, proposal: TeeProposal, participant: &AuthenticatedParticipantId) -> u64 {
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
    fn count_votes(&self, proposal: &TeeProposal) -> u64 {
        self.proposal_by_account
            .values()
            .filter(|&prop| prop.code_hash == proposal.code_hash)
            .count() as u64
    }

    /// Clears all proposals.
    pub fn clear_votes(&mut self) {
        self.proposal_by_account.clear();
    }
}
