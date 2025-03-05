use std::collections::HashSet;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, PublicKey};

use crate::errors::Error;
use crate::errors::{InvalidState, VoteError};
use crate::primitives::{Candidates, Participants, PkVotes, Votes};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolContractState {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolContractState::NotInitialized => "NotInitialized",
            ProtocolContractState::Initializing(_) => "Initializing",
            ProtocolContractState::Running(_) => "Running",
            ProtocolContractState::Resharing(_) => "Resharing",
        }
    }
    pub fn is_participant(&self, voter: AccountId) -> Result<AccountId, Error> {
        match &self {
            ProtocolContractState::Initializing(state) => {
                if !state.candidates.contains_key(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::Running(state) => {
                if !state.participants.contains_key(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::Resharing(state) => {
                if !state.old_participants.contains_key(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        }
        Ok(voter)
    }
    pub fn threshold(&self) -> Result<usize, Error> {
        match self {
            ProtocolContractState::Initializing(state) => Ok(state.threshold),
            ProtocolContractState::Running(state) => Ok(state.threshold),
            ProtocolContractState::Resharing(state) => Ok(state.threshold),
            ProtocolContractState::NotInitialized => {
                Err(InvalidState::UnexpectedProtocolState.message(self.name()))
            }
        }
    }
}
