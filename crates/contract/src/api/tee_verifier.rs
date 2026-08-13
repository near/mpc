//! The account trusted to verify DCAP quotes, and the participant votes that
//! change it.

use std::collections::{BTreeMap, BTreeSet};

use crate::errors::InvalidState;
use crate::{
    errors::Error, primitives::votes::ProposalHash, tee::verifier_votes::VerifierChangeProposal,
};

use crate::dto_mapping::IntoInterfaceType;
use crate::primitives::key_state::AuthenticatedParticipantId;
use mpc_primitives::hash::TeeVerifierCodeHash;
use near_mpc_contract_interface::types as dtos;
use near_sdk::{AccountId, env, log, near};

use crate::state::ProtocolContractState;
use crate::{MpcContract, MpcContractExt};

#[near]
impl MpcContract {
    /// Vote for a candidate account to become the trusted verifier contract
    /// account, committing to the code hash the voter audited. When the proposal
    /// crosses the signing threshold, the trusted verifier account is updated
    /// and all pending verifier-change votes are cleared.
    #[handle_result]
    pub fn vote_tee_verifier_change(
        &mut self,
        candidate_account_id: AccountId,
        expected_code_hash: TeeVerifierCodeHash,
    ) -> Result<(), Error> {
        log!(
            "vote_tee_verifier_change: signer={}, candidate={}, expected_code_hash={}",
            env::signer_account_id(),
            candidate_account_id,
            expected_code_hash,
        );
        self.voter_or_panic();

        // Voting in the already-current verifier is a no-op
        if self.tee_verifier_account_id.as_ref() == Some(&candidate_account_id) {
            return Ok(());
        }

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();
        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;

        let proposal = VerifierChangeProposal {
            candidate_account_id,
            expected_code_hash,
        };
        if let Some(new_verifier) =
            self.tee_verifier_votes
                .vote(proposal, participant, threshold_parameters)?
        {
            log!("vote_tee_verifier_change: new verifier = {}", new_verifier);
            self.tee_verifier_account_id = Some(new_verifier);
        }
        Ok(())
    }

    /// Withdraw the caller's current vote on any pending verifier-change
    /// proposal. No-op if the caller has not voted.
    #[handle_result]
    pub fn withdraw_tee_verifier_vote(&mut self) -> Result<(), Error> {
        log!(
            "withdraw_tee_verifier_vote: signer={}",
            env::signer_account_id(),
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();
        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;

        self.tee_verifier_votes.withdraw(&participant);
        Ok(())
    }

    /// Private endpoint to drop verifier-change votes cast by non-participants
    /// after resharing.
    #[private]
    #[handle_result]
    pub fn remove_non_participant_tee_verifier_votes(&mut self) -> Result<(), Error> {
        log!(
            "remove_non_participant_tee_verifier_votes: signer={}",
            env::signer_account_id()
        );

        let participants = match &self.protocol_state {
            ProtocolContractState::Running(state) => state.parameters.participants(),
            _ => {
                return Err(InvalidState::ProtocolStateNotRunning.into());
            }
        };

        self.tee_verifier_votes.retain(participants);

        Ok(())
    }

    /// Returns the pending TEE verifier-change votes, keyed by proposal.
    pub fn tee_verifier_votes(
        &self,
    ) -> BTreeMap<ProposalHash, BTreeSet<dtos::AuthenticatedParticipantId>> {
        self.tee_verifier_votes
            .pending()
            .iter()
            .map(|(proposal, voters)| {
                (
                    *proposal,
                    voters.iter().map(|v| v.into_dto_type()).collect(),
                )
            })
            .collect()
    }

    /// Returns the trusted TEE verifier contract account, or [`None`] until
    /// participants vote one in via [`Self::vote_tee_verifier_change`].
    pub fn tee_verifier_account_id(&self) -> Option<AccountId> {
        self.tee_verifier_account_id.clone()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::*;
    use crate::primitives::thresholds::GovernanceThreshold;
    use crate::primitives::thresholds::GovernanceThresholdParameters;
    use std::{collections::BTreeMap, panic};

    use crate::state::key_event::tests::Environment;

    use crate::*;

    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    #[test]
    fn vote_tee_verifier_change__should_apply_candidate_when_threshold_reached() {
        // Given a running contract with 3 participants, signing threshold 2,
        // starting unconfigured.
        let (mut contract, participants, _) = setup_tee_test_contract(3, 2);
        assert_eq!(contract.tee_verifier_account_id, None);
        let participant_account_ids: Vec<AccountId> = participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        let candidate: AccountId = "verifier.near".parse().unwrap();
        let code_hash = TeeVerifierCodeHash::new([7u8; 32]);

        let vote_as = |contract: &mut MpcContract, account_id: &AccountId| {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_tee_verifier_change(candidate.clone(), code_hash)
                .expect("vote should succeed");
        };

        // When the first participant votes (below threshold), the verifier is unchanged.
        vote_as(&mut contract, &participant_account_ids[0]);
        assert_eq!(contract.tee_verifier_account_id, None);

        // When the second participant votes, threshold is reached and the
        // candidate becomes the trusted verifier.
        vote_as(&mut contract, &participant_account_ids[1]);
        assert_eq!(contract.tee_verifier_account_id, Some(candidate));
    }

    #[test]
    fn tee_verifier_account_id__should_report_none_until_threshold_then_the_candidate() {
        // Given
        let (mut contract, _, _) = setup_tee_test_contract(3, 2);
        let voters = participant_account_ids(&contract);
        let candidate: AccountId = "verifier.near".parse().unwrap();
        let code_hash = TeeVerifierCodeHash::new([7u8; 32]);

        let vote_as = |contract: &mut MpcContract, account_id: &AccountId| {
            Environment::new(None, Some(account_id.clone()), None);
            contract
                .vote_tee_verifier_change(candidate.clone(), code_hash)
                .expect("vote should succeed");
        };

        assert_eq!(contract.tee_verifier_account_id(), None);

        // When
        vote_as(&mut contract, &voters[0]);
        assert_eq!(contract.tee_verifier_account_id(), None);
        vote_as(&mut contract, &voters[1]);

        // Then
        assert_eq!(contract.tee_verifier_account_id(), Some(candidate));
    }

    #[test]
    fn remove_non_participant_tee_verifier_votes__should_drop_votes_from_dropped_participants() {
        // Given a running contract with 3 participants, signing threshold 3, where
        // two participants have cast votes for distinct candidates (neither crosses
        // threshold, so both stay pending).
        let (mut contract, participants, _) = setup_tee_test_contract(3, 3);
        let voters = participant_account_ids(&contract);
        let code_hash = TeeVerifierCodeHash::new([7u8; 32]);

        // Vote as `account_id` for `candidate`, returning that voter's authenticated id.
        let vote_as =
            |contract: &mut MpcContract, account_id: &AccountId, candidate: &AccountId| {
                Environment::new(None, Some(account_id.clone()), None);
                contract
                    .vote_tee_verifier_change(candidate.clone(), code_hash)
                    .expect("vote should succeed");
                AuthenticatedParticipantId::new(&participants).unwrap()
            };

        // The single-voter pending bucket: proposal(candidate) -> {voter}.
        let bucket = |candidate: &AccountId, voter: &AuthenticatedParticipantId| {
            let proposal = VerifierChangeProposal {
                candidate_account_id: candidate.clone(),
                expected_code_hash: code_hash,
            };
            (
                ProposalHash::from(proposal),
                BTreeSet::from([voter.into_dto_type()]),
            )
        };

        let candidate_a: AccountId = "verifier-a.near".parse().unwrap();
        let candidate_b: AccountId = "verifier-b.near".parse().unwrap();
        let auth_a = vote_as(&mut contract, &voters[0], &candidate_a);
        let auth_b = vote_as(&mut contract, &voters[1], &candidate_b);

        // Then both single-voter buckets are pending.
        assert_eq!(
            contract.tee_verifier_votes(),
            BTreeMap::from([bucket(&candidate_a, &auth_a), bucket(&candidate_b, &auth_b)]),
        );

        // When resharing drops the first participant and the post-resharing cleanup runs.
        {
            let ProtocolContractState::Running(ref mut state) = contract.protocol_state else {
                panic!("expected Running");
            };
            state.parameters = GovernanceThresholdParameters::new(
                participants.subset(1..3),
                GovernanceThreshold::new(2),
            )
            .unwrap();
        }
        Environment::new(None, Some(env::current_account_id()), None);
        contract
            .remove_non_participant_tee_verifier_votes()
            .unwrap();

        // Then only the still-participant's vote (candidate B) remains.
        assert_eq!(
            contract.tee_verifier_votes(),
            BTreeMap::from([bucket(&candidate_b, &auth_b)]),
        );
    }
}
