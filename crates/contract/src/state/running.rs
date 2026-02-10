use super::initializing::InitializingContractState;
use super::key_event::KeyEvent;
use super::resharing::ResharingContractState;
use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{DomainError, Error, InvalidParameters, VoteError};
use crate::primitives::{
    domain::{
        AddDomainsVotes, DomainConfig, DomainId, DomainRegistry, ImportDomainVotes,
        SignatureScheme,
    },
    key_state::{
        AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
        Keyset,
    },
    thresholds::ThresholdParameters,
    votes::ThresholdParametersVotes,
};
use near_account_id::AccountId;
use near_sdk::near;
use std::collections::{BTreeSet, HashSet};

/// In this state, the contract is ready to process signature requests.
///
/// Proposals can be submitted to modify the state:
///  - vote_add_domains, upon threshold agreement, transitions into the
///    Initializing state to generate keys for new domains.
///  - vote_new_parameters, upon threshold agreement, transitions into the
///    Resharing state to reshare keys for new participants and also change the
///    threshold if desired.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningContractState {
    /// The domains for which we have a key ready for signature processing.
    pub domains: DomainRegistry,
    /// The keys that are currently in use; for each domain provides an unique identifier for a
    /// distributed key, so that the nodes can identify which local keyshare to use.
    pub keyset: Keyset,
    /// The current participants and threshold.
    pub parameters: ThresholdParameters,
    /// Votes for proposals for a new set of participants and threshold.
    pub parameters_votes: ThresholdParametersVotes,
    /// Votes for proposals to add new domains.
    pub add_domains_votes: AddDomainsVotes,
    /// Votes for importing a domain with a pre-existing key from an external MPC instance.
    pub import_domain_votes: ImportDomainVotes,
    /// The previous epoch id for a resharing state that was cancelled.
    /// This epoch id is tracked, as the next time the state transitions to resharing,
    /// we can't reuse a previously cancelled epoch id.
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl RunningContractState {
    pub fn new(domains: DomainRegistry, keyset: Keyset, parameters: ThresholdParameters) -> Self {
        RunningContractState {
            domains,
            keyset,
            parameters,
            parameters_votes: ThresholdParametersVotes::default(),
            add_domains_votes: AddDomainsVotes::default(),
            import_domain_votes: ImportDomainVotes::default(),
            previously_cancelled_resharing_epoch_id: None,
        }
    }

    pub fn transition_to_resharing_no_checks(
        &mut self,
        proposal: &ThresholdParameters,
    ) -> Option<ResharingContractState> {
        if let Some(first_domain) = self.domains.get_domain_by_index(0) {
            let epoch_id = self.prospective_epoch_id();

            Some(ResharingContractState {
                previous_running_state: RunningContractState::new(
                    self.domains.clone(),
                    self.keyset.clone(),
                    self.parameters.clone(),
                ),
                reshared_keys: Vec::new(),
                resharing_key: KeyEvent::new(epoch_id, first_domain.clone(), proposal.clone()),
                cancellation_requests: HashSet::new(),
            })
        } else {
            // A new ThresholdParameters was proposed, but we have no keys, so directly
            // transition into Running state but bump the EpochId.
            *self = RunningContractState::new(
                self.domains.clone(),
                Keyset::new(self.keyset.epoch_id.next(), Vec::new()),
                proposal.clone(),
            );
            None
        }
    }

    /// Casts a vote for `proposal` to the current state, propagating any errors.
    /// Returns ResharingContractState if the proposal is accepted.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: &ThresholdParameters,
    ) -> Result<Option<ResharingContractState>, Error> {
        let expected_prospective_epoch_id = self.prospective_epoch_id();

        if prospective_epoch_id != expected_prospective_epoch_id {
            return Err(InvalidParameters::EpochMismatch {
                expected: expected_prospective_epoch_id,
                provided: prospective_epoch_id,
            }
            .into());
        }

        if self.process_new_parameters_proposal(proposal)? {
            return Ok(self.transition_to_resharing_no_checks(proposal));
        }
        Ok(None)
    }

    pub fn prospective_epoch_id(&self) -> EpochId {
        match self.previously_cancelled_resharing_epoch_id {
            // If `cancelled_epoch_id`, then a resharing has already
            // been attempted but was cancelled.
            // We must make sure to not reuse previously used prospective epoch ids,
            // and continue from the last prospective epoch id for the previous resharing attempt.
            Some(cancelled_epoch_id) => cancelled_epoch_id,
            // No resharing has been attempted for this running state.
            None => self.keyset.epoch_id,
        }
        .next()
    }

    /// Casts a vote for `proposal`, removing any previous votes by `env::signer_account_id()`.
    /// Fails if the proposal is invalid or the signer is not a proposed participant.
    /// Returns true if all participants of the proposed parameters voted for it.
    pub(super) fn process_new_parameters_proposal(
        &mut self,
        proposal: &ThresholdParameters,
    ) -> Result<bool, Error> {
        // ensure the proposal is valid against the current parameters
        self.parameters.validate_incoming_proposal(proposal)?;

        // ensure the signer is a proposed participant
        let candidate = AuthenticatedAccountId::new(proposal.participants())?;

        // If the signer is not a participant of the current epoch, they can only vote after
        // `threshold` participant of the current epoch have casted their vote to admit them.
        if AuthenticatedAccountId::new(self.parameters.participants()).is_err() {
            let n_votes = self
                .parameters_votes
                .n_votes(proposal, self.parameters.participants());
            if n_votes < self.parameters.threshold().value() {
                return Err(VoteError::VoterPending.into());
            }
        }

        // finally, vote.
        let n_votes = self.parameters_votes.vote(proposal, candidate);
        Ok(proposal.participants().len() as u64 == n_votes)
    }

    /// Casts a vote for the signer participant to add new domains, replacing any previous vote.
    /// If the number of votes for the same set of new domains reaches the number of participants,
    /// returns the InitializingContractState we should transition into to generate keys for these
    /// new domains.
    pub fn vote_add_domains(
        &mut self,
        domains: Vec<DomainConfig>,
    ) -> Result<Option<InitializingContractState>, Error> {
        if domains.is_empty() {
            return Err(DomainError::AddDomainsMustAddAtLeastOneDomain.into());
        }
        let participant = AuthenticatedParticipantId::new(self.parameters.participants())?;
        let n_votes = self.add_domains_votes.vote(domains.clone(), &participant);
        if self.parameters.participants().len() as u64 == n_votes {
            let new_domains = self.domains.add_domains(domains.clone())?;
            Ok(Some(InitializingContractState {
                generated_keys: self.keyset.domains.clone(),
                domains: new_domains,
                epoch_id: self.keyset.epoch_id,
                generating_key: KeyEvent::new(
                    self.keyset.epoch_id,
                    domains[0].clone(),
                    self.parameters.clone(),
                ),
                cancel_votes: BTreeSet::new(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Casts a vote to import a domain with a pre-existing Secp256k1 key.
    /// When all participants vote for the same key, the domain is added directly
    /// in the Running state without going through key generation.
    pub fn vote_import_domain(
        &mut self,
        public_key: PublicKeyExtended,
    ) -> Result<Option<DomainId>, Error> {
        if !matches!(public_key, PublicKeyExtended::Secp256k1 { .. }) {
            return Err(DomainError::ImportDomainUnsupportedScheme.into());
        }
        if self.keyset.domains.iter().any(|kfd| kfd.key == public_key) {
            return Err(DomainError::ImportDomainKeyAlreadyExists.into());
        }
        let participant = AuthenticatedParticipantId::new(self.parameters.participants())?;
        let n_votes = self.import_domain_votes.vote(public_key.clone(), &participant);
        if self.parameters.participants().len() as u64 == n_votes {
            let domain_id = self.domains.add_domain(SignatureScheme::Secp256k1);
            self.keyset.domains.push(KeyForDomain {
                domain_id,
                key: public_key,
                attempt: AttemptId::new(),
            });
            self.import_domain_votes = ImportDomainVotes::default();
            Ok(Some(domain_id))
        } else {
            Ok(None)
        }
    }

    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.parameters.participants().is_participant(account_id)
    }
}

#[cfg(test)]
pub mod running_tests {
    use rstest::rstest;

    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::test_utils::{gen_threshold_params, NUM_PROTOCOLS};
    use crate::state::key_event::tests::Environment;
    use crate::state::test_utils::gen_valid_params_proposal;
    use crate::{
        primitives::votes::ThresholdParametersVotes, state::test_utils::gen_running_state,
    };

    fn test_running_for(num_domains: usize) {
        let mut state = gen_running_state(num_domains);
        println!(
            "Participants: {}, threshold: {}",
            state.parameters.participants().len(),
            state.parameters.threshold().value()
        );
        let mut env = Environment::new(None, None, None);
        let participants = state.parameters.participants().clone();
        // Assert that random proposals get rejected.
        for (account_id, _, _) in participants.participants() {
            let ksp = gen_threshold_params(30);
            env.set_signer(account_id);
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &ksp)
                .unwrap_err();
        }
        // Assert that proposals of the wrong epoch ID get rejected.
        {
            let ksp = gen_valid_params_proposal(&state.parameters);
            env.set_signer(&participants.participants()[0].0);
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id, &ksp)
                .unwrap_err();
            let _ = state
                .vote_new_parameters(state.keyset.epoch_id.next().next(), &ksp)
                .unwrap_err();
        }
        // Assert that disagreeing proposals do not reach consensus.
        // Generate an extra proposal for the next step.
        let mut proposals = Vec::new();
        for i in 0..participants.participants().len() + 1 {
            loop {
                let proposal = gen_valid_params_proposal(&state.parameters);
                if proposals.contains(&proposal) {
                    continue;
                }
                if i < participants.participants().len()
                    && !proposal
                        .participants()
                        .is_participant(&participants.participants()[i].0)
                {
                    continue;
                }
                proposals.push(proposal.clone());
                break;
            }
        }
        for (i, (account_id, _, _)) in participants.participants().iter().enumerate() {
            env.set_signer(account_id);
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposals[i])
                .unwrap()
                .is_none());
        }

        // Now let's vote for agreeing proposals.
        let proposal = proposals.last().unwrap().clone();

        let original_epoch_id = state.keyset.epoch_id;
        let mut resharing = None;
        // existing participants vote
        let mut n_votes = 0;
        for (account_id, _, _) in participants.participants().iter() {
            if !proposal.participants().is_participant(account_id) {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        // candidates vote
        for (account_id, _, _) in proposal.participants().participants().iter() {
            if participants.is_participant(account_id) {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        if num_domains == 0 {
            // If there are no domains, we should transition directly to Running with a higher
            // epoch ID, not resharing.
            assert_eq!(state.keyset.epoch_id, original_epoch_id.next());
            assert_eq!(state.parameters_votes, ThresholdParametersVotes::default());
            assert_eq!(state.add_domains_votes, AddDomainsVotes::default());
        } else {
            let resharing = resharing.unwrap();
            assert_eq!(
                resharing.previous_running_state.parameters,
                state.parameters
            );
            assert_eq!(
                resharing.prospective_epoch_id(),
                state.keyset.epoch_id.next(),
            );
            assert_eq!(resharing.resharing_key.proposed_parameters(), &proposal);
        }
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(NUM_PROTOCOLS)]
    #[case(2*NUM_PROTOCOLS)]
    fn test_running(#[case] n: usize) {
        test_running_for(n);
    }

    mod import_domain_tests {
        use crate::crypto_shared::types::PublicKeyExtended;
        use crate::primitives::test_utils::bogus_ed25519_public_key_extended;
        use crate::state::key_event::tests::Environment;
        use crate::state::test_utils::gen_running_state;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::SecretKey;

        fn gen_secp256k1_public_key_extended() -> PublicKeyExtended {
            let secret_key = SecretKey::random(&mut rand::thread_rng());
            let public_key = secret_key.public_key();
            let encoded = public_key.to_encoded_point(false);
            // NEAR SDK Secp256k1 public key: 65 bytes = 0x04 prefix + 64 bytes
            // But near_sdk::PublicKey stores them with a 0 prefix byte for SECP256K1.
            let bytes: Vec<u8> = encoded.as_bytes()[1..].to_vec(); // drop 0x04 prefix, keep 64 bytes
            let near_public_key =
                near_sdk::PublicKey::from_parts(near_sdk::CurveType::SECP256K1, bytes).unwrap();
            PublicKeyExtended::Secp256k1 { near_public_key }
        }

        #[test]
        fn test_vote_import_domain_happy_path() {
            let mut state = gen_running_state(1);
            let mut env = Environment::new(None, None, None);
            let participants = state.parameters.participants().clone();
            let public_key = gen_secp256k1_public_key_extended();

            let initial_domain_count = state.domains.domains().len();
            let initial_keyset_count = state.keyset.domains.len();

            // All participants vote with the same key.
            for (i, (account_id, _, _)) in participants.participants().iter().enumerate() {
                env.set_signer(account_id);
                let result = state.vote_import_domain(public_key.clone()).unwrap();
                if i < participants.len() - 1 {
                    // Not yet consensus.
                    assert!(result.is_none());
                } else {
                    // Last vote triggers domain creation.
                    let domain_id = result.expect("Should have created domain");
                    assert_eq!(state.domains.domains().len(), initial_domain_count + 1);
                    assert_eq!(state.keyset.domains.len(), initial_keyset_count + 1);
                    // Check the new domain is in the keyset with the correct key.
                    let last_kfd = state.keyset.domains.last().unwrap();
                    assert_eq!(last_kfd.domain_id, domain_id);
                    let kfd_pk: contract_interface::types::PublicKey = last_kfd.key.clone().into();
                    let expected_pk: contract_interface::types::PublicKey = public_key.clone().into();
                    assert_eq!(kfd_pk, expected_pk);
                }
            }
        }

        #[test]
        fn test_vote_import_domain_partial_votes() {
            let mut state = gen_running_state(1);
            let mut env = Environment::new(None, None, None);
            let participants = state.parameters.participants().clone();
            let public_key = gen_secp256k1_public_key_extended();

            let initial_domain_count = state.domains.domains().len();

            // Only first participant votes.
            let (account_id, _, _) = &participants.participants()[0];
            env.set_signer(account_id);
            let result = state.vote_import_domain(public_key.clone()).unwrap();
            assert!(result.is_none());

            // No domain created.
            assert_eq!(state.domains.domains().len(), initial_domain_count);
        }

        #[test]
        fn test_vote_import_domain_disagreeing_votes() {
            let mut state = gen_running_state(1);
            let mut env = Environment::new(None, None, None);
            let participants = state.parameters.participants().clone();

            let initial_domain_count = state.domains.domains().len();

            // Each participant votes for a different key.
            for (account_id, _, _) in participants.participants().iter() {
                let public_key = gen_secp256k1_public_key_extended();
                env.set_signer(account_id);
                let result = state.vote_import_domain(public_key).unwrap();
                assert!(result.is_none());
            }

            // No domain created because votes disagree.
            assert_eq!(state.domains.domains().len(), initial_domain_count);
        }

        #[test]
        fn test_vote_import_domain_non_participant() {
            let mut state = gen_running_state(1);
            let _env = Environment::new(None, None, None);
            let public_key = gen_secp256k1_public_key_extended();

            // The environment's default signer is not a participant.
            let result = state.vote_import_domain(public_key);
            result.unwrap_err();
        }

        #[test]
        fn test_vote_import_domain_rejects_duplicate_key() {
            let mut state = gen_running_state(1);
            let mut env = Environment::new(None, None, None);
            let participants = state.parameters.participants().clone();
            let public_key = gen_secp256k1_public_key_extended();

            // First import: all participants vote for the same key.
            for (account_id, _, _) in participants.participants().iter() {
                env.set_signer(account_id);
                state.vote_import_domain(public_key.clone()).unwrap();
            }

            // Verify domain was created.
            let domain_count = state.keyset.domains.len();
            assert!(domain_count >= 2);

            // Second import attempt with the same key should fail.
            let (account_id, _, _) = &participants.participants()[0];
            env.set_signer(account_id);
            let result = state.vote_import_domain(public_key);
            result.unwrap_err();
        }

        #[test]
        fn test_vote_import_domain_rejects_ed25519() {
            let mut state = gen_running_state(1);
            let mut env = Environment::new(None, None, None);
            let participants = state.parameters.participants().clone();

            let ed25519_key = bogus_ed25519_public_key_extended();
            let (account_id, _, _) = &participants.participants()[0];
            env.set_signer(account_id);
            let result = state.vote_import_domain(ed25519_key);
            result.unwrap_err();
        }
    }
}
