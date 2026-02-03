use super::resharing::ResharingContractState;
use super::InitializingContractState;
use crate::primitives::test_utils::{bogus_ed25519_public_key_extended, gen_domains_to_add};
use crate::primitives::{key_state::AttemptId, test_utils::gen_domain_registry};
use crate::state::key_event::tests::Environment;
use crate::state::running::RunningContractState;
use std::collections::BTreeSet;

use crate::primitives::{
    key_state::{EpochId, KeyForDomain, Keyset},
    participants::{ParticipantId, Participants},
    test_utils::{gen_participant, gen_threshold_params},
    thresholds::{Threshold, ThresholdParameters},
};
use rand::Rng;

pub fn gen_valid_params_proposal(params: &ThresholdParameters) -> ThresholdParameters {
    let mut rng = rand::thread_rng();
    let current_k = params.threshold().value() as usize;
    let current_n = params.participants().len();
    let n_old_participants: usize = rng.gen_range(current_k..current_n + 1);
    let current_participants = params.participants();
    let mut old_ids: BTreeSet<ParticipantId> = current_participants
        .participants()
        .map(|(_, id, _)| *id)
        .collect();
    let mut new_ids = BTreeSet::new();
    while new_ids.len() < (n_old_participants as usize) {
        let x: usize = rng.gen::<usize>() % old_ids.len();
        let c = *old_ids.iter().nth(x).unwrap();
        new_ids.insert(c);
        old_ids.remove(&c);
    }
    let mut new_participants = Participants::default();
    for id in new_ids {
        let account_id = current_participants.account_id(&id).unwrap();
        let info = current_participants.info(&account_id).unwrap();
        let _ = new_participants.insert_with_id(account_id, info.clone(), id);
    }
    let max_added: usize = rng.gen_range(0..10);
    let mut next_id = current_participants.next_id();
    for i in 0..max_added {
        let (account_id, info) = gen_participant(i);
        let _ = new_participants.insert_with_id(account_id, info, next_id);
        next_id = next_id.next();
    }

    let threshold = ((new_participants.len() as f64) * 0.6).ceil() as u64;
    ThresholdParameters::new(new_participants, Threshold::new(threshold)).unwrap()
}

/// Generates a resharing state with the given number of domains.
/// We do this by starting from the Running state and calling vote_new_parameters to have it
/// transition into Resharing. (This also tests the transitioning code path.)
pub fn gen_resharing_state(num_domains: usize) -> (Environment, ResharingContractState) {
    let mut env = Environment::new(Some(100), None, None);
    let mut running = gen_running_state(num_domains);
    let proposal = gen_valid_params_proposal(&running.parameters);
    let mut resharing_state = None;

    // Current participants must vote first (before new candidates can vote)
    let current_account_ids: BTreeSet<_> = running
        .parameters
        .participants()
        .participants()
        .map(|(a, _, _)| a.clone())
        .collect();

    for (account, _, _) in proposal.participants().participants() {
        if current_account_ids.contains(account) {
            env.set_signer(account);
            assert!(resharing_state.is_none());
            resharing_state = running
                .vote_new_parameters(running.keyset.epoch_id.next(), &proposal)
                .unwrap();
        }
    }
    // Then new candidates vote
    for (account, _, _) in proposal.participants().participants() {
        if !current_account_ids.contains(account) {
            env.set_signer(account);
            assert!(resharing_state.is_none());
            resharing_state = running
                .vote_new_parameters(running.keyset.epoch_id.next(), &proposal)
                .unwrap();
        }
    }
    (
        env,
        resharing_state.expect("Should've transitioned into resharing"),
    )
}
/// Generates a Running state that contains this many domains.
pub fn gen_running_state(num_domains: usize) -> RunningContractState {
    let epoch_id = EpochId::new(rand::thread_rng().gen());
    let domains = gen_domain_registry(num_domains);

    let mut keys = Vec::new();
    for domain in domains.domains() {
        let mut attempt = AttemptId::default();
        let x: usize = rand::thread_rng().gen();
        let x = x % 800;
        for _ in 0..x {
            attempt = attempt.next();
        }
        keys.push(KeyForDomain {
            attempt,
            domain_id: domain.id,
            key: bogus_ed25519_public_key_extended(),
        });
    }
    let max_n = 30;
    let threshold_parameters = gen_threshold_params(max_n);
    RunningContractState::new(domains, Keyset::new(epoch_id, keys), threshold_parameters)
}

/// Randomly generates an InitializingContractState where we already have keys for
/// `num_generated` domains, and we are targeting `num_domains` total domains.
/// This is done by starting from a Running state with `num_generated` keys and then transition
/// into Initializing state by calling vote_add_domains. (We also test that code path.)
pub fn gen_initializing_state(
    num_domains: usize,
    num_generated: usize,
) -> (Environment, InitializingContractState) {
    let mut env = Environment::new(None, None, None);
    let mut running = gen_running_state(num_generated);
    let domains_to_add = gen_domains_to_add(&running.domains, num_domains - num_generated);

    let mut initializing_state = None;
    for entry in running.parameters.participants().participants_vec() {
        env.set_signer(&entry.account_id);
        assert!(initializing_state.is_none());
        initializing_state = running.vote_add_domains(domains_to_add.clone()).unwrap();
    }
    let initializing_state = initializing_state
        .expect("Enough votes to add domains should transition into initializing");
    (env, initializing_state)
}
