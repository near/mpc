use std::collections::{BTreeMap, BTreeSet, HashSet};

use near_mpc_contract_interface::types::{
    AttemptId, EpochId, InitializingContractState, KeyEvent, ProtocolContractState,
    ResharingContractState, RunningContractState,
};

const RUNNING_STATE_FIXTURE: &str = include_str!("../assets/contract_state.json");

/// Epoch of the fixture's keyset.
pub fn must_get_fixture_epoch_id() -> EpochId {
    must_get_running_contract_state().keyset.epoch_id
}

pub fn must_get_running_state_with_epoch(epoch_id: u64) -> ProtocolContractState {
    let mut running = must_get_running_contract_state();
    running.keyset.epoch_id = EpochId::new(epoch_id);
    ProtocolContractState::Running(running)
}

/// What contract initialization leaves behind: `Running`, but without any key yet.
pub fn must_get_running_state_without_domains() -> ProtocolContractState {
    let mut running = must_get_running_contract_state();
    running.keyset.epoch_id = EpochId::new(0);
    running.keyset.domains.clear();
    ProtocolContractState::Running(running)
}

/// Initializing state that has not generated any key yet.
pub fn must_get_initializing_state() -> ProtocolContractState {
    let running = must_get_running_contract_state();
    let generating_key = must_get_key_event(&running, running.keyset.epoch_id);
    ProtocolContractState::Initializing(InitializingContractState {
        domains: running.domains.clone(),
        epoch_id: running.keyset.epoch_id,
        generated_keys: vec![],
        generating_key,
        cancel_votes: BTreeSet::new(),
    })
}

/// Resharing state for the epoch following the fixture's running epoch.
pub fn must_get_resharing_state() -> ProtocolContractState {
    let running = must_get_running_contract_state();
    let resharing_key = must_get_key_event(&running, running.keyset.epoch_id.next());
    ProtocolContractState::Resharing(ResharingContractState {
        previous_running_state: running,
        reshared_keys: vec![],
        resharing_key,
        cancellation_requests: HashSet::new(),
        per_domain_thresholds: BTreeMap::new(),
    })
}

fn must_get_running_contract_state() -> RunningContractState {
    let state: ProtocolContractState = serde_json::from_str(RUNNING_STATE_FIXTURE)
        .expect("contract state fixture must deserialize");
    let ProtocolContractState::Running(running) = state else {
        panic!("contract state fixture must be a Running state");
    };
    running
}

fn must_get_key_event(running: &RunningContractState, epoch_id: EpochId) -> KeyEvent {
    KeyEvent {
        epoch_id,
        domain: running.domains.domains[0].clone(),
        parameters: running.parameters.clone(),
        instance: None,
        next_attempt_id: AttemptId::default(),
    }
}
