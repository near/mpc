use crate::sandbox::utils::{
    consts::{GAS_FOR_VOTE_CANCEL_RESHARING, GAS_FOR_VOTE_NEW_PARAMETERS, GAS_FOR_VOTE_RESHARED},
    mpc_contract::get_state,
    transactions::execute_async_transactions,
};
use contract_interface::types::ProtocolContractState;
use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
use near_workspaces::{Account, Contract};
use serde::Serialize;
use serde_json::json;

pub async fn conclude_resharing(
    contract: &Contract,
    all_participants: &[Account],
    prospective_epoch_id: EpochId,
) -> anyhow::Result<()> {
    let ProtocolContractState::Resharing(resharing_state) = get_state(contract).await else {
        anyhow::bail!("expected resharing state");
    };
    if resharing_state.prospective_epoch_id().get() != prospective_epoch_id.get() {
        anyhow::bail!("epoch id mismatch");
    }
    let domain_configs = resharing_state
        .previous_running_state
        .domains
        .domains
        .clone();
    for domain_config in &domain_configs {
        let key_event_id = KeyEventId {
            epoch_id: prospective_epoch_id,
            domain_id: domain_config.id.0.into(),
            attempt_id: AttemptId::new(),
        };
        let state = get_state(contract).await;
        if !matches!(state, ProtocolContractState::Resharing(_)) {
            anyhow::bail!("expected resharing state");
        }
        start_reshare_instance(contract, all_participants, key_event_id).await?;

        vote_reshared(contract, all_participants, key_event_id).await?;
    }
    Ok(())
}

pub async fn vote_cancel_reshaing(contract: &Contract, accounts: &[Account]) -> anyhow::Result<()> {
    execute_async_transactions(
        accounts,
        contract,
        "vote_cancel_resharing",
        &json!({}),
        GAS_FOR_VOTE_CANCEL_RESHARING,
    )
    .await
}

pub async fn vote_new_parameters(
    contract: &Contract,
    prospective_epoch_id: u64,
    proposal: &impl Serialize,
    persistent_participants: &[Account],
    new_participants: &[Account],
) -> anyhow::Result<()> {
    let json_args = json!({
        "prospective_epoch_id": prospective_epoch_id,
        "proposal": proposal,
    });
    // At least threshold old participants need to vote first,
    // here we are just using all of them
    execute_async_transactions(
        persistent_participants,
        contract,
        "vote_new_parameters",
        &json_args,
        GAS_FOR_VOTE_NEW_PARAMETERS,
    )
    .await?;

    // then new participant can vote
    execute_async_transactions(
        new_participants,
        contract,
        "vote_new_parameters",
        &json_args,
        GAS_FOR_VOTE_NEW_PARAMETERS,
    )
    .await?;
    Ok(())
}

pub async fn start_reshare_instance(
    contract: &Contract,
    accounts: &[Account],
    key_event_id: KeyEventId,
) -> anyhow::Result<()> {
    let state = get_state(contract).await;
    let active = match &state {
        ProtocolContractState::Initializing(s) => {
            &s.generating_key.parameters.participants.participants
        }
        ProtocolContractState::Running(s) => &s.parameters.participants.participants,
        ProtocolContractState::Resharing(s) => {
            &s.resharing_key.parameters.participants.participants
        }
        ProtocolContractState::NotInitialized => {
            panic!("protocol state must be initialized")
        }
    };
    let leader = accounts
        .iter()
        .min_by_key(|a| {
            active
                .iter()
                .find(|(account_id, _, _)| account_id.0 == *a.id())
                .map(|(_, pid, _)| *pid)
                .unwrap()
        })
        .unwrap();
    let result = leader
        .call(contract.id(), "start_reshare_instance")
        .args_json(json!({"key_event_id": key_event_id}))
        .transact()
        .await?;
    if !result.is_success() {
        anyhow::bail!("{result:#?}");
    }
    Ok(())
}

pub async fn vote_reshared(
    contract: &Contract,
    accounts: &[Account],
    key_event_id: KeyEventId,
) -> anyhow::Result<()> {
    execute_async_transactions(
        accounts,
        contract,
        "vote_reshared",
        &json!({"key_event_id": key_event_id}),
        GAS_FOR_VOTE_RESHARED,
    )
    .await
}

/// Performs a complete resharing operation with the given parameters.
/// This includes voting for new parameters, starting reshare instances for each domain,
/// and voting reshared to complete the transition.
pub async fn do_resharing(
    remaining_accounts: &[Account],
    contract: &Contract,
    new_threshold_parameters: impl Serialize,
    prospective_epoch_id: EpochId,
) -> anyhow::Result<()> {
    vote_new_parameters(
        contract,
        prospective_epoch_id.get(),
        &new_threshold_parameters,
        remaining_accounts,
        &[],
    )
    .await?;
    conclude_resharing(contract, remaining_accounts, prospective_epoch_id).await?;
    Ok(())
}
