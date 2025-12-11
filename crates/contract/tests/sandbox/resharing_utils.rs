use mpc_contract::{
    primitives::{
        key_state::{AttemptId, EpochId, KeyEventId},
        thresholds::ThresholdParameters,
    },
    state::ProtocolContractState,
};
use near_workspaces::{Account, Contract};
use serde_json::json;
use utilities::AccountIdExtV1;

use super::common::{
    execute_async_transactions, get_state, GAS_FOR_VOTE_CANCEL_RESHARING,
    GAS_FOR_VOTE_NEW_PARAMETERS, GAS_FOR_VOTE_RESHARED,
};

pub async fn conclude_resharing(
    contract: &Contract,
    all_participants: &[Account],
    prospective_epoch_id: EpochId,
) -> anyhow::Result<()> {
    let ProtocolContractState::Resharing(resharing_state) = get_state(contract).await else {
        anyhow::bail!("expected resharing state");
    };
    if resharing_state.prospective_epoch_id() != prospective_epoch_id {
        anyhow::bail!("epoch id mismatch");
    }
    let domain_configs = resharing_state.previous_running_state.domains.domains();
    for domain_config in domain_configs {
        let key_event_id = KeyEventId {
            epoch_id: prospective_epoch_id,
            domain_id: domain_config.id,
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
    proposal: &ThresholdParameters,
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
    let participants = state.active_participants();
    let leader = accounts
        .iter()
        .min_by_key(|a| participants.id(&a.id().as_v2_account_id()).unwrap())
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
    new_threshold_parameters: ThresholdParameters,
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
