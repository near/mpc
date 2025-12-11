use contract_interface::types::{self as dtos};
use mpc_contract::primitives::{domain::DomainConfig, key_state::KeyEventId};
use near_workspaces::{Account, Contract};
use serde_json::json;
use utilities::AccountIdExtV1;

use super::common::{
    execute_async_transactions, get_state, GAS_FOR_VOTE_NEW_DOMAIN, GAS_FOR_VOTE_PK,
};

pub async fn vote_add_domains(
    contract: &Contract,
    accounts: &[Account],
    domains: &[DomainConfig],
) -> anyhow::Result<()> {
    let args = json!({
        "domains": domains,
    });
    execute_async_transactions(
        accounts,
        contract,
        "vote_add_domains",
        &args,
        GAS_FOR_VOTE_NEW_DOMAIN,
    )
    .await
}

pub async fn start_keygen_instance(
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
        .call(contract.id(), "start_keygen_instance")
        .args_json(json!({"key_event_id": key_event_id}))
        .transact()
        .await?;
    if !result.is_success() {
        anyhow::bail!("{result:#?}");
    }
    Ok(())
}

pub async fn vote_public_key(
    contract: &Contract,
    accounts: &[Account],
    key_event_id: KeyEventId,
    public_key: dtos::PublicKey,
) -> anyhow::Result<()> {
    let vote_pk_args = json!( {
        "key_event_id": key_event_id,
        "public_key": public_key,
    });

    execute_async_transactions(
        accounts,
        contract,
        "vote_pk",
        &vote_pk_args,
        GAS_FOR_VOTE_PK,
    )
    .await
}
