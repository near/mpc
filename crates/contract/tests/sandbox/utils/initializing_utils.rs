use dtos::KeyEventId;
use near_mpc_contract_interface::types::DomainConfig;
use near_mpc_contract_interface::types::{self as dtos};
use near_workspaces::{Account, Contract};

use super::{
    mpc_contract::get_state,
    transactions::{CallMpcContract, all_receipts_successful, execute_async_handle_calls},
};

pub async fn vote_add_domains(
    contract: &Contract,
    accounts: &[Account],
    domains: &[DomainConfig],
) -> anyhow::Result<()> {
    execute_async_handle_calls(accounts, contract, |handle| {
        let domains = domains.to_vec();
        async move { handle.vote_add_domains(domains).await }
    })
    .await
}

pub async fn start_keygen_instance(
    contract: &Contract,
    accounts: &[Account],
    key_event_id: KeyEventId,
) -> anyhow::Result<()> {
    let state = get_state(contract).await;
    let active = match &state {
        dtos::ProtocolContractState::Initializing(s) => {
            &s.generating_key.parameters.participants.participants
        }
        dtos::ProtocolContractState::Running(s) => &s.parameters.participants.participants,
        dtos::ProtocolContractState::Resharing(s) => {
            &s.resharing_key.parameters.participants.participants
        }
        dtos::ProtocolContractState::NotInitialized => {
            panic!("protocol state must be initialized")
        }
    };
    let leader = accounts
        .iter()
        .min_by_key(|a| {
            active
                .iter()
                .find(|(account_id, _, _)| account_id == a.id())
                .map(|(_, pid, _)| *pid)
                .unwrap()
        })
        .unwrap();
    let result = leader
        .call_mpc(contract.id())
        .start_keygen_instance(key_event_id)
        .await?;
    all_receipts_successful(result)?;
    Ok(())
}

pub async fn vote_public_key(
    contract: &Contract,
    accounts: &[Account],
    key_event_id: KeyEventId,
    public_key: dtos::PublicKey,
) -> anyhow::Result<()> {
    execute_async_handle_calls(accounts, contract, |handle| {
        let public_key = public_key.clone();
        async move { handle.vote_pk(key_event_id, public_key).await }
    })
    .await
}
