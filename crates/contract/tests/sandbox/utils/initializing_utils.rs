use dtos::KeyEventId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::DomainConfig;
use near_mpc_contract_interface::types::{self as dtos};
use near_workspaces::{Account, Contract};
use serde_json::json;

use super::{
    consts::{GAS_FOR_VOTE_NEW_DOMAIN, GAS_FOR_VOTE_PK},
    mpc_contract::get_state,
    transactions::execute_async_transactions,
};
use crate::sandbox::common::OldDomainConfig;

pub async fn vote_add_domains(
    contract: &Contract,
    accounts: &[Account],
    domains: &[DomainConfig],
) -> anyhow::Result<()> {
    // Serialize with the legacy `curve`-bearing shape so the call works against
    // both production binaries (which still require `curve`) and the current
    // contract (which accepts both shapes via the DTO compat shim). Drop this
    // conversion after the 3.10 release is the production contract on Mainnet
    // and Testnet.
    let old_domains: Vec<OldDomainConfig> = domains.iter().map(OldDomainConfig::from).collect();
    let args = json!({
        "domains": old_domains,
    });
    execute_async_transactions(
        accounts,
        contract,
        method_names::VOTE_ADD_DOMAINS,
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
        .call(contract.id(), method_names::START_KEYGEN_INSTANCE)
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
        method_names::VOTE_PK,
        &vote_pk_args,
        GAS_FOR_VOTE_PK,
    )
    .await
}
