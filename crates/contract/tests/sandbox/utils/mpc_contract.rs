use std::collections::BTreeSet;

use super::transactions::all_receipts_successful;
use contract_interface::method_names;
use contract_interface::types::{
    Attestation, Ed25519PublicKey, Participants, ProtocolContractState, Threshold,
};
use mpc_contract::tee::tee_state::NodeId;
use mpc_primitives::hash::MpcDockerImageHash;
use near_workspaces::{result::ExecutionFinalResult, Account, Contract};

pub async fn get_state(contract: &Contract) -> ProtocolContractState {
    contract
        .view(method_names::STATE)
        .await
        .unwrap()
        .json()
        .unwrap()
}

pub async fn get_participants(contract: &Contract) -> anyhow::Result<Participants> {
    let state = get_state(contract).await;
    let ProtocolContractState::Running(running) = state else {
        panic!("Expected running state")
    };

    Ok(running.parameters.participants)
}

/// Helper function to get TEE participants from contract.
pub async fn get_tee_accounts(contract: &Contract) -> anyhow::Result<BTreeSet<NodeId>> {
    Ok(contract
        .call(method_names::GET_TEE_ACCOUNTS)
        .args_json(serde_json::json!({}))
        .max_gas()
        .transact()
        .await?
        .json::<Vec<NodeId>>()?
        .into_iter()
        .collect())
}

/// Helper function to submit participant info with TEE attestation.
pub async fn submit_participant_info(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &Ed25519PublicKey,
) -> anyhow::Result<ExecutionFinalResult> {
    let result = account
        .call(contract.id(), method_names::SUBMIT_PARTICIPANT_INFO)
        .args_json((attestation, tls_key))
        .max_gas()
        .transact()
        .await?;
    dbg!(&result);
    Ok(result)
}

pub async fn get_participant_attestation(
    contract: &Contract,
    tls_key: &Ed25519PublicKey,
) -> anyhow::Result<Option<Attestation>> {
    let result = contract
        .as_account()
        .call(contract.id(), method_names::GET_ATTESTATION)
        .args_json(serde_json::json!({
            "tls_public_key": tls_key
        }))
        .max_gas()
        .transact()
        .await?;

    Ok(result.json()?)
}

pub async fn assert_running_return_participants(
    contract: &Contract,
) -> anyhow::Result<Participants> {
    // Verify contract is back to running state with new threshold
    let final_state: ProtocolContractState = contract.view(method_names::STATE).await?.json()?;
    let ProtocolContractState::Running(running_state) = final_state else {
        panic!(
            "Expected contract to be in Running state after resharing, but got: {:?}",
            final_state
        );
    };
    Ok(running_state.parameters.participants)
}

pub async fn assert_running_return_threshold(contract: &Contract) -> Threshold {
    let final_state: ProtocolContractState = get_state(contract).await;
    let ProtocolContractState::Running(running_state) = final_state else {
        panic!(
            "Expected contract to be in Running state: {:?}",
            final_state
        );
    };
    running_state.parameters.threshold
}

pub async fn vote_for_hash(
    account: &Account,
    contract: &Contract,
    image_hash: &MpcDockerImageHash,
) -> anyhow::Result<()> {
    let result = account
        .call(contract.id(), method_names::VOTE_CODE_HASH)
        .args_json(serde_json::json!({"code_hash": image_hash}))
        .transact()
        .await?;
    all_receipts_successful(result)?;
    Ok(())
}
