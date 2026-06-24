use std::collections::BTreeSet;

use super::transactions::all_receipts_successful;
use mpc_contract::tee::tee_state::NodeId;
use mpc_primitives::hash::{LauncherImageHash, NodeImageHash};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    Attestation, Ed25519PublicKey, Participants, ProtocolContractState, Threshold,
};
use near_workspaces::{Account, Contract, result::ExecutionFinalResult};

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

/// Like [`submit_participant_info`] but attaches `deposit` — used by the async
/// `Dstack` tests that assert the deposit is refunded on rejection/timeout.
pub async fn submit_participant_info_with_deposit(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &Ed25519PublicKey,
    deposit: near_workspaces::types::NearToken,
) -> anyhow::Result<ExecutionFinalResult> {
    Ok(account
        .call(contract.id(), method_names::SUBMIT_PARTICIPANT_INFO)
        .args_json((attestation, tls_key))
        .deposit(deposit)
        .max_gas()
        .transact()
        .await?)
}

/// Reads the `sandbox-test-methods`-only `has_pending_attestation` view. The
/// contract under test must be built with that feature (`with_sandbox_test_methods`).
pub async fn has_pending_attestation(
    contract: &Contract,
    account_id: &near_workspaces::AccountId,
) -> anyhow::Result<bool> {
    Ok(contract
        .view("has_pending_attestation")
        .args_json(serde_json::json!({ "account_id": account_id }))
        .await?
        .json()?)
}

pub async fn vote_tee_verifier_change(
    account: &Account,
    contract: &Contract,
    candidate_account_id: &near_workspaces::AccountId,
    expected_code_hash: [u8; 32],
) -> anyhow::Result<()> {
    // `expected_code_hash` is a `TeeVerifierCodeHash`, which the contract
    // deserializes from a hex string (not a byte array), so wrap it in the typed
    // hash to get the right JSON form.
    let expected_code_hash = mpc_primitives::hash::TeeVerifierCodeHash::new(expected_code_hash);
    all_receipts_successful(
        account
            .call(contract.id(), method_names::VOTE_TEE_VERIFIER_CHANGE)
            .args_json(serde_json::json!({
                "candidate_account_id": candidate_account_id,
                "expected_code_hash": expected_code_hash,
            }))
            .transact()
            .await?,
    )
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
    image_hash: &NodeImageHash,
) -> anyhow::Result<()> {
    let result = account
        .call(contract.id(), method_names::VOTE_CODE_HASH)
        .args_json(serde_json::json!({"code_hash": image_hash}))
        .transact()
        .await?;
    all_receipts_successful(result)?;
    Ok(())
}

pub async fn vote_add_launcher_hash(
    account: &Account,
    contract: &Contract,
    launcher_hash: &LauncherImageHash,
) -> anyhow::Result<()> {
    let result = account
        .call(contract.id(), method_names::VOTE_ADD_LAUNCHER_HASH)
        .args_json(serde_json::json!({"launcher_hash": launcher_hash}))
        .transact()
        .await?;
    all_receipts_successful(result)?;
    Ok(())
}
