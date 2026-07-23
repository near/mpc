use std::collections::BTreeSet;

use super::transactions::{SandboxCaller, all_receipts_successful};
use mpc_contract::tee::tee_state::NodeId;
use mpc_primitives::hash::{LauncherImageHash, NodeImageHash, TeeVerifierCodeHash};
use near_mpc_contract_interface::{
    client::MpcContractHandle,
    method_names,
    types::{
        Attestation, Ed25519PublicKey, GovernanceThreshold, Participants, ProtocolContractState,
    },
};
use near_workspaces::{
    Account, AccountId, Contract, result::ExecutionFinalResult, types::NearToken,
};

pub fn total_gas_fee(result: &ExecutionFinalResult) -> NearToken {
    result
        .outcomes()
        .iter()
        .map(|outcome| outcome.tokens_burnt)
        .fold(NearToken::from_yoctonear(0), NearToken::saturating_add)
}

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

pub async fn submit_participant_info(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &Ed25519PublicKey,
) -> anyhow::Result<ExecutionFinalResult> {
    // TODO(#3906): check if inlining is nicer once we ported the entire contract interface.
    let contract_handle = MpcContractHandle::new(SandboxCaller(account), contract.id().clone());
    contract_handle
        .submit_participant_info(attestation.clone(), tls_key.clone())
        .await
        .map_err(Into::into)
}

pub async fn vote_tee_verifier_change(
    account: &Account,
    contract: &Contract,
    candidate_account_id: &AccountId,
    expected_code_hash: [u8; 32],
) -> anyhow::Result<()> {
    let expected_code_hash = TeeVerifierCodeHash::new(expected_code_hash);
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

pub async fn tee_verifier_account_id(contract: &Contract) -> Option<AccountId> {
    contract
        .view(method_names::TEE_VERIFIER_ACCOUNT_ID)
        .await
        .unwrap()
        .json()
        .unwrap()
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

pub async fn assert_running_return_threshold(contract: &Contract) -> GovernanceThreshold {
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
