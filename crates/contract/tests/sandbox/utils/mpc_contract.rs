use std::collections::BTreeSet;

use crate::sandbox::utils::transactions::CallMpcContract;

use super::transactions::all_receipts_successful;
use mpc_contract::tee::{measurements::ContractExpectedMeasurements, tee_state::NodeId};
use mpc_primitives::hash::{LauncherImageHash, NodeImageHash, TeeVerifierCodeHash};
use near_mpc_contract_interface::{
    method_names,
    types::{
        Attestation, Config, Ed25519PublicKey, GovernanceThreshold, Participants,
        ProtocolContractState, VerifiedAttestation,
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

pub async fn get_config(contract: &Contract) -> anyhow::Result<Config> {
    Ok(contract.view(method_names::CONFIG).await?.json()?)
}

pub async fn get_state(contract: &Contract) -> ProtocolContractState {
    contract
        .view(method_names::STATE)
        .await
        .unwrap()
        .json()
        .unwrap()
}

pub async fn get_allowed_launcher_image_hashes(
    contract: &Contract,
) -> anyhow::Result<Vec<LauncherImageHash>> {
    Ok(contract
        .view(method_names::ALLOWED_LAUNCHER_IMAGE_HASHES)
        .await?
        .json()?)
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

pub async fn prepay_attestation_grants(
    payer: &Account,
    contract: &Contract,
    beneficiary: &AccountId,
    grants: u32,
) -> anyhow::Result<ExecutionFinalResult> {
    // The fee is read from `config()`, the way an operator reads it.
    let config = get_config(contract).await?;
    let total = NearToken::from_millinear(
        u128::from(config.attestation_storage_fee_millinear) * u128::from(grants),
    );
    Ok(payer
        .call(contract.id(), method_names::PREPAY_ATTESTATION_STORAGE)
        .args_json(serde_json::json!({ "account_id": beneficiary, "grants": grants }))
        .deposit(total)
        .max_gas()
        .transact()
        .await?)
}

/// Prepays one grant, then submits. For a first submission; a re-attestation of a key the
/// account already owns consumes no grant and should use [`submit_participant_info`].
pub async fn prepay_and_submit_participant_info(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &Ed25519PublicKey,
) -> anyhow::Result<ExecutionFinalResult> {
    let prepayment = prepay_attestation_grants(account, contract, account.id(), 1).await?;
    anyhow::ensure!(prepayment.is_success(), "prepayment failed: {prepayment:?}");
    submit_participant_info(account, contract, attestation, tls_key).await
}

/// Submits without prepaying anything.
pub async fn submit_participant_info(
    account: &Account,
    contract: &Contract,
    attestation: &Attestation,
    tls_key: &Ed25519PublicKey,
) -> anyhow::Result<ExecutionFinalResult> {
    // TODO(#3906): check if inlining is nicer once we ported the entire contract interface.
    let contract_handle = account.call_mpc(contract.id());
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
) -> anyhow::Result<Option<VerifiedAttestation>> {
    Ok(contract
        .view(method_names::GET_ATTESTATION)
        .args_json(serde_json::json!({
            "tls_public_key": tls_key
        }))
        .await?
        .json()?)
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

pub async fn vote_add_os_measurement(
    account: &Account,
    contract: &Contract,
    measurement: &ContractExpectedMeasurements,
) -> anyhow::Result<()> {
    let result = account
        .call(contract.id(), method_names::VOTE_ADD_OS_MEASUREMENT)
        .args_json(serde_json::json!({"measurement": measurement}))
        .transact()
        .await?;
    all_receipts_successful(result)?;
    Ok(())
}
