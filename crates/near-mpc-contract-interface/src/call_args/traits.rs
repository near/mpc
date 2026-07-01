use std::future::Future;

use mpc_call_args::{FunctionCallArgs, NearGas, NearToken};
use mpc_primitives::AccountId;
use near_mpc_crypto_types::{CKDRequest, CKDResponse, SignatureRequest, SignatureResponse};

use super::error::CallError;
use super::request_factory::{
    make_ckd_request_args, make_propose_update_args, make_register_backup_service_args,
    make_register_foreign_chain_support_args, make_respond_args, make_respond_ckd_args,
    make_respond_verify_foreign_chain_tx_args, make_sign_request_args,
    make_start_node_migration_args, make_submit_participant_info_args,
    make_verify_foreign_chain_tx_args, make_vote_add_domains_args, make_vote_cancel_keygen_args,
    make_vote_cancel_resharing_args, make_vote_new_parameters_args, make_vote_update_args,
};
use crate::types::{
    CKDRequestArgs, DomainConfig, Ed25519PublicKey, EpochId, ProposedThresholdParameters,
    SignRequestArgs, SupportedForeignChains, VerifyForeignTransactionRequest,
    VerifyForeignTransactionRequestArgs, VerifyForeignTransactionResponse,
};

/// A client that can execute a [`FunctionCallArgs`] against a deployed MPC
/// contract identified by its [`AccountId`].
///
/// Implemented once per backend (e.g. the sandbox and e2e test clients). The
/// free functions in this module are written against this trait, so each
/// contract method gets a single typed call helper that works on every backend.
pub trait CallContract {
    /// Backend-specific successful call outcome.
    type Output;

    fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> impl Future<Output = Result<Self::Output, CallError>> + Send;
}

// --- user requests ---

pub async fn send_sign_request<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    request: &SignRequestArgs,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_sign_request_args(request)?)
        .await
}

pub async fn send_ckd_request<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    request: &CKDRequestArgs,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_ckd_request_args(request)?)
        .await
}

pub async fn send_verify_foreign_transaction<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    request: &VerifyForeignTransactionRequestArgs,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_verify_foreign_chain_tx_args(request)?)
        .await
}

// --- node responses ---

pub async fn respond<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    request: &SignatureRequest,
    response: &SignatureResponse,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_respond_args(request, response)?)
        .await
}

pub async fn respond_ckd<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    request: &CKDRequest,
    response: &CKDResponse,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_respond_ckd_args(request, response)?)
        .await
}

pub async fn respond_verify_foreign_transaction<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    request: &VerifyForeignTransactionRequest,
    response: &VerifyForeignTransactionResponse,
) -> Result<C::Output, CallError> {
    client
        .call_contract(
            contract_id,
            make_respond_verify_foreign_chain_tx_args(request, response)?,
        )
        .await
}

// --- governance / admin ---

pub async fn propose_update<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    code: &[u8],
    gas: NearGas,
    deposit: NearToken,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_propose_update_args(code, gas, deposit)?)
        .await
}

pub async fn vote_new_parameters<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    prospective_epoch_id: EpochId,
    proposal: &ProposedThresholdParameters,
) -> Result<C::Output, CallError> {
    client
        .call_contract(
            contract_id,
            make_vote_new_parameters_args(prospective_epoch_id, proposal)?,
        )
        .await
}

pub async fn vote_add_domains<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    domains: &[DomainConfig],
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_vote_add_domains_args(domains)?)
        .await
}

pub async fn vote_cancel_keygen<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    next_domain_id: u64,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_vote_cancel_keygen_args(next_domain_id)?)
        .await
}

pub async fn vote_cancel_resharing<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_vote_cancel_resharing_args()?)
        .await
}

pub async fn vote_update<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    id: u64,
) -> Result<C::Output, CallError> {
    client
        .call_contract(contract_id, make_vote_update_args(id)?)
        .await
}

pub async fn register_backup_service<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    backup_service_info: serde_json::Value,
) -> Result<C::Output, CallError> {
    client
        .call_contract(
            contract_id,
            make_register_backup_service_args(backup_service_info)?,
        )
        .await
}

pub async fn register_foreign_chain_support<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    foreign_chain_support: &SupportedForeignChains,
) -> Result<C::Output, CallError> {
    client
        .call_contract(
            contract_id,
            make_register_foreign_chain_support_args(foreign_chain_support)?,
        )
        .await
}

pub async fn start_node_migration<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    destination_node_info: serde_json::Value,
) -> Result<C::Output, CallError> {
    client
        .call_contract(
            contract_id,
            make_start_node_migration_args(destination_node_info)?,
        )
        .await
}

pub async fn submit_participant_info<C: CallContract>(
    client: &C,
    contract_id: &AccountId,
    proposed_participant_attestation: serde_json::Value,
    tls_public_key: &Ed25519PublicKey,
) -> Result<C::Output, CallError> {
    client
        .call_contract(
            contract_id,
            make_submit_participant_info_args(proposed_participant_attestation, tls_public_key)?,
        )
        .await
}
