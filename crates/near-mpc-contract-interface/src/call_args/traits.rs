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

/// Generates one typed call helper per contract method. Each expands to
/// `client.call_contract(contract_id, <factory>(<args>)?).await`, so it works on
/// any [`CallContract`] backend regardless of its `Output`.
macro_rules! call_helpers {
    ($( $helper:ident => $factory:ident ( $( $arg:ident : $ty:ty ),* $(,)? ) );* $(;)?) => {
        $(
            pub async fn $helper<C: CallContract>(
                client: &C,
                contract_id: &AccountId,
                $( $arg : $ty ),*
            ) -> Result<C::Output, CallError> {
                client
                    .call_contract(contract_id, $factory($( $arg ),*)?)
                    .await
            }
        )*
    };
}

call_helpers! {
    send_sign_request => make_sign_request_args(request: &SignRequestArgs);
    send_ckd_request => make_ckd_request_args(request: &CKDRequestArgs);
    send_verify_foreign_transaction => make_verify_foreign_chain_tx_args(request: &VerifyForeignTransactionRequestArgs);
    respond => make_respond_args(request: &SignatureRequest, response: &SignatureResponse);
    respond_ckd => make_respond_ckd_args(request: &CKDRequest, response: &CKDResponse);
    respond_verify_foreign_transaction => make_respond_verify_foreign_chain_tx_args(request: &VerifyForeignTransactionRequest, response: &VerifyForeignTransactionResponse);
    propose_update => make_propose_update_args(code: &[u8], gas: NearGas, deposit: NearToken);
    vote_new_parameters => make_vote_new_parameters_args(prospective_epoch_id: EpochId, proposal: &ProposedThresholdParameters);
    vote_add_domains => make_vote_add_domains_args(domains: &[DomainConfig]);
    vote_cancel_keygen => make_vote_cancel_keygen_args(next_domain_id: u64);
    vote_cancel_resharing => make_vote_cancel_resharing_args();
    vote_update => make_vote_update_args(id: u64);
    register_backup_service => make_register_backup_service_args(backup_service_info: serde_json::Value);
    register_foreign_chain_support => make_register_foreign_chain_support_args(foreign_chain_support: &SupportedForeignChains);
    start_node_migration => make_start_node_migration_args(destination_node_info: serde_json::Value);
    submit_participant_info => make_submit_participant_info_args(proposed_participant_attestation: serde_json::Value, tls_public_key: &Ed25519PublicKey);
}
