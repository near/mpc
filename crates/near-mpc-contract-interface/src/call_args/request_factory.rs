use mpc_call_args::{FunctionCallArgs, NearGas, NearToken};
use near_mpc_crypto_types::{
    CKDAppPublicKey, CKDRequest, CKDResponse, SignatureRequest, SignatureResponse,
};
use serde_json::json;

use super::consts::{CKD_PV_GAS, MAX_GAS, SIGN_DEPOSIT, SIGN_GAS};
use super::error::CallError;
use crate::{
    method_names::{
        PROPOSE_UPDATE, REGISTER_BACKUP_SERVICE, REGISTER_FOREIGN_CHAIN_SUPPORT,
        REQUEST_APP_PRIVATE_KEY, RESPOND, RESPOND_CKD, RESPOND_VERIFY_FOREIGN_TX, SIGN,
        START_NODE_MIGRATION, SUBMIT_PARTICIPANT_INFO, VERIFY_FOREIGN_TRANSACTION,
        VOTE_ADD_DOMAINS, VOTE_CANCEL_KEYGEN, VOTE_CANCEL_RESHARING, VOTE_NEW_PARAMETERS,
        VOTE_UPDATE,
    },
    types::{
        CKDRequestArgs, DomainConfig, Ed25519PublicKey, EpochId, ProposeUpdateArgs,
        ProposedThresholdParameters, SignRequestArgs, SupportedForeignChains,
        VerifyForeignTransactionRequest, VerifyForeignTransactionRequestArgs,
        VerifyForeignTransactionResponse,
    },
};

pub fn make_ckd_request_args(request: &CKDRequestArgs) -> Result<FunctionCallArgs, CallError> {
    let gas = match request.app_public_key {
        CKDAppPublicKey::AppPublicKey(_) => SIGN_GAS,
        CKDAppPublicKey::AppPublicKeyPV(_) => CKD_PV_GAS,
    };
    let args = json!({"request": serde_json::to_value(request)?})
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: REQUEST_APP_PRIVATE_KEY.to_string(),
        args,
        gas,
        deposit: SIGN_DEPOSIT,
    })
}

pub fn make_sign_request_args(args: &SignRequestArgs) -> Result<FunctionCallArgs, CallError> {
    let body = json!({ "request": serde_json::to_value(args)? })
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: SIGN.to_string(),
        args: body,
        gas: SIGN_GAS,
        deposit: SIGN_DEPOSIT,
    })
}

pub fn make_verify_foreign_chain_tx_args(
    request: &VerifyForeignTransactionRequestArgs,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({"request": serde_json::to_value(request)?})
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: VERIFY_FOREIGN_TRANSACTION.to_string(),
        args,
        gas: SIGN_GAS,
        deposit: SIGN_DEPOSIT,
    })
}

pub fn make_propose_update_args(
    code: &[u8],
    gas: NearGas,
    deposit: NearToken,
) -> Result<FunctionCallArgs, CallError> {
    let args = borsh::to_vec(&ProposeUpdateArgs {
        code: Some(code.to_vec()),
        config: None,
    })?;
    Ok(FunctionCallArgs {
        method_name: PROPOSE_UPDATE.to_string(),
        args,
        gas,
        deposit,
    })
}

pub fn make_respond_args(
    request: &SignatureRequest,
    response: &SignatureResponse,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({"request": serde_json::to_value(request)?, "response": serde_json::to_value(response)?})
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: RESPOND.to_string(),
        args,
        // todo: this is too much, we should benchmark and reduce it
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_respond_ckd_args(
    request: &CKDRequest,
    response: &CKDResponse,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({"request": serde_json::to_value(request)?, "response": serde_json::to_value(response)?})
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: RESPOND_CKD.to_string(),
        args,
        // todo: this is too much, we should benchmark and reduce it
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_respond_verify_foreign_chain_tx_args(
    request: &VerifyForeignTransactionRequest,
    response: &VerifyForeignTransactionResponse,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({
        "request": request,
        "response": response,
    })
    .to_string()
    .into_bytes();
    Ok(FunctionCallArgs {
        method_name: RESPOND_VERIFY_FOREIGN_TX.to_string(),
        args,
        // todo: this is too much, we should benchmark and reduce it
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_vote_new_parameters_args(
    prospective_epoch_id: EpochId,
    proposal: &ProposedThresholdParameters,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({
        "prospective_epoch_id": prospective_epoch_id,
        "proposal": serde_json::to_value(proposal)?,
    })
    .to_string()
    .into_bytes();
    Ok(FunctionCallArgs {
        method_name: VOTE_NEW_PARAMETERS.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_vote_add_domains_args(domains: &[DomainConfig]) -> Result<FunctionCallArgs, CallError> {
    let args = json!({ "domains": serde_json::to_value(domains)? })
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: VOTE_ADD_DOMAINS.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_vote_cancel_keygen_args(next_domain_id: u64) -> Result<FunctionCallArgs, CallError> {
    let args = json!({ "next_domain_id": next_domain_id })
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: VOTE_CANCEL_KEYGEN.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_vote_cancel_resharing_args() -> Result<FunctionCallArgs, CallError> {
    let args = json!({}).to_string().into_bytes();
    Ok(FunctionCallArgs {
        method_name: VOTE_CANCEL_RESHARING.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_vote_update_args(id: u64) -> Result<FunctionCallArgs, CallError> {
    let args = json!({ "id": id }).to_string().into_bytes();
    Ok(FunctionCallArgs {
        method_name: VOTE_UPDATE.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_register_backup_service_args(
    backup_service_info: serde_json::Value,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({ "backup_service_info": backup_service_info })
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: REGISTER_BACKUP_SERVICE.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_register_foreign_chain_support_args(
    foreign_chain_support: &SupportedForeignChains,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({ "foreign_chain_support": serde_json::to_value(foreign_chain_support)? })
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: REGISTER_FOREIGN_CHAIN_SUPPORT.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_start_node_migration_args(
    destination_node_info: serde_json::Value,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({ "destination_node_info": destination_node_info })
        .to_string()
        .into_bytes();
    Ok(FunctionCallArgs {
        method_name: START_NODE_MIGRATION.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}

pub fn make_submit_participant_info_args(
    proposed_participant_attestation: serde_json::Value,
    tls_public_key: &Ed25519PublicKey,
) -> Result<FunctionCallArgs, CallError> {
    let args = json!({
        "proposed_participant_attestation": proposed_participant_attestation,
        "tls_public_key": serde_json::to_value(tls_public_key)?,
    })
    .to_string()
    .into_bytes();
    Ok(FunctionCallArgs {
        method_name: SUBMIT_PARTICIPANT_INFO.to_string(),
        args,
        gas: MAX_GAS,
        deposit: NearToken::from_near(0),
    })
}
