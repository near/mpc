use mpc_call_args::{FunctionCallArgs, NearGas, NearToken};
use mpc_primitives::domain::DomainId;
use near_mpc_crypto_types::CKDAppPublicKey;
use serde_json::json;

use crate::{
    method_names::{PROPOSE_UPDATE, REQUEST_APP_PRIVATE_KEY, SIGN, VERIFY_FOREIGN_TRANSACTION},
    types::{ProposeUpdateArgs, VerifyForeignTransactionRequestArgs},
};

// todo: probably you want a const file for these
const SIGN_GAS: NearGas = NearGas::from_tgas(15);
// AppPublicKeyPV does an on-chain bls12381_pairing_check (2 pairs) before yielding,
// which costs significantly more than a plain CKD or sign request.
const CKD_PV_GAS: NearGas = NearGas::from_tgas(100);
const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

pub fn make_ckd_request_args(
    domain_id: DomainId,
    app_public_key: CKDAppPublicKey,
) -> FunctionCallArgs {
    let gas = match app_public_key {
        CKDAppPublicKey::AppPublicKey(_) => SIGN_GAS,
        CKDAppPublicKey::AppPublicKeyPV(_) => CKD_PV_GAS,
    };
    let args = json! ({
        "request": {
            "domain_id": domain_id,
            "derivation_path": "test",
            "app_public_key": app_public_key,
        }
    })
    .to_string()
    .into_bytes();
    FunctionCallArgs {
        method_name: REQUEST_APP_PRIVATE_KEY.to_string(),
        args,
        gas,
        deposit: SIGN_DEPOSIT,
    }
}

pub fn make_sign_request_args(domain_id: DomainId, payload: serde_json::Value) -> FunctionCallArgs {
    let args = json!({
        "request": {
            "domain_id": domain_id,
            "path": "test",
            "payload_v2": payload,
        }
    })
    .to_string()
    .into_bytes();
    FunctionCallArgs {
        method_name: SIGN.to_string(),
        args,
        gas: SIGN_GAS,
        deposit: SIGN_DEPOSIT,
    }
}

// not sure about this error path here..
pub fn make_verify_foreign_chain_tx_args(
    request: &VerifyForeignTransactionRequestArgs,
) -> anyhow::Result<FunctionCallArgs> {
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
) -> anyhow::Result<FunctionCallArgs> {
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
