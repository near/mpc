use std::sync::Arc;

use chain_gateway::transaction_sender::TransactionSigner;
use ed25519_dalek::{SigningKey, VerifyingKey};

fn public_key_str(signing_key: &SigningKey) -> String {
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    let verifying_key_vec: Vec<u8> = verifying_key.as_bytes().to_vec();
    let near_pk: near_sdk::PublicKey =
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, verifying_key_vec).unwrap();
    String::from(&near_pk)
}

#[derive(Clone)]
pub struct Contract {
    pub account_id: near_account_id::AccountId,
    pub signing_key: SigningKey,
}

impl Contract {
    pub fn public_key_str(&self) -> String {
        public_key_str(&self.signing_key)
    }
}

pub(super) fn compiled_test_contract_wasm() -> Vec<u8> {
    test_utils::contract_build::build_contract(
        "crates/chain-gateway-test-contract/Cargo.toml",
        None,
        &[],
    )
}

#[derive(Clone)]
pub struct TestAccount {
    pub account_id: near_account_id::AccountId,
    pub signing_key: SigningKey,
    pub signer: Arc<TransactionSigner>,
}

impl TestAccount {
    pub fn new(account_id: near_account_id::AccountId, signing_key: SigningKey) -> Self {
        let signer = Arc::new(TransactionSigner::from_key(
            account_id.clone(),
            signing_key.clone(),
        ));
        Self {
            account_id,
            signing_key,
            signer,
        }
    }
    pub fn public_key_str(&self) -> String {
        public_key_str(&self.signing_key)
    }
}

pub(super) fn test_contract(account_id: near_account_id::AccountId) -> Contract {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    Contract {
        account_id,
        signing_key,
    }
}
