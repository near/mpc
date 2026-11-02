use ed25519_dalek::{SigningKey, VerifyingKey};
use near_kit_primitives::signer::{InMemorySigner, SecretKey};

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

    /// The contract's own key, for calls the contract makes to itself.
    pub fn signer(&self) -> InMemorySigner {
        in_memory_signer(&self.account_id, &self.signing_key)
    }
}

fn in_memory_signer(account_id: &near_account_id::AccountId, key: &SigningKey) -> InMemorySigner {
    InMemorySigner::new(
        account_id.clone(),
        SecretKey::ed25519_from_bytes(key.to_bytes()),
    )
}

pub(super) fn compiled_test_contract_wasm() -> Vec<u8> {
    test_utils::contract_build::ContractBuilder::new(
        "crates/chain-gateway-test-contract/Cargo.toml",
    )
    .build()
}

#[derive(Clone)]
pub struct TestAccount {
    pub account_id: near_account_id::AccountId,
    pub signing_key: SigningKey,
    pub signer: InMemorySigner,
}

impl TestAccount {
    pub fn new(account_id: near_account_id::AccountId, signing_key: SigningKey) -> Self {
        let signer = in_memory_signer(&account_id, &signing_key);
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
