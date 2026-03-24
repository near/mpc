use ed25519_dalek::{SigningKey, VerifyingKey};

const TEST_CONTRACT_ACCOUNT: &str = "test-contract.near";

pub struct Contract {
    pub account_id: near_account_id::AccountId,
    pub signing_key: SigningKey,
}

impl Contract {
    pub fn public_key_str(&self) -> String {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        let verifying_key_vec: Vec<u8> = verifying_key.as_bytes().to_vec();
        let near_pk: near_sdk::PublicKey =
            near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, verifying_key_vec)
                .unwrap();
        String::from(&near_pk)
    }
}

pub(super) fn test_contract() -> Contract {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    Contract {
        account_id: TEST_CONTRACT_ACCOUNT.parse().unwrap(),
        signing_key,
    }
}

pub(super) fn compiled_test_contract_wasm() -> &'static [u8] {
    chain_gateway_test_contract::compiled_wasm()
}
