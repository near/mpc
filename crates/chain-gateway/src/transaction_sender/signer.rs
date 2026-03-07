use ed25519_dalek::{SigningKey, VerifyingKey};
use k256::ecdsa::signature::Signer;
use near_account_id::AccountId;
use near_indexer::near_primitives::account::AccessKey;
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction, SignedTransaction, Transaction, TransactionV0,
};
use near_indexer_primitives::types::{Balance, Gas};
use std::sync::Mutex;

use crate::types::LatestFinalBlockInfo;

pub struct TransactionSigner {
    signing_key: SigningKey,
    account_id: AccountId,
    nonce: Mutex<u64>,
}

impl TransactionSigner {
    pub fn from_key(account_id: AccountId, signing_key: SigningKey) -> Self {
        TransactionSigner {
            account_id,
            signing_key,
            nonce: Mutex::new(0),
        }
    }

    /// Atomically increments the nonce and returns the previous value
    fn make_nonce(&self, last_known_block_height: u64) -> u64 {
        let min_nonce = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * last_known_block_height;
        let mut nonce = self.nonce.lock().unwrap();
        let new_nonce = std::cmp::max(min_nonce, *nonce + 1);
        *nonce = new_nonce;
        new_nonce
    }

    pub(crate) fn create_and_sign_function_call_tx(
        &self,
        receiver_id: AccountId,
        method_name: String,
        args: Vec<u8>,
        gas: Gas,
        info: LatestFinalBlockInfo,
    ) -> SignedTransaction {
        let action = FunctionCallAction {
            method_name,
            args,
            gas,
            deposit: Balance::from_near(0),
        };

        let verifying_key = self.signing_key.verifying_key();
        let verifying_key_bytes: &[u8; 32] = verifying_key.as_bytes();
        #[allow(clippy::disallowed_methods)]
        let near_core_public_key = near_crypto::ED25519PublicKey(*verifying_key_bytes).into();

        let transaction = Transaction::V0(TransactionV0 {
            signer_id: self.account_id.clone(),
            public_key: near_core_public_key,
            nonce: self.make_nonce(info.observed_at.into()),
            receiver_id,
            block_hash: info.value,
            actions: vec![action.into()],
        });

        let tx_hash = transaction.get_hash_and_size().0;

        let signature: ed25519_dalek::Signature = self.signing_key.sign(&tx_hash.0);
        let near_crypto_signature: near_crypto::Signature =
            near_crypto::Signature::ED25519(signature);

        SignedTransaction::new(near_crypto_signature, transaction.clone())
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
pub(super) fn test_signer() -> TransactionSigner {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    TransactionSigner::from_key("test.near".parse().unwrap(), signing_key)
}

#[cfg(test)]
mod tests {
    use near_indexer_primitives::CryptoHash;

    use super::*;

    const TEST_GAS: Gas = Gas::from_gas(300_000_000_000_000);

    #[test]
    fn public_key_derives_from_signing_key() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let signer = TransactionSigner::from_key("test.near".parse().unwrap(), signing_key.clone());
        assert_eq!(signer.public_key(), signing_key.verifying_key());
    }

    #[test]
    fn nonce_starts_at_block_height_minimum() {
        let signer = test_signer();
        let height = 100;
        let expected = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * height;
        assert_eq!(signer.make_nonce(height), expected);
    }

    #[test]
    fn nonce_increments_monotonically() {
        let signer = test_signer();
        let height = 100;
        let first = signer.make_nonce(height);
        let second = signer.make_nonce(height);
        let third = signer.make_nonce(height);
        assert_eq!(second, first + 1);
        assert_eq!(third, first + 2);
    }

    #[test]
    fn nonce_jumps_on_block_height_increase() {
        let signer = test_signer();
        let _ = signer.make_nonce(100);
        let _ = signer.make_nonce(100);

        let new_height = 200;
        let nonce = signer.make_nonce(new_height);
        let expected_min = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * new_height;
        assert_eq!(nonce, expected_min);
    }

    #[test]
    fn create_and_sign_builds_correct_transaction() {
        let signer = test_signer();
        let receiver_id: AccountId = "receiver.near".parse().unwrap();
        let args = b"test args".to_vec();
        let gas = TEST_GAS;
        let block_hash = near_indexer_primitives::CryptoHash::default();
        let block_height = 100;

        let signed_tx = signer.create_and_sign_function_call_tx(
            receiver_id.clone(),
            "do_something".to_string(),
            args.clone(),
            gas,
            LatestFinalBlockInfo {
                observed_at: block_height.into(),
                value: block_hash,
            },
        );

        let tx = match &signed_tx.transaction {
            Transaction::V0(tx) => tx,
            _ => panic!("expected Transaction::V0"),
        };
        assert_eq!(tx.signer_id, "test.near".parse::<AccountId>().unwrap());
        assert_eq!(tx.receiver_id, receiver_id);
        assert_eq!(tx.block_hash, block_hash);
        assert_eq!(tx.actions.len(), 1);

        match &tx.actions[0] {
            near_indexer_primitives::near_primitives::transaction::Action::FunctionCall(action) => {
                assert_eq!(action.method_name, "do_something");
                assert_eq!(action.args, b"test args");
                assert_eq!(action.gas, gas);
            }
            other => panic!("expected FunctionCall action, got {other:?}"),
        }
    }

    #[test]
    fn signature_is_valid() {
        let signer = test_signer();
        let signed_tx = signer.create_and_sign_function_call_tx(
            "receiver.near".parse().unwrap(),
            "method".to_string(),
            vec![],
            TEST_GAS,
            LatestFinalBlockInfo {
                observed_at: 100.into(),
                value: CryptoHash::default(),
            },
        );

        let tx_hash = signed_tx.get_hash();
        match &signed_tx.signature {
            near_crypto::Signature::ED25519(sig) => {
                use ed25519_dalek::Verifier;
                signer
                    .public_key()
                    .verify(&tx_hash.0, sig)
                    .expect("signature should be valid");
            }
            other => panic!("expected ED25519 signature, got {other:?}"),
        }
    }
}
