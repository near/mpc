use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
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

    /// Atomically increments the nonce and returns the new value
    fn make_nonce(&self, last_known_block_height: u64) -> u64 {
        let min_nonce = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER
            .checked_mul(last_known_block_height)
            .expect("we don't expect to exceed a block height of 18 trillion");
        let mut nonce = self.nonce.lock().expect("require non-posioned mutex");
        let new_nonce = std::cmp::max(
            min_nonce,
            (*nonce)
                .checked_add(1)
                .expect("nonce should be much lower than U64::MAX"),
        );
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
        #[expect(clippy::disallowed_methods)]
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

        SignedTransaction::new(near_crypto_signature, transaction)
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use near_account_id::AccountId;
    use near_indexer::near_primitives::{account::AccessKey, transaction::Transaction};
    use near_indexer_primitives::types::Gas;
    use rand::{SeedableRng, rngs::StdRng};

    use crate::{transaction_sender::TransactionSigner, types::LatestFinalBlockInfo};

    const TEST_GAS: Gas = Gas::from_gas(300_000_000_000_000);

    #[test]
    fn test_public_key_derives_from_signing_key() {
        // Given: a signer derived from an account id
        let account_id: AccountId = "test.near".parse().unwrap();
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let signer = TransactionSigner::from_key(account_id.clone(), signing_key.clone());
        // Then: expect the public key to derive from the signing key
        assert_eq!(signer.public_key(), signing_key.verifying_key());
        // additional sanity check
        assert_eq!(signer.account_id(), &account_id);
    }

    #[test]
    fn test_nonce_starts_at_block_height_minimum() {
        // Given: a signer
        let mut rng = StdRng::seed_from_u64(42);
        let signer = TransactionSigner::from_rng(&mut rng);
        // When: for any given block height
        for height in [100, 101, 200, 2000, 5000] {
            // Then: expect the nonce to match the minimum required value
            let expected = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * height;
            assert_eq!(signer.make_nonce(height), expected);
            // subsequent nonce requests shouldn't matter if we jump block height
            let _ = signer.make_nonce(height);
        }
    }

    #[test]
    fn test_nonce_increments_monotonically() {
        // Given: a signer
        let mut rng = StdRng::seed_from_u64(42);
        let signer = TransactionSigner::from_rng(&mut rng);
        let height = 100;
        // When: generating consecutive nonces for the same block height
        let first = signer.make_nonce(height);
        let second = signer.make_nonce(height);
        let third = signer.make_nonce(height);
        // Then: expect nonces to be strictly increasing
        assert_eq!(second, first + 1);
        assert_eq!(third, first + 2);
    }

    #[test]
    fn test_create_and_sign_returns_valid_transaction() {
        // Given: a signer
        const SEED: u64 = 40393;
        let signer = TransactionSigner::from_rng(&mut StdRng::seed_from_u64(SEED));
        let signer_clone = TransactionSigner::from_rng(&mut StdRng::seed_from_u64(SEED));
        let receiver_id: AccountId = "receiver.near".parse().unwrap();
        let args = b"test args".to_vec();
        let gas = TEST_GAS;
        let method_name = "do_something".to_string();
        let info = LatestFinalBlockInfo {
            observed_at: 100.into(),
            value: near_indexer_primitives::CryptoHash::hash_bytes(b"test_bytes"),
        };

        // When: it signs a transaction
        let signed_tx = signer.create_and_sign_function_call_tx(
            receiver_id.clone(),
            method_name.clone(),
            args.clone(),
            gas,
            info.clone(),
        );

        // Then: expect the signed transaction to be valid
        let tx = match &signed_tx.transaction {
            Transaction::V0(tx) => tx,
            _ => panic!("expected Transaction::V0"),
        };

        assert_eq!(tx.nonce, signer_clone.make_nonce(info.observed_at.into()));
        assert_eq!(tx.signer_id, signer.account_id);
        assert_eq!(tx.receiver_id, receiver_id);
        assert_eq!(tx.block_hash, info.value);
        assert_eq!(tx.actions.len(), 1);
        match &tx.actions[0] {
            near_indexer_primitives::near_primitives::transaction::Action::FunctionCall(action) => {
                assert_eq!(action.method_name, method_name);
                assert_eq!(action.args, args);
                assert_eq!(action.gas, gas);
            }
            other => panic!("expected FunctionCall action, got {other:?}"),
        }

        // additonnally, assert the signature is valid
        let tx_hash = signed_tx.get_hash();
        match &signed_tx.signature {
            near_crypto::Signature::ED25519(sig) => {
                ed25519_dalek::Verifier::verify(&signer.public_key(), &tx_hash.0, sig)
                    .expect("signature should be valid");
            }
            other => panic!("expected ED25519 signature, got {other:?}"),
        }
    }

    #[test]
    fn test_signer_is_deterministic() {
        // Given: two signers with same state
        const SEED: u64 = 40393;
        let signer = TransactionSigner::from_rng(&mut StdRng::seed_from_u64(SEED));
        let signer_clone = TransactionSigner::from_rng(&mut StdRng::seed_from_u64(SEED));

        // When: the two signers sign the same transaction
        let receiver_id: AccountId = "receiver.near".parse().unwrap();
        let args = b"test args".to_vec();
        let gas = TEST_GAS;
        let method_name = "do_something".to_string();
        let info = LatestFinalBlockInfo {
            observed_at: 100.into(),
            value: near_indexer_primitives::CryptoHash::hash_bytes(b"test_bytes"),
        };

        // Then: expect the signed transactions to be an exact match
        let signed_tx = signer.create_and_sign_function_call_tx(
            receiver_id.clone(),
            method_name.clone(),
            args.clone(),
            gas,
            info.clone(),
        );
        let signed_tx_clone = signer_clone.create_and_sign_function_call_tx(
            receiver_id.clone(),
            method_name.clone(),
            args.clone(),
            gas,
            info.clone(),
        );
        assert_eq!(signed_tx, signed_tx_clone);
    }
}
