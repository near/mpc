use crate::config::RespondConfig;
use crate::indexer::types::ChainSendTransactionRequest;
use ed25519_dalek::{SigningKey, VerifyingKey};
use k256::ecdsa::signature::Signer;
use near_indexer::near_primitives::account::AccessKey;
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction, SignedTransaction, Transaction, TransactionV0,
};
use near_indexer_primitives::types::{AccountId, Gas};
use near_indexer_primitives::CryptoHash;
use std::sync::Arc;
use std::sync::Mutex;

pub(crate) struct TransactionSigner {
    signing_key: SigningKey,
    account_id: AccountId,
    nonce: Mutex<u64>,
}

impl TransactionSigner {
    pub(crate) fn from_key(account_id: AccountId, signing_key: SigningKey) -> Self {
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
        block_hash: CryptoHash,
        block_height: u64,
    ) -> SignedTransaction {
        let action = FunctionCallAction {
            method_name,
            args,
            gas,
            deposit: 0,
        };

        let verifying_key = self.signing_key.verifying_key();
        let verifying_key_bytes: &[u8; 32] = verifying_key.as_bytes();
        #[allow(clippy::disallowed_methods)]
        let near_core_public_key = near_crypto::ED25519PublicKey(*verifying_key_bytes).into();

        let transaction = Transaction::V0(TransactionV0 {
            signer_id: self.account_id.clone(),
            public_key: near_core_public_key,
            nonce: self.make_nonce(block_height),
            receiver_id,
            block_hash,
            actions: vec![action.into()],
        });

        let tx_hash = transaction.get_hash_and_size().0;

        let signature: ed25519_dalek::Signature = self.signing_key.sign(&tx_hash.0);
        let near_crypto_signature: near_crypto::Signature =
            near_crypto::Signature::ED25519(signature);

        SignedTransaction::new(near_crypto_signature, transaction.clone())
    }

    pub(crate) fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

pub(crate) struct TransactionSigners {
    /// Signers that we cycle through for responding to signature requests.
    /// These can correspond to arbitrary near accounts.
    respond_signers: Vec<Arc<TransactionSigner>>,
    /// Signer we use for signing vote_pk, vote_reshared, etc., which must
    /// correspond to the account that this node runs under.
    owner_signer: Arc<TransactionSigner>,
    /// next respond signer to use.
    next_id: usize,
}

impl TransactionSigners {
    pub fn new(
        respond_config: RespondConfig,
        owner_account_id: AccountId,
        owner_signing_key: SigningKey,
    ) -> anyhow::Result<Self> {
        let respond_signers = respond_config
            .access_keys
            .iter()
            .map(|key| {
                Arc::new(TransactionSigner::from_key(
                    respond_config.account_id.clone(),
                    key.clone(),
                ))
            })
            .collect::<Vec<_>>();
        let owner_signer = Arc::new(TransactionSigner::from_key(
            owner_account_id,
            owner_signing_key,
        ));
        anyhow::ensure!(
            !respond_signers.is_empty(),
            "At least one responding access key must be provided",
        );
        Ok(TransactionSigners {
            respond_signers,
            owner_signer,
            next_id: 0,
        })
    }

    fn next_respond_signer(&mut self) -> Arc<TransactionSigner> {
        let signer = self.respond_signers[self.next_id].clone();
        self.next_id = (self.next_id + 1) % self.respond_signers.len();
        signer
    }

    fn owner_signer(&self) -> Arc<TransactionSigner> {
        self.owner_signer.clone()
    }

    pub fn signer_for(&mut self, req: &ChainSendTransactionRequest) -> Arc<TransactionSigner> {
        match req {
            ChainSendTransactionRequest::Respond(_) => self.next_respond_signer(),
            ChainSendTransactionRequest::CKDRespond(_) => self.next_respond_signer(),
            _ => self.owner_signer(),
        }
    }
}
