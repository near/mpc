use ed25519_dalek::{SigningKey, VerifyingKey};
use k256::ecdsa::signature::Signer;
use near_account_id::AccountId;
use near_indexer::near_primitives::account::AccessKey;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::near_primitives::transaction::{
    FunctionCallAction,
    SignedTransaction,
    Transaction,
    TransactionV0,
    // todo: no direct imports of near internals
};
use near_indexer_primitives::types::{Balance, Gas};
use std::sync::{Arc, Mutex};

use crate::errors::ChainGatewayError;
use crate::near_internals_wrapper::{RpcHandlerWrapper, ViewClientWrapper};

#[derive(Clone)]
pub struct TransactionSender {
    /// rpc handler for sending txs to the chain (internal type, c.f. indexer.rs)
    rpc_handler: Arc<RpcHandlerWrapper>,
    /// method to the view client to query the latest final block (needed for nonce computation)
    view_client: Arc<ViewClientWrapper>,
}

/// we could probably make this a trait for testing?
impl TransactionSender {
    pub(crate) fn new(
        rpc_handler: Arc<RpcHandlerWrapper>,
        view_client: Arc<ViewClientWrapper>,
    ) -> Self {
        Self {
            rpc_handler,
            view_client,
        }
    }
    async fn submit_tx(
        &self,
        transaction: near_indexer::near_primitives::transaction::SignedTransaction,
    ) -> Result<(), ChainGatewayError> {
        self.rpc_handler
            .submit_tx(transaction)
            .await
            .map_err(|err| ChainGatewayError::RpcClient {
                source: Box::new(err),
            })
    }
    /// creates a function call transaction for contract `receiver_id` with method `method_name` and args `args`
    /// returns the CryptoHash for the receipt, such that the execution outcome can be tracked
    pub async fn submit_function_call_tx(
        &self,
        // Key with which this transaction should be signed
        signer: Arc<TransactionSigner>,
        // contract on which this method should be called
        receiver_id: AccountId,
        // method name to call
        method_name: String,
        // arguments for the method
        args: Vec<u8>,
        // gas to attach
        gas: Gas,
    ) -> Result<CryptoHash, ChainGatewayError> {
        let block = self.view_client.latest_final_block().await.map_err(|err| {
            ChainGatewayError::SendTransactionError {
                context: "could not query last final block".to_string(),
                source: Box::new(err),
            }
        })?;

        let transaction = signer.create_and_sign_function_call_tx(
            receiver_id,
            method_name,
            args,
            gas,
            block.header.hash,
            block.header.height,
        );

        let tx_hash = transaction.get_hash();

        tracing::info!(
            tx_hash = ?tx_hash,
            public_key = ?signer.public_key(),
            nonce = transaction.transaction.nonce(),
            "sending transaction",
        );
        self.submit_tx(transaction).await?;
        Ok(tx_hash)
    }
}

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

    fn create_and_sign_function_call_tx(
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
            deposit: Balance::from_near(0),
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

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}
