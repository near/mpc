use async_trait::async_trait;
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

/// Testing seam: abstracts querying the latest finalized block.
#[async_trait]
trait LatestBlock: Send + Sync {
    async fn latest_final_block(
        &self,
    ) -> Result<near_indexer_primitives::views::BlockView, ChainGatewayError>;
}

/// Testing seam: abstracts submitting a signed transaction.
#[async_trait]
trait SubmitTx: Send + Sync {
    async fn submit_tx(&self, transaction: SignedTransaction) -> Result<(), ChainGatewayError>;
}

struct BlockQuerier(Arc<ViewClientWrapper>);

#[async_trait]
impl LatestBlock for BlockQuerier {
    async fn latest_final_block(
        &self,
    ) -> Result<near_indexer_primitives::views::BlockView, ChainGatewayError> {
        self.0.latest_final_block().await.map_err(|err| {
            ChainGatewayError::SendTransactionError {
                context: "could not query last final block".to_string(),
                source: Arc::new(err),
            }
        })
    }
}

struct TxSubmitter(Arc<RpcHandlerWrapper>);

#[async_trait]
impl SubmitTx for TxSubmitter {
    async fn submit_tx(&self, transaction: SignedTransaction) -> Result<(), ChainGatewayError> {
        self.0
            .submit_tx(transaction)
            .await
            .map_err(|err| ChainGatewayError::RpcClient {
                source: Arc::new(err),
            })
    }
}

#[derive(Clone)]
pub struct TransactionSender {
    /// rpc handler for sending txs to the chain (internal type, c.f. indexer.rs)
    rpc_handler: Arc<dyn SubmitTx>,
    /// method to the view client to query the latest final block (needed for nonce computation)
    view_client: Arc<dyn LatestBlock>,
}

impl TransactionSender {
    pub(crate) fn new(
        rpc_handler: Arc<RpcHandlerWrapper>,
        view_client: Arc<ViewClientWrapper>,
    ) -> Self {
        Self {
            rpc_handler: Arc::new(TxSubmitter(rpc_handler)),
            view_client: Arc::new(BlockQuerier(view_client)),
        }
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
        let block = self.view_client.latest_final_block().await?;

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
        self.rpc_handler.submit_tx(transaction).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use near_indexer_primitives::views::{BlockHeaderView, BlockView};

    const TEST_GAS: Gas = Gas::from_gas(300_000_000_000_000);

    fn test_signer() -> TransactionSigner {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        TransactionSigner::from_key("test.near".parse().unwrap(), signing_key)
    }

    // --- TransactionSigner tests ---

    #[test]
    fn public_key_derives_from_signing_key() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let signer =
            TransactionSigner::from_key("test.near".parse().unwrap(), signing_key.clone());
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
        let block_hash = CryptoHash::default();
        let block_height = 100;

        let signed_tx = signer.create_and_sign_function_call_tx(
            receiver_id.clone(),
            "do_something".to_string(),
            args.clone(),
            gas,
            block_hash,
            block_height,
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
            near_indexer_primitives::near_primitives::transaction::Action::FunctionCall(
                action,
            ) => {
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
            CryptoHash::default(),
            100,
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

    // --- TransactionSender tests ---

    struct FakeBlockQuerier(Result<BlockView, ChainGatewayError>);

    #[async_trait]
    impl LatestBlock for FakeBlockQuerier {
        async fn latest_final_block(
            &self,
        ) -> Result<near_indexer_primitives::views::BlockView, ChainGatewayError> {
            self.0.clone()
        }
    }

    struct FakeTxSubmitter {
        result: Result<(), ChainGatewayError>,
        submitted: Arc<Mutex<Vec<SignedTransaction>>>,
    }

    #[async_trait]
    impl SubmitTx for FakeTxSubmitter {
        async fn submit_tx(
            &self,
            transaction: SignedTransaction,
        ) -> Result<(), ChainGatewayError> {
            self.submitted.lock().unwrap().push(transaction);
            self.result.clone()
        }
    }

    fn test_block(height: u64) -> BlockView {
        BlockView {
            author: "test.near".parse().unwrap(),
            header: BlockHeaderView {
                height,
                ..Default::default()
            },
            chunks: vec![],
        }
    }

    fn test_sender(
        block: Result<BlockView, ChainGatewayError>,
        submit_result: Result<(), ChainGatewayError>,
    ) -> (TransactionSender, Arc<Mutex<Vec<SignedTransaction>>>) {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let sender = TransactionSender {
            view_client: Arc::new(FakeBlockQuerier(block)),
            rpc_handler: Arc::new(FakeTxSubmitter {
                result: submit_result,
                submitted: submitted.clone(),
            }),
        };
        (sender, submitted)
    }

    #[tokio::test]
    async fn submit_returns_transaction_hash() {
        let (sender, _) = test_sender(Ok(test_block(100)), Ok(()));
        let signer = Arc::new(test_signer());

        let hash = sender
            .submit_function_call_tx(
                signer,
                "receiver.near".parse().unwrap(),
                "method".to_string(),
                vec![],
                TEST_GAS,
            )
            .await
            .unwrap();

        assert_ne!(hash, CryptoHash::default());
    }

    #[tokio::test]
    async fn view_client_error_propagates() {
        let err = ChainGatewayError::SendTransactionError {
            context: "test error".to_string(),
            source: Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "test")),
        };
        let (sender, _) = test_sender(Err(err), Ok(()));
        let signer = Arc::new(test_signer());

        let result = sender
            .submit_function_call_tx(
                signer,
                "receiver.near".parse().unwrap(),
                "method".to_string(),
                vec![],
                TEST_GAS,
            )
            .await;

        assert!(matches!(
            result,
            Err(ChainGatewayError::SendTransactionError { .. })
        ));
    }

    #[tokio::test]
    async fn rpc_error_propagates() {
        let err = ChainGatewayError::RpcClient {
            source: Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "test")),
        };
        let (sender, _) = test_sender(Ok(test_block(100)), Err(err));
        let signer = Arc::new(test_signer());

        let result = sender
            .submit_function_call_tx(
                signer,
                "receiver.near".parse().unwrap(),
                "method".to_string(),
                vec![],
                TEST_GAS,
            )
            .await;

        assert!(matches!(
            result,
            Err(ChainGatewayError::RpcClient { .. })
        ));
    }

    #[tokio::test]
    async fn submits_signed_transaction_to_rpc() {
        let (sender, submitted) = test_sender(Ok(test_block(100)), Ok(()));
        let signer = Arc::new(test_signer());

        let hash = sender
            .submit_function_call_tx(
                signer,
                "receiver.near".parse().unwrap(),
                "method".to_string(),
                b"args".to_vec(),
                TEST_GAS,
            )
            .await
            .unwrap();

        let txs = submitted.lock().unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].get_hash(), hash);
    }
}
