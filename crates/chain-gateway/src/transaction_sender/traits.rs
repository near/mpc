use async_trait::async_trait;
use near_account_id::AccountId;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::types::Gas;
use std::sync::Arc;

use crate::errors::ChainGatewayError;

use super::TransactionSigner;

/// Blanket-implemented for all `T: TransactionSubmitter` (internal, for testing).
/// External users implement this trait directly for testing.
#[async_trait]
pub trait FunctionCallSubmitter: Send + Sync + Clone + 'static {
    async fn submit_function_call_tx(
        &self,
        signer: Arc<TransactionSigner>,
        receiver_id: AccountId,
        method_name: String,
        args: Vec<u8>,
        gas: Gas,
    ) -> Result<CryptoHash, ChainGatewayError>;
}

/// Internal low-level seam combining block queries and tx submission.
#[async_trait]
pub(super) trait TransactionSubmitter: Send + Sync + Clone + 'static {
    /// Returns (block_hash, block_height) of the latest finalized block.
    async fn latest_final_block_info(&self) -> Result<(CryptoHash, u64), ChainGatewayError>;
    /// Submits a pre-signed transaction to the network.
    async fn submit_signed_tx(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), ChainGatewayError>;
}

#[async_trait]
impl<T: TransactionSubmitter + Send + Sync> FunctionCallSubmitter for T {
    async fn submit_function_call_tx(
        &self,
        signer: Arc<TransactionSigner>,
        receiver_id: AccountId,
        method_name: String,
        args: Vec<u8>,
        gas: Gas,
    ) -> Result<CryptoHash, ChainGatewayError> {
        let (block_hash, block_height) = self.latest_final_block_info().await?;

        let transaction = signer.create_and_sign_function_call_tx(
            receiver_id,
            method_name,
            args,
            gas,
            block_hash,
            block_height,
        );

        let tx_hash = transaction.get_hash();

        tracing::info!(
            tx_hash = ?tx_hash,
            public_key = ?signer.public_key(),
            nonce = transaction.transaction.nonce(),
            "sending transaction",
        );
        self.submit_signed_tx(transaction).await?;
        Ok(tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_indexer_primitives::near_primitives::transaction::Transaction;
    use std::sync::Mutex;

    const TEST_GAS: Gas = Gas::from_gas(300_000_000_000_000);

    fn test_signer() -> TransactionSigner {
        crate::transaction_sender::signer::test_signer()
    }

    #[derive(Clone)]
    struct MockTransactionSubmitter {
        block_result: Result<(CryptoHash, u64), ChainGatewayError>,
        submit_result: Result<(), ChainGatewayError>,
        submitted: Arc<Mutex<Vec<SignedTransaction>>>,
    }

    #[async_trait]
    impl TransactionSubmitter for MockTransactionSubmitter {
        async fn latest_final_block_info(&self) -> Result<(CryptoHash, u64), ChainGatewayError> {
            self.block_result.clone()
        }
        async fn submit_signed_tx(
            &self,
            transaction: SignedTransaction,
        ) -> Result<(), ChainGatewayError> {
            self.submitted.lock().unwrap().push(transaction);
            self.submit_result.clone()
        }
    }

    fn test_submitter(
        block_hash: CryptoHash,
        block_height: u64,
        submit_result: Result<(), ChainGatewayError>,
    ) -> (MockTransactionSubmitter, Arc<Mutex<Vec<SignedTransaction>>>) {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let submitter = MockTransactionSubmitter {
            block_result: Ok((block_hash, block_height)),
            submit_result,
            submitted: submitted.clone(),
        };
        (submitter, submitted)
    }

    fn test_submitter_with_block_error(err: ChainGatewayError) -> MockTransactionSubmitter {
        MockTransactionSubmitter {
            block_result: Err(err),
            submit_result: Ok(()),
            submitted: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[tokio::test]
    async fn blanket_impl_builds_and_submits_correct_transaction() {
        // Use a non-default block hash to verify it flows through.
        let block_hash = CryptoHash::hash_bytes(b"test block");
        let block_height = 42u64;
        let receiver_id: AccountId = "receiver.near".parse().unwrap();
        let method_name = "do_something".to_string();
        let args = b"test args".to_vec();

        let (submitter, submitted) = test_submitter(block_hash, block_height, Ok(()));

        // Two signers from the same key — deterministic ed25519 means identical transactions.
        let signer_a = Arc::new(test_signer());
        let signer_b = test_signer();

        let returned_hash = submitter
            .submit_function_call_tx(
                signer_a,
                receiver_id.clone(),
                method_name.clone(),
                args.clone(),
                TEST_GAS,
            )
            .await
            .unwrap();

        // Build the expected transaction independently.
        let expected_tx = signer_b.create_and_sign_function_call_tx(
            receiver_id.clone(),
            method_name.clone(),
            args.clone(),
            TEST_GAS,
            block_hash,
            block_height,
        );

        let txs = submitted.lock().unwrap();
        assert_eq!(txs.len(), 1, "exactly one transaction should be submitted");

        let submitted_tx = &txs[0];

        // The submitted transaction should be identical to the one we built manually.
        assert_eq!(submitted_tx.get_hash(), expected_tx.get_hash());
        // The returned hash should match.
        assert_eq!(returned_hash, expected_tx.get_hash());

        // Verify the transaction fields for completeness.
        let tx = match &submitted_tx.transaction {
            Transaction::V0(tx) => tx,
            _ => panic!("expected Transaction::V0"),
        };
        assert_eq!(tx.signer_id, "test.near".parse::<AccountId>().unwrap());
        assert_eq!(tx.receiver_id, receiver_id);
        assert_eq!(tx.block_hash, block_hash);

        match &tx.actions[0] {
            near_indexer_primitives::near_primitives::transaction::Action::FunctionCall(action) => {
                assert_eq!(action.method_name, "do_something");
                assert_eq!(action.args, b"test args");
                assert_eq!(action.gas, TEST_GAS);
            }
            other => panic!("expected FunctionCall action, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blanket_impl_propagates_block_query_error() {
        let err = ChainGatewayError::SendTransactionError {
            context: "test error".to_string(),
            source: Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "test")),
        };
        let submitter = test_submitter_with_block_error(err);

        let result = submitter
            .submit_function_call_tx(
                Arc::new(test_signer()),
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
    async fn blanket_impl_does_not_submit_on_block_error() {
        let err = ChainGatewayError::SendTransactionError {
            context: "block error".to_string(),
            source: Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "test")),
        };
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let submitter = MockTransactionSubmitter {
            block_result: Err(err),
            submit_result: Ok(()),
            submitted: submitted.clone(),
        };

        let _ = submitter
            .submit_function_call_tx(
                Arc::new(test_signer()),
                "receiver.near".parse().unwrap(),
                "method".to_string(),
                vec![],
                TEST_GAS,
            )
            .await;

        assert!(
            submitted.lock().unwrap().is_empty(),
            "no transaction should be submitted when block query fails"
        );
    }

    #[tokio::test]
    async fn blanket_impl_propagates_submit_error() {
        let err = ChainGatewayError::RpcClient {
            source: Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "test")),
        };
        let (submitter, _) = test_submitter(CryptoHash::default(), 100, Err(err));

        let result = submitter
            .submit_function_call_tx(
                Arc::new(test_signer()),
                "receiver.near".parse().unwrap(),
                "method".to_string(),
                vec![],
                TEST_GAS,
            )
            .await;

        assert!(matches!(result, Err(ChainGatewayError::RpcClient { .. })));
    }
}
