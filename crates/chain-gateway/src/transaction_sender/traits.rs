use async_trait::async_trait;
use near_account_id::AccountId;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::Gas;
use std::sync::Arc;

use crate::errors::ChainGatewayError;
use crate::primitives::{LatestFinalBlockInfoFetcher, SignedTransactionSubmitter};

use super::TransactionSigner;

/// Blanket-implemented for all `T: TransactionSubmitter` (internal, for testing).
/// External users implement this trait directly for testing.
#[async_trait]
pub trait FunctionCallSubmitter:
    LatestFinalBlockInfoFetcher + SignedTransactionSubmitter + Send + Sync + Clone + 'static
{
    async fn submit_function_call_tx(
        &self,
        signer: Arc<TransactionSigner>,
        receiver_id: AccountId,
        method_name: String,
        args: Vec<u8>,
        gas: Gas,
    ) -> Result<CryptoHash, ChainGatewayError> {
        // todo: simplify error handling
        let info = self.latest_final_block().await.map_err(|err| {
            ChainGatewayError::ViewClient {
                op: crate::errors::ChainGatewayOp::FetchFinalBlock,
                source: Arc::new(err),
            }
        })?;

        let transaction =
            signer.create_and_sign_function_call_tx(receiver_id, method_name, args, gas, info);

        let tx_hash = transaction.get_hash();

        tracing::info!(
            tx_hash = ?tx_hash,
            public_key = ?signer.public_key(),
            nonce = transaction.transaction.nonce(),
            "sending transaction",
        );
        // todo: simplify error handling
        self.submit_signed_transaction(transaction)
            .await
            .map_err(|err| ChainGatewayError::RpcClient {
                source: Arc::new(err),
            })?;
        Ok(tx_hash)
    }
}
//
///// Internal low-level seam combining block queries and tx submission.
//#[async_trait]
//pub(super) trait TransactionSubmitter:
//    LatestFinalBlockInfoFetcher + SignedTransactionSubmitter + Send + Sync + Clone + 'static
//{
//}
//
//#[async_trait]
//impl<T: TransactionSubmitter + Send + Sync> FunctionCallSubmitter for T {
//    async fn submit_function_call_tx(
//        &self,
//        signer: Arc<TransactionSigner>,
//        receiver_id: AccountId,
//        method_name: String,
//        args: Vec<u8>,
//        gas: Gas,
//    ) -> Result<CryptoHash, ChainGatewayError> {
//        let (block_hash, block_height) = self.latest_final_block_info().await?;
//
//        let transaction = signer.create_and_sign_function_call_tx(
//            receiver_id,
//            method_name,
//            args,
//            gas,
//            block_hash,
//            block_height,
//        );
//
//        let tx_hash = transaction.get_hash();
//
//        tracing::info!(
//            tx_hash = ?tx_hash,
//            public_key = ?signer.public_key(),
//            nonce = transaction.transaction.nonce(),
//            "sending transaction",
//        );
//        self.submit_signed_tx(transaction).await?;
//        Ok(tx_hash)
//    }
//}

#[cfg(test)]
mod tests {
    use crate::types::LatestFinalBlockInfo;

    use super::*;
    use near_indexer::near_primitives::transaction::SignedTransaction;
    use near_indexer_primitives::near_primitives::transaction::Transaction;
    use std::{io::ErrorKind, sync::Mutex};

    const TEST_GAS: Gas = Gas::from_gas(300_000_000_000_000);

    fn test_signer() -> TransactionSigner {
        crate::transaction_sender::signer::test_signer()
    }

    type MyError = Arc<std::io::Error>;

    #[derive(Clone)]
    struct MockTransactionSubmitter {
        block_result: Result<LatestFinalBlockInfo, MyError>,
        submit_result: Result<(), ChainGatewayError>,
        submitted: Arc<Mutex<Vec<SignedTransaction>>>,
    }

    #[async_trait]
    impl LatestFinalBlockInfoFetcher for MockTransactionSubmitter {
        type Error = MyError;
        async fn latest_final_block(&self) -> Result<LatestFinalBlockInfo, Self::Error> {
            self.block_result.clone()
        }
    }

    #[async_trait]
    impl SignedTransactionSubmitter for MockTransactionSubmitter {
        type Error = ChainGatewayError;
        async fn submit_signed_transaction(
            &self,
            transaction: SignedTransaction,
        ) -> Result<(), ChainGatewayError> {
            self.submitted.lock().unwrap().push(transaction);
            self.submit_result.clone()
        }
    }

    impl FunctionCallSubmitter for MockTransactionSubmitter {}

    fn test_submitter(
        info: &LatestFinalBlockInfo,
        submit_result: Result<(), ChainGatewayError>,
    ) -> (MockTransactionSubmitter, Arc<Mutex<Vec<SignedTransaction>>>) {
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let submitter = MockTransactionSubmitter {
            block_result: Ok(info.clone()),
            submit_result,
            submitted: submitted.clone(),
        };
        (submitter, submitted)
    }

    fn test_submitter_with_block_error(err: MyError) -> MockTransactionSubmitter {
        MockTransactionSubmitter {
            block_result: Err(err),
            submit_result: Ok(()),
            submitted: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[tokio::test]
    async fn blanket_impl_builds_and_submits_correct_transaction() {
        // Use a non-default block hash to verify it flows through.
        let info = LatestFinalBlockInfo {
            observed_at: 42.into(),
            value: CryptoHash::hash_bytes(b"test block"),
        };
        let receiver_id: AccountId = "receiver.near".parse().unwrap();
        let method_name = "do_something".to_string();
        let args = b"test args".to_vec();

        let expected_block_hash = info.value;
        let (submitter, submitted) = test_submitter(&info, Ok(()));

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
            info,
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
        assert_eq!(tx.block_hash, expected_block_hash);

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
        let err = Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "test"));
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
            Err(ChainGatewayError::ViewClient { .. })
        ));
    }

    #[tokio::test]
    async fn blanket_impl_does_not_submit_on_block_error() {
        let err = Arc::new(std::io::Error::new(ErrorKind::Other, "test"));
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
        let info = LatestFinalBlockInfo {
            observed_at: 42.into(),
            value: CryptoHash::hash_bytes(b"test block"),
        };
        let err = ChainGatewayError::RpcClient {
            source: Arc::new(std::io::Error::new(std::io::ErrorKind::Other, "test")),
        };
        let (submitter, _) = test_submitter(&info, Err(err));

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
