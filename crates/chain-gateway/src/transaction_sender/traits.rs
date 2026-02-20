use async_trait::async_trait;
use near_account_id::AccountId;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::Gas;
use std::sync::Arc;

use crate::errors::ChainGatewayError;
use crate::primitives::{LatestFinalBlockInfoFetcher, SignedTransactionSubmitter};

use super::TransactionSigner;

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
        let info =
            self.latest_final_block()
                .await
                .map_err(|err| ChainGatewayError::FetchFinalBlock {
                    source: Arc::new(err),
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
        self.submit_signed_transaction(transaction)
            .await
            .map_err(|err| ChainGatewayError::SubmitTransaction {
                source: Arc::new(err),
            })?;
        Ok(tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mock::{MockChainStateBuilder, MockError},
        transaction_sender::signer::test_signer,
        types::LatestFinalBlockInfo,
    };

    use super::*;
    use near_indexer::near_primitives::serialize::dec_format::DecType;

    use rand::{SeedableRng, rngs::StdRng};

    struct TransactionCall {
        receiver_id: AccountId,
        method_name: String,
        args: Vec<u8>,
        gas: Gas,
    }

    fn test_call() -> TransactionCall {
        let receiver_id: AccountId = "receiver.near".parse().unwrap();
        let method_name = "do_something".to_string();
        let args = b"test args".to_vec();
        let gas = Gas::from_u64(300);
        TransactionCall {
            receiver_id,
            method_name,
            args,
            gas,
        }
    }

    #[tokio::test]
    async fn test_submit_function_call_tx_wraps_latest_final_block_error() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let expected_source = MockError::LatestFinalBlockError;
        let mock_chain_state = MockChainStateBuilder::new()
            .with_latest_block(Err(expected_source.clone()))
            .build();
        let call = test_call();
        let signer = Arc::new(test_signer(&mut rng));
        let res = mock_chain_state
            .submit_function_call_tx(
                signer,
                call.receiver_id,
                call.method_name,
                call.args,
                call.gas,
            )
            .await
            .unwrap_err();
        if let ChainGatewayError::FetchFinalBlock { source } = res {
            assert_eq!(expected_source.to_string(), source.to_string());
        } else {
            panic!("unexpected error: {:?}", res);
        }
        // ensure the transaction was not submitted
        assert!(mock_chain_state.signed_transactions().await.is_empty());
    }

    #[tokio::test]
    async fn test_submit_function_call_tx_submits_correct_transaction() {
        // Given
        const SEED: u64 = 42;
        let call = test_call();
        let signer = Arc::new(test_signer(&mut StdRng::seed_from_u64(SEED)));
        let signer_clone = Arc::new(test_signer(&mut StdRng::seed_from_u64(SEED)));

        let info = LatestFinalBlockInfo {
            observed_at: 13290.into(),
            value: near_indexer_primitives::CryptoHash::hash_bytes(b"test_bytes"),
        };
        let mock_chain_state = MockChainStateBuilder::new()
            .with_latest_block(Ok(info.clone()))
            .with_signed_transaction_submitter_response(Ok(()))
            .build();

        // When
        let res = mock_chain_state
            .submit_function_call_tx(
                signer,
                call.receiver_id.clone(),
                call.method_name.clone(),
                call.args.clone(),
                call.gas,
            )
            .await
            .unwrap();

        // Then
        let expected = signer_clone.create_and_sign_function_call_tx(
            call.receiver_id,
            call.method_name,
            call.args,
            call.gas,
            info,
        );

        assert_eq!(expected.transaction.get_hash_and_size().0, res);

        let found = mock_chain_state.signed_transactions().await;
        assert_eq!(found, vec![expected]);
    }

    #[tokio::test]
    async fn test_submit_function_call_tx_submits_propagates_rpc_error() {
        // Given
        const SEED: u64 = 42;
        let call = test_call();
        let signer = Arc::new(test_signer(&mut StdRng::seed_from_u64(SEED)));

        let info = LatestFinalBlockInfo {
            observed_at: 13290.into(),
            value: near_indexer_primitives::CryptoHash::hash_bytes(b"test_bytes"),
        };
        let expected_source = MockError::RpcError;
        let mock_chain_state = MockChainStateBuilder::new()
            .with_latest_block(Ok(info.clone()))
            .with_signed_transaction_submitter_response(Err(expected_source.clone()))
            .build();

        // When
        let res = mock_chain_state
            .submit_function_call_tx(
                signer,
                call.receiver_id.clone(),
                call.method_name.clone(),
                call.args.clone(),
                call.gas,
            )
            .await
            .unwrap_err();

        // Then
        if let ChainGatewayError::SubmitTransaction { source } = res {
            assert_eq!(expected_source.to_string(), source.to_string());
        } else {
            panic!("unexpected error: {:?}", res);
        }
        // ensure the transaction was submitted
        assert_eq!(mock_chain_state.signed_transactions().await.len(), 1);
    }
}
