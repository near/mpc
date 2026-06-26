use near_account_id::AccountId;
use near_indexer_primitives::CryptoHash;

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use crate::transaction_sender::TransactionSigner;
use crate::types::FunctionCallArgs;

pub trait SubmitFunctionCall {
    fn submit_function_call_tx(
        &self,
        signer: &TransactionSigner,
        receiver_id: AccountId,
        call: FunctionCallArgs,
    ) -> impl Future<Output = Result<CryptoHash, ChainGatewayError>> + Send;
}

impl<T> SubmitFunctionCall for T
where
    T: FetchLatestFinalBlockInfo + SubmitSignedTransaction,
{
    async fn submit_function_call_tx(
        &self,
        signer: &TransactionSigner,
        receiver_id: AccountId,
        call: FunctionCallArgs,
    ) -> Result<CryptoHash, ChainGatewayError> {
        let method_name = call.method_name.clone();
        let info = self.fetch_latest_final_block_info().await.map_err(|err| {
            ChainGatewayError::FetchFinalBlock {
                op: ChainGatewayOp::SubmitFunctionCallTransaction {
                    signer: signer.account_id().to_string(),
                    receiver_id: receiver_id.to_string(),
                    method_name: method_name.clone(),
                },
                message: err.to_string(),
            }
        })?;

        let transaction = signer.create_and_sign_function_call_tx(receiver_id.clone(), call, info);

        let tx_hash = transaction.get_hash();

        tracing::info!(
            tx_hash = ?tx_hash,
            public_key = ?signer.public_key(),
            nonce = ?transaction.transaction.nonce(),
            "sending transaction",
        );

        self.submit_signed_transaction(transaction)
            .await
            .map_err(|err| ChainGatewayError::SubmitSignedTransaction {
                op: ChainGatewayOp::SubmitFunctionCallTransaction {
                    signer: signer.account_id().to_string(),
                    receiver_id: receiver_id.to_string(),
                    method_name,
                },
                message: err.to_string(),
            })?;
        Ok(tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::{ChainGatewayError, ChainGatewayOp},
        mock::{MockChainStateBuilder, MockError},
        transaction_sender::{SubmitFunctionCall, TransactionSigner},
        types::{FunctionCallArgs, LatestFinalBlockInfo},
    };

    use near_account_id::AccountId;

    use crate::NearGas;
    use near_token::NearToken;
    use rand::{SeedableRng, rngs::StdRng};

    fn generate_test_call<R>(rng: &mut R) -> (AccountId, FunctionCallArgs)
    where
        R: rand::Rng,
    {
        let suffix: u32 = rng.r#gen();
        let receiver_id: AccountId = format!("receiver{suffix}.near").parse().unwrap();
        let suffix: u32 = rng.r#gen();
        let method_name = format!("do_something_{suffix}");
        let mut args = vec![0u8; 16];
        rng.fill(&mut args[..]);
        let gas = NearGas::from_gas(300);
        let deposit = NearToken::from_yoctonear(0);
        (
            receiver_id,
            FunctionCallArgs {
                method_name,
                args,
                gas,
                deposit,
            },
        )
    }

    #[tokio::test]
    async fn test_submit_function_call_tx_wraps_latest_final_block_error() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let expected_source = MockError::LatestFinalBlockError;
        let mock_chain_state = MockChainStateBuilder::new()
            .with_latest_block(Err(expected_source.clone()))
            .build();
        let (receiver_id, call) = generate_test_call(&mut rng);
        let signer = TransactionSigner::from_rng(&mut rng);
        // When
        let res = mock_chain_state
            .submit_function_call_tx(&signer, receiver_id.clone(), call.clone())
            .await
            .unwrap_err();
        // Then
        assert_eq!(
            res,
            ChainGatewayError::FetchFinalBlock {
                op: ChainGatewayOp::SubmitFunctionCallTransaction {
                    signer: signer.account_id().to_string(),
                    receiver_id: receiver_id.to_string(),
                    method_name: call.method_name
                },
                message: expected_source.to_string()
            }
        );
        // ensure the transaction was not submitted
        assert_eq!(mock_chain_state.signed_transactions().await, vec![]);
    }

    #[tokio::test]
    async fn test_submit_function_call_tx_submits_correct_transaction() {
        // Given
        const SEED: u64 = 42;
        let mut rng = StdRng::seed_from_u64(SEED);
        let (receiver_id, call) = generate_test_call(&mut rng);
        let signer = TransactionSigner::from_rng(&mut rng.clone());
        let signer_clone = TransactionSigner::from_rng(&mut rng);

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
            .submit_function_call_tx(&signer, receiver_id.clone(), call.clone())
            .await
            .unwrap();

        // Then
        let expected = signer_clone.create_and_sign_function_call_tx(receiver_id, call, info);

        assert_eq!(expected.transaction.get_hash_and_size().0, res);

        let found = mock_chain_state.signed_transactions().await;
        assert_eq!(found, vec![expected]);
    }

    #[tokio::test]
    async fn test_submit_function_call_tx_submits_propagates_rpc_error() {
        // Given
        const SEED: u64 = 42;
        let mut rng = StdRng::seed_from_u64(SEED);
        let (receiver_id, call) = generate_test_call(&mut rng);
        let signer = TransactionSigner::from_rng(&mut StdRng::seed_from_u64(SEED));

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
            .submit_function_call_tx(&signer, receiver_id.clone(), call.clone())
            .await
            .unwrap_err();

        // Then
        assert_eq!(
            res,
            ChainGatewayError::SubmitSignedTransaction {
                op: ChainGatewayOp::SubmitFunctionCallTransaction {
                    signer: signer.account_id().to_string(),
                    receiver_id: receiver_id.to_string(),
                    method_name: call.method_name
                },
                message: expected_source.to_string()
            }
        );
        // ensure the transaction was submitted
        assert_eq!(mock_chain_state.signed_transactions().await.len(), 1);
    }
}
