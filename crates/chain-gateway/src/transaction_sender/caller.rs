use std::sync::atomic::{AtomicUsize, Ordering};

use near_account_id::AccountId;
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_indexer_primitives::CryptoHash;
use near_mpc_bounded_collections::NonEmptyVec;

use crate::errors::ChainGatewayError;
use crate::transaction_sender::{SubmitFunctionCall, TransactionSigner};

pub struct AccountCaller<T> {
    submitter: T,
    signers: NonEmptyVec<TransactionSigner>,
    next: AtomicUsize,
}

impl<T> AccountCaller<T> {
    pub fn new(submitter: T, signers: NonEmptyVec<TransactionSigner>) -> Self {
        Self {
            submitter,
            signers,
            next: AtomicUsize::new(0),
        }
    }
}

impl<T: SubmitFunctionCall + Sync> CallContract for AccountCaller<T> {
    type Output = CryptoHash;
    type Error = ChainGatewayError;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<CryptoHash, ChainGatewayError> {
        let signer = &self.signers[self.next.fetch_add(1, Ordering::Relaxed) % self.signers.len()];
        self.submitter
            .submit_function_call_tx(signer, contract_id.clone(), call_args)
            .await
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::AccountCaller;
    use crate::errors::{ChainGatewayError, ChainGatewayOp};
    use crate::mock::{MockChainStateBuilder, MockError};
    use crate::transaction_sender::TransactionSigner;
    use crate::types::LatestFinalBlockInfo;
    use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
    use near_account_id::AccountId;
    use near_contract_transport::{CallContract, FunctionCallArgs, NearGas, NearToken};
    use near_indexer::near_primitives::transaction::SignedTransaction;
    use near_indexer_primitives::CryptoHash;

    fn test_call() -> FunctionCallArgs {
        FunctionCallArgs {
            method_name: "do_something".to_string(),
            args: b"{}".to_vec(),
            gas: NearGas::from_gas(1),
            deposit: NearToken::from_yoctonear(0),
        }
    }

    fn signed_by(tx: &SignedTransaction, verifying_key: &VerifyingKey) -> bool {
        match &tx.signature {
            near_crypto::Signature::ED25519(sig) => {
                verifying_key.verify(&tx.get_hash().0, sig).is_ok()
            }
            _ => false,
        }
    }

    #[tokio::test]
    async fn account_caller__should_round_robin_across_the_signer_pool() {
        // Given
        let account: AccountId = "signer.near".parse().unwrap();
        let signer0 =
            TransactionSigner::from_key(account.clone(), SigningKey::from_bytes(&[1u8; 32]));
        let signer1 = TransactionSigner::from_key(account, SigningKey::from_bytes(&[2u8; 32]));
        let (key0, key1) = (signer0.public_key(), signer1.public_key());
        let mock = MockChainStateBuilder::new()
            .with_latest_block(Ok(LatestFinalBlockInfo {
                observed_at: 100.into(),
                value: CryptoHash::hash_bytes(b"blk"),
            }))
            .with_signed_transaction_submitter_response(Ok(()))
            .build();
        let contract: AccountId = "contract.near".parse().unwrap();
        let caller = AccountCaller::new(mock.clone(), vec![signer0, signer1].try_into().unwrap());

        // When
        let first_hash = caller.call_contract(&contract, test_call()).await.unwrap();
        caller.call_contract(&contract, test_call()).await.unwrap();
        caller.call_contract(&contract, test_call()).await.unwrap();

        // Then
        let submitted = mock.signed_transactions().await;
        assert_eq!(submitted.len(), 3);
        assert!(signed_by(&submitted[0], &key0));
        assert!(signed_by(&submitted[1], &key1));
        assert!(signed_by(&submitted[2], &key0));
        assert_eq!(first_hash, submitted[0].get_hash());
    }

    #[tokio::test]
    async fn account_caller__should_map_a_submit_failure_to_call_error() {
        // Given
        let account: AccountId = "signer.near".parse().unwrap();
        let signer =
            TransactionSigner::from_key(account.clone(), SigningKey::from_bytes(&[1u8; 32]));
        let expected_source = MockError::LatestFinalBlockError;
        let mock = MockChainStateBuilder::new()
            .with_latest_block(Err(expected_source.clone()))
            .build();
        let contract: AccountId = "contract.near".parse().unwrap();
        let caller = AccountCaller::new(mock, vec![signer].try_into().unwrap());

        // When
        let call = test_call();
        let err = caller
            .call_contract(&contract, call.clone())
            .await
            .unwrap_err();

        // Then
        assert_eq!(
            err,
            ChainGatewayError::FetchFinalBlock {
                op: ChainGatewayOp::SubmitFunctionCallTransaction {
                    signer: account.to_string(),
                    receiver_id: contract.to_string(),
                    method_name: call.method_name
                },
                message: expected_source.to_string()
            }
        );
    }
}
