use std::collections::HashMap;
use std::sync::Mutex;

use near_account_id::AccountId;
use near_indexer::near_primitives::account::AccessKey;
use near_indexer::near_primitives::borsh;
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::CryptoHash;
use near_kit_primitives::protocol::{Action, Transaction};
use near_kit_primitives::rpc::{BlockReference, ViewFunctionResult};
use near_kit_primitives::signer::{PublicKey, Signer};
use near_kit_primitives::{TxSender, Viewer};

use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use crate::types::BlockHeight;

/// Sends transactions from `signer`'s account through the node behind
/// `gateway`, without waiting for them to execute: a send resolves to a
/// [`SentTransaction`] once the node has routed it. Views go to `gateway`.
///
/// `signer` picks the key for each transaction; a
/// [`RotatingSigner`](near_kit_primitives::signer::RotatingSigner) spreads them
/// over a pool of access keys. Nonces are tracked per key, starting from the
/// minimum the latest final block allows. The key is picked before anything
/// else, so a failed send still reports it ([`SendFailure`]).
pub struct GatewaySender<G, S> {
    gateway: G,
    signer: S,
    nonces: Mutex<HashMap<PublicKey, u64>>,
}

/// A transaction the node routed, and how it was signed, for the caller's
/// records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentTransaction {
    pub tx_hash: CryptoHash,
    pub public_key: PublicKey,
    pub nonce: u64,
    pub signature: near_crypto::Signature,
    /// The latest final block when the transaction was built; its hash is the
    /// transaction's block hash.
    pub block_height: BlockHeight,
}

/// A send that failed, with the key it was signed with (or picked for it).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{error} (access key {public_key})")]
pub struct SendFailure {
    pub public_key: PublicKey,
    #[source]
    pub error: ChainGatewayError,
}

impl<G, S> GatewaySender<G, S> {
    pub fn new(gateway: G, signer: S) -> Self {
        Self {
            gateway,
            signer,
            nonces: Mutex::new(HashMap::new()),
        }
    }

    /// The larger of the next nonce for `key` and the minimum at `height`.
    fn next_nonce(&self, key: &PublicKey, height: BlockHeight) -> u64 {
        let min_nonce = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER
            .checked_mul(height.into())
            .expect("we don't expect to exceed a block height of 18 trillion");
        let mut nonces = self.nonces.lock().expect("require non-poisoned mutex");
        let nonce = nonces.entry(key.clone()).or_default();
        *nonce = (*nonce + 1).max(min_nonce);
        *nonce
    }
}

impl<G, S> TxSender for GatewaySender<G, S>
where
    G: FetchLatestFinalBlockInfo + SubmitSignedTransaction,
    S: Signer,
{
    type Output = SentTransaction;
    type SendError = SendFailure;

    fn account_id(&self) -> &AccountId {
        self.signer.account_id()
    }

    async fn send(
        &self,
        receiver_id: AccountId,
        actions: Vec<Action>,
    ) -> Result<SentTransaction, SendFailure> {
        let key = self.signer.key();
        let failure = |error| SendFailure {
            public_key: key.public_key().clone(),
            error,
        };
        let op = ChainGatewayOp::SubmitFunctionCallTransaction {
            signer: self.account_id().to_string(),
            receiver_id: receiver_id.to_string(),
            method_name: method_names(&actions),
        };
        let info = self
            .gateway
            .fetch_latest_final_block_info()
            .await
            .map_err(|err| {
                failure(ChainGatewayError::FetchFinalBlock {
                    op: op.clone(),
                    message: err.to_string(),
                })
            })?;

        let transaction = Transaction::new(
            self.account_id().clone(),
            key.public_key().clone(),
            self.next_nonce(key.public_key(), info.height),
            receiver_id,
            info.hash.0.into(),
            actions,
        );
        let signature = key
            .sign(transaction.get_hash().as_bytes())
            .await
            .map_err(|err| {
                failure(ChainGatewayError::Sign {
                    op: op.clone(),
                    message: err.to_string(),
                })
            })?;
        let transaction: SignedTransaction =
            borsh::from_slice(&transaction.into_signed(signature).to_bytes())
                .expect("near-kit and nearcore encode transactions alike");

        let sent = SentTransaction {
            tx_hash: transaction.get_hash(),
            public_key: key.public_key().clone(),
            nonce: transaction.transaction.nonce().nonce(),
            signature: transaction.signature.clone(),
            block_height: info.height,
        };
        tracing::info!(
            tx_hash = ?sent.tx_hash,
            public_key = %sent.public_key,
            nonce = sent.nonce,
            "sending transaction",
        );
        self.gateway
            .submit_signed_transaction(transaction)
            .await
            .map_err(|err| {
                failure(ChainGatewayError::SubmitSignedTransaction {
                    op,
                    message: err.to_string(),
                })
            })?;
        Ok(sent)
    }
}

impl<G: Viewer, S: Send + Sync> Viewer for GatewaySender<G, S> {
    type ViewError = G::ViewError;

    fn view_function(
        &self,
        contract_id: &AccountId,
        method: &str,
        args: &[u8],
        block: BlockReference,
    ) -> impl Future<Output = Result<ViewFunctionResult, Self::ViewError>> + Send {
        self.gateway.view_function(contract_id, method, args, block)
    }
}

fn method_names(actions: &[Action]) -> String {
    actions
        .iter()
        .map(|action| match action {
            Action::FunctionCall(call) => call.method_name.as_str(),
            _ => "<not a function call>",
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{GatewaySender, SendFailure, SentTransaction};
    use crate::errors::{ChainGatewayError, ChainGatewayOp};
    use crate::mock::{MockChainState, MockChainStateBuilder, MockError};
    use crate::types::LatestFinalBlockInfo;
    use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
    use near_account_id::AccountId;
    use near_indexer::near_primitives::account::AccessKey;
    use near_indexer::near_primitives::transaction::{Action, SignedTransaction, Transaction};
    use near_indexer_primitives::CryptoHash;
    use near_kit_primitives::protocol::Action as KitAction;
    use near_kit_primitives::signer::{InMemorySigner, RotatingSigner, SecretKey, Signer};
    use near_kit_primitives::{Gas, NearToken, TxSender};

    const HEIGHT: u64 = 100;

    fn chain() -> MockChainState {
        MockChainStateBuilder::new()
            .with_latest_block(Ok(LatestFinalBlockInfo {
                height: HEIGHT.into(),
                hash: CryptoHash::hash_bytes(b"blk"),
            }))
            .with_signed_transaction_submitter_response(Ok(()))
            .build()
    }

    fn call() -> KitAction {
        KitAction::function_call(
            "do_something",
            b"{}".to_vec(),
            Gas::from_tgas(1),
            NearToken::from_yoctonear(1),
        )
    }

    fn signer_for(seed: u8) -> InMemorySigner {
        InMemorySigner::new(
            "signer.near".parse::<AccountId>().unwrap(),
            SecretKey::ed25519_from_bytes([seed; 32]),
        )
    }

    fn signed_by(tx: &SignedTransaction, seed: u8) -> bool {
        let key: VerifyingKey = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        match &tx.signature {
            near_crypto::Signature::ED25519(sig) => key.verify(&tx.get_hash().0, sig).is_ok(),
            _ => false,
        }
    }

    #[tokio::test]
    async fn send__should_submit_a_nearcore_transaction_signed_by_the_signer() {
        // Given
        let chain = chain();
        let sender = GatewaySender::new(chain.clone(), signer_for(1));

        // When
        let sent = sender
            .send("contract.near".parse().unwrap(), vec![call()])
            .await
            .unwrap();

        // Then
        let [submitted] = chain.signed_transactions().try_into().unwrap();
        assert_eq!(
            sent,
            SentTransaction {
                tx_hash: submitted.get_hash(),
                public_key: signer_for(1).key().public_key().clone(),
                nonce: AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * HEIGHT,
                signature: submitted.signature.clone(),
                block_height: HEIGHT.into(),
            }
        );
        assert!(signed_by(&submitted, 1));
        let Transaction::V0(tx) = &submitted.transaction else {
            panic!("expected Transaction::V0");
        };
        assert_eq!(tx.signer_id.as_str(), "signer.near");
        assert_eq!(tx.receiver_id.as_str(), "contract.near");
        assert_eq!(tx.block_hash, CryptoHash::hash_bytes(b"blk"));
        assert_eq!(
            tx.nonce,
            AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * HEIGHT
        );
        let [Action::FunctionCall(action)] = tx.actions.as_slice() else {
            panic!("expected one function call, got {:?}", tx.actions);
        };
        assert_eq!(action.method_name, "do_something");
        assert_eq!(action.args, b"{}");
        assert_eq!(action.gas.as_gas(), Gas::from_tgas(1).as_gas());
        assert_eq!(action.deposit.as_yoctonear(), 1);
    }

    #[tokio::test]
    async fn send__should_increment_the_nonce_per_key() {
        // Given
        let chain = chain();
        let sender = GatewaySender::new(chain.clone(), signer_for(1));

        // When
        for _ in 0..3 {
            sender
                .send("contract.near".parse().unwrap(), vec![call()])
                .await
                .unwrap();
        }

        // Then
        let nonces: Vec<u64> = chain
            .signed_transactions()
            .iter()
            .map(|tx| tx.transaction.nonce().nonce())
            .collect();
        let first = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * HEIGHT;
        assert_eq!(nonces, [first, first + 1, first + 2]);
    }

    #[tokio::test]
    async fn send__should_rotate_through_a_key_pool() {
        // Given
        let chain = chain();
        let pool = RotatingSigner::from_signers(vec![signer_for(1), signer_for(2)]).unwrap();
        let sender = GatewaySender::new(chain.clone(), pool);

        // When
        let mut keys = Vec::new();
        for _ in 0..3 {
            let sent = sender
                .send("contract.near".parse().unwrap(), vec![call()])
                .await
                .unwrap();
            keys.push(sent.public_key);
        }

        // Then
        let key = |seed| signer_for(seed).key().public_key().clone();
        assert_eq!(keys, [key(1), key(2), key(1)]);
        let submitted = chain.signed_transactions();
        assert!(signed_by(&submitted[0], 1));
        assert!(signed_by(&submitted[1], 2));
        assert!(signed_by(&submitted[2], 1));
        let first = AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER * HEIGHT;
        assert_eq!(submitted[2].transaction.nonce().nonce(), first + 1);
    }

    #[tokio::test]
    async fn send__should_wrap_a_latest_final_block_error_and_not_submit() {
        // Given
        let chain = MockChainStateBuilder::new()
            .with_latest_block(Err(MockError::LatestFinalBlockError))
            .build();
        let sender = GatewaySender::new(chain.clone(), signer_for(1));

        // When
        let err = sender
            .send("contract.near".parse().unwrap(), vec![call()])
            .await
            .unwrap_err();

        // Then
        assert_eq!(
            err,
            SendFailure {
                public_key: signer_for(1).key().public_key().clone(),
                error: ChainGatewayError::FetchFinalBlock {
                    op: ChainGatewayOp::SubmitFunctionCallTransaction {
                        signer: "signer.near".to_string(),
                        receiver_id: "contract.near".to_string(),
                        method_name: "do_something".to_string(),
                    },
                    message: MockError::LatestFinalBlockError.to_string(),
                },
            }
        );
        assert_eq!(chain.signed_transactions(), vec![]);
    }

    #[tokio::test]
    async fn send__should_wrap_a_submit_error() {
        // Given
        let chain = MockChainStateBuilder::new()
            .with_latest_block(Ok(LatestFinalBlockInfo {
                height: HEIGHT.into(),
                hash: CryptoHash::hash_bytes(b"blk"),
            }))
            .with_signed_transaction_submitter_response(Err(MockError::RpcError))
            .build();
        let sender = GatewaySender::new(chain.clone(), signer_for(1));

        // When
        let err = sender
            .send("contract.near".parse().unwrap(), vec![call()])
            .await
            .unwrap_err();

        // Then
        assert_eq!(
            err,
            SendFailure {
                public_key: signer_for(1).key().public_key().clone(),
                error: ChainGatewayError::SubmitSignedTransaction {
                    op: ChainGatewayOp::SubmitFunctionCallTransaction {
                        signer: "signer.near".to_string(),
                        receiver_id: "contract.near".to_string(),
                        method_name: "do_something".to_string(),
                    },
                    message: MockError::RpcError.to_string(),
                },
            }
        );
        assert_eq!(chain.signed_transactions().len(), 1);
    }
}
