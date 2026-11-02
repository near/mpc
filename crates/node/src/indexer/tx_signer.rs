use crate::config::RespondConfig;
use crate::indexer::types::ChainSendTransactionRequest;
use anyhow::Context;
use chain_gateway::ChainGateway;
use chain_gateway::transaction_sender::GatewaySender;
use ed25519_dalek::SigningKey;
use near_account_id::AccountId;
use near_kit_primitives::signer::{InMemorySigner, RotatingSigner, SecretKey, Signer};
use std::sync::Arc;

/// Signs and submits through the node's gateway. Each sender tracks the nonce
/// of every key it signs with.
pub(crate) type NodeSender<G = ChainGateway> = GatewaySender<G, Arc<dyn Signer>>;

pub(crate) struct TransactionSigners<G = ChainGateway> {
    /// Rotates through the respond keys for responding to signature requests.
    /// They can belong to an arbitrary near account.
    respond: Arc<NodeSender<G>>,
    /// Signs vote_pk, vote_reshared, etc., which must come from the account
    /// that this node runs under.
    owner: Arc<NodeSender<G>>,
}

impl<G: Clone> TransactionSigners<G> {
    pub fn new(
        gateway: G,
        respond_config: RespondConfig,
        owner_account_id: AccountId,
        owner_signing_key: SigningKey,
    ) -> anyhow::Result<Self> {
        let respond_keys = respond_config.access_keys.iter().map(secret_key).collect();
        let respond = RotatingSigner::new(respond_config.account_id, respond_keys)
            .context("At least one responding access key must be provided")?;
        let owner = InMemorySigner::new(owner_account_id, secret_key(&owner_signing_key));
        Ok(TransactionSigners {
            respond: Arc::new(GatewaySender::new(
                gateway.clone(),
                Arc::new(respond) as Arc<dyn Signer>,
            )),
            owner: Arc::new(GatewaySender::new(
                gateway,
                Arc::new(owner) as Arc<dyn Signer>,
            )),
        })
    }

    pub fn signer_for(&self, req: &ChainSendTransactionRequest) -> Arc<NodeSender<G>> {
        match req {
            ChainSendTransactionRequest::Respond(_) => self.respond.clone(),
            ChainSendTransactionRequest::CKDRespond(_) => self.respond.clone(),
            _ => self.owner.clone(),
        }
    }
}

fn secret_key(key: &SigningKey) -> SecretKey {
    SecretKey::ed25519_from_bytes(key.to_bytes())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::TransactionSigners;
    use crate::config::RespondConfig;
    use crate::indexer::types::ChainSendTransactionRequest;
    use chain_gateway::mock::{MockChainState, MockChainStateBuilder};
    use chain_gateway::types::LatestFinalBlockInfo;
    use ed25519_dalek::SigningKey;
    use near_account_id::AccountId;
    use near_indexer_primitives::CryptoHash;
    use near_kit_primitives::TxSender;
    use near_kit_primitives::signer::PublicKey;
    use near_mpc_contract_interface::call_args::SignatureRespondArgs;
    use near_mpc_contract_interface::types::{
        DomainId, K256AffinePoint, K256Scalar, K256Signature, Payload, SignatureRequest,
        SignatureResponse,
    };

    fn signers() -> (TransactionSigners<MockChainState>, MockChainState) {
        let chain = MockChainStateBuilder::new()
            .with_latest_block(Ok(LatestFinalBlockInfo {
                height: 100.into(),
                hash: CryptoHash::hash_bytes(b"blk"),
            }))
            .with_signed_transaction_submitter_response(Ok(()))
            .build();
        let respond = RespondConfig {
            account_id: "responder.near".parse().unwrap(),
            access_keys: vec![
                SigningKey::from_bytes(&[1; 32]),
                SigningKey::from_bytes(&[2; 32]),
            ],
        };
        let signers = TransactionSigners::new(
            chain.clone(),
            respond,
            "owner.near".parse().unwrap(),
            SigningKey::from_bytes(&[3; 32]),
        )
        .unwrap();
        (signers, chain)
    }

    fn respond() -> ChainSendTransactionRequest {
        ChainSendTransactionRequest::Respond(SignatureRespondArgs::new(
            SignatureRequest::new(
                DomainId(0),
                Payload::Ecdsa([7u8; 32].into()),
                &"alice.near".parse().unwrap(),
                "test",
            ),
            SignatureResponse::Secp256k1(K256Signature {
                big_r: K256AffinePoint {
                    affine_point: [7u8; 33],
                },
                s: K256Scalar { scalar: [7u8; 32] },
                recovery_id: 0,
            }),
        ))
    }

    fn key(seed: u8) -> PublicKey {
        PublicKey::ed25519_from_bytes(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    }

    async fn send(
        signers: &TransactionSigners<MockChainState>,
        request: ChainSendTransactionRequest,
    ) -> (AccountId, PublicKey) {
        let sender = signers.signer_for(&request);
        let sent = sender
            .send(
                "mpc.near".parse().unwrap(),
                vec![request.function_call().into_action().unwrap()],
            )
            .await
            .unwrap();
        (sender.account_id().clone(), sent.public_key)
    }

    #[tokio::test]
    async fn signer_for__should_rotate_responses_and_send_the_rest_from_the_owner() {
        // Given
        let (signers, chain) = signers();
        let responder: AccountId = "responder.near".parse().unwrap();
        let owner: AccountId = "owner.near".parse().unwrap();

        // When
        let mut sent = Vec::new();
        for request in [
            respond(),
            respond(),
            ChainSendTransactionRequest::VerifyTee(),
            respond(),
        ] {
            sent.push(send(&signers, request).await);
        }

        // Then
        assert_eq!(
            sent,
            [
                (responder.clone(), key(1)),
                (responder.clone(), key(2)),
                (owner, key(3)),
                (responder, key(1)),
            ]
        );
        let nonces: Vec<u64> = chain
            .signed_transactions()
            .iter()
            .map(|tx| tx.transaction.nonce().nonce())
            .collect();
        let first =
            near_indexer::near_primitives::account::AccessKey::ACCESS_KEY_NONCE_RANGE_MULTIPLIER
                * 100;
        assert_eq!(nonces, [first, first, first, first + 1]);
    }

    #[test]
    fn new__should_require_a_respond_key() {
        let chain = MockChainStateBuilder::new().build();
        let respond = RespondConfig {
            account_id: "responder.near".parse().unwrap(),
            access_keys: Vec::new(),
        };
        let result = TransactionSigners::new(
            chain,
            respond,
            "owner.near".parse().unwrap(),
            SigningKey::from_bytes(&[3; 32]),
        );
        assert!(result.is_err());
    }
}
