use crate::network::wire_format::VerifyForeignTxTaskId;
use std::collections::HashSet;

use anyhow::bail;
use foreign_chain_inspector::{RpcQuorum, Verdict};
use threshold_signatures::{ecdsa::Signature, frost_secp256k1::VerifyingKey};

use crate::foreign_chain_policy::SupportersByForeignChain;
use crate::foreign_chain_rpc_policy::{self, RpcQuorumError};
use crate::metrics;
use crate::primitives::ParticipantId;
use crate::providers::ecdsa::triple::participants_from_triples;
use crate::providers::verify_foreign_tx::inspect_request::inspect_request;
use crate::providers::verify_foreign_tx::inspection::{Inspection, TransientErrors};
use crate::providers::verify_foreign_tx::node_outcome::NodeOutcome;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use crate::{
    network::NetworkTaskChannel, primitives::UniqueId,
    providers::verify_foreign_tx::VerifyForeignTxProvider, types::SignatureId,
};
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types::{self as dtos, ECDSA_PAYLOAD_SIZE_BYTES};
use near_mpc_contract_interface::types::{Payload, Tweak};
use tokio::time::{Duration, timeout};

const TRIPLE_TAKE_GRACE_PERIOD: Duration = Duration::from_secs(1);

fn build_signature_request(
    request: &VerifyForeignTxRequest,
    foreign_tx_payload: &dtos::ForeignTxSignPayload,
) -> anyhow::Result<SignatureRequest> {
    let msg_hash = foreign_tx_payload.compute_msg_hash()?;
    if let Some(expected_payload_hash) = &request.expected_payload_hash
        && expected_payload_hash != &msg_hash
    {
        bail!(
            "computed payload hash {msg_hash:?} does not match the request's expected payload hash {expected_payload_hash:?}"
        );
    }
    let payload_hash: [u8; ECDSA_PAYLOAD_SIZE_BYTES] = msg_hash.into();
    let payload_bytes: BoundedVec<u8, ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES> =
        payload_hash.into();

    Ok(SignatureRequest {
        id: request.id,
        receipt_id: request.receipt_id,
        payload: Payload::Ecdsa(payload_bytes),
        tweak: Tweak::new([0u8; 32]),
        entropy: request.entropy,
        timestamp_nanosec: request.timestamp_nanosec,
        domain: request.domain_id,
    })
}

// Awaits on the future for specified grace duration, and calls on_slow
// if grace period expires.
async fn await_with_slow_hook<F: Future>(
    grace: Duration,
    fut: F,
    on_slow: impl FnOnce(),
) -> F::Output {
    tokio::pin!(fut);
    match timeout(grace, &mut fut).await {
        Ok(output) => output,
        Err(_) => {
            on_slow();
            fut.await
        }
    }
}

impl VerifyForeignTxProvider {
    pub(crate) async fn make_verify_foreign_tx_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<((dtos::ForeignTxSignPayload, Signature), VerifyingKey)> {
        let foreign_tx_request = self.verify_foreign_tx_request_store.get(id).await?;
        let requested_chain = foreign_tx_request.request.chain();

        let chain_supporters: HashSet<ParticipantId> = {
            let snapshot = self.supporters_by_foreign_chain.borrow().clone();
            ensure_chain_is_available(&snapshot, foreign_tx_request.request.chain()).inspect_err(
                |_| metrics::MPC_NUM_VERIFY_FOREIGN_TX_UNAVAILABLE_CHAIN_REJECTIONS.inc(),
            )?;
            snapshot.get(&requested_chain).cloned().unwrap_or_default()
        };

        // Leader selection already narrows to chain supporters. Re-check as
        // defense-in-depth, since the supporters snapshot may have changed
        // between leader selection and this attempt.
        let my_participant_id = self.ecdsa_signature_provider.my_participant_id();
        if !chain_supporters.contains(&my_participant_id) {
            metrics::MPC_NUM_VERIFY_FOREIGN_TX_UNAVAILABLE_CHAIN_REJECTIONS.inc();
            anyhow::bail!(
                "selected as leader for a {requested_chain:?} request but this node no longer \
                 supports that chain. Supporters must have changed since leader selection"
            );
        }

        let response_payload = self
            .execute_foreign_chain_request(
                &foreign_tx_request.request,
                foreign_tx_request.payload_version,
            )
            .await?;

        // Build and validate the request before a triple pair is popped, so invalid/malicious
        // requests don't cost one.
        let sign_request = build_signature_request(&foreign_tx_request, &response_payload)?;

        let keyshare = self
            .ecdsa_signature_provider
            .keyshare(foreign_tx_request.domain_id)?;
        let (paired_triple_id, triples) = await_with_slow_hook(
            TRIPLE_TAKE_GRACE_PERIOD,
            self.ecdsa_signature_provider
                .triple_store_for_t(keyshare.reconstruction_threshold)?
                .take_owned_matching(chain_supporters.iter().copied().collect()),
            || {
                metrics::MPC_NUM_VERIFY_FOREIGN_TX_TRIPLE_WAITS.inc();
                tracing::warn!(
                    ?requested_chain,
                    "no chain-compatible triple pairs available, waiting"
                )
            },
        )
        .await;
        let channel = self.ecdsa_signature_provider.new_channel_for_task(
            VerifyForeignTxTaskId::VerifyForeignTxOnlinePresign {
                id,
                paired_triple_id,
            },
            participants_from_triples(&triples.0, &triples.1),
        )?;
        let (signature, public_key) = self
            .ecdsa_signature_provider
            .make_online_presign_signature_leader_given_parameters(
                sign_request,
                keyshare,
                triples,
                channel,
            )
            .await?;
        Ok(((response_payload, signature), public_key))
    }

    pub(super) async fn make_verify_foreign_tx_online_presign_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let sign_request = self.verified_follower_sign_request(id).await?;
        self.ecdsa_signature_provider
            .make_online_presign_signature_follower_given_request(
                channel,
                paired_triple_id,
                sign_request,
            )
            .await
    }

    async fn verified_follower_sign_request(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<SignatureRequest> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let foreign_tx_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.verify_foreign_tx_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let response_payload = self
            .execute_foreign_chain_request(
                &foreign_tx_request.request,
                foreign_tx_request.payload_version,
            )
            .await?;

        build_signature_request(&foreign_tx_request, &response_payload)
    }

    fn rpc_quorum(&self, chain: dtos::ForeignChain) -> Result<RpcQuorum, NoRpcQuorumError> {
        let (_, local_chain) = self
            .config
            .foreign_chains
            .iter_chains()
            .find(|(configured, _)| *configured == chain)
            .ok_or(NoRpcQuorumError::NotConfigured { chain })?;
        let whitelist = self.foreign_chain_whitelist.borrow();
        let entry = whitelist
            .get(&chain)
            .ok_or(NoRpcQuorumError::NotWhitelisted { chain })?;
        foreign_chain_rpc_policy::rpc_quorum(local_chain, entry)
            .map_err(|source| NoRpcQuorumError::Unreachable { chain, source })
    }

    // TODO(#2677): Any negative verdict or errors here only makes this node abstain from
    // responding and lets the request time out. We should produce a response for unhappy
    // paths as well.
    async fn execute_foreign_chain_request(
        &self,
        request: &dtos::ForeignChainRpcRequest,
        payload_version: dtos::ForeignTxPayloadVersion,
    ) -> anyhow::Result<dtos::ForeignTxSignPayload> {
        let verdict = self
            .inspect_foreign_chain_request(request, TransientErrors::Fail)
            .await??;
        let values = require_extracted(verdict)?;
        let payload = match payload_version {
            dtos::ForeignTxPayloadVersion::V1 => {
                dtos::ForeignTxSignPayload::V1(dtos::ForeignTxSignPayloadV1 {
                    request: request.clone(),
                    values,
                })
            }
            _ => bail!("unsupported payload_version"),
        };
        Ok(payload)
    }

    /// Inspects the foreign transaction and checks the extracted values against the expected
    /// ones. An error means this node could not inspect. That is a refusal, not a
    /// [`NodeOutcome`].
    // TODO(#5123): call from the V2 signing flow.
    #[expect(dead_code)]
    pub(crate) async fn reach_node_outcome(
        &self,
        request: &dtos::VerifyForeignTransactionRequestV2,
    ) -> anyhow::Result<NodeOutcome> {
        let inspection = self
            .inspect_foreign_chain_request(&request.request, TransientErrors::Retry)
            .await?;
        Ok(NodeOutcome::new(inspection, &request.expected_values))
    }

    async fn inspect_foreign_chain_request(
        &self,
        request: &dtos::ForeignChainRpcRequest,
        transient_errors: TransientErrors,
    ) -> anyhow::Result<Inspection> {
        // Check that the requested chain is still available when this
        // point is reached.
        ensure_chain_is_available(&self.supporters_by_foreign_chain.borrow(), request.chain())
            .inspect_err(|_| {
                metrics::MPC_NUM_VERIFY_FOREIGN_TX_UNAVAILABLE_CHAIN_REJECTIONS.inc()
            })?;
        let quorum = self
            .rpc_quorum(request.chain())
            .inspect_err(|_| metrics::MPC_NUM_VERIFY_FOREIGN_TX_NO_RPC_QUORUM_REJECTIONS.inc())?;

        inspect_request(&self.inspectors, &quorum, request, transient_errors).await
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "requested chain {requested:?} is not in the list of available foreign chains on the MPC contract"
)]
struct ChainNotAvailableError {
    requested: dtos::ForeignChain,
}

#[derive(Debug, thiserror::Error)]
enum NoRpcQuorumError {
    #[error("{chain:?} is not configured on this node")]
    NotConfigured { chain: dtos::ForeignChain },
    #[error("{chain:?} is not whitelisted")]
    NotWhitelisted { chain: dtos::ForeignChain },
    #[error("this node cannot reach the RPC quorum for {chain:?}: {source}")]
    Unreachable {
        chain: dtos::ForeignChain,
        #[source]
        source: RpcQuorumError,
    },
}

/// A chain counts as available when the supporters map has an entry for it:
/// the chain is available on the contract and a signing quorum of current
/// participants supports it.
fn ensure_chain_is_available(
    supporters_by_foreign_chain: &SupportersByForeignChain,
    foreign_chain: dtos::ForeignChain,
) -> Result<(), ChainNotAvailableError> {
    if supporters_by_foreign_chain.contains_key(&foreign_chain) {
        Ok(())
    } else {
        Err(ChainNotAvailableError {
            requested: foreign_chain,
        })
    }
}

fn require_extracted<V>(verdict: Verdict<V>) -> anyhow::Result<Vec<V>> {
    verdict
        .into_extracted()
        .map_err(|failing| anyhow::anyhow!("the transaction failed verification: {failing}"))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::ParticipantId;
    use std::{
        assert_matches,
        collections::{BTreeMap, HashSet},
    };

    fn bitcoin_supporters() -> SupportersByForeignChain {
        BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            HashSet::from([ParticipantId::from_raw(1)]),
        )])
    }

    #[test]
    fn build_signature_request__should_reject_payload_not_matching_expected_hash() {
        // Given
        let request = verify_foreign_tx_request(Some(dtos::Hash256([1u8; 32])));
        let payload = bitcoin_payload();

        // When
        let result = build_signature_request(&request, &payload);

        // Then
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("does not match the request's expected payload hash"),
            "expected the payload hash mismatch error, got: {error}",
        );
    }

    #[test]
    fn build_signature_request__should_accept_any_payload_without_expected_hash() {
        // Given
        let request = verify_foreign_tx_request(None);

        // When
        let result = build_signature_request(&request, &bitcoin_payload());

        // Then
        result.unwrap();
    }

    #[test]
    fn ensure_chain_is_available__should_succeed_when_chain_has_supporters() {
        // Given
        let supporters = bitcoin_supporters();

        // When, then
        assert_matches!(
            ensure_chain_is_available(&supporters, bitcoin_request().chain()),
            Ok(_)
        );
    }

    #[test]
    fn ensure_chain_is_available__should_fail_when_chain_has_no_supporters() {
        // Given: the supporters map covers Bitcoin, but the request is for Ethereum.
        let supporters = bitcoin_supporters();
        let ethereum_request = dtos::ForeignChainRpcRequest::Ethereum(dtos::EvmRpcRequest {
            tx_id: dtos::EvmTxId([0; 32]),
            extractors: [].into(),
            finality: dtos::EvmFinality::Finalized,
        });

        // When, then
        assert_matches!(
            ensure_chain_is_available(&supporters, ethereum_request.chain()),
            Err(ChainNotAvailableError {
                requested: dtos::ForeignChain::Ethereum
            })
        );
    }

    fn bitcoin_request() -> dtos::ForeignChainRpcRequest {
        dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(6),
            extractors: [dtos::BitcoinExtractor::BlockHash].into(),
        })
    }

    fn bitcoin_payload() -> dtos::ForeignTxSignPayload {
        dtos::ForeignTxSignPayload::V1(dtos::ForeignTxSignPayloadV1 {
            request: bitcoin_request(),
            values: vec![dtos::ExtractedValue::BitcoinExtractedValue(
                dtos::BitcoinExtractedValue::BlockHash(dtos::Hash256([42u8; 32])),
            )],
        })
    }

    fn verify_foreign_tx_request(
        expected_payload_hash: Option<dtos::Hash256>,
    ) -> VerifyForeignTxRequest {
        VerifyForeignTxRequest {
            id: near_indexer_primitives::CryptoHash([1u8; 32]),
            receipt_id: near_indexer_primitives::CryptoHash([2u8; 32]),
            request: bitcoin_request(),
            payload_version: dtos::ForeignTxPayloadVersion::V1,
            expected_payload_hash,
            entropy: [0u8; 32],
            timestamp_nanosec: 0,
            domain_id: mpc_primitives::domain::DomainId(0),
        }
    }
}
