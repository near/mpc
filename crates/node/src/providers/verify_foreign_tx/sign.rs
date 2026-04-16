use anyhow::{bail, Context};
use foreign_chain_inspector::abstract_chain::inspector::Abstract;
use foreign_chain_inspector::bitcoin::inspector::{BitcoinExtractor, BitcoinInspector};
use foreign_chain_inspector::bnb::inspector::Bnb;
use foreign_chain_inspector::evm::inspector::{EvmChain, EvmExtractedValue, EvmExtractor, EvmInspector};
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::starknet::inspector::{
    StarknetExtractor, StarknetFinality, StarknetInspector,
};
use foreign_chain_inspector::{EthereumFinality, ForeignChainInspector};
use rand::seq::SliceRandom;
use rand::SeedableRng;
use threshold_signatures::{ecdsa::Signature, frost_secp256k1::VerifyingKey};
use tokio_util::time::FutureExt;

use crate::indexer::ReadForeignChainPolicy;
use crate::metrics;
use crate::providers::verify_foreign_tx::VerifyForeignTxTaskId;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use crate::{
    network::NetworkTaskChannel, primitives::UniqueId,
    providers::verify_foreign_tx::VerifyForeignTxProvider, types::SignatureId,
};
use mpc_contract::primitives::signature::{Payload, Tweak};
use mpc_node_config::ForeignChainsConfig;
use near_indexer_primitives::CryptoHash;
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types::{self as dtos, ECDSA_PAYLOAD_SIZE_BYTES};
use tokio::time::{timeout, Duration};

const FOREIGN_CHAIN_INSPECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Selects a pre-built HTTP client for a chain using the same deterministic
/// provider-selection logic. Returns an error when the chain is not configured.
fn select_client(
    clients: &[HttpClient],
    request_id: &CryptoHash,
    my_participant_index: usize,
    chain_name: &str,
) -> anyhow::Result<HttpClient> {
    let index = select_provider(clients.len(), request_id, my_participant_index)
        .with_context(|| format!("{chain_name} provider config is missing"))?;
    Ok(clients[index].clone())
}

/// Runs extraction on any [`ForeignChainInspector`] with a uniform timeout.
async fn run_inspection<I: ForeignChainInspector>(
    inspector: &I,
    tx_id: I::TransactionId,
    finality: I::Finality,
    extractors: Vec<I::Extractor>,
) -> anyhow::Result<Vec<I::ExtractedValue>> {
    inspector
        .extract(tx_id, finality, extractors)
        .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
        .await
        .context("timed out during execution of foreign chain request")?
        .map_err(Into::into)
}

/// Handles inspection for any EVM-compatible chain (Abstract, BNB, Base, …).
async fn inspect_evm_chain<Chain: EvmChain + Send>(
    client: HttpClient,
    request: &dtos::EvmRpcRequest,
) -> anyhow::Result<Vec<dtos::ExtractedValue>>
where
    EvmExtractedValue<Chain>: Into<dtos::ExtractedValue>,
{
    let inspector = EvmInspector::<HttpClient, Chain>::new(client);
    let tx_id: Chain::TransactionHash = request.tx_id.0.into();
    let finality: EthereumFinality = request.finality.clone().try_into()?;
    let extractors: Vec<EvmExtractor> = request
        .extractors
        .iter()
        .cloned()
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()?;

    let values = run_inspection(&inspector, tx_id, finality, extractors).await?;
    Ok(values.into_iter().map(Into::into).collect())
}

fn build_signature_request(
    request: &VerifyForeignTxRequest,
    foreign_tx_payload: &dtos::ForeignTxSignPayload,
) -> anyhow::Result<SignatureRequest> {
    let payload_hash: [u8; ECDSA_PAYLOAD_SIZE_BYTES] =
        foreign_tx_payload.compute_msg_hash()?.into();
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

impl<ForeignChainPolicyReader> VerifyForeignTxProvider<ForeignChainPolicyReader>
where
    ForeignChainPolicyReader: ReadForeignChainPolicy,
{
    pub(super) async fn make_verify_foreign_tx_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<((dtos::ForeignTxSignPayload, Signature), VerifyingKey)> {
        let foreign_tx_request = self.verify_foreign_tx_request_store.get(id).await?;

        let domain_data = self
            .ecdsa_signature_provider
            .domain_data(foreign_tx_request.domain_id.into())?;
        let (presignature_id, presignature) = domain_data.presignature_store.take_owned().await;
        let participants = presignature.participants.clone();
        let channel = self.ecdsa_signature_provider.new_channel_for_task(
            VerifyForeignTxTaskId::VerifyForeignTx {
                id,
                presignature_id,
            },
            participants,
        )?;

        let my_participant_index = channel
            .participants()
            .iter()
            .position(|&p| p == channel.my_participant_id())
            .context("my participant ID not found in participants list")?;

        let response_payload = self
            .execute_foreign_chain_request(
                id,
                &foreign_tx_request.request,
                my_participant_index,
                foreign_tx_request.payload_version,
            )
            .await?;

        let sign_request = build_signature_request(&foreign_tx_request, &response_payload)?;

        let response = self
            .ecdsa_signature_provider
            .make_signature_leader_given_parameters(sign_request, presignature, channel)
            .await?;
        Ok(((response_payload, response.0), response.1))
    }

    pub(super) async fn make_verify_foreign_tx_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
        presignature_id: UniqueId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let foreign_tx_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.verify_foreign_tx_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let participants = channel.participants();
        let my_participant_id = channel.my_participant_id();
        let my_participant_index = participants
            .iter()
            .position(|&p| p == my_participant_id)
            .context("my participant ID not found in participants list")?;

        let response_payload = self
            .execute_foreign_chain_request(
                id,
                &foreign_tx_request.request,
                my_participant_index,
                foreign_tx_request.payload_version,
            )
            .await?;

        let sign_request = build_signature_request(&foreign_tx_request, &response_payload)?;

        self.ecdsa_signature_provider
            .make_signature_follower_given_request(channel, presignature_id, sign_request)
            .await
    }

    async fn execute_foreign_chain_request(
        &self,
        request_id: SignatureId,
        request: &dtos::ForeignChainRpcRequest,
        my_participant_index: usize,
        payload_version: dtos::ForeignTxPayloadVersion,
    ) -> anyhow::Result<dtos::ForeignTxSignPayload> {
        validate_foreign_chain_policy(
            &self.config.foreign_chains,
            &self.foreign_chain_policy_reader,
            request,
        )
        .await?;

        let values: Vec<dtos::ExtractedValue> = match request {
            dtos::ForeignChainRpcRequest::Ethereum(_) => {
                bail!("ForeignChainRpcRequest::Ethereum is unsupported")
            }
            dtos::ForeignChainRpcRequest::Solana(_) => {
                bail!("ForeignChainRpcRequest::Solana is unsupported")
            }
            dtos::ForeignChainRpcRequest::Bitcoin(request) => {
                let client = select_client(
                    &self.clients.bitcoin,
                    &request_id,
                    my_participant_index,
                    "bitcoin",
                )?;
                let inspector = BitcoinInspector::new(client);
                let tx_id = request.tx_id.0.into();
                let confirmations = request.confirmations.0.into();
                let extractors: Vec<BitcoinExtractor> = request
                    .extractors
                    .iter()
                    .cloned()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?;
                let values = run_inspection(&inspector, tx_id, confirmations, extractors).await?;
                values.into_iter().map(Into::into).collect()
            }
            dtos::ForeignChainRpcRequest::Abstract(request) => {
                let client = select_client(
                    &self.clients.abstract_chain,
                    &request_id,
                    my_participant_index,
                    "abstract",
                )?;
                inspect_evm_chain::<Abstract>(client, request).await?
            }
            dtos::ForeignChainRpcRequest::Bnb(request) => {
                let client = select_client(
                    &self.clients.bnb,
                    &request_id,
                    my_participant_index,
                    "bnb",
                )?;
                inspect_evm_chain::<Bnb>(client, request).await?
            }
            dtos::ForeignChainRpcRequest::Starknet(request) => {
                let client = select_client(
                    &self.clients.starknet,
                    &request_id,
                    my_participant_index,
                    "starknet",
                )?;
                let inspector = StarknetInspector::new(client);
                let tx_id = request.tx_id.0 .0.into();
                let finality: StarknetFinality = request.finality.clone().try_into()?;
                let extractors: Vec<StarknetExtractor> = request
                    .extractors
                    .iter()
                    .cloned()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?;
                let values = run_inspection(&inspector, tx_id, finality, extractors).await?;
                values.into_iter().map(Into::into).collect()
            }
            _ => bail!("unsupported foreign chain request"),
        };
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
}

#[derive(Debug, thiserror::Error)]
enum ValidateForeignChainPolicyError {
    #[error("local foreign_chains config is empty; cannot process foreign chain request")]
    LocalConfigEmpty,
    #[error("failed to fetch on-chain foreign chain policy")]
    FetchOnChainPolicy(#[source] anyhow::Error),
    #[error(
        "local foreign chain policy does not match on-chain policy: local={local:?}, on_chain={on_chain:?}"
    )]
    PolicyMismatch {
        local: dtos::ForeignChainPolicy,
        on_chain: dtos::ForeignChainPolicy,
    },
    #[error("requested chain {requested:?} is not present in the on-chain foreign chain policy")]
    ChainNotInPolicy { requested: dtos::ForeignChain },
}

async fn validate_foreign_chain_policy(
    foreign_chains_config: &ForeignChainsConfig,
    policy_reader: &impl ReadForeignChainPolicy,
    request: &dtos::ForeignChainRpcRequest,
) -> Result<(), ValidateForeignChainPolicyError> {
    let local_policy = foreign_chains_config
        .to_policy()
        .ok_or(ValidateForeignChainPolicyError::LocalConfigEmpty)?;

    let on_chain_policy = policy_reader
        .get_foreign_chain_policy()
        .await
        .map_err(ValidateForeignChainPolicyError::FetchOnChainPolicy)?;

    if on_chain_policy != local_policy {
        return Err(ValidateForeignChainPolicyError::PolicyMismatch {
            local: local_policy,
            on_chain: on_chain_policy,
        });
    }

    let requested_chain = request.chain();
    if !on_chain_policy
        .chains
        .iter()
        .any(|(chain, _)| *chain == requested_chain)
    {
        return Err(ValidateForeignChainPolicyError::ChainNotInPolicy {
            requested: requested_chain,
        });
    }

    Ok(())
}

/// Deterministically selects a provider index based on the request ID and the node's
/// position within the participant set.
///
/// Uses the request ID as a seed to create a deterministic permutation of provider indices,
/// then selects the index at position `my_participant_index % num_providers`. This ensures
/// that RPC selection is balanced.
fn select_provider(
    num_providers: usize,
    request_id: &CryptoHash,
    my_participant_index: usize,
) -> Option<usize> {
    if num_providers == 0 {
        return None;
    }
    let mut indices: Vec<usize> = (0..num_providers).collect();
    let mut rng = rand::rngs::StdRng::from_seed(request_id.0);
    indices.shuffle(&mut rng);
    Some(indices[my_participant_index % num_providers])
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::indexer::MockReadForeignChainPolicy;
    use assert_matches::assert_matches;
    use mpc_node_config::{
        BitcoinApiVariant, BitcoinChainConfig, BitcoinProviderConfig, ForeignChainsConfig,
    };
    use near_mpc_bounded_collections::NonEmptyBTreeSet;
    use std::collections::BTreeMap;

    fn bitcoin_request() -> dtos::ForeignChainRpcRequest {
        dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(6),
            extractors: vec![dtos::BitcoinExtractor::BlockHash],
        })
    }

    fn bitcoin_foreign_chains_config() -> ForeignChainsConfig {
        let providers = near_mpc_bounded_collections::NonEmptyBTreeMap::new(
            "public".to_string(),
            BitcoinProviderConfig {
                rpc_url: "https://blockstream.info/api".to_string(),
                api_variant: BitcoinApiVariant::Esplora,
                auth: Default::default(),
            },
        );
        ForeignChainsConfig {
            bitcoin: Some(BitcoinChainConfig {
                timeout_sec: 30,
                max_retries: 3,
                providers,
            }),
            ..Default::default()
        }
    }

    fn bitcoin_chain_policy() -> dtos::ForeignChainPolicy {
        dtos::ForeignChainPolicy {
            chains: BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://blockstream.info/api".to_string(),
                }),
            )]),
        }
    }

    fn mock_policy_reader(policy: dtos::ForeignChainPolicy) -> MockReadForeignChainPolicy {
        let mut reader = MockReadForeignChainPolicy::new();
        reader
            .expect_get_foreign_chain_policy()
            .returning(move || Box::pin(std::future::ready(Ok(policy.clone()))));
        reader
    }

    #[test]
    fn select_provider__returns_none_for_zero_providers() {
        let request_id = CryptoHash([0; 32]);
        assert_eq!(select_provider(0, &request_id, 0), None);
    }

    #[test]
    fn select_provider__returns_some_for_single_provider() {
        let request_id = CryptoHash([1; 32]);
        assert_eq!(select_provider(1, &request_id, 0), Some(0));
        assert_eq!(select_provider(1, &request_id, 1), Some(0));
        assert_eq!(select_provider(1, &request_id, 5), Some(0));
    }

    #[test]
    fn select_provider__is_deterministic_for_same_inputs() {
        let request_id = CryptoHash([42; 32]);
        let result1 = select_provider(3, &request_id, 1);
        let result2 = select_provider(3, &request_id, 1);
        assert_eq!(result1, result2);
    }

    #[test]
    fn select_provider__different_participants_get_different_providers_when_enough_providers() {
        let request_id = CryptoHash([7; 32]);
        let num_providers = 3;
        let selections: Vec<usize> = (0..num_providers)
            .map(|i| select_provider(num_providers, &request_id, i).unwrap())
            .collect();
        // With 3 participants and 3 providers, each should get a unique provider
        let mut sorted = selections.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), num_providers);
    }

    #[test]
    fn select_provider__different_requests_produce_different_permutations() {
        let request_a = CryptoHash([1; 32]);
        let request_b = CryptoHash([2; 32]);
        let num_providers = 5;
        let selections_a: Vec<usize> = (0..num_providers)
            .map(|i| select_provider(num_providers, &request_a, i).unwrap())
            .collect();
        let selections_b: Vec<usize> = (0..num_providers)
            .map(|i| select_provider(num_providers, &request_b, i).unwrap())
            .collect();
        // Different request IDs should (almost certainly) produce different permutations
        assert_ne!(selections_a, selections_b);
    }

    #[test]
    fn select_provider__wraps_around_when_more_participants_than_providers() {
        let request_id = CryptoHash([99; 32]);
        let num_providers = 3;
        // Participant indices beyond num_providers should wrap around
        for i in 0..num_providers {
            assert_eq!(
                select_provider(num_providers, &request_id, i),
                select_provider(num_providers, &request_id, i + num_providers),
            );
        }
    }

    #[tokio::test]
    async fn validate_foreign_chain_policy__should_succeed_when_policies_match_and_chain_present() {
        let config = bitcoin_foreign_chains_config();
        let reader = mock_policy_reader(bitcoin_chain_policy());

        validate_foreign_chain_policy(&config, &reader, &bitcoin_request())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_foreign_chain_policy__should_fail_when_chain_not_in_policy() {
        let config = bitcoin_foreign_chains_config();
        // On-chain policy has Bitcoin, but request is for Ethereum
        let reader = mock_policy_reader(bitcoin_chain_policy());
        let ethereum_request = dtos::ForeignChainRpcRequest::Ethereum(dtos::EvmRpcRequest {
            tx_id: dtos::EvmTxId([0; 32]),
            extractors: vec![],
            finality: dtos::EvmFinality::Finalized,
        });

        // Policies match (both bitcoin-only), but request is for Ethereum.
        // The policy match check passes, but the chain-in-policy check fails.
        let result = validate_foreign_chain_policy(&config, &reader, &ethereum_request).await;
        assert_matches!(
            result,
            Err(ValidateForeignChainPolicyError::ChainNotInPolicy { .. })
        );
    }

    #[tokio::test]
    async fn validate_foreign_chain_policy__should_fail_when_policies_mismatch() {
        let config = bitcoin_foreign_chains_config();
        // On-chain policy differs (different RPC URL)
        let reader = mock_policy_reader(dtos::ForeignChainPolicy {
            chains: BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                NonEmptyBTreeSet::new(dtos::RpcProvider {
                    rpc_url: "https://different-provider.example.com/api".to_string(),
                }),
            )]),
        });

        let result = validate_foreign_chain_policy(&config, &reader, &bitcoin_request()).await;
        assert_matches!(
            result,
            Err(ValidateForeignChainPolicyError::PolicyMismatch { .. })
        );
    }

    #[tokio::test]
    async fn validate_foreign_chain_policy__should_fail_when_local_config_empty() {
        let config = ForeignChainsConfig::default();
        let reader = mock_policy_reader(bitcoin_chain_policy());

        let result = validate_foreign_chain_policy(&config, &reader, &bitcoin_request()).await;
        assert_matches!(
            result,
            Err(ValidateForeignChainPolicyError::LocalConfigEmpty)
        );
    }
}
