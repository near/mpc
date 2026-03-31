use crate::metrics;
use crate::providers::verify_foreign_tx::VerifyForeignTxTaskId;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use crate::{
    network::NetworkTaskChannel, primitives::UniqueId,
    providers::verify_foreign_tx::VerifyForeignTxProvider, types::SignatureId,
};
use anyhow::{bail, Context};
use foreign_chain_inspector::abstract_chain::inspector::{AbstractExtractor, AbstractInspector};
use foreign_chain_inspector::bitcoin::inspector::{BitcoinExtractor, BitcoinInspector};
use foreign_chain_inspector::starknet::inspector::{
    StarknetExtractor, StarknetFinality, StarknetInspector,
};
use foreign_chain_inspector::ForeignChainInspector;
use foreign_chain_inspector::{self, EthereumFinality};
use mpc_contract::primitives::signature::{Bytes, Payload, Tweak};
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::types as dtos;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use threshold_signatures::{ecdsa::Signature, frost_secp256k1::VerifyingKey};
use tokio::time::{timeout, Duration};
use tokio_util::time::FutureExt;

const FOREIGN_CHAIN_INSPECTION_TIMEOUT: Duration = Duration::from_secs(5);

fn build_signature_request(
    request: &VerifyForeignTxRequest,
    foreign_tx_payload: &dtos::ForeignTxSignPayload,
) -> anyhow::Result<SignatureRequest> {
    let payload_hash: [u8; 32] = foreign_tx_payload.compute_msg_hash()?.into();
    let payload_bytes =
        Bytes::new(payload_hash.to_vec()).map_err(|err| anyhow::format_err!("{err}"))?;
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

impl VerifyForeignTxProvider {
    pub(super) async fn make_verify_foreign_tx_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<((dtos::ForeignTxSignPayload, Signature), VerifyingKey)> {
        let foreign_tx_request = self.verify_foreign_tx_request_store.get(id).await?;

        let domain_data = self
            .ecdsa_signature_provider
            .domain_data(foreign_tx_request.domain_id)?;
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
        let values: Vec<dtos::ExtractedValue> = match request {
            dtos::ForeignChainRpcRequest::Ethereum(_request) => {
                bail!("ForeignChainRpcRequest::Ethereum is unsupported")
            }
            dtos::ForeignChainRpcRequest::Solana(_request) => {
                bail!("ForeignChainRpcRequest::Solana is unsupported")
            }
            dtos::ForeignChainRpcRequest::Bitcoin(request) => {
                let Some(bitcoin_config) = &self.config.foreign_chains.bitcoin else {
                    anyhow::bail!("bitcoin provider config is missing")
                };

                let provider_index = select_provider(
                    bitcoin_config.providers.len(),
                    &request_id,
                    my_participant_index,
                );

                let bitcoin_provider_config =
                    provider_index.and_then(|i| bitcoin_config.providers.values().nth(i));

                let Some(bitcoin_provider_config) = bitcoin_provider_config else {
                    anyhow::bail!("found empty list of providers for bitcoin")
                };

                let public_node_url = bitcoin_provider_config.rpc_url.clone();

                let http_client = foreign_chain_inspector::build_http_client(
                    public_node_url,
                    bitcoin_provider_config.auth.clone().try_into()?,
                )?;
                let inspector = BitcoinInspector::new(http_client);

                let transaction_id = request.tx_id.0.into();
                let block_confirmations = request.confirmations.0.into();
                let extractors: Vec<BitcoinExtractor> = request
                    .extractors
                    .iter()
                    .cloned()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?;

                let extracted_values = inspector
                    .extract(transaction_id, block_confirmations, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??;

                extracted_values.into_iter().map(Into::into).collect()
            }
            dtos::ForeignChainRpcRequest::Abstract(request) => {
                let Some(abstract_config) = &self.config.foreign_chains.abstract_chain else {
                    anyhow::bail!("abstract provider config is missing")
                };

                let provider_index = select_provider(
                    abstract_config.providers.len(),
                    &request_id,
                    my_participant_index,
                );

                let abstract_provider_config =
                    provider_index.and_then(|i| abstract_config.providers.values().nth(i));

                let Some(abstract_provider_config) = abstract_provider_config else {
                    anyhow::bail!("found empty list of providers for abstract")
                };

                let public_node_url = abstract_provider_config.rpc_url.clone();

                let http_client = foreign_chain_inspector::build_http_client(
                    public_node_url,
                    abstract_provider_config.auth.clone().try_into()?,
                )?;
                let inspector = AbstractInspector::new(http_client);

                let transaction_id = request.tx_id.0.into();
                let finality: EthereumFinality = request.finality.clone().try_into()?;
                let extractors: Vec<AbstractExtractor> = request
                    .extractors
                    .iter()
                    .cloned()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?;

                let values = inspector
                    .extract(transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??;

                values.into_iter().map(Into::into).collect()
            }
            dtos::ForeignChainRpcRequest::Starknet(request) => {
                let Some(starknet_config) = &self.config.foreign_chains.starknet else {
                    anyhow::bail!("starknet provider config is missing")
                };

                let provider_index = select_provider(
                    starknet_config.providers.len(),
                    &request_id,
                    my_participant_index,
                );

                let starknet_provider_config =
                    provider_index.and_then(|i| starknet_config.providers.values().nth(i));

                let Some(starknet_provider_config) = starknet_provider_config else {
                    anyhow::bail!("found empty list of providers for starknet")
                };

                let rpc_url = starknet_provider_config.rpc_url.clone();

                let http_client = foreign_chain_inspector::build_http_client(
                    rpc_url,
                    starknet_provider_config.auth.clone().try_into()?,
                )?;
                let inspector = StarknetInspector::new(http_client);

                let transaction_id = request.tx_id.0 .0.into();
                let finality: StarknetFinality = request.finality.clone().try_into()?;
                let extractors: Vec<StarknetExtractor> = request
                    .extractors
                    .iter()
                    .cloned()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?;

                let extracted_values = inspector
                    .extract(transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??;

                extracted_values.into_iter().map(Into::into).collect()
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
    use crate::config::{
        BitcoinApiVariant, BitcoinChainConfig, BitcoinProviderConfig, ForeignChainsConfig,
    };
    use crate::indexer::MockReadForeignChainPolicy;
    use assert_matches::assert_matches;
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
}
