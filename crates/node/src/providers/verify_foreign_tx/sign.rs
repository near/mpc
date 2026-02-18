use anyhow::{bail, Context};
use foreign_chain_inspector::abstract_chain::inspector::{AbstractExtractor, AbstractInspector};
use foreign_chain_inspector::bitcoin::inspector::{BitcoinExtractor, BitcoinInspector};
use foreign_chain_inspector::starknet::inspector::{
    StarknetExtractor, StarknetFinality, StarknetInspector,
};
use foreign_chain_inspector::ForeignChainInspector;
use foreign_chain_inspector::{self, EthereumFinality};
use rand::rngs::OsRng;
use threshold_signatures::{ecdsa::Signature, frost_secp256k1::VerifyingKey};
use tokio_util::time::FutureExt;

use crate::config::ForeignChainsConfig;
use crate::indexer::ReadForeignChainPolicy;
use crate::metrics;
use crate::providers::verify_foreign_tx::VerifyForeignTxTaskId;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use crate::{
    network::NetworkTaskChannel, primitives::UniqueId,
    providers::verify_foreign_tx::VerifyForeignTxProvider, types::SignatureId,
};
use contract_interface::types as dtos;
use mpc_contract::primitives::signature::{Bytes, Payload, Tweak};
use rand::seq::IteratorRandom;
use tokio::time::{timeout, Duration};

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
        tweak: Tweak::new(request.tweak.0),
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

        let response_payload = self
            .execute_foreign_chain_request(&foreign_tx_request.request)
            .await?;

        let sign_request = build_signature_request(&foreign_tx_request, &response_payload)?;

        let domain_data = self
            .ecdsa_signature_provider
            .domain_data(sign_request.domain)?;
        let (presignature_id, presignature) = domain_data.presignature_store.take_owned().await;
        let participants = presignature.participants.clone();
        let channel = self.ecdsa_signature_provider.new_channel_for_task(
            VerifyForeignTxTaskId::VerifyForeignTx {
                id,
                presignature_id,
            },
            participants,
        )?;

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

        let response_payload = self
            .execute_foreign_chain_request(&foreign_tx_request.request)
            .await?;

        let sign_request = build_signature_request(&foreign_tx_request, &response_payload)?;

        self.ecdsa_signature_provider
            .make_signature_follower_given_request(channel, presignature_id, sign_request)
            .await
    }

    async fn execute_foreign_chain_request(
        &self,
        request: &dtos::ForeignChainRpcRequest,
    ) -> anyhow::Result<dtos::ForeignTxSignPayload> {
        validate_foreign_chain_policy(
            &self.config.foreign_chains,
            &self.foreign_chain_policy_reader,
            request,
        )
        .await?;

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

                // TODO: implement a better algorithm here that guarantees that different nodes get different providers
                let bitcoin_provider_config = bitcoin_config.providers.values().choose(&mut OsRng);

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
                // TODO(#2088): implement a better algorithm here that guarantees that different nodes get different providers
                let abstract_provider_config =
                    abstract_config.providers.values().choose(&mut OsRng);

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

                let starknet_provider_config =
                    starknet_config.providers.values().choose(&mut OsRng);

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
        Ok(dtos::ForeignTxSignPayload::V1(
            dtos::ForeignTxSignPayloadV1 {
                request: request.clone(),
                values,
            },
        ))
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

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use crate::config::{
        BitcoinApiVariant, BitcoinChainConfig, BitcoinProviderConfig, ForeignChainsConfig,
    };
    use crate::indexer::MockReadForeignChainPolicy;
    use assert_matches::assert_matches;
    use non_empty_collections::NonEmptyBTreeSet;
    use std::collections::BTreeMap;

    fn bitcoin_request() -> dtos::ForeignChainRpcRequest {
        dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(6),
            extractors: vec![dtos::BitcoinExtractor::BlockHash],
        })
    }

    fn bitcoin_foreign_chains_config() -> ForeignChainsConfig {
        let providers = non_empty_collections::NonEmptyBTreeMap::new(
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
