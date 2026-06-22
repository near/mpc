use anyhow::{Context, bail};
use foreign_chain_inspector::abstract_chain::inspector::AbstractExtractor;
use foreign_chain_inspector::aptos::inspector::{AptosExtractor, AptosFinality};
use foreign_chain_inspector::arbitrum::inspector::ArbitrumExtractor;
use foreign_chain_inspector::base::inspector::BaseExtractor;
use foreign_chain_inspector::bitcoin::inspector::BitcoinExtractor;
use foreign_chain_inspector::bnb::inspector::BnbExtractor;
use foreign_chain_inspector::hyperevm::inspector::HyperEvmExtractor;
use foreign_chain_inspector::polygon::inspector::PolygonExtractor;
use foreign_chain_inspector::starknet::inspector::{StarknetExtractor, StarknetFinality};
use foreign_chain_inspector::{EthereumFinality, ForeignChainInspector};
use threshold_signatures::{ecdsa::Signature, frost_secp256k1::VerifyingKey};
use tokio_util::time::FutureExt;

use crate::config::ParticipantsConfig;
use crate::indexer::ReadAvailableForeignChains;
use crate::metrics;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::VerifyForeignTxTaskId;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use crate::{
    network::NetworkTaskChannel, primitives::UniqueId,
    providers::verify_foreign_tx::VerifyForeignTxProvider, types::SignatureId,
};
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types as contract_dtos;
use near_mpc_contract_interface::types::{self as dtos, ECDSA_PAYLOAD_SIZE_BYTES};
use near_mpc_contract_interface::types::{Payload, Tweak};
use near_mpc_crypto_types::Ed25519PublicKey;
use tokio::time::{Duration, timeout};

const FOREIGN_CHAIN_INSPECTION_TIMEOUT: Duration = Duration::from_secs(5);

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
    ForeignChainPolicyReader: ReadAvailableForeignChains,
{
    pub(super) async fn make_verify_foreign_tx_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<((dtos::ForeignTxSignPayload, Signature), VerifyingKey)> {
        let foreign_tx_request = self.verify_foreign_tx_request_store.get(id).await?;

        let domain_data = self
            .ecdsa_signature_provider
            .domain_data(foreign_tx_request.domain_id)?;
        let foreign_chains_configs = self
            .foreign_chain_policy_reader
            .get_foreign_chains_configs()
            .await?;
        let requested_chain = foreign_tx_request.request.chain();

        let max_attempts = domain_data.presignature_store.num_owned().max(1);
        let mut incompatible = 0usize;

        let (presignature_id, presignature) = loop {
            let (id, ps) = domain_data.presignature_store.take_owned().await;
            if participants_support_chain(
                &ps.participants,
                self.ecdsa_signature_provider.participants_config(),
                &foreign_chains_configs,
                &requested_chain,
            ) {
                break (id, ps);
            }
            domain_data.presignature_store.add_owned(id, ps);
            incompatible += 1;
            if incompatible >= max_attempts {
                bail!(
                    "no presignature found whose participants all support chain \
                     {requested_chain:?} after scanning {incompatible} presignature(s)"
                );
            }
        };
        let participants = presignature.participants.clone();

        let channel = self.ecdsa_signature_provider.new_channel_for_task(
            VerifyForeignTxTaskId::VerifyForeignTx {
                id,
                presignature_id,
            },
            participants,
        )?;

        let response_payload = self
            .execute_foreign_chain_request(
                &foreign_tx_request.request,
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

        let response_payload = self
            .execute_foreign_chain_request(
                &foreign_tx_request.request,
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
        request: &dtos::ForeignChainRpcRequest,
        payload_version: dtos::ForeignTxPayloadVersion,
    ) -> anyhow::Result<dtos::ForeignTxSignPayload> {
        is_chain_available(&self.foreign_chain_policy_reader, request).await?;

        let values: Vec<dtos::ExtractedValue> = match request {
            dtos::ForeignChainRpcRequest::Ethereum(_request) => {
                bail!("ForeignChainRpcRequest::Ethereum is unsupported")
            }
            dtos::ForeignChainRpcRequest::Solana(_request) => {
                bail!("ForeignChainRpcRequest::Solana is unsupported")
            }
            dtos::ForeignChainRpcRequest::Bitcoin(request) => {
                let inspector = self
                    .inspectors
                    .bitcoin
                    .as_ref()
                    .context("no inspector configured for bitcoin")?;
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
                let inspector = self
                    .inspectors
                    .abstract_chain
                    .as_ref()
                    .context("no inspector configured for abstract")?;

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
            dtos::ForeignChainRpcRequest::Bnb(request) => {
                let inspector = self
                    .inspectors
                    .bnb
                    .as_ref()
                    .context("no inspector configured for BNB")?;

                let transaction_id = request.tx_id.0.into();
                let finality: EthereumFinality = request.finality.clone().try_into()?;
                let extractors: Vec<BnbExtractor> = request
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
            dtos::ForeignChainRpcRequest::Base(request) => {
                let inspector = self
                    .inspectors
                    .base
                    .as_ref()
                    .context("no inspector configured for Base")?;

                let transaction_id = request.tx_id.0.into();
                let finality: EthereumFinality = request.finality.clone().try_into()?;
                let extractors: Vec<BaseExtractor> = request
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
            dtos::ForeignChainRpcRequest::Arbitrum(request) => {
                let inspector = self
                    .inspectors
                    .arbitrum
                    .as_ref()
                    .context("no inspector configured for Arbitrum")?;

                let transaction_id = request.tx_id.0.into();
                let finality: EthereumFinality = request.finality.clone().try_into()?;
                let extractors: Vec<ArbitrumExtractor> = request
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
            dtos::ForeignChainRpcRequest::HyperEvm(request) => {
                let inspector = self
                    .inspectors
                    .hyper_evm
                    .as_ref()
                    .context("no inspector configured for HyperEVM")?;

                let transaction_id = request.tx_id.0.into();
                let finality: EthereumFinality = request.finality.clone().try_into()?;
                let extractors: Vec<HyperEvmExtractor> = request
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
            dtos::ForeignChainRpcRequest::Polygon(request) => {
                let inspector = self
                    .inspectors
                    .polygon
                    .as_ref()
                    .context("no inspector configured for Polygon")?;

                let transaction_id = request.tx_id.0.into();
                let finality: EthereumFinality = request.finality.clone().try_into()?;
                let extractors: Vec<PolygonExtractor> = request
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
                let inspector = self
                    .inspectors
                    .starknet
                    .as_ref()
                    .context("no inspector configured for Starknet")?;

                let transaction_id = request.tx_id.0.0.into();
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
            dtos::ForeignChainRpcRequest::Ton(_request) => {
                bail!("ForeignChainRpcRequest::Ton is unsupported")
            }
            dtos::ForeignChainRpcRequest::Aptos(request) => {
                let inspector = self
                    .inspectors
                    .aptos
                    .as_ref()
                    .context("no inspector configured for Aptos")?;

                let tx_id = request.tx_id.0.into();
                let finality: AptosFinality = request.finality.clone().try_into()?;
                let extractors: Vec<AptosExtractor> = request
                    .extractors
                    .iter()
                    .cloned()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?;

                let extracted_values = inspector
                    .extract(tx_id, finality, extractors)
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

#[derive(Debug, thiserror::Error)]
enum ForeignChainAvailabilityError {
    #[error("failed to fetch available chains from the contract")]
    FailedToReadContract(#[source] anyhow::Error),
    #[error(
        "requested chain {requested:?} is not in the list of available foreign chains on the MPC contract"
    )]
    ChainNotAvailable { requested: dtos::ForeignChain },
}

async fn is_chain_available(
    policy_reader: &impl ReadAvailableForeignChains,
    request: &dtos::ForeignChainRpcRequest,
) -> Result<(), ForeignChainAvailabilityError> {
    let available_chains = policy_reader
        .get_available_chains()
        .await
        .map_err(ForeignChainAvailabilityError::FailedToReadContract)?;

    let requested_chain = request.chain();

    if available_chains.contains(&requested_chain) {
        Ok(())
    } else {
        Err(ForeignChainAvailabilityError::ChainNotAvailable {
            requested: requested_chain,
        })
    }
}

fn participants_support_chain(
    participants: &[ParticipantId],
    participants_config: &ParticipantsConfig,
    foreign_chains_configs: &contract_dtos::ForeignChainsConfigs,
    chain: &contract_dtos::ForeignChain,
) -> bool {
    participants.iter().all(|participant_id| {
        let Some(info) = participants_config.get_info(*participant_id) else {
            return false;
        };
        let tls_key = Ed25519PublicKey::from(&info.p2p_public_key);
        foreign_chains_configs
            .get(&tls_key)
            .is_some_and(|config| config.contains(chain))
    })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::config::{ParticipantInfo, ParticipantsConfig};
    use crate::indexer::MockReadAvailableForeignChains;
    use assert_matches::assert_matches;
    use ed25519_dalek::SigningKey;
    use std::collections::{BTreeMap, BTreeSet};

    fn make_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn make_participant_info(id: u32, key: &SigningKey) -> ParticipantInfo {
        ParticipantInfo {
            id: ParticipantId::from_raw(id),
            address: "127.0.0.1".to_string(),
            port: 3000,
            p2p_public_key: key.verifying_key(),
            near_account_id: format!("node{id}.near").parse().unwrap(),
        }
    }

    fn tls_key_for(signing_key: &SigningKey) -> Ed25519PublicKey {
        Ed25519PublicKey::from(&signing_key.verifying_key())
    }

    fn bitcoin_chain_config() -> dtos::ForeignChainsConfig {
        BTreeSet::from([dtos::ForeignChain::Bitcoin]).into()
    }

    fn foreign_chains_configs_with(
        key: Ed25519PublicKey,
        config: dtos::ForeignChainsConfig,
    ) -> dtos::ForeignChainsConfigs {
        BTreeMap::from([(key, config)]).into()
    }

    fn bitcoin_request() -> dtos::ForeignChainRpcRequest {
        dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(6),
            extractors: vec![dtos::BitcoinExtractor::BlockHash],
        })
    }

    fn bitcoin_available_chains() -> dtos::AvailableForeignChains {
        BTreeSet::from([dtos::ForeignChain::Bitcoin]).into()
    }

    fn mock_policy_reader(
        available: dtos::AvailableForeignChains,
    ) -> MockReadAvailableForeignChains {
        let mut reader = MockReadAvailableForeignChains::new();
        reader
            .expect_get_available_chains()
            .returning(move || Box::pin(std::future::ready(Ok(available.clone()))));
        reader.expect_get_foreign_chains_configs().returning(|| {
            Box::pin(std::future::ready(
                Ok(dtos::ForeignChainsConfigs::default()),
            ))
        });
        reader
    }

    #[test]
    fn participants_support_chain__should_return_true_when_all_support_chain() {
        // Given
        let key = make_signing_key(1);
        let participants_config = ParticipantsConfig {
            threshold: 1,
            participants: vec![make_participant_info(1, &key)],
        };
        let configs = foreign_chains_configs_with(tls_key_for(&key), bitcoin_chain_config());

        // when, then:
        assert!(participants_support_chain(
            &[ParticipantId::from_raw(1)],
            &participants_config,
            &configs,
            &dtos::ForeignChain::Bitcoin,
        ));
    }

    #[test]
    fn participants_support_chain__should_return_false_when_participant_has_no_config_entry() {
        // Given
        let key = make_signing_key(1);
        let participants_config = ParticipantsConfig {
            threshold: 1,
            participants: vec![make_participant_info(1, &key)],
        };
        // No entry in configs for this participant's TLS key.
        let configs = dtos::ForeignChainsConfigs::default();

        // when, then:
        assert!(!participants_support_chain(
            &[ParticipantId::from_raw(1)],
            &participants_config,
            &configs,
            &dtos::ForeignChain::Bitcoin,
        ));
    }

    #[test]
    fn participants_support_chain__should_return_false_when_chain_not_in_participant_config() {
        // Given
        let key = make_signing_key(1);
        let participants_config = ParticipantsConfig {
            threshold: 1,
            participants: vec![make_participant_info(1, &key)],
        };
        // Participant is registered but only for Bitcoin, not Ethereum.
        let configs = foreign_chains_configs_with(tls_key_for(&key), bitcoin_chain_config());

        // when, then:
        assert!(!participants_support_chain(
            &[ParticipantId::from_raw(1)],
            &participants_config,
            &configs,
            &dtos::ForeignChain::Ethereum,
        ));
    }

    #[test]
    fn participants_support_chain__should_return_false_when_participant_id_not_in_config() {
        // Given
        let key = make_signing_key(1);
        let participants_config = ParticipantsConfig {
            threshold: 1,
            participants: vec![make_participant_info(1, &key)],
        };
        // Participant ID 99 has no entry in participants_config.
        let configs = foreign_chains_configs_with(tls_key_for(&key), bitcoin_chain_config());

        // when, then:
        assert!(!participants_support_chain(
            &[ParticipantId::from_raw(99)],
            &participants_config,
            &configs,
            &dtos::ForeignChain::Bitcoin,
        ));
    }

    // ── is_chain_available ────────────────────────────────────────────────────

    #[tokio::test]
    async fn is_chain_available__should_succeed_when_chain_is_present() {
        // Given
        let reader = mock_policy_reader(bitcoin_available_chains());

        // when, then:
        assert_matches!(is_chain_available(&reader, &bitcoin_request()).await, Ok(_));
    }

    #[tokio::test]
    async fn is_chain_available__should_fail_when_chain_is_not_present() {
        // Given
        // Available set has Bitcoin, but request is for Ethereum.
        let reader = mock_policy_reader(bitcoin_available_chains());
        let ethereum_request = dtos::ForeignChainRpcRequest::Ethereum(dtos::EvmRpcRequest {
            tx_id: dtos::EvmTxId([0; 32]),
            extractors: vec![],
            finality: dtos::EvmFinality::Finalized,
        });

        // when, then:
        assert_matches!(
            is_chain_available(&reader, &ethereum_request).await,
            Err(ForeignChainAvailabilityError::ChainNotAvailable {
                requested: dtos::ForeignChain::Ethereum
            })
        );
    }
}
