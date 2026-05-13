use anyhow::{bail, Context};
use foreign_chain_inspector::abstract_chain::inspector::AbstractExtractor;
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

use crate::indexer::ReadSupportedForeignChain;
use crate::metrics;
use crate::providers::verify_foreign_tx::VerifyForeignTxTaskId;
use crate::types::{SignatureRequest, VerifyForeignTxRequest};
use crate::{
    network::NetworkTaskChannel, primitives::UniqueId,
    providers::verify_foreign_tx::VerifyForeignTxProvider, types::SignatureId,
};
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types::{self as dtos, ECDSA_PAYLOAD_SIZE_BYTES};
use near_mpc_contract_interface::types::{Payload, Tweak};
use tokio::time::{timeout, Duration};

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
    ForeignChainPolicyReader: ReadSupportedForeignChain,
{
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
        chain_is_supported(&self.foreign_chain_policy_reader, request).await?;

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

#[derive(Debug, thiserror::Error)]
enum ForeignChainSupportError {
    #[error("failed to fetch supported chains on the contract")]
    FailedToReadContract(#[source] anyhow::Error),
    #[error(
        "requested chain {requested:?} is not present in the list of supported foreign chains on the MPC contract"
    )]
    ChainNotSupported { requested: dtos::ForeignChain },
}

async fn chain_is_supported(
    policy_reader: &impl ReadSupportedForeignChain,
    request: &dtos::ForeignChainRpcRequest,
) -> Result<(), ForeignChainSupportError> {
    let on_chain_foreign_chains_support = policy_reader
        .get_supported_chains()
        .await
        .map_err(ForeignChainSupportError::FailedToReadContract)?;

    let requested_chain = request.chain();

    if on_chain_foreign_chains_support.contains(&requested_chain) {
        Ok(())
    } else {
        Err(ForeignChainSupportError::ChainNotSupported {
            requested: requested_chain,
        })
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::indexer::MockReadSupportedForeignChain;
    use assert_matches::assert_matches;
    use std::collections::BTreeSet;

    fn bitcoin_request() -> dtos::ForeignChainRpcRequest {
        dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(6),
            extractors: vec![dtos::BitcoinExtractor::BlockHash],
        })
    }

    fn bitcoin_chain_policy() -> dtos::SupportedForeignChains {
        BTreeSet::from([dtos::ForeignChain::Bitcoin]).into()
    }

    fn mock_policy_reader(policy: dtos::SupportedForeignChains) -> MockReadSupportedForeignChain {
        let mut reader = MockReadSupportedForeignChain::new();
        reader
            .expect_get_supported_chains()
            .returning(move || Box::pin(std::future::ready(Ok(policy.clone()))));
        reader
    }

    #[tokio::test]
    async fn chain_is_supported__should_succeed_when_chain_is_present_in_policy() {
        let reader = mock_policy_reader(bitcoin_chain_policy());

        assert_matches!(chain_is_supported(&reader, &bitcoin_request()).await, Ok(_));
    }

    #[tokio::test]
    async fn chain_is_supported__should_fail_when_chain_is_not_present_in_policy() {
        // On-chain policy has Bitcoin, but request is for Ethereum
        let reader = mock_policy_reader(bitcoin_chain_policy());
        let ethereum_request = dtos::ForeignChainRpcRequest::Ethereum(dtos::EvmRpcRequest {
            tx_id: dtos::EvmTxId([0; 32]),
            extractors: vec![],
            finality: dtos::EvmFinality::Finalized,
        });

        let result = chain_is_supported(&reader, &ethereum_request).await;
        assert_matches!(
            result,
            Err(ForeignChainSupportError::ChainNotSupported {
                requested: dtos::ForeignChain::Ethereum
            })
        );
    }
}
