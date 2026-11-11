use anyhow::{Context, bail};
use foreign_chain_inspector::abstract_chain::inspector::AbstractExtractor;
use foreign_chain_inspector::adi::inspector::AdiExtractor;
use foreign_chain_inspector::aptos::inspector::{AptosExtractor, AptosFinality};
use foreign_chain_inspector::arbitrum::inspector::ArbitrumExtractor;
use foreign_chain_inspector::avalanche::inspector::AvalancheExtractor;
use foreign_chain_inspector::base::inspector::BaseExtractor;
use foreign_chain_inspector::bitcoin::inspector::BitcoinExtractor;
use foreign_chain_inspector::bnb::inspector::BnbExtractor;
use foreign_chain_inspector::ethereum::inspector::EthereumExtractor;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvmExtractor;
use foreign_chain_inspector::polygon::inspector::PolygonExtractor;
use foreign_chain_inspector::starknet::inspector::{StarknetExtractor, StarknetFinality};
use foreign_chain_inspector::sui::inspector::{SuiExtractor, SuiFinality};
use foreign_chain_inspector::svm::inspector::{SvmChain, SvmExtractor, SvmFinality, SvmInspector};
use foreign_chain_inspector::{EthereumFinality, RpcQuorum};
use near_mpc_contract_interface::types as dtos;
use tokio_util::time::FutureExt;

use crate::providers::verify_foreign_tx::sign::require_extracted;
use crate::providers::verify_foreign_tx::{
    FOREIGN_CHAIN_INSPECTION_TIMEOUT, ForeignChainInspectors, MeasuredFanOut,
};

pub(crate) async fn inspect_request(
    inspectors: &ForeignChainInspectors<HttpClient>,
    quorum: &RpcQuorum,
    request: &dtos::ForeignChainRpcRequest,
) -> anyhow::Result<Vec<dtos::ExtractedValue>> {
    let values: Vec<dtos::ExtractedValue> = match request {
        dtos::ForeignChainRpcRequest::Ethereum(request) => {
            let inspector = inspectors
                .ethereum
                .as_ref()
                .context("no inspector configured for Ethereum")?;

            let transaction_id = request.tx_id.0.into();
            let finality: EthereumFinality = request.finality.clone().try_into()?;
            let extractors: Vec<EthereumExtractor> = request
                .extractors
                .iter()
                .cloned()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?;
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Solana(request) => {
            let inspector = inspectors
                .solana
                .as_ref()
                .context("no inspector configured for Solana")?;
            execute_svm_request(inspector, quorum, request).await?
        }
        dtos::ForeignChainRpcRequest::Fogo(request) => {
            let inspector = inspectors
                .fogo
                .as_ref()
                .context("no inspector configured for Fogo")?;
            execute_svm_request(inspector, quorum, request).await?
        }
        dtos::ForeignChainRpcRequest::Bitcoin(request) => {
            let inspector = inspectors
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
            let extracted_values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, block_confirmations, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            extracted_values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Abstract(request) => {
            let inspector = inspectors
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
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Bnb(request) => {
            let inspector = inspectors
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
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Base(request) => {
            let inspector = inspectors
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
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Arbitrum(request) => {
            let inspector = inspectors
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
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::HyperEvm(request) => {
            let inspector = inspectors
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
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Polygon(request) => {
            let inspector = inspectors
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
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Avalanche(request) => {
            let inspector = inspectors
                .avalanche
                .as_ref()
                .context("no inspector configured for Avalanche")?;

            let transaction_id = request.tx_id.0.into();
            let finality: EthereumFinality = request.finality.clone().try_into()?;
            let extractors: Vec<AvalancheExtractor> = request
                .extractors
                .iter()
                .cloned()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?;
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Adi(request) => {
            let inspector = inspectors
                .adi
                .as_ref()
                .context("no inspector configured for ADI")?;

            let transaction_id = request.tx_id.0.into();
            let finality: EthereumFinality = request.finality.clone().try_into()?;
            let extractors: Vec<AdiExtractor> = request
                .extractors
                .iter()
                .cloned()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?;
            let values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;
            values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Starknet(request) => {
            let inspector = inspectors
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

            let extracted_values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, transaction_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;

            extracted_values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Ton(_request) => {
            bail!("ForeignChainRpcRequest::Ton is unsupported")
        }
        dtos::ForeignChainRpcRequest::Aptos(request) => {
            let inspector = inspectors
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

            let extracted_values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, tx_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;

            extracted_values.into_iter().map(Into::into).collect()
        }
        dtos::ForeignChainRpcRequest::Sui(request) => {
            let inspector = inspectors
                .sui
                .as_ref()
                .context("no inspector configured for Sui")?;

            let tx_id = request.tx_id.0.into();
            let finality: SuiFinality = request.finality.clone().try_into()?;
            let extractors: Vec<SuiExtractor> = request
                .extractors
                .iter()
                .cloned()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?;

            let extracted_values = require_extracted(
                inspector
                    .extract_with_quorum(quorum, tx_id, finality, extractors)
                    .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
                    .await
                    .context("timed out during execution of foreign chain request")??,
            )?;

            extracted_values.into_iter().map(Into::into).collect()
        }
        _ => bail!("unsupported foreign chain request"),
    };
    Ok(values)
}

async fn execute_svm_request<Chain>(
    inspector: &MeasuredFanOut<SvmInspector<HttpClient, Chain>>,
    quorum: &RpcQuorum,
    request: &dtos::SvmRpcRequest,
) -> anyhow::Result<Vec<dtos::ExtractedValue>>
where
    Chain: SvmChain + Clone + Send + Sync + 'static,
{
    let tx_id = request.tx_id.0.into();
    let finality: SvmFinality = request.finality.clone().try_into()?;
    let extractors: Vec<SvmExtractor> = request
        .extractors
        .iter()
        .cloned()
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()?;

    let values = require_extracted(
        inspector
            .extract_with_quorum(quorum, tx_id, finality, extractors)
            .timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
            .await
            .context("timed out during execution of foreign chain request")??,
    )?;

    Ok(values.into_iter().map(Into::into).collect())
}
