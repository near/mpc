//! Startup sample-transaction probes for foreign-chain RPC providers.
//!
//! See `docs/foreign-chain-transactions.md` ("Provider Startup Validation"). Each configured chain
//! may carry a `sample_tx_id`; for those chains, every provider is probed against that tx before
//! the chain is registered on-chain. If any provider fails, the entire chain is excluded from the
//! registration so the operator notices and fixes the configuration.

use crate::config::auth_config_to_rpc_auth;
use foreign_chain_inspector::abstract_chain::inspector::AbstractInspector;
use foreign_chain_inspector::arbitrum::inspector::ArbitrumInspector;
use foreign_chain_inspector::base::inspector::BaseInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::bnb::inspector::BnbInspector;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvmInspector;
use foreign_chain_inspector::polygon::inspector::PolygonInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_contract_interface::types::ForeignChain;
use std::collections::BTreeSet;

/// Probe every configured (chain, provider) pair that has a `sample_tx_id`. Returns the set of
/// chains where at least one provider failed the probe — callers should exclude these from the
/// registered configuration.
///
/// Chains without a configured `sample_tx_id` are never reported here (probing is opt-in).
pub async fn chains_with_failed_probe(config: &ForeignChainsConfig) -> BTreeSet<ForeignChain> {
    let mut failed = BTreeSet::new();

    probe_chain(
        &config.bitcoin,
        ForeignChain::Bitcoin,
        &mut failed,
        |c, tx| Box::pin(async move { BitcoinInspector::new(c).probe_sample_tx(&tx).await }),
    )
    .await;

    probe_chain(
        &config.abstract_chain,
        ForeignChain::Abstract,
        &mut failed,
        |c, tx| Box::pin(async move { AbstractInspector::new(c).probe_sample_tx(&tx).await }),
    )
    .await;

    probe_chain(&config.base, ForeignChain::Base, &mut failed, |c, tx| {
        Box::pin(async move { BaseInspector::new(c).probe_sample_tx(&tx).await })
    })
    .await;

    probe_chain(&config.bnb, ForeignChain::Bnb, &mut failed, |c, tx| {
        Box::pin(async move { BnbInspector::new(c).probe_sample_tx(&tx).await })
    })
    .await;

    probe_chain(
        &config.arbitrum,
        ForeignChain::Arbitrum,
        &mut failed,
        |c, tx| Box::pin(async move { ArbitrumInspector::new(c).probe_sample_tx(&tx).await }),
    )
    .await;

    probe_chain(
        &config.hyper_evm,
        ForeignChain::HyperEvm,
        &mut failed,
        |c, tx| Box::pin(async move { HyperEvmInspector::new(c).probe_sample_tx(&tx).await }),
    )
    .await;

    probe_chain(
        &config.polygon,
        ForeignChain::Polygon,
        &mut failed,
        |c, tx| Box::pin(async move { PolygonInspector::new(c).probe_sample_tx(&tx).await }),
    )
    .await;

    probe_chain(
        &config.starknet,
        ForeignChain::Starknet,
        &mut failed,
        |c, tx| Box::pin(async move { StarknetInspector::new(c).probe_sample_tx(&tx).await }),
    )
    .await;

    failed
}

type BoxedProbeFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), foreign_chain_inspector::ProbeError>> + Send>,
>;

/// Runs the per-provider probe for a single chain. The inspector type is hidden behind the
/// `make_probe` closure so each call site stays type-correct without leaking the generic into the
/// helper's signature. On the first provider failure the chain is recorded and the loop exits —
/// one broken provider disqualifies the whole chain.
async fn probe_chain<F>(
    chain_cfg: &Option<ForeignChainConfig>,
    chain: ForeignChain,
    failed: &mut BTreeSet<ForeignChain>,
    make_probe: F,
) where
    F: Fn(HttpClient, String) -> BoxedProbeFuture,
{
    let Some(cfg) = chain_cfg else { return };
    let Some(sample_tx) = cfg.sample_tx_id.clone() else {
        return;
    };

    for (provider_name, provider) in cfg.providers.iter() {
        let client = match build_client(provider) {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(
                    chain = ?chain,
                    provider = %**provider_name,
                    rpc_url = %provider.rpc_url,
                    error = %err,
                    "failed to build RPC client for sample-tx probe; chain will be excluded from registration",
                );
                failed.insert(chain);
                return;
            }
        };

        if let Err(err) = make_probe(client, sample_tx.clone()).await {
            tracing::warn!(
                chain = ?chain,
                provider = %**provider_name,
                rpc_url = %provider.rpc_url,
                error = %err,
                "sample-tx probe failed; chain will be excluded from registration",
            );
            failed.insert(chain);
            return;
        }
    }
}

fn build_client(provider: &ForeignChainProviderConfig) -> anyhow::Result<HttpClient> {
    let mut url = provider.rpc_url.clone();
    let rpc_auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
    Ok(foreign_chain_inspector::build_http_client(url, rpc_auth)?)
}
