//! Builders shared by the probe's test modules.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::future::{Pending, Ready};
use std::num::NonZeroU64;

use foreign_chain_health_check::probe::{
    ProbeReport, ProviderCounts, ProviderHealth, ProviderStatus,
};
use futures::future::Either;
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::metrics;

pub(super) const ALCHEMY_URL: &str = "https://alchemy.example.com";

pub(super) fn row(
    chain: dtos::ForeignChain,
    provider: &str,
    status: ProviderStatus,
) -> ProviderHealth {
    ProviderHealth {
        chain,
        provider: dtos::ProviderId(provider.to_string()),
        status,
    }
}

pub(super) fn chain_config(providers: &[(&str, ForeignChainProviderConfig)]) -> ForeignChainConfig {
    let providers: BTreeMap<RpcProviderName, ForeignChainProviderConfig> = providers
        .iter()
        .map(|(name, config)| (RpcProviderName::from(name.to_string()), config.clone()))
        .collect();
    ForeignChainConfig {
        timeout_sec: NonZeroU64::new(30).unwrap(),
        max_retries: NonZeroU64::new(3).unwrap(),
        expected_network_fingerprint: None,
        providers: NonEmptyBTreeMap::try_from(providers).expect("a test chain has a provider"),
    }
}

/// Covers only the chains the probe tests use.
pub(super) fn foreign_chains(
    chains: impl IntoIterator<Item = (dtos::ForeignChain, ForeignChainConfig)>,
) -> ForeignChainsConfig {
    let mut local = ForeignChainsConfig::default();
    for (chain, config) in chains {
        let slot = match chain {
            dtos::ForeignChain::Polygon => &mut local.polygon,
            dtos::ForeignChain::Ethereum => &mut local.ethereum,
            dtos::ForeignChain::Base => &mut local.base,
            dtos::ForeignChain::Bnb => &mut local.bnb,
            other => panic!("no test config slot for {other:?}"),
        };
        *slot = Some(config);
    }
    local
}

pub(super) fn chain_entry(
    providers: &[(&str, dtos::ProviderConfig)],
    quorum: u64,
) -> dtos::ChainEntry {
    let providers: BTreeMap<dtos::ProviderId, dtos::ProviderConfig> = providers
        .iter()
        .map(|(id, config)| (dtos::ProviderId(id.to_string()), config.clone()))
        .collect();
    dtos::ChainEntry {
        providers: NonEmptyBTreeMap::try_from(providers).expect("a test whitelist has a provider"),
        quorum,
    }
}

/// Gives provider `p` the base URL `https://p.example.com`, so `ALCHEMY_URL` matches `alchemy`.
pub(super) fn whitelist_of(
    chain: dtos::ForeignChain,
    providers: &[&str],
    quorum: u64,
) -> ForeignChainWhitelist {
    let providers: Vec<(&str, dtos::ProviderConfig)> = providers
        .iter()
        .map(|provider| {
            let config = dtos::ProviderConfig {
                base_url: format!("https://{provider}.example.com"),
                auth_scheme: dtos::AuthScheme::None,
                chain_routing: dtos::ChainRouting::Embedded,
            };
            (*provider, config)
        })
        .collect();
    BTreeMap::from([(chain, chain_entry(&providers, quorum))])
}

/// A config with a provider without auth per `(chain, local name, rpc_url, status)`, and the probe
/// report of that config.
pub(super) fn config_with_report(
    providers: &[(dtos::ForeignChain, &str, &str, ProviderStatus)],
) -> (ForeignChainsConfig, ProbeReport) {
    let mut providers_per_chain: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (chain, name, rpc_url, _) in providers {
        let provider = ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth: AuthConfig::None,
        };
        providers_per_chain
            .entry(*chain)
            .or_default()
            .push((*name, provider));
    }
    let local = foreign_chains(
        providers_per_chain
            .into_iter()
            .map(|(chain, providers)| (chain, chain_config(&providers))),
    );
    let rows: Vec<ProviderHealth> = providers
        .iter()
        .map(|(chain, name, _, status)| row(*chain, name, status.clone()))
        .collect();
    (local, ProbeReport::from(rows))
}

pub(super) fn polygon_with_report(
    providers: &[(&str, &str, ProviderStatus)],
) -> (ForeignChainsConfig, ProbeReport) {
    let providers: Vec<_> = providers
        .iter()
        .map(|(name, rpc_url, status)| {
            (dtos::ForeignChain::Polygon, *name, *rpc_url, status.clone())
        })
        .collect();
    config_with_report(&providers)
}

pub(super) fn no_whitelist() -> watch::Receiver<Option<ForeignChainWhitelist>> {
    watch::channel(None).1
}

pub(super) fn empty_report() -> ProbeReport {
    ProbeReport::from(vec![])
}

/// Counts its calls and answers `report` to the first `max_calls`. Later calls never answer, so a
/// loop that probes too often parks there and fails its test on the count instead of spinning
/// inside one poll.
pub(super) fn capped_probe(
    calls: &Cell<usize>,
    max_calls: usize,
    report: ProbeReport,
) -> impl Fn() -> Either<Ready<ProbeReport>, Pending<ProbeReport>> + '_ {
    move || {
        calls.update(|count| count + 1);
        if calls.get() <= max_calls {
            Either::Left(std::future::ready(report.clone()))
        } else {
            Either::Right(std::future::pending())
        }
    }
}

pub(super) fn logged_times(
    lines: &[&str],
    level: &str,
    message: &str,
    times: usize,
) -> Result<(), String> {
    let logged = lines
        .iter()
        .filter(|line| line.contains(level) && line.contains(message))
        .count();
    (logged == times)
        .then_some(())
        .ok_or_else(|| format!("{level} {message:?} logged {logged} times, expected {times}"))
}

pub(super) fn gauges(chain: &str) -> ProviderCounts {
    let count = |gauge: &prometheus::IntGaugeVec| {
        usize::try_from(gauge.with_label_values(&[chain]).get()).expect("a gauge is never negative")
    };
    ProviderCounts {
        configured: count(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED),
        healthy: count(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY),
    }
}
