//! Builders shared by the probe's test modules.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::{Pending, Ready};
use std::num::NonZeroU64;

use foreign_chain_health_check::probe::{
    ProbeReport, ProviderCounts, ProviderHealth, ProviderStatus,
};
use futures::future::Either;
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::metrics;

const CHAIN_TIMEOUT_SEC: NonZeroU64 = NonZeroU64::new(30).unwrap();
const CHAIN_MAX_RETRIES: NonZeroU64 = NonZeroU64::new(3).unwrap();

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
        timeout_sec: CHAIN_TIMEOUT_SEC,
        max_retries: CHAIN_MAX_RETRIES,
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

/// Gives provider `p` the base URL `https://p.example.com`.
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

pub(super) fn no_whitelist() -> watch::Receiver<Option<ForeignChainWhitelist>> {
    watch::channel(None).1
}

pub(super) fn empty_report() -> ProbeReport {
    ProbeReport::from(vec![])
}

/// Past `max_calls` the probe never answers, so a loop that probes too often parks there and
/// fails its test on the count instead of spinning inside one poll.
pub(super) fn mock_probe(
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

/// Records the whitelist each round finished with.
pub(super) fn mock_finish_round(
    whitelists_seen: &RefCell<Vec<Option<ForeignChainWhitelist>>>,
) -> impl Fn(&ProbeReport, Option<&ForeignChainWhitelist>) + '_ {
    move |_, whitelist| whitelists_seen.borrow_mut().push(whitelist.cloned())
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
