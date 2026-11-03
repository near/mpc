//! Builders shared by the probe's test modules.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::future::{Pending, Ready};

use foreign_chain_health_check::probe::{
    ProbeReport, ProviderCounts, ProviderHealth, ProviderStatus,
};
use futures::future::Either;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;

use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::metrics;

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
