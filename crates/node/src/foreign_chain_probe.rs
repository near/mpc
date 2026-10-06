//! Periodic probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`].

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use foreign_chain_health_check::probe::{
    ProbeReport, ProviderHealth, ProviderStatus, probe_all_providers,
};
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use mpc_node_config::{ForeignChainConfig, ForeignChainsConfig};
use near_mpc_contract_interface::types as dtos;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::foreign_chain_whitelist_verifier::find_whitelist_match;
use crate::indexer::tee::ForeignChainWhitelist;
use crate::metrics;
use crate::tick::Tick;

/// Asks every configured RPC provider which network it serves, once per tick of `ticker` and
/// whenever `whitelist` changes, and reports the verdicts as logs and metrics. Diagnostic only:
/// nothing gates on the result.
///
/// Each probed chain is also judged against `whitelist`. A local provider counts for the whitelist
/// provider it matches by URL only when no part of it differs, as
/// [`provider_identity`](mpc_node_config::foreign_chains::provider_identity) describes. A chain is
/// healthy when at least its quorum of whitelist providers count and all of them are healthy. Until
/// the whitelist is first read from the contract, chain health is logged as unknown.
pub async fn run_periodic_probe(
    foreign_chains: ForeignChainsConfig,
    whitelist: watch::Receiver<Option<ForeignChainWhitelist>>,
    ticker: impl Tick,
) {
    if foreign_chains.is_empty() {
        warn!("no foreign chain is configured: this node cannot verify foreign-chain transactions");
        return;
    }

    probe_periodically(
        || probe_all_providers(&foreign_chains, &InspectorFactory),
        &foreign_chains,
        whitelist,
        ticker,
    )
    .await;
}

async fn probe_periodically<Probe: Future<Output = ProbeReport>>(
    probe: impl Fn() -> Probe,
    local: &ForeignChainsConfig,
    mut whitelist: watch::Receiver<Option<ForeignChainWhitelist>>,
    mut ticker: impl Tick,
) {
    let mut whitelist_open = true;
    loop {
        // Ticks win ties, so a whitelist update that lands with a tick is judged in that round
        // rather than in an extra one.
        tokio::select! {
            biased;
            () = ticker.tick() => {}
            changed = whitelist.changed(), if whitelist_open => {
                // A closed channel stays ready, which would probe in a busy loop.
                if changed.is_err() {
                    whitelist_open = false;
                    continue;
                }
            }
        }

        info!("probing foreign-chain RPC providers");
        let report = probe().await;
        publish_metrics(&report);
        log_report(&report);
        let health = whitelist
            .borrow_and_update()
            .as_ref()
            .map(|whitelist| judge(&report, local, whitelist));
        match health {
            Some(health) => log_chain_health(&health),
            None => info!(
                "foreign chain health is unknown: the provider whitelist has not been read from the contract yet"
            ),
        }
    }
}

/// A probed chain judged against the provider whitelist. Counts cover whitelist providers that a
/// local provider matches with no mismatch.
#[derive(Debug, PartialEq, Eq)]
enum ChainHealth {
    Healthy,
    BelowQuorum {
        whitelisted: usize,
        quorum: u64,
    },
    UnhealthyProviders {
        unhealthy: usize,
        whitelisted: usize,
    },
    NotWhitelisted,
}

fn judge(
    report: &ProbeReport,
    local: &ForeignChainsConfig,
    whitelist: &ForeignChainWhitelist,
) -> BTreeMap<dtos::ForeignChain, ChainHealth> {
    let mut probed_rows: BTreeMap<dtos::ForeignChain, Vec<&ProviderHealth>> = BTreeMap::new();
    for row in report.rows().iter().filter(|row| row.status.was_probed()) {
        probed_rows.entry(row.chain).or_default().push(row);
    }
    let local_chains: BTreeMap<dtos::ForeignChain, &ForeignChainConfig> =
        local.iter_chains().collect();

    probed_rows
        .into_iter()
        .filter_map(|(chain, rows)| {
            let health = match whitelist.get(&chain) {
                None => ChainHealth::NotWhitelisted,
                // The probe only reports chains of `local`, so the lookup finds every probed chain.
                Some(entry) => judge_whitelisted_chain(&rows, local_chains.get(&chain)?, entry),
            };
            Some((chain, health))
        })
        .collect()
}

/// A whitelist provider counts once, however many local providers match it, and is healthy only
/// when all of them are.
fn judge_whitelisted_chain(
    rows: &[&ProviderHealth],
    local_chain: &ForeignChainConfig,
    entry: &dtos::ChainEntry,
) -> ChainHealth {
    let mut healthy_by_whitelist_id: BTreeMap<&dtos::ProviderId, bool> = BTreeMap::new();
    for row in rows {
        if let Some(whitelist_id) = conforming_whitelist_id(local_chain, &row.provider, entry) {
            *healthy_by_whitelist_id.entry(whitelist_id).or_insert(true) &= row.status.is_healthy();
        }
    }
    let whitelisted = healthy_by_whitelist_id.len();

    if !usize::try_from(entry.quorum).is_ok_and(|quorum| whitelisted >= quorum) {
        return ChainHealth::BelowQuorum {
            whitelisted,
            quorum: entry.quorum,
        };
    }

    match healthy_by_whitelist_id
        .values()
        .filter(|healthy| !**healthy)
        .count()
    {
        0 => ChainHealth::Healthy,
        unhealthy => ChainHealth::UnhealthyProviders {
            unhealthy,
            whitelisted,
        },
    }
}

/// Probe rows name a provider by its local config name.
fn conforming_whitelist_id<'w>(
    local_chain: &ForeignChainConfig,
    local_name: &dtos::ProviderId,
    entry: &'w dtos::ChainEntry,
) -> Option<&'w dtos::ProviderId> {
    let (_, local_provider) = local_chain
        .providers
        .iter()
        .find(|(name, _)| name.as_str() == local_name.0)?;
    let whitelist_match = find_whitelist_match(entry, local_provider)?;
    whitelist_match
        .mismatches
        .is_empty()
        .then_some(whitelist_match.id)
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    probed: usize,
    healthy: usize,
}

fn summarize(rows: &[ProviderHealth]) -> Summary {
    Summary {
        probed: rows.iter().filter(|row| row.status.was_probed()).count(),
        healthy: rows.iter().filter(|row| row.status.is_healthy()).count(),
    }
}

fn log_report(report: &ProbeReport) {
    let rows = report.rows();
    for row in rows {
        match &row.status {
            ProviderStatus::Healthy => info!(
                chain = %row.chain.label(),
                provider = %row.provider,
                "foreign-chain RPC provider serves the expected network",
            ),
            ProviderStatus::ProbeNotImplemented => info!(
                chain = %row.chain.label(),
                provider = %row.provider,
                "foreign-chain RPC provider cannot be checked",
            ),
            unhealthy => warn!(
                chain = %row.chain.label(),
                provider = %row.provider,
                status = ?unhealthy,
                "foreign-chain RPC provider is unhealthy",
            ),
        }
    }

    let Summary { probed, healthy } = summarize(rows);
    if probed == 0 {
        let chains: BTreeSet<&str> = rows.iter().map(|row| row.chain.label()).collect();
        warn!(
            ?chains,
            "no RPC provider was checked: none of the configured foreign chains has a probe"
        );
        return;
    }
    info!("foreign-chain RPC provider probe complete: {healthy}/{probed} providers healthy");
}

fn log_chain_health(health_per_chain: &BTreeMap<dtos::ForeignChain, ChainHealth>) {
    for (chain, health) in health_per_chain {
        let chain = chain.label();
        match health {
            ChainHealth::Healthy => info!(%chain, "foreign chain is healthy"),
            ChainHealth::BelowQuorum {
                whitelisted,
                quorum,
            } => warn!(
                %chain,
                whitelisted,
                quorum,
                "foreign chain is below quorum: configure more whitelisted RPC providers",
            ),
            ChainHealth::UnhealthyProviders {
                unhealthy,
                whitelisted,
            } => warn!(
                %chain,
                unhealthy,
                whitelisted,
                "foreign chain is unhealthy: a whitelisted RPC provider failed the probe",
            ),
            ChainHealth::NotWhitelisted => {
                info!(%chain, "foreign chain is not whitelisted: health not judged")
            }
        }
    }
}

fn publish_metrics(report: &ProbeReport) {
    let probed_chains: BTreeSet<dtos::ForeignChain> = report
        .rows()
        .iter()
        .filter(|row| row.status.was_probed())
        .map(|row| row.chain)
        .collect();

    for (chain, counts) in report.counts_per_chain() {
        if !probed_chains.contains(&chain) {
            continue;
        }
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED
            .with_label_values(&[chain.label()])
            .set(i64::try_from(counts.configured).expect("provider count never exceeds i64"));
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY
            .with_label_values(&[chain.label()])
            .set(i64::try_from(counts.healthy).expect("provider count never exceeds i64"));
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::tick::MockTicker;
    use foreign_chain_health_check::probe::ProviderCounts;
    use mpc_node_config::foreign_chains::RpcProviderName;
    use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use prometheus::core::Collector as _;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::num::NonZeroU64;
    use tracing_test::traced_test;

    fn labelled_chains(gauge: &prometheus::IntGaugeVec) -> BTreeSet<String> {
        gauge
            .collect()
            .iter()
            .flat_map(|family| family.get_metric())
            .flat_map(|metric| metric.get_label())
            .map(|label| label.value().to_string())
            .collect()
    }

    fn gauges(chain: &str) -> ProviderCounts {
        ProviderCounts {
            configured: metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED
                .with_label_values(&[chain])
                .get() as usize,
            healthy: metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY
                .with_label_values(&[chain])
                .get() as usize,
        }
    }

    fn row(chain: dtos::ForeignChain, provider: &str, status: ProviderStatus) -> ProviderHealth {
        ProviderHealth {
            chain,
            provider: dtos::ProviderId(provider.to_string()),
            status,
        }
    }

    fn whitelist_of(
        chain: dtos::ForeignChain,
        providers: &[&str],
        quorum: u64,
    ) -> ForeignChainWhitelist {
        let providers: BTreeMap<dtos::ProviderId, dtos::ProviderConfig> = providers
            .iter()
            .map(|provider| {
                let config = dtos::ProviderConfig {
                    base_url: format!("https://{provider}.example.com"),
                    auth_scheme: dtos::AuthScheme::None,
                    chain_routing: dtos::ChainRouting::Embedded,
                };
                (dtos::ProviderId(provider.to_string()), config)
            })
            .collect();
        let entry = dtos::ChainEntry {
            providers: providers.try_into().expect("a whitelisted provider"),
            quorum,
        };
        BTreeMap::from([(chain, entry)])
    }

    fn no_whitelist() -> watch::Receiver<Option<ForeignChainWhitelist>> {
        watch::channel(None).1
    }

    /// A Polygon config with a provider without auth per `(local name, rpc_url)` pair.
    fn must_polygon(providers: &[(&str, &str)]) -> ForeignChainsConfig {
        let providers: BTreeMap<RpcProviderName, ForeignChainProviderConfig> = providers
            .iter()
            .map(|(name, rpc_url)| {
                let provider = ForeignChainProviderConfig {
                    rpc_url: rpc_url.to_string(),
                    auth: AuthConfig::None,
                };
                (RpcProviderName::from(name.to_string()), provider)
            })
            .collect();
        ForeignChainsConfig {
            polygon: Some(ForeignChainConfig {
                timeout_sec: NonZeroU64::new(30).expect("30 is not zero"),
                max_retries: NonZeroU64::new(3).expect("3 is not zero"),
                expected_network_fingerprint: None,
                providers: NonEmptyBTreeMap::try_from(providers)
                    .expect("a test chain has a provider"),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn summarize__should_count_only_the_providers_a_probe_covers() {
        // Given
        let rows = [
            row(dtos::ForeignChain::Base, "only", ProviderStatus::Healthy),
            row(dtos::ForeignChain::Bnb, "only", ProviderStatus::Unreachable),
            row(
                dtos::ForeignChain::Ton,
                "only",
                ProviderStatus::ProbeNotImplemented,
            ),
        ];

        // When
        let summary = summarize(&rows);

        // Then
        assert_eq!(
            summary,
            Summary {
                probed: 2,
                healthy: 1
            }
        );
    }

    #[test]
    fn summarize__should_count_nothing_probed_when_no_chain_has_a_probe() {
        // Given
        let rows = [row(
            dtos::ForeignChain::Ton,
            "only",
            ProviderStatus::ProbeNotImplemented,
        )];

        // When
        let summary = summarize(&rows);

        // Then
        assert_eq!(
            summary,
            Summary {
                probed: 0,
                healthy: 0
            }
        );
    }

    /// `HyperEvm` is labelled `hyper_evm`, so the series is keyed by the config key rather than the
    /// variant name.
    #[test]
    fn publish_metrics__should_count_the_providers_of_each_chain() {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::HyperEvm,
                "alchemy",
                ProviderStatus::Healthy,
            ),
            row(
                dtos::ForeignChain::HyperEvm,
                "quicknode",
                ProviderStatus::Unreachable,
            ),
            row(dtos::ForeignChain::Aptos, "only", ProviderStatus::TimedOut),
        ]);

        // When
        publish_metrics(&report);

        // Then
        assert_eq!(
            gauges("hyper_evm"),
            ProviderCounts {
                configured: 2,
                healthy: 1
            }
        );
        assert_eq!(
            gauges("aptos"),
            ProviderCounts {
                configured: 1,
                healthy: 0
            }
        );
    }

    /// A `0` healthy for a chain no probe covers would read as every provider failing.
    #[test]
    fn publish_metrics__should_publish_no_counts_for_an_unprobeable_chain() {
        // Given
        let report = ProbeReport::from(vec![
            row(dtos::ForeignChain::Bnb, "only", ProviderStatus::Healthy),
            row(
                dtos::ForeignChain::Ton,
                "only",
                ProviderStatus::ProbeNotImplemented,
            ),
        ]);

        // When
        publish_metrics(&report);

        // Then
        let chains = labelled_chains(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED);
        assert!(chains.contains("bnb"));
        assert!(!chains.contains("ton"));
    }

    #[test]
    fn probe_periodically__should_probe_once_per_tick() {
        // Given
        let probe_count = Cell::new(0);
        let probe = || {
            probe_count.update(|count| count + 1);
            std::future::ready(ProbeReport::from(vec![]))
        };

        // When
        run_future_once(probe_periodically(
            probe,
            &ForeignChainsConfig::default(),
            no_whitelist(),
            MockTicker::new(3),
        ));

        // Then
        assert_eq!(probe_count.get(), 3);
    }

    #[test]
    fn probe_periodically__should_replace_the_gauges_of_the_previous_round() {
        // Given
        let rounds = RefCell::new(VecDeque::from([
            ProbeReport::from(vec![row(
                dtos::ForeignChain::Starknet,
                "only",
                ProviderStatus::Healthy,
            )]),
            ProbeReport::from(vec![row(
                dtos::ForeignChain::Starknet,
                "only",
                ProviderStatus::Unreachable,
            )]),
        ]));
        let probe_dispatch =
            || std::future::ready(rounds.borrow_mut().pop_front().expect("a report per tick"));
        let ticker = MockTicker::new(1);
        let local = ForeignChainsConfig::default();

        // When
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            probe_dispatch,
            &local,
            no_whitelist(),
            ticker.clone(),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };
        let metrics_after_the_first_round = gauges("starknet");
        ticker.schedule(1);
        run_future_once(parked_probe_loop);

        // Then
        assert_eq!(
            metrics_after_the_first_round,
            ProviderCounts {
                configured: 1,
                healthy: 1
            }
        );
        assert_eq!(
            gauges("starknet"),
            ProviderCounts {
                configured: 1,
                healthy: 0
            }
        );
    }

    #[test]
    fn run_periodic_probe__should_stop_when_no_foreign_chain_is_configured() {
        // Given
        let foreign_chains = ForeignChainsConfig::default();
        let ticker = MockTicker::new(1);

        // When
        let outcome = run_future_once(run_periodic_probe(
            foreign_chains,
            no_whitelist(),
            ticker.clone(),
        ));

        // Then
        assert_eq!(ticker.unspent(), 1, "no round should have run");
        assert!(
            matches!(outcome, MaybeReady::Ready(())),
            "the probe should return rather than park on its ticker"
        );
    }

    #[test]
    fn judge__should_report_a_chain_healthy_when_quorum_whitelisted_providers_pass() {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::Polygon,
                "alchemy",
                ProviderStatus::Healthy,
            ),
            row(
                dtos::ForeignChain::Polygon,
                "quicknode",
                ProviderStatus::Healthy,
            ),
        ]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy", "quicknode"], 2);
        let local = must_polygon(&[
            ("alchemy", "https://alchemy.example.com"),
            ("quicknode", "https://quicknode.example.com"),
        ]);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(dtos::ForeignChain::Polygon, ChainHealth::Healthy)])
        );
    }

    /// The whitelisted provider is unreachable too, so this also pins below quorum taking
    /// precedence over a failing provider.
    #[test]
    fn judge__should_not_count_providers_missing_from_the_whitelist_towards_the_quorum() {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::Polygon,
                "alchemy",
                ProviderStatus::Unreachable,
            ),
            row(
                dtos::ForeignChain::Polygon,
                "own_node",
                ProviderStatus::Healthy,
            ),
        ]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy", "quicknode"], 2);
        let local = must_polygon(&[
            ("alchemy", "https://alchemy.example.com"),
            ("own_node", "https://own-node.example.org"),
        ]);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(
                dtos::ForeignChain::Polygon,
                ChainHealth::BelowQuorum {
                    whitelisted: 1,
                    quorum: 2
                }
            )])
        );
    }

    #[test]
    fn judge__should_ignore_the_health_of_providers_missing_from_the_whitelist() {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::Polygon,
                "alchemy",
                ProviderStatus::Healthy,
            ),
            row(
                dtos::ForeignChain::Polygon,
                "own_node",
                ProviderStatus::Unreachable,
            ),
        ]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let local = must_polygon(&[
            ("alchemy", "https://alchemy.example.com"),
            ("own_node", "https://own-node.example.org"),
        ]);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(dtos::ForeignChain::Polygon, ChainHealth::Healthy)])
        );
    }

    #[test]
    fn judge__should_report_a_chain_unhealthy_when_any_whitelisted_provider_fails() {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::Polygon,
                "alchemy",
                ProviderStatus::Healthy,
            ),
            row(
                dtos::ForeignChain::Polygon,
                "quicknode",
                ProviderStatus::Unreachable,
            ),
        ]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy", "quicknode"], 1);
        let local = must_polygon(&[
            ("alchemy", "https://alchemy.example.com"),
            ("quicknode", "https://quicknode.example.com"),
        ]);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(
                dtos::ForeignChain::Polygon,
                ChainHealth::UnhealthyProviders {
                    unhealthy: 1,
                    whitelisted: 2
                }
            )])
        );
    }

    #[test]
    fn judge__should_not_judge_a_chain_missing_from_the_whitelist() {
        // Given
        let report = ProbeReport::from(vec![row(
            dtos::ForeignChain::Sui,
            "alchemy",
            ProviderStatus::Healthy,
        )]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let local = ForeignChainsConfig::default();

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(dtos::ForeignChain::Sui, ChainHealth::NotWhitelisted)])
        );
    }

    #[test]
    fn judge__should_leave_out_a_chain_no_probe_covers() {
        // Given
        let report = ProbeReport::from(vec![row(
            dtos::ForeignChain::Ton,
            "only",
            ProviderStatus::ProbeNotImplemented,
        )]);
        let whitelist = whitelist_of(dtos::ForeignChain::Ton, &["only"], 1);
        let local = ForeignChainsConfig::default();

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert!(health.is_empty());
    }

    #[test]
    fn judge__should_match_local_providers_to_the_whitelist_by_url_not_by_name() {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::Polygon,
                "my_alchemy",
                ProviderStatus::Healthy,
            ),
            row(
                dtos::ForeignChain::Polygon,
                "my_quicknode",
                ProviderStatus::Healthy,
            ),
        ]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy", "quicknode"], 2);
        let local = must_polygon(&[
            ("my_alchemy", "https://alchemy.example.com"),
            ("my_quicknode", "https://quicknode.example.com"),
        ]);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(dtos::ForeignChain::Polygon, ChainHealth::Healthy)])
        );
    }

    #[test]
    fn judge__should_not_count_a_provider_that_differs_from_its_whitelist_provider() {
        // Given
        let report = ProbeReport::from(vec![row(
            dtos::ForeignChain::Polygon,
            "alchemy",
            ProviderStatus::Healthy,
        )]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let local = must_polygon(&[("alchemy", "http://alchemy.example.com")]);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(
                dtos::ForeignChain::Polygon,
                ChainHealth::BelowQuorum {
                    whitelisted: 0,
                    quorum: 1
                }
            )])
        );
    }

    #[test]
    fn judge__should_count_a_whitelist_provider_once_and_healthy_only_when_all_its_local_providers_are()
     {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::Polygon,
                "alchemy_a",
                ProviderStatus::Healthy,
            ),
            row(
                dtos::ForeignChain::Polygon,
                "alchemy_b",
                ProviderStatus::Unreachable,
            ),
        ]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let local = must_polygon(&[
            ("alchemy_a", "https://alchemy.example.com/a"),
            ("alchemy_b", "https://alchemy.example.com/b"),
        ]);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(
                dtos::ForeignChain::Polygon,
                ChainHealth::UnhealthyProviders {
                    unhealthy: 1,
                    whitelisted: 1
                }
            )])
        );
    }

    #[test]
    #[traced_test]
    fn probe_periodically__should_warn_for_a_chain_below_quorum() {
        // Given
        let probe = || {
            std::future::ready(ProbeReport::from(vec![row(
                dtos::ForeignChain::Polygon,
                "alchemy",
                ProviderStatus::Healthy,
            )]))
        };
        let (_whitelist_sender, whitelist) = watch::channel(Some(whitelist_of(
            dtos::ForeignChain::Polygon,
            &["alchemy", "quicknode"],
            2,
        )));

        let local = must_polygon(&[("alchemy", "https://alchemy.example.com")]);

        // When
        run_future_once(probe_periodically(
            probe,
            &local,
            whitelist,
            MockTicker::new(1),
        ));

        // Then
        logs_assert(|lines: &[&str]| {
            let warned = lines.iter().any(|line| {
                line.contains("WARN") && line.contains("foreign chain is below quorum")
            });
            if warned {
                Ok(())
            } else {
                Err("no WARN line reports the chain below quorum".to_string())
            }
        });
    }

    #[test]
    #[traced_test]
    fn probe_periodically__should_log_chain_health_unknown_before_the_whitelist_is_read() {
        // Given
        let probe = || {
            std::future::ready(ProbeReport::from(vec![row(
                dtos::ForeignChain::Arbitrum,
                "alchemy",
                ProviderStatus::Healthy,
            )]))
        };
        let (_whitelist_sender, whitelist) = watch::channel(None);

        // When
        run_future_once(probe_periodically(
            probe,
            &ForeignChainsConfig::default(),
            whitelist,
            MockTicker::new(1),
        ));

        // Then
        assert!(logs_contain("foreign chain health is unknown"));
    }

    #[test]
    fn probe_periodically__should_probe_again_once_the_whitelist_is_read() {
        // Given
        let probe_count = Cell::new(0);
        let probe = || {
            probe_count.set(probe_count.get() + 1);
            std::future::ready(ProbeReport::from(vec![]))
        };
        let (whitelist_sender, whitelist) = watch::channel(None);
        let local = ForeignChainsConfig::default();
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            probe,
            &local,
            whitelist,
            MockTicker::new(1),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };

        // When
        whitelist_sender.send_replace(Some(whitelist_of(
            dtos::ForeignChain::Polygon,
            &["alchemy"],
            1,
        )));
        run_future_once(parked_probe_loop);

        // Then
        assert_eq!(probe_count.get(), 2);
    }
}
