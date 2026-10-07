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
use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::metrics;
use crate::tick::Tick;

/// Asks every configured RPC provider which network it serves, once per tick of `ticker` and
/// whenever `whitelist_rx` changes, and reports the verdicts as logs and metrics. Diagnostic only:
/// nothing gates on the result.
///
/// Each probed chain is also judged against the whitelist. A local provider counts for the
/// whitelist provider it matches by URL only when no part of it differs, as
/// [`provider_identity`](mpc_node_config::foreign_chains::provider_identity) describes. A chain is
/// healthy when at least its quorum of whitelist providers count and all of them are healthy. Until
/// the whitelist is first read from the contract, chain health is logged as unknown.
pub async fn run_periodic_probe(
    foreign_chains: ForeignChainsConfig,
    whitelist_rx: watch::Receiver<Option<ForeignChainWhitelist>>,
    ticker: impl Tick,
) {
    if foreign_chains.is_empty() {
        warn!("no foreign chain is configured: this node cannot verify foreign-chain transactions");
        return;
    }

    probe_periodically(
        || probe_all_providers(&foreign_chains, &InspectorFactory),
        &foreign_chains,
        whitelist_rx,
        ticker,
    )
    .await;
}

async fn probe_periodically<Probe: Future<Output = ProbeReport>>(
    probe: impl Fn() -> Probe,
    local: &ForeignChainsConfig,
    mut whitelist_rx: watch::Receiver<Option<ForeignChainWhitelist>>,
    mut ticker: impl Tick,
) {
    loop {
        // Ticks win ties. A whitelist update that lands with a tick is judged in that round, not
        // in an extra one. `Err` means the sender is gone. It disables the branch, so the loop
        // waits for the next tick and never spins.
        tokio::select! {
            biased;
            () = ticker.tick() => {}
            Ok(()) = whitelist_rx.changed() => {}
        }

        info!("probing foreign-chain RPC providers");
        let report = probe().await;
        publish_metrics(&report);
        log_report(&report);
        let health_per_chain = whitelist_rx
            .borrow_and_update()
            .as_ref()
            .map(|whitelist| judge(&report, local, whitelist));
        match health_per_chain {
            Some(health_per_chain) => log_chain_health(&health_per_chain),
            None => info!(
                "foreign chain health is unknown: the provider whitelist has not been read from the contract yet"
            ),
        }
    }
}

/// A probed chain judged against the provider whitelist. `whitelisted` is the number of whitelist
/// providers that a local provider counts for, see [`counted_whitelist_id`].
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
    let mut health_per_chain = BTreeMap::new();
    for (chain, local_chain) in local.iter_chains() {
        let probed_rows: Vec<&ProviderHealth> = report
            .rows()
            .iter()
            .filter(|row| row.chain == chain && row.status.was_probed())
            .collect();
        if probed_rows.is_empty() {
            continue;
        }
        let health = match whitelist.get(&chain) {
            None => ChainHealth::NotWhitelisted,
            Some(whitelist_entry) => judge_chain(&probed_rows, local_chain, whitelist_entry),
        };
        health_per_chain.insert(chain, health);
    }
    health_per_chain
}

/// A whitelist provider counts once, however many local providers match it. It is healthy only
/// when all of them are.
fn judge_chain(
    probed_rows: &[&ProviderHealth],
    local_chain: &ForeignChainConfig,
    whitelist_entry: &dtos::ChainEntry,
) -> ChainHealth {
    let mut counted_whitelist_ids: BTreeSet<&dtos::ProviderId> = BTreeSet::new();
    let mut unhealthy_whitelist_ids: BTreeSet<&dtos::ProviderId> = BTreeSet::new();
    for row in probed_rows {
        let Some(whitelist_id) =
            counted_whitelist_id(local_chain, &row.provider.0, whitelist_entry)
        else {
            continue;
        };
        counted_whitelist_ids.insert(whitelist_id);
        if !row.status.is_healthy() {
            unhealthy_whitelist_ids.insert(whitelist_id);
        }
    }

    let whitelisted = counted_whitelist_ids.len();
    let quorum_met =
        usize::try_from(whitelist_entry.quorum).is_ok_and(|quorum| whitelisted >= quorum);
    if !quorum_met {
        ChainHealth::BelowQuorum {
            whitelisted,
            quorum: whitelist_entry.quorum,
        }
    } else if !unhealthy_whitelist_ids.is_empty() {
        ChainHealth::UnhealthyProviders {
            unhealthy: unhealthy_whitelist_ids.len(),
            whitelisted,
        }
    } else {
        ChainHealth::Healthy
    }
}

/// Probe rows name a provider by its local config name.
fn counted_whitelist_id<'w>(
    local_chain: &ForeignChainConfig,
    local_name: &str,
    whitelist_entry: &'w dtos::ChainEntry,
) -> Option<&'w dtos::ProviderId> {
    let (_, local_provider) = local_chain
        .providers
        .iter()
        .find(|(name, _)| name.as_str() == local_name)?;
    let whitelist_match = find_whitelist_match(whitelist_entry, local_provider)?;
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
    use rstest::rstest;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::num::NonZeroU64;
    use tracing_test::traced_test;

    const ALCHEMY_URL: &str = "https://alchemy.example.com";
    const QUICKNODE_URL: &str = "https://quicknode.example.com";
    const OWN_NODE_URL: &str = "https://own-node.example.org";

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

    /// Gives provider `p` the base URL `https://p.example.com`, so [`ALCHEMY_URL`] and
    /// [`QUICKNODE_URL`] match and [`OWN_NODE_URL`] does not.
    fn must_whitelist_of(
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

    fn counting_probe(
        probe_count: &Cell<usize>,
    ) -> impl Fn() -> std::future::Ready<ProbeReport> + '_ {
        move || {
            probe_count.update(|count| count + 1);
            std::future::ready(ProbeReport::from(vec![]))
        }
    }

    fn line_at_level(lines: &[&str], level: &str, message: &str) -> Result<(), String> {
        let logged = lines
            .iter()
            .any(|line| line.contains(level) && line.contains(message));
        logged
            .then_some(())
            .ok_or_else(|| format!("no {level} line says {message:?}"))
    }

    /// A Polygon config with a provider without auth per `(local name, rpc_url, status)`, and the
    /// probe report of that config.
    fn must_polygon(
        providers: &[(&str, &str, ProviderStatus)],
    ) -> (ForeignChainsConfig, ProbeReport) {
        let mut local_providers = BTreeMap::new();
        let mut rows = Vec::new();
        for (name, rpc_url, status) in providers {
            let provider = ForeignChainProviderConfig {
                rpc_url: rpc_url.to_string(),
                auth: AuthConfig::None,
            };
            local_providers.insert(RpcProviderName::from(name.to_string()), provider);
            rows.push(row(dtos::ForeignChain::Polygon, name, status.clone()));
        }
        let local = ForeignChainsConfig {
            polygon: Some(ForeignChainConfig {
                timeout_sec: NonZeroU64::new(30).expect("30 is not zero"),
                max_retries: NonZeroU64::new(3).expect("3 is not zero"),
                expected_network_fingerprint: None,
                providers: NonEmptyBTreeMap::try_from(local_providers)
                    .expect("a test chain has a provider"),
            }),
            ..Default::default()
        };
        (local, ProbeReport::from(rows))
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

        // When
        run_future_once(probe_periodically(
            counting_probe(&probe_count),
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

    #[rstest]
    #[case::healthy_when_quorum_whitelisted_providers_pass(
        &[
            ("alchemy", ALCHEMY_URL, ProviderStatus::Healthy),
            ("quicknode", QUICKNODE_URL, ProviderStatus::Healthy),
        ],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::Healthy
    )]
    #[case::matched_by_url_not_by_name(
        &[
            ("my_alchemy", ALCHEMY_URL, ProviderStatus::Healthy),
            ("my_quicknode", QUICKNODE_URL, ProviderStatus::Healthy),
        ],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::Healthy
    )]
    #[case::unhealthy_when_any_whitelisted_provider_fails(
        &[
            ("alchemy", ALCHEMY_URL, ProviderStatus::Healthy),
            ("quicknode", QUICKNODE_URL, ProviderStatus::Unreachable),
        ],
        &["alchemy", "quicknode"],
        1,
        ChainHealth::UnhealthyProviders { unhealthy: 1, whitelisted: 2 }
    )]
    #[case::below_quorum_wins_over_a_failing_provider(
        &[
            ("alchemy", ALCHEMY_URL, ProviderStatus::Unreachable),
            ("own_node", OWN_NODE_URL, ProviderStatus::Healthy),
        ],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::BelowQuorum { whitelisted: 1, quorum: 2 }
    )]
    #[case::health_of_a_provider_missing_from_the_whitelist_ignored(
        &[
            ("alchemy", ALCHEMY_URL, ProviderStatus::Healthy),
            ("own_node", OWN_NODE_URL, ProviderStatus::Unreachable),
        ],
        &["alchemy"],
        1,
        ChainHealth::Healthy
    )]
    #[case::provider_that_differs_from_its_whitelist_provider_not_counted(
        &[("alchemy", "http://alchemy.example.com", ProviderStatus::Healthy)],
        &["alchemy"],
        1,
        ChainHealth::BelowQuorum { whitelisted: 0, quorum: 1 }
    )]
    #[case::whitelist_provider_counted_once_and_healthy_only_when_all_its_local_providers_are(
        &[
            ("alchemy_a", "https://alchemy.example.com/a", ProviderStatus::Healthy),
            ("alchemy_b", "https://alchemy.example.com/b", ProviderStatus::Unreachable),
        ],
        &["alchemy"],
        1,
        ChainHealth::UnhealthyProviders { unhealthy: 1, whitelisted: 1 }
    )]
    fn judge__should_judge_a_chain_by_its_counted_whitelist_providers(
        #[case] local_providers: &[(&str, &str, ProviderStatus)],
        #[case] whitelist_providers: &[&str],
        #[case] quorum: u64,
        #[case] expected: ChainHealth,
    ) {
        // Given
        let (local, report) = must_polygon(local_providers);
        let whitelist = must_whitelist_of(dtos::ForeignChain::Polygon, whitelist_providers, quorum);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(dtos::ForeignChain::Polygon, expected)])
        );
    }

    #[test]
    fn judge__should_not_judge_a_chain_missing_from_the_whitelist() {
        // Given
        let (local, report) = must_polygon(&[("alchemy", ALCHEMY_URL, ProviderStatus::Healthy)]);
        let whitelist = must_whitelist_of(dtos::ForeignChain::Ethereum, &["alchemy"], 1);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(dtos::ForeignChain::Polygon, ChainHealth::NotWhitelisted)])
        );
    }

    #[test]
    fn judge__should_leave_out_a_chain_no_probe_covers() {
        // Given
        let (local, report) =
            must_polygon(&[("alchemy", ALCHEMY_URL, ProviderStatus::ProbeNotImplemented)]);
        let whitelist = must_whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert!(health.is_empty());
    }

    #[test]
    #[traced_test]
    fn probe_periodically__should_warn_for_a_chain_below_quorum() {
        // Given
        let (local, report) = must_polygon(&[("alchemy", ALCHEMY_URL, ProviderStatus::Healthy)]);
        let probe = || std::future::ready(report.clone());
        let (_whitelist_tx, whitelist_rx) = watch::channel(Some(must_whitelist_of(
            dtos::ForeignChain::Polygon,
            &["alchemy", "quicknode"],
            2,
        )));

        // When
        run_future_once(probe_periodically(
            probe,
            &local,
            whitelist_rx,
            MockTicker::new(1),
        ));

        // Then
        logs_assert(|lines: &[&str]| line_at_level(lines, "WARN", "foreign chain is below quorum"));
    }

    #[test]
    #[traced_test]
    fn log_chain_health__should_warn_only_for_a_chain_below_quorum_or_unhealthy() {
        // Given
        let health_per_chain = BTreeMap::from([
            (dtos::ForeignChain::Polygon, ChainHealth::Healthy),
            (
                dtos::ForeignChain::Base,
                ChainHealth::BelowQuorum {
                    whitelisted: 1,
                    quorum: 2,
                },
            ),
            (
                dtos::ForeignChain::Bnb,
                ChainHealth::UnhealthyProviders {
                    unhealthy: 1,
                    whitelisted: 2,
                },
            ),
            (dtos::ForeignChain::Ethereum, ChainHealth::NotWhitelisted),
        ]);

        // When
        log_chain_health(&health_per_chain);

        // Then
        let expected_levels = [
            ("INFO", "foreign chain is healthy"),
            ("WARN", "foreign chain is below quorum"),
            ("WARN", "foreign chain is unhealthy"),
            ("INFO", "foreign chain is not whitelisted"),
        ];
        logs_assert(|lines: &[&str]| {
            expected_levels
                .iter()
                .try_for_each(|(level, message)| line_at_level(lines, level, message))
        });
    }

    #[test]
    #[traced_test]
    fn probe_periodically__should_log_chain_health_unknown_before_the_whitelist_is_read() {
        // Given
        let (local, report) = must_polygon(&[("alchemy", ALCHEMY_URL, ProviderStatus::Healthy)]);
        let probe = || std::future::ready(report.clone());
        let (_whitelist_tx, whitelist_rx) = watch::channel(None);

        // When
        run_future_once(probe_periodically(
            probe,
            &local,
            whitelist_rx,
            MockTicker::new(1),
        ));

        // Then
        assert!(logs_contain("foreign chain health is unknown"));
    }

    #[test]
    fn probe_periodically__should_probe_again_once_the_whitelist_is_read() {
        // Given
        let probe_count = Cell::new(0);
        let (whitelist_tx, whitelist_rx) = watch::channel(None);
        let local = ForeignChainsConfig::default();
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            counting_probe(&probe_count),
            &local,
            whitelist_rx,
            MockTicker::new(1),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };

        // When
        whitelist_tx.send_replace(Some(must_whitelist_of(
            dtos::ForeignChain::Polygon,
            &["alchemy"],
            1,
        )));
        run_future_once(parked_probe_loop);

        // Then
        assert_eq!(probe_count.get(), 2);
    }

    #[test]
    fn probe_periodically__should_probe_once_when_a_whitelist_change_lands_with_a_tick() {
        // One run catches a lost `biased` half the time, because `select!` then polls a random
        // branch first.
        for _ in 0..64 {
            // Given
            let probe_count = Cell::new(0);
            let (whitelist_tx, whitelist_rx) = watch::channel(None);
            whitelist_tx.send_replace(Some(must_whitelist_of(
                dtos::ForeignChain::Polygon,
                &["alchemy"],
                1,
            )));
            let local = ForeignChainsConfig::default();

            // When
            let outcome = run_future_once(probe_periodically(
                counting_probe(&probe_count),
                &local,
                whitelist_rx,
                MockTicker::new(1),
            ));

            // Then
            assert_eq!(probe_count.get(), 1);
            assert!(
                matches!(outcome, MaybeReady::Future(_)),
                "the loop should park on its ticker rather than probe again"
            );
        }
    }

    #[test]
    fn probe_periodically__should_keep_probing_on_ticks_once_the_whitelist_sender_is_gone() {
        // Given
        let probe_count = Cell::new(0);
        let local = ForeignChainsConfig::default();
        let (whitelist_tx, whitelist_rx) = watch::channel(None);
        drop(whitelist_tx);
        let ticker = MockTicker::new(1);
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            counting_probe(&probe_count),
            &local,
            whitelist_rx,
            ticker.clone(),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };

        // When
        ticker.schedule(1);
        let outcome = run_future_once(parked_probe_loop);

        // Then
        assert_eq!(probe_count.get(), 2);
        assert!(
            matches!(outcome, MaybeReady::Future(_)),
            "the loop should park on its ticker rather than probe again"
        );
    }
}
