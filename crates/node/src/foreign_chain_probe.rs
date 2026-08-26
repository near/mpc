//! Periodic probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`].

use std::collections::BTreeSet;
use std::future::Future;

use foreign_chain_health_check::probe::{
    ProbeReport, ProviderHealth, ProviderStatus, probe_all_providers,
};
use mpc_node_config::ForeignChainsConfig;
use near_mpc_contract_interface::types as dtos;
use tracing::{info, warn};

use crate::metrics;
use crate::tick::Tick;

/// Asks every configured RPC provider which network it serves, once per tick of `ticker`, and
/// reports the verdicts as logs and metrics. Diagnostic only: nothing gates on the result.
pub async fn run_periodic_probe(foreign_chains: ForeignChainsConfig, ticker: impl Tick) {
    if foreign_chains.is_empty() {
        warn!("no foreign chain is configured: this node cannot verify foreign-chain transactions");
        return;
    }

    probe_periodically(|| probe_all_providers(&foreign_chains), ticker).await;
}

async fn probe_periodically<Probe: Future<Output = ProbeReport>>(
    probe: impl Fn() -> Probe,
    mut ticker: impl Tick,
) {
    loop {
        ticker.tick().await;

        info!("probing foreign-chain RPC providers");
        let report = probe().await;
        publish_metrics(&report);
        log_report(&report);
    }
}

fn is_probed(row: &ProviderHealth) -> bool {
    row.status != ProviderStatus::ProbeNotImplemented
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    probed: usize,
    healthy: usize,
}

fn summarize(rows: &[ProviderHealth]) -> Summary {
    Summary {
        probed: rows.iter().filter(|row| is_probed(row)).count(),
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

fn publish_metrics(report: &ProbeReport) {
    let probed_chains: BTreeSet<dtos::ForeignChain> = report
        .rows()
        .iter()
        .filter(|row| is_probed(row))
        .map(|row| row.chain)
        .collect();

    for (chain, counts) in report.counts_per_chain() {
        if !probed_chains.contains(&chain) {
            continue;
        }
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED
            .with_label_values(&[chain.label()])
            .set(counts.configured as i64);
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY
            .with_label_values(&[chain.label()])
            .set(counts.healthy as i64);
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::tick::MockTicker;
    use foreign_chain_health_check::probe::ProviderCounts;
    use prometheus::core::Collector as _;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

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

    #[test]
    fn summarize__should_count_only_the_providers_a_probe_covers() {
        // Given
        let rows = [
            row(dtos::ForeignChain::Base, "only", ProviderStatus::Healthy),
            row(dtos::ForeignChain::Bnb, "only", ProviderStatus::Unreachable),
            row(
                dtos::ForeignChain::Solana,
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
            dtos::ForeignChain::Solana,
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
                dtos::ForeignChain::Solana,
                "only",
                ProviderStatus::ProbeNotImplemented,
            ),
        ]);

        // When
        publish_metrics(&report);

        // Then
        let chains = labelled_chains(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED);
        assert!(chains.contains("bnb"));
        assert!(!chains.contains("solana"));
    }

    #[test]
    fn probe_periodically__should_probe_once_per_tick() {
        // Given
        let probe_count = Cell::new(0);
        let probe = || {
            probe_count.set(probe_count.get() + 1);
            std::future::ready(ProbeReport::from(vec![]))
        };

        // When
        run_future_once(probe_periodically(probe, MockTicker::new(3)));

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

        // When
        let MaybeReady::Future(parked_probe_loop) =
            run_future_once(probe_periodically(probe_dispatch, ticker.clone()))
        else {
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
        let outcome = run_future_once(run_periodic_probe(foreign_chains, ticker.clone()));

        // Then
        assert_eq!(ticker.unspent(), 1, "no round should have run");
        assert!(
            matches!(outcome, MaybeReady::Ready(())),
            "the probe should return rather than park on its ticker"
        );
    }
}
