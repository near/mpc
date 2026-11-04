//! Logs each probe round's provider verdicts and publishes them as metrics.

use std::collections::BTreeSet;

use foreign_chain_health_check::probe::{ProbeReport, ProviderHealth, ProviderStatus};
use near_mpc_contract_interface::types as dtos;
use tracing::{info, warn};

use crate::metrics;

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

pub(super) fn log_report(report: &ProbeReport) {
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

pub(super) fn publish_metrics(report: &ProbeReport) {
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
    use foreign_chain_health_check::probe::ProviderCounts;
    use prometheus::core::Collector as _;

    use super::*;
    use crate::foreign_chain_probe::test_utils::{gauges, row};

    fn labelled_chains(gauge: &prometheus::IntGaugeVec) -> BTreeSet<String> {
        gauge
            .collect()
            .iter()
            .flat_map(|family| family.get_metric())
            .flat_map(|metric| metric.get_label())
            .map(|label| label.value().to_string())
            .collect()
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
}
