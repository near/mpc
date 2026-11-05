//! Summarizes each probe round's provider verdicts, logs the unhealthy ones, and publishes the
//! verdicts as metrics.

use std::collections::BTreeSet;

use foreign_chain_health_check::probe::{ProbeReport, ProviderHealth};
use near_mpc_contract_interface::types as dtos;

use crate::metrics;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Summary {
    pub(super) probed: usize,
    pub(super) healthy: usize,
    /// Providers of a chain the probe cannot check.
    pub(super) unchecked: usize,
    pub(super) unchecked_chains: BTreeSet<&'static str>,
}

pub(super) fn summarize(rows: &[ProviderHealth]) -> Summary {
    let unchecked = || rows.iter().filter(|row| !row.status.was_probed());
    Summary {
        probed: rows.iter().filter(|row| row.status.was_probed()).count(),
        healthy: rows.iter().filter(|row| row.status.is_healthy()).count(),
        unchecked: unchecked().count(),
        unchecked_chains: unchecked().map(|row| row.chain.label()).collect(),
    }
}

pub(super) fn provider_is_unhealthy(row: &ProviderHealth) -> bool {
    row.status.was_probed() && !row.status.is_healthy()
}

pub(super) fn log_unhealthy_provider(row: &ProviderHealth) {
    tracing::warn!(
        chain = %row.chain.label(),
        provider = %row.provider,
        status = ?row.status,
        "foreign-chain RPC provider is unhealthy",
    );
}

pub(super) fn log_nothing_checked(rows: &[ProviderHealth]) {
    let chains: BTreeSet<&str> = rows.iter().map(|row| row.chain.label()).collect();
    tracing::warn!(
        ?chains,
        "no RPC provider was checked: none of the configured foreign chains has a probe"
    );
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
    use foreign_chain_health_check::probe::{ProviderCounts, ProviderStatus};
    use prometheus::core::Collector as _;
    use rstest::rstest;

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
                healthy: 1,
                unchecked: 1,
                unchecked_chains: BTreeSet::from(["ton"]),
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
                healthy: 0,
                unchecked: 1,
                unchecked_chains: BTreeSet::from(["ton"]),
            }
        );
    }

    #[rstest]
    #[case::healthy(ProviderStatus::Healthy, false)]
    #[case::not_checkable(ProviderStatus::ProbeNotImplemented, false)]
    #[case::unreachable(ProviderStatus::Unreachable, true)]
    #[case::missing_fingerprint(ProviderStatus::MissingExpectedFingerprint, true)]
    fn provider_is_unhealthy__should_hold_only_for_a_probed_provider_that_failed(
        #[case] status: ProviderStatus,
        #[case] expected: bool,
    ) {
        // Given
        let row = row(dtos::ForeignChain::Polygon, "only", status);

        // When
        let unhealthy = provider_is_unhealthy(&row);

        // Then
        assert_eq!(unhealthy, expected);
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
