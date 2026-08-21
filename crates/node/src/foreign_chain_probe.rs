//! Startup probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`].

use std::collections::BTreeSet;

use foreign_chain_health_check::probe::{
    ProbeReport, ProviderHealth, ProviderStatus, probe_all_providers,
};
use mpc_node_config::ForeignChainsConfig;
use near_mpc_contract_interface::types as dtos;
use tracing::{info, warn};

use crate::metrics;

/// Asks every configured RPC provider which network it serves and logs a line per provider plus an
/// `x/y providers healthy` summary. Diagnostic only.
pub async fn run_startup_probe(foreign_chains: ForeignChainsConfig) {
    if foreign_chains.is_empty() {
        warn!("no foreign chain is configured: this node cannot verify foreign-chain transactions");
        return;
    }

    info!("probing foreign-chain RPC providers");
    let report = probe_all_providers(&foreign_chains).await;
    publish_metrics(&report);
    log_report(&report);
}

fn is_probed(row: &ProviderHealth) -> bool {
    row.status != ProviderStatus::ProbeNotImplemented
}

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
            "no RPC provider was checked at startup: the foreign chains configured cannot be checked by the node"
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
    use prometheus::core::Collector as _;

    /// The chains a gauge holds a series for.
    fn labelled_chains(gauge: &prometheus::IntGaugeVec) -> Vec<String> {
        gauge
            .collect()
            .iter()
            .flat_map(|family| family.get_metric())
            .flat_map(|metric| metric.get_label())
            .map(|label| label.value().to_string())
            .collect()
    }

    fn counts(chain: &str) -> (i64, i64) {
        (
            metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED
                .with_label_values(&[chain])
                .get(),
            metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY
                .with_label_values(&[chain])
                .get(),
        )
    }

    fn row(chain: dtos::ForeignChain, provider: &str, status: ProviderStatus) -> ProviderHealth {
        ProviderHealth {
            chain,
            provider: dtos::ProviderId(provider.to_string()),
            status,
        }
    }

    /// Solana has no probe, so its provider belongs in neither total.
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
        assert_eq!((summary.healthy, summary.probed), (1, 2));
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
        assert_eq!(summary.probed, 0);
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
        assert_eq!(counts("hyper_evm"), (2, 1));
        assert_eq!(counts("aptos"), (1, 0));
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
        assert!(chains.contains(&"bnb".to_string()));
        assert!(!chains.contains(&"solana".to_string()));
    }
}
