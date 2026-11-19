use std::collections::BTreeMap;

use foreign_chain_inspector::NetworkFingerprint;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    rows: Vec<ProviderHealth>,
}

impl From<Vec<ProviderHealth>> for ProbeReport {
    fn from(rows: Vec<ProviderHealth>) -> Self {
        Self { rows }
    }
}

impl ProbeReport {
    pub fn rows(&self) -> &[ProviderHealth] {
        &self.rows
    }

    /// The rows of `chain` whose provider was checked against the chain's expected network
    /// fingerprint.
    pub fn probed_rows(&self, chain: ForeignChain) -> Vec<&ProviderHealth> {
        self.rows
            .iter()
            .filter(|row| {
                row.chain == chain
                    && row.status.was_probed()
                    && row.status != ProviderStatus::MissingExpectedFingerprint
            })
            .collect()
    }

    pub fn counts_per_chain(&self) -> BTreeMap<ForeignChain, ProviderCounts> {
        let mut counts: BTreeMap<ForeignChain, ProviderCounts> = BTreeMap::new();
        for row in &self.rows {
            let entry = counts.entry(row.chain).or_default();
            entry.configured += 1;
            if row.status.is_healthy() {
                entry.healthy += 1;
            }
        }
        counts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderCounts {
    pub configured: usize,
    pub healthy: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHealth {
    pub chain: ForeignChain,
    pub provider: ProviderId,
    pub status: ProviderStatus,
}

/// One provider's verdict. Anything other than [`ProviderStatus::Healthy`] is unhealthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Healthy,
    WrongNetwork {
        expected: NetworkFingerprint,
        observed: NetworkFingerprint,
    },
    /// DNS, TLS, connection refused, 5xx, or rate limiting.
    Unreachable,
    /// The provider answered and refused: credentials invalid, or not enabled for this chain.
    RequestRejected,
    MalformedResponse,
    TimedOut,
    AuthTokenUnresolved,
    ClientSetupFailed,
    /// The chain is configured without an `expected_network_fingerprint`, so its providers cannot
    /// be checked.
    MissingExpectedFingerprint,
    ProbeNotImplemented,
}

impl ProviderStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub fn was_probed(&self) -> bool {
        !matches!(self, Self::ProbeNotImplemented)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn probed_rows__should_keep_only_the_rows_of_the_chain_checked_against_a_fingerprint() {
        // Given
        let row = |chain, provider: &str, status| ProviderHealth {
            chain,
            provider: ProviderId(provider.to_owned()),
            status,
        };
        let report = ProbeReport::from(vec![
            row(ForeignChain::Ethereum, "healthy", ProviderStatus::Healthy),
            row(ForeignChain::Ethereum, "down", ProviderStatus::Unreachable),
            row(
                ForeignChain::Ethereum,
                "unchecked",
                ProviderStatus::MissingExpectedFingerprint,
            ),
            row(
                ForeignChain::Ethereum,
                "no_inspector",
                ProviderStatus::ProbeNotImplemented,
            ),
            row(ForeignChain::Base, "other_chain", ProviderStatus::Healthy),
        ]);

        // When
        let probed: Vec<&str> = report
            .probed_rows(ForeignChain::Ethereum)
            .into_iter()
            .map(|row| row.provider.0.as_str())
            .collect();

        // Then
        assert_eq!(probed, ["healthy", "down"]);
    }
}
