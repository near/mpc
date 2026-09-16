use std::collections::BTreeMap;
use std::time::Duration;

use foreign_chain_inspector::{ProviderFailure, RecordProviderCall};
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

use crate::metrics;

/// Records provider calls under pseudonymous labels (`p0`, `p1`, ...). The `/metrics`
/// endpoint is public, so real provider names would reveal which RPC vendors the node uses.
#[derive(Clone)]
pub(crate) struct ProviderCallMetrics {
    chain: ForeignChain,
    labels: BTreeMap<ProviderId, String>,
}

impl ProviderCallMetrics {
    pub(super) fn new<'a>(
        chain: ForeignChain,
        providers: impl IntoIterator<Item = &'a ProviderId>,
    ) -> Self {
        let mut names: Vec<_> = providers.into_iter().collect();
        names.sort();
        let labels: BTreeMap<_, _> = names
            .into_iter()
            .enumerate()
            .map(|(index, provider)| (provider.clone(), format!("p{index}")))
            .collect();
        for label in labels.values() {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
                .with_label_values(&[chain.label(), label]);
            for kind in Kind::ALL {
                metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL.with_label_values(&[
                    chain.label(),
                    label,
                    kind.label(),
                ]);
            }
        }
        Self { chain, labels }
    }
}

impl RecordProviderCall for ProviderCallMetrics {
    fn record(&self, provider: &ProviderId, elapsed: Duration, failure: Option<ProviderFailure>) {
        // The node builds fan-out and this recorder from the same provider list, so this is
        // unreachable in practice. If this were to happen somehow, we drop the observation
        // instead of panicing.
        let Some(label) = self.labels.get(provider) else {
            tracing::debug!(
                chain = self.chain.label(),
                %provider,
                "provider call reported for an unknown provider; dropping the observation"
            );
            return;
        };
        let Some(failure) = failure else {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
                .with_label_values(&[self.chain.label(), label])
                .observe(elapsed.as_secs_f64());
            return;
        };
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
            .with_label_values(&[self.chain.label(), label, Kind::from(failure).label()])
            .inc();
    }
}

/// The `kind` label of [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL`].
#[derive(Clone, Copy)]
enum Kind {
    Transient,
    NonTransient,
    Timeout,
}

impl Kind {
    const ALL: [Self; 3] = [Self::Transient, Self::NonTransient, Self::Timeout];

    fn label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::NonTransient => "non_transient",
            Self::Timeout => "timeout",
        }
    }
}

impl From<ProviderFailure> for Kind {
    fn from(failure: ProviderFailure) -> Self {
        match failure {
            ProviderFailure::Unreachable => Self::Transient,
            ProviderFailure::Rejected | ProviderFailure::Malformed => Self::NonTransient,
            ProviderFailure::TimedOut => Self::Timeout,
        }
    }
}

/// The registry is process global, so each test records under its own chain label.
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    const PROVIDER: &str = "a-provider";

    fn timed(chain: ForeignChain, label: &str) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[chain.label(), label])
            .get_sample_count()
    }

    fn errored(chain: ForeignChain, label: &str, kind: Kind) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
            .with_label_values(&[chain.label(), label, kind.label()])
            .get()
    }

    fn exposed_registry() -> String {
        let mut buffer = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&prometheus::default_registry().gather(), &mut buffer)
            .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn provider_call_metrics__should_time_answers_and_count_failures() {
        // Given
        let chain = ForeignChain::Bitcoin;
        let provider = ProviderId(PROVIDER.to_string());
        let recorder = ProviderCallMetrics::new(chain, [&provider]);

        // When
        for failure in [
            None,
            Some(ProviderFailure::Unreachable),
            Some(ProviderFailure::Rejected),
            Some(ProviderFailure::Malformed),
            Some(ProviderFailure::TimedOut),
        ] {
            recorder.record(&provider, Duration::from_millis(10), failure);
        }

        // Then
        assert_eq!(timed(chain, "p0"), 1);
        assert_eq!(errored(chain, "p0", Kind::Transient), 1);
        assert_eq!(errored(chain, "p0", Kind::NonTransient), 2);
        assert_eq!(errored(chain, "p0", Kind::Timeout), 1);
    }

    #[test]
    fn provider_call_metrics__should_assign_labels_by_sorted_provider_name() {
        // Given
        let chain = ForeignChain::Starknet;
        let providers: Vec<ProviderId> = ["zeta", "alpha", "mid"]
            .into_iter()
            .map(|name| ProviderId(name.to_string()))
            .collect();
        let recorder = ProviderCallMetrics::new(chain, &providers);

        // When: the alphabetically middle provider answers once and fails once.
        recorder.record(&providers[2], Duration::from_millis(10), None);
        recorder.record(
            &providers[2],
            Duration::from_millis(10),
            Some(ProviderFailure::Unreachable),
        );

        // Then: its series is p1, not p2, so input order does not matter.
        assert_eq!(timed(chain, "p1"), 1);
        assert_eq!(errored(chain, "p1", Kind::Transient), 1);
        assert_eq!(timed(chain, "p0"), 0);
        assert_eq!(timed(chain, "p2"), 0);
        assert_eq!(errored(chain, "p0", Kind::Transient), 0);
        assert_eq!(errored(chain, "p2", Kind::Transient), 0);
    }

    #[test]
    fn provider_call_metrics_new__should_publish_every_series_before_the_first_call() {
        // When
        let _recorder =
            ProviderCallMetrics::new(ForeignChain::Ethereum, [&ProviderId(PROVIDER.to_string())]);

        // Then
        let exposed = exposed_registry();
        let count = |metric: &str| {
            exposed
                .lines()
                .filter(|line| {
                    line.starts_with(metric)
                        && line.contains(r#"chain="ethereum""#)
                        && line.contains(r#"provider="p0""#)
                })
                .count()
        };
        assert_eq!(
            count("mpc_foreign_chain_provider_inspection_seconds_count"),
            1
        );
        assert_eq!(count("mpc_foreign_chain_provider_errors_total"), 3);
    }
}
