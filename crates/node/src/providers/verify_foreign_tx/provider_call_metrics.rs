use std::collections::BTreeMap;

use foreign_chain_inspector::{ProviderFailure, TimeProviderCall};
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};
use prometheus::HistogramTimer;

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
            for outcome in Outcome::ALL {
                metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS.with_label_values(&[
                    chain.label(),
                    label,
                    outcome.label(),
                ]);
            }
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS
                .with_label_values(&[chain.label(), label]);
            for failure in ProviderFailure::ALL {
                metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL.with_label_values(&[
                    chain.label(),
                    label,
                    kind_label(failure),
                ]);
            }
        }
        Self { chain, labels }
    }
}

/// The timer runs on the dropped series, so a call abandoned with the timer still running is
/// recorded there by the timer's own destructor. Observing a call discards the timer and records
/// the elapsed time under its outcome instead.
impl TimeProviderCall for ProviderCallMetrics {
    /// [`None`] for a provider this recorder does not know, whose calls go unrecorded.
    type Timer = Option<HistogramTimer>;

    fn start_timer(&self, provider: &ProviderId) -> Option<HistogramTimer> {
        // The node builds the fan-out and this recorder from the same provider list, so an
        // unknown provider is unreachable in practice. Should it happen, the call goes
        // unrecorded rather than panicking.
        let Some(label) = self.labels.get(provider) else {
            tracing::debug!(
                chain = self.chain.label(),
                %provider,
                "provider call started for an unknown provider; not recording it"
            );
            return None;
        };
        Some(
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS
                .with_label_values(&[self.chain.label(), label])
                .start_timer(),
        )
    }

    fn observe(
        &self,
        timer: Option<HistogramTimer>,
        provider: &ProviderId,
        failure: Option<ProviderFailure>,
    ) {
        let (Some(timer), Some(label)) = (timer, self.labels.get(provider)) else {
            return;
        };
        let elapsed = timer.stop_and_discard();
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[self.chain.label(), label, Outcome::of(failure).label()])
            .observe(elapsed);
        if let Some(failure) = failure {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
                .with_label_values(&[self.chain.label(), label, kind_label(failure)])
                .inc();
        }
    }
}

/// The `outcome` label of [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS`].
#[derive(Clone, Copy)]
enum Outcome {
    Answered,
    Failed,
}

impl Outcome {
    const ALL: [Self; 2] = [Self::Answered, Self::Failed];

    fn of(failure: Option<ProviderFailure>) -> Self {
        if failure.is_some() {
            Self::Failed
        } else {
            Self::Answered
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Failed => "failed",
        }
    }
}

/// The `kind` label of [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL`]. A call the fan-out
/// abandoned has no kind; it is timed in [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS`].
fn kind_label(failure: ProviderFailure) -> &'static str {
    match failure {
        ProviderFailure::Unreachable => "unreachable",
        ProviderFailure::Rejected => "rejected",
        ProviderFailure::Malformed => "malformed",
        ProviderFailure::MismatchedVerdict => "mismatched",
        ProviderFailure::TimedOut => "timed_out",
    }
}

/// The registry is process global, so each test records under its own chain label.
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    const PROVIDER: &str = "a-provider";

    fn timed(chain: ForeignChain, label: &str, outcome: Outcome) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[chain.label(), label, outcome.label()])
            .get_sample_count()
    }

    fn dropped(chain: ForeignChain, label: &str) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS
            .with_label_values(&[chain.label(), label])
            .get_sample_count()
    }

    fn errored(chain: ForeignChain, label: &str, failure: ProviderFailure) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
            .with_label_values(&[chain.label(), label, kind_label(failure)])
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
    fn provider_call_metrics__should_time_every_returned_call_and_count_failures() {
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
            Some(ProviderFailure::MismatchedVerdict),
        ] {
            recorder.observe(recorder.start_timer(&provider), &provider, failure);
        }

        // Then
        assert_eq!(timed(chain, "p0", Outcome::Answered), 1);
        assert_eq!(timed(chain, "p0", Outcome::Failed), 5);
        assert_eq!(dropped(chain, "p0"), 0);
        for failure in ProviderFailure::ALL {
            assert_eq!(errored(chain, "p0", failure), 1);
        }
    }

    #[test]
    fn provider_call_metrics__should_time_a_dropped_call_when_its_handle_is_dropped() {
        // Given
        let chain = ForeignChain::Base;
        let provider = ProviderId(PROVIDER.to_string());
        let recorder = ProviderCallMetrics::new(chain, [&provider]);

        // When
        drop(recorder.start_timer(&provider));

        // Then
        assert_eq!(dropped(chain, "p0"), 1);
        assert_eq!(timed(chain, "p0", Outcome::Answered), 0);
        assert_eq!(timed(chain, "p0", Outcome::Failed), 0);
        for failure in ProviderFailure::ALL {
            assert_eq!(errored(chain, "p0", failure), 0);
        }
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
        recorder.observe(recorder.start_timer(&providers[2]), &providers[2], None);
        recorder.observe(
            recorder.start_timer(&providers[2]),
            &providers[2],
            Some(ProviderFailure::Unreachable),
        );

        // Then: its series is p1, not p2, so input order does not matter.
        assert_eq!(timed(chain, "p1", Outcome::Answered), 1);
        assert_eq!(timed(chain, "p1", Outcome::Failed), 1);
        assert_eq!(errored(chain, "p1", ProviderFailure::Unreachable), 1);
        for label in ["p0", "p2"] {
            assert_eq!(timed(chain, label, Outcome::Answered), 0);
            assert_eq!(timed(chain, label, Outcome::Failed), 0);
            assert_eq!(errored(chain, label, ProviderFailure::Unreachable), 0);
        }
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
            2
        );
        assert_eq!(count("mpc_foreign_chain_provider_dropped_seconds_count"), 1);
        assert_eq!(count("mpc_foreign_chain_provider_errors_total"), 5);
    }
}
