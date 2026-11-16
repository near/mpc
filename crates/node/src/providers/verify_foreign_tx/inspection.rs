use std::hash::Hash;

use foreign_chain_inspector::{
    FanOut, ForeignChainInspectionError, ForeignChainInspector, RETRY_BACKOFF, RpcQuorum,
    TimeProviderCall, Verdict,
};
use near_mpc_contract_interface::types as dtos;
use tokio::time::Duration;
use tokio_util::time::FutureExt;

pub(crate) const FOREIGN_CHAIN_INSPECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// The result of one inspection: a [`Verdict`] on the extracted values, or the error that kept
/// the providers from reaching one.
pub(crate) type Inspection = Result<Verdict<dtos::ExtractedValue>, ForeignChainInspectionError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransientErrors {
    Fail,
    /// Retries a transient error until [`FOREIGN_CHAIN_INSPECTION_TIMEOUT`] runs out, then returns
    /// the last one. The pause before a retry starts at [`RETRY_BACKOFF`] and doubles each time,
    /// so a rate limited provider is never asked again at once.
    Retry,
}

pub(crate) async fn inspect<Inspector, Recorder>(
    fan_out: &FanOut<Inspector, Recorder>,
    quorum: &RpcQuorum,
    tx_id: Inspector::TransactionId,
    finality: Inspector::Finality,
    extractors: Vec<Inspector::Extractor>,
    transient_errors: TransientErrors,
) -> Inspection
where
    Inspector: ForeignChainInspector + Clone + Send + Sync + 'static,
    Inspector::TransactionId: Clone + Send + 'static,
    Inspector::Finality: Clone + Send + 'static,
    Inspector::Extractor: Clone + Send + 'static,
    Inspector::ExtractedValue: Into<dtos::ExtractedValue>
        + Send
        + 'static
        + Clone
        + PartialEq
        + Eq
        + Hash
        + std::fmt::Debug,
    Recorder: TimeProviderCall + Clone + 'static,
{
    let verdict = inspect_within_cap(transient_errors, || {
        fan_out.extract_with_quorum(quorum, tx_id.clone(), finality.clone(), extractors.clone())
    })
    .await?;
    Ok(verdict_into_dto(verdict))
}

async fn inspect_within_cap<V, Attempt>(
    transient_errors: TransientErrors,
    mut inspect_once: impl FnMut() -> Attempt,
) -> Result<Verdict<V>, ForeignChainInspectionError>
where
    Attempt: Future<Output = Result<Verdict<V>, ForeignChainInspectionError>>,
{
    let mut last_transient_error = None;
    let mut backoff = RETRY_BACKOFF;
    let attempts = async {
        loop {
            match inspect_once().await {
                Err(error)
                    if transient_errors == TransientErrors::Retry && error.is_transient() =>
                {
                    tracing::debug!(%error, "retrying a transient foreign chain inspection error");
                    last_transient_error = Some(error);
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
                inspection => return inspection,
            }
        }
    };
    let inspection = attempts.timeout(FOREIGN_CHAIN_INSPECTION_TIMEOUT).await;
    inspection.unwrap_or_else(|_| {
        Err(last_transient_error.unwrap_or(ForeignChainInspectionError::Timeout))
    })
}

fn verdict_into_dto<V: Into<dtos::ExtractedValue>>(
    verdict: Verdict<V>,
) -> Verdict<dtos::ExtractedValue> {
    match verdict {
        Verdict::Extracted(values) => {
            Verdict::Extracted(values.into_iter().map(Into::into).collect())
        }
        Verdict::TransactionFailed => Verdict::TransactionFailed,
        Verdict::TransactionNotFound => Verdict::TransactionNotFound,
        Verdict::NonCanonicalBlock {
            block_number,
            receipt_hash,
            canonical_hash,
        } => Verdict::NonCanonicalBlock {
            block_number,
            receipt_hash,
            canonical_hash,
        },
        Verdict::LogIndexOutOfBounds => Verdict::LogIndexOutOfBounds,
        Verdict::AccountNotFound => Verdict::AccountNotFound,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use foreign_chain_inspector::bitcoin::BitcoinExtractedValue;
    use near_mpc_bounded_collections::NonEmptyVec;
    use near_mpc_contract_interface::types::ProviderId;
    use std::assert_matches;
    use std::cell::Cell;
    use std::collections::BTreeSet;
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Fails with a transient error on its first call and finds one block hash after that.
    #[derive(Clone, Default)]
    struct FlakyInspector {
        calls: Arc<AtomicUsize>,
    }

    impl ForeignChainInspector for FlakyInspector {
        type TransactionId = ();
        type Finality = ();
        type Extractor = ();
        type ExtractedValue = BitcoinExtractedValue;

        async fn extract(
            &self,
            _: (),
            _: (),
            _: Vec<()>,
        ) -> Result<Verdict<BitcoinExtractedValue>, ForeignChainInspectionError> {
            match self.calls.fetch_add(1, Ordering::SeqCst) {
                0 => Err(transient_error()),
                _ => Ok(Verdict::Extracted(vec![BitcoinExtractedValue::BlockHash(
                    [7; 32].into(),
                )])),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn inspect__should_retry_through_the_fan_out_and_convert_the_values() {
        // Given
        let provider = ProviderId("p0".to_string());
        let inspector = FlakyInspector::default();
        let fan_out = FanOut::new(
            NonEmptyVec::from_vec(vec![(provider.clone(), inspector.clone())]).unwrap(),
        );
        let quorum = RpcQuorum {
            required: NonZeroUsize::MIN,
            whitelisted: BTreeSet::from([provider]),
        };

        // When
        let inspection = inspect(&fan_out, &quorum, (), (), vec![()], TransientErrors::Retry).await;

        // Then
        assert_eq!(
            inspection.unwrap(),
            Verdict::Extracted(vec![dtos::ExtractedValue::BitcoinExtractedValue(
                dtos::BitcoinExtractedValue::BlockHash(dtos::Hash256([7; 32])),
            )])
        );
        assert_eq!(inspector.calls.load(Ordering::SeqCst), 2);
    }

    fn transient_error() -> ForeignChainInspectionError {
        ForeignChainInspectionError::RpcRequestFailed("unreachable".to_string())
    }

    #[tokio::test(start_paused = true)]
    async fn inspect_within_cap__should_retry_transient_errors_until_a_verdict() {
        // Given
        let calls = Cell::new(0);
        let inspect_once = || {
            calls.set(calls.get() + 1);
            let inspection = match calls.get() {
                1 | 2 => Err(transient_error()),
                _ => Ok(Verdict::Extracted(vec![7u8])),
            };
            async move { inspection }
        };

        // When
        let inspection = inspect_within_cap(TransientErrors::Retry, inspect_once).await;

        // Then
        assert_eq!(inspection.unwrap(), Verdict::Extracted(vec![7u8]));
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn inspect_within_cap__should_return_the_last_transient_error_when_the_cap_runs_out() {
        // Given
        let calls = Cell::new(0);
        let started = tokio::time::Instant::now();
        let inspect_once = || {
            calls.set(calls.get() + 1);
            let error = match calls.get() {
                1 => transient_error(),
                _ => ForeignChainInspectionError::NotFinalized,
            };
            async { Err::<Verdict<u8>, _>(error) }
        };

        // When
        let inspection = inspect_within_cap(TransientErrors::Retry, inspect_once).await;

        // Then
        assert_matches!(inspection, Err(ForeignChainInspectionError::NotFinalized));
        assert_eq!(started.elapsed(), FOREIGN_CHAIN_INSPECTION_TIMEOUT);
        assert!(calls.get() > 1);
    }

    #[tokio::test(start_paused = true)]
    async fn inspect_within_cap__should_bound_the_fan_outs_within_the_cap_when_rate_limited() {
        // Given
        let calls = Cell::new(0);
        let inspect_once = || {
            calls.set(calls.get() + 1);
            async {
                Err::<Verdict<u8>, _>(ForeignChainInspectionError::RpcRequestFailed(
                    "HTTP status 429".to_string(),
                ))
            }
        };

        // When
        inspect_within_cap(TransientErrors::Retry, inspect_once)
            .await
            .unwrap_err();

        // Then
        assert!(calls.get() <= 5, "{} fan outs within the cap", calls.get());
    }

    #[tokio::test(start_paused = true)]
    async fn inspect_within_cap__should_not_retry_a_transient_error_when_told_to_fail() {
        // Given
        let calls = Cell::new(0);
        let inspect_once = || {
            calls.set(calls.get() + 1);
            async { Err::<Verdict<u8>, _>(transient_error()) }
        };

        // When
        let inspection = inspect_within_cap(TransientErrors::Fail, inspect_once).await;

        // Then
        assert_matches!(
            inspection,
            Err(ForeignChainInspectionError::RpcRequestFailed(_))
        );
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn inspect_within_cap__should_not_retry_an_inspector_mismatch() {
        // Given
        let calls = Cell::new(0);
        let inspect_once = || {
            calls.set(calls.get() + 1);
            async { Err::<Verdict<u8>, _>(ForeignChainInspectionError::InspectorResponseMismatch) }
        };

        // When
        let inspection = inspect_within_cap(TransientErrors::Retry, inspect_once).await;

        // Then
        assert_matches!(
            inspection,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn inspect_within_cap__should_time_out_a_hanging_inspection_when_told_to_fail() {
        // Given
        let inspect_once = || std::future::pending::<Result<Verdict<u8>, _>>();

        // When
        let inspection = inspect_within_cap(TransientErrors::Fail, inspect_once).await;

        // Then
        assert_matches!(inspection, Err(ForeignChainInspectionError::Timeout));
    }
}
