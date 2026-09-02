//! Integration tests for [`FanOut`].
//!
//! The mock is generated locally with `mockall::mock!` so the production trait
//! definition stays clean and `mockall` is only pulled in as a dev-dep. The
//! `impl Clone for Inspector` block makes the mock satisfy [`FanOut`]'s
//! `Inspector: Clone` bound; mockall doesn't deep-clone expectations, so the
//! factory below sets the same `expect_extract` behaviour on every clone.

#![expect(non_snake_case)]

use std::{pin::Pin, sync::Arc, time::Duration};

use assert_matches::assert_matches;
use foreign_chain_inspector::{
    FanOut, ForeignChainInspectionError, ForeignChainInspector, HexBytes, ProviderFailure,
    RecordProviderCall, Verdict,
};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::ProviderId;
use tokio::sync::mpsc;

mockall::mock! {
    Inspector {}

    impl ForeignChainInspector for Inspector {
        type TransactionId = ();
        type Finality = ();
        type Extractor = ();
        type ExtractedValue = u32;

        fn extract(
            &self,
            tx_id: (),
            finality: (),
            extractors: Vec<()>,
        ) -> impl Future<Output = Result<Verdict<u32>, ForeignChainInspectionError>> + Send;
    }

    impl Clone for Inspector {
        fn clone(&self) -> Self;
    }
}

type ResponseFn =
    Arc<dyn Fn() -> Result<Verdict<u32>, ForeignChainInspectionError> + Send + Sync + 'static>;

/// Answers with `response()` whenever `extract` is called, and clones into another mock that
/// does the same.
///
/// [`FanOut::extract`] calls [`clone()`] on the inspector and only `extract` on the
/// resulting clone; the inverse never happens. We allow `times(0..)` on both
/// expectations so a single helper covers both "original" and "cloned" roles
/// without surprising the test author with expectation failures on drop.
fn mock_returning(response: ResponseFn) -> MockInspector {
    mock_awaiting(Arc::new(move || Box::pin(std::future::ready(response()))))
}

type Response =
    Pin<Box<dyn Future<Output = Result<Verdict<u32>, ForeignChainInspectionError>> + Send>>;
type ResponseFutureFn = Arc<dyn Fn() -> Response + Send + Sync>;

/// Answers with `respond()` whenever `extract` is called, and clones into another mock that
/// does the same.
fn mock_awaiting(respond: ResponseFutureFn) -> MockInspector {
    let mut m = MockInspector::new();
    let for_extract = Arc::clone(&respond);
    m.expect_extract()
        .returning(move |_, _, _| for_extract())
        .times(0..);
    m.expect_clone()
        .returning(move || mock_awaiting(Arc::clone(&respond)))
        .times(0..);
    m
}

/// tokio rounds timer deadlines up to the millisecond, so keep `delay` whole milliseconds.
fn mock_answering_after(delay: Duration) -> MockInspector {
    mock_awaiting(Arc::new(move || {
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(Verdict::Extracted(vec![1]))
        })
    }))
}

fn mock_never_answering(asked: mpsc::UnboundedSender<()>) -> MockInspector {
    mock_awaiting(Arc::new(move || {
        let asked = asked.clone();
        Box::pin(async move {
            let _ = asked.send(());
            std::future::pending().await
        })
    }))
}

/// Strict variant of [`mock_returning`]: the original is cloned exactly once,
/// and the resulting clone has `extract` called exactly once. Use this when a
/// test needs to verify that the fan-out spawns one task per inspector.
fn mock_called_once(response: ResponseFn) -> MockInspector {
    let mut original = MockInspector::new();
    original
        .expect_clone()
        .returning(move || {
            let response = Arc::clone(&response);
            let mut clone = MockInspector::new();
            clone
                .expect_extract()
                .returning(move |_, _, _| Box::pin(std::future::ready(response())))
                .times(1);
            clone
        })
        .times(1);
    original
}

fn ok(values: Vec<u32>) -> ResponseFn {
    Arc::new(move || Ok(Verdict::Extracted(values.clone())))
}

fn verdict(make: impl Fn() -> Verdict<u32> + Send + Sync + 'static) -> ResponseFn {
    Arc::new(move || Ok(make()))
}

fn err(make: impl Fn() -> ForeignChainInspectionError + Send + Sync + 'static) -> ResponseFn {
    Arc::new(move || Err(make()))
}

fn fan_out_of(inspectors: Vec<MockInspector>) -> FanOut<MockInspector> {
    let named: Vec<(ProviderId, MockInspector)> = inspectors
        .into_iter()
        .enumerate()
        .map(|(index, inspector)| (ProviderId(format!("provider-{index}")), inspector))
        .collect();
    let inspectors: NonEmptyVec<(ProviderId, MockInspector)> = named
        .try_into()
        .expect("test must provide at least one inspector");
    FanOut::new(inspectors)
}

type ReportedCall = (ProviderId, Duration, Option<ProviderFailure>);

/// A channel rather than a shared [`Vec`], so a test can await a call reported from a task it
/// does not hold.
struct ReportedCalls(mpsc::UnboundedSender<ReportedCall>);

impl RecordProviderCall for ReportedCalls {
    fn record(&self, provider: &ProviderId, elapsed: Duration, failure: Option<ProviderFailure>) {
        let _ = self.0.send((provider.clone(), elapsed, failure));
    }
}

fn measured_fan_out_of(
    inspectors: Vec<MockInspector>,
) -> (FanOut<MockInspector>, mpsc::UnboundedReceiver<ReportedCall>) {
    let (calls, reported) = mpsc::unbounded_channel();
    let fan_out = fan_out_of(inspectors).measuring(Arc::new(ReportedCalls(calls)));
    (fan_out, reported)
}

fn reported_by_provider(reported: &mut mpsc::UnboundedReceiver<ReportedCall>) -> Vec<ReportedCall> {
    let mut calls = Vec::new();
    while let Ok(call) = reported.try_recv() {
        calls.push(call);
    }
    calls.sort_by(|left, right| left.0.cmp(&right.0));
    calls
}

mod measurement {
    use super::*;

    #[tokio::test]
    async fn fan_out_extract__should_report_one_call_per_provider() {
        // Given
        let make = || mock_returning(ok(vec![1]));
        let (fan_out, mut reported) = measured_fan_out_of(vec![make(), make(), make()]);

        // When
        fan_out.extract((), (), vec![]).await.unwrap();

        // Then
        let calls = reported_by_provider(&mut reported);
        let providers: Vec<&str> = calls
            .iter()
            .map(|(provider, _, _)| provider.0.as_str())
            .collect();
        assert_eq!(providers, ["provider-0", "provider-1", "provider-2"]);
        assert!(calls.iter().all(|(_, _, failure)| failure.is_none()));
    }

    #[tokio::test]
    async fn fan_out_extract__should_report_a_failure_only_when_the_provider_is_at_fault() {
        // Given
        let unreachable = mock_returning(err(|| {
            ForeignChainInspectionError::RpcRequestFailed("connection refused".to_string())
        }));
        let not_finalized = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let ruling_out = mock_returning(verdict(|| Verdict::TransactionFailed));
        let (fan_out, mut reported) =
            measured_fan_out_of(vec![unreachable, not_finalized, ruling_out]);

        // When
        let _ = fan_out.extract((), (), vec![]).await;

        // Then
        let failures: Vec<_> = reported_by_provider(&mut reported)
            .into_iter()
            .map(|(_, _, failure)| failure)
            .collect();
        assert_eq!(failures, [Some(ProviderFailure::Unreachable), None, None]);
    }

    #[tokio::test(start_paused = true)]
    async fn fan_out_extract__should_report_the_time_the_provider_took_to_answer() {
        // Given
        let answers_in = Duration::from_millis(750);
        let (fan_out, mut reported) = measured_fan_out_of(vec![mock_answering_after(answers_in)]);

        // When
        fan_out.extract((), (), vec![]).await.unwrap();

        // Then
        assert_matches!(
            reported_by_provider(&mut reported)[..],
            [(_, elapsed, _)] if elapsed == answers_in
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fan_out_extract__should_report_a_timeout_when_the_caller_gives_up() {
        // Given
        let (asked, mut was_asked) = mpsc::unbounded_channel();
        let (fan_out, mut reported) = measured_fan_out_of(vec![mock_never_answering(asked)]);
        let mut extract = Box::pin(fan_out.extract((), (), vec![]));
        tokio::select! {
            _ = &mut extract => panic!("the provider never answers"),
            _ = was_asked.recv() => {}
        }

        // When
        drop(extract);

        // Then
        let call = tokio::time::timeout(Duration::from_secs(5), reported.recv())
            .await
            .expect("the abandoned call must be reported");
        assert_matches!(call, Some((_, _, Some(ProviderFailure::TimedOut))));
    }
}

mod all_extract {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_extracted_values_when_all_inspectors_agree() {
        // Given
        let make = || mock_returning(ok(vec![1, 2, 3]));
        let fan_out = fan_out_of(vec![make(), make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn fan_out__should_succeed_when_built_from_a_single_inspector() {
        // Given: the smallest valid NonEmptyVec — a single inspector.
        let only = mock_returning(ok(vec![7]));
        let fan_out = fan_out_of(vec![only]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![7]));
    }

    #[tokio::test]
    async fn fan_out__should_query_every_inspector_exactly_once() {
        // Given: strict mocks that panic on Drop if not invoked exactly once.
        let fan_out = fan_out_of(vec![
            mock_called_once(ok(vec![1, 2])),
            mock_called_once(ok(vec![1, 2])),
            mock_called_once(ok(vec![1, 2])),
        ]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then: mockall verifies call counts on drop.
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![1, 2]));
    }
}

mod extracted_values_disagree {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_mismatch_error_when_inspectors_disagree() {
        // Given: two inspectors agree on [1, 2, 3], one disagrees with [9, 9, 9].
        // Agreement is unanimity, not majority.
        let agreeing = || mock_returning(ok(vec![1, 2, 3]));
        let disagreeing = mock_returning(ok(vec![9, 9, 9]));
        let fan_out = fan_out_of(vec![agreeing(), disagreeing, agreeing()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_successes_differ_in_length() {
        // Given
        let a = mock_returning(ok(vec![1, 2, 3]));
        let b = mock_returning(ok(vec![1, 2]));
        let fan_out = fan_out_of(vec![a, b]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_successes_are_permutations() {
        // Given: Vec equality is order-sensitive, so a permutation must be a mismatch.
        let a = mock_returning(ok(vec![1, 2, 3]));
        let b = mock_returning(ok(vec![3, 2, 1]));
        let fan_out = fan_out_of(vec![a, b]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }
}

mod split_extracted_and_failing {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_some_extract_and_others_rule_the_tx_out() {
        // Given: one extraction, one failing verdict, one tolerated error. The error does not
        // mask the substantive disagreement.
        let extracting = mock_returning(ok(vec![1]));
        let failing = mock_returning(verdict(|| Verdict::TransactionFailed));
        let erring = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![extracting, failing, erring]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }
}

mod failing_verdicts_agree {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_transaction_failed_when_all_inspectors_agree() {
        // Given
        let make = || mock_returning(verdict(|| Verdict::TransactionFailed));
        let fan_out = fan_out_of(vec![make(), make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::TransactionFailed));
    }

    #[tokio::test]
    async fn fan_out__should_return_the_verdict_when_fielded_verdicts_are_identical() {
        // Given
        let non_canonical = || {
            mock_returning(verdict(|| Verdict::NonCanonicalBlock {
                block_number: 1,
                receipt_hash: HexBytes(vec![1]),
                canonical_hash: HexBytes(vec![2]),
            }))
        };
        let fan_out = fan_out_of(vec![non_canonical(), non_canonical()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::NonCanonicalBlock { .. }));
    }
}

mod failing_verdicts_disagree {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_inspectors_report_different_verdict_variants() {
        // Given
        let a = mock_returning(verdict(|| Verdict::TransactionFailed));
        let b = mock_returning(verdict(|| Verdict::LogIndexOutOfBounds));
        let fan_out = fan_out_of(vec![a, b]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_verdicts_share_a_variant_but_differ_in_fields() {
        // Given: both providers call the block non canonical but name different canonical
        // hashes, so they describe different chains.
        let non_canonical = |canonical_hash: Vec<u8>| {
            mock_returning(verdict(move || Verdict::NonCanonicalBlock {
                block_number: 1,
                receipt_hash: HexBytes(vec![1]),
                canonical_hash: HexBytes(canonical_hash.clone()),
            }))
        };
        let fan_out = fan_out_of(vec![non_canonical(vec![2]), non_canonical(vec![3])]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }
}

mod all_err {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_propagate_the_error_when_all_inspectors_fail_the_same_way() {
        // Given
        let make = || mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::NotFinalized));
    }

    #[tokio::test]
    async fn fan_out__should_propagate_an_error_when_error_variants_disagree() {
        // Given: two different errors. Errors are not verdicts, so the fan-out does not gate
        // them on variant agreement: the result must be one of them and must not be
        // InspectorResponseMismatch.
        let a = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let b = mock_returning(err(|| {
            ForeignChainInspectionError::RpcRequestRejected("HTTP status 401".to_string())
        }));
        let fan_out = fan_out_of(vec![a, b]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        let err = result.expect_err("expected fan-out to return an error");
        assert!(
            !matches!(err, ForeignChainInspectionError::InspectorResponseMismatch),
            "error disagreement must not be reported as mismatch, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn fan_out__should_propagate_a_provider_fault_when_no_inspector_reaches_a_verdict() {
        // Given
        let make = || {
            mock_returning(err(|| {
                ForeignChainInspectionError::MalformedRpcResponse("garbage".to_string())
            }))
        };
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }
}

mod tolerate_errors {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_tolerate_every_error_kind_when_one_inspector_extracts() {
        // Given: a transient condition and a deterministic provider fault around a single
        // extraction; both error kinds are tolerated alike.
        let not_finalized = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let rejected = mock_returning(err(|| {
            ForeignChainInspectionError::RpcRequestRejected("HTTP status 401".to_string())
        }));
        let extracting = mock_returning(ok(vec![7]));
        let fan_out = fan_out_of(vec![not_finalized, extracting, rejected]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![7]));
    }

    #[tokio::test]
    async fn fan_out__should_tolerate_every_error_kind_when_another_inspector_rules_the_tx_out() {
        // Given: the failing verdict wins over a transient condition and a provider fault.
        let not_finalized = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let malformed = mock_returning(err(|| {
            ForeignChainInspectionError::MalformedRpcResponse("garbage".to_string())
        }));
        let failing = mock_returning(verdict(|| Verdict::TransactionFailed));
        let fan_out = fan_out_of(vec![malformed, failing, not_finalized]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::TransactionFailed));
    }
}
