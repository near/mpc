//! Integration tests for [`FanOut`].
//!
//! The mock is generated locally with `mockall::mock!` so the production trait
//! definition stays clean and `mockall` is only pulled in as a dev-dep. The
//! `impl Clone for Inspector` block makes the mock satisfy [`FanOut`]'s
//! `Inspector: Clone` bound; mockall doesn't deep-clone expectations, so the
//! factory below sets the same `expect_extract` behaviour on every clone.

#![expect(non_snake_case)]
pub mod common;

use std::{assert_matches, pin::Pin, sync::Arc, time::Duration};

use crate::common::{INSPECTION_TIMEOUT, any_single_provider, fan_out_of};
use foreign_chain_inspector::{
    FanOut, ForeignChainInspectionError, ForeignChainInspector, HexBytes, ProviderFailure,
    RpcQuorum, TimeProviderCall, Verdict,
};
use near_mpc_contract_interface::types::ProviderId;
use rstest::rstest;
use std::num::NonZeroUsize;
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

/// Builds a mock whose `extract` answers with `response()` at once.
fn mock_returning(response: ResponseFn) -> MockInspector {
    mock_awaiting(Arc::new(move || Box::pin(std::future::ready(response()))))
}

type Response =
    Pin<Box<dyn Future<Output = Result<Verdict<u32>, ForeignChainInspectionError>> + Send>>;
type ResponseFutureFn = Arc<dyn Fn() -> Response + Send + Sync>;

/// Builds a mock whose `extract` awaits the future `respond()` produces, and whose
/// `clone()` produces another mock with the same behaviour.
///
/// [`FanOut::extract_with_quorum`] calls `clone()` on the inspector and only `extract` on the
/// resulting clone; the inverse never happens. We allow `times(0..)` on both
/// expectations so a single helper covers both "original" and "cloned" roles
/// without surprising the test author with expectation failures on drop.
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

fn non_canonical_verdict(canonical_hash: u8) -> Verdict<u32> {
    Verdict::NonCanonicalBlock {
        block_number: 1,
        receipt_hash: HexBytes(vec![1]),
        canonical_hash: HexBytes(vec![canonical_hash]),
    }
}

fn non_canonical(canonical_hash: u8) -> ResponseFn {
    verdict(move || non_canonical_verdict(canonical_hash))
}

fn err(make: impl Fn() -> ForeignChainInspectionError + Send + Sync + 'static) -> ResponseFn {
    Arc::new(move || Err(make()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallEnd {
    Observed(Option<ProviderFailure>),
    Dropped,
}

type ReportedCall = (ProviderId, CallEnd);

#[derive(Clone)]
struct ReportedCalls(mpsc::UnboundedSender<ReportedCall>);

impl TimeProviderCall for ReportedCalls {
    type Timer = RecordingTimer;

    fn start_timer(&self, provider: &ProviderId) -> RecordingTimer {
        RecordingTimer {
            calls: self.0.clone(),
            provider: provider.clone(),
            observed: false,
        }
    }

    fn observe(
        &self,
        mut timer: RecordingTimer,
        provider: &ProviderId,
        failure: Option<ProviderFailure>,
    ) {
        timer.observed = true;
        let _ = self.0.send((provider.clone(), CallEnd::Observed(failure)));
    }
}

/// Reports the call as dropped unless it was observed first.
struct RecordingTimer {
    calls: mpsc::UnboundedSender<ReportedCall>,
    provider: ProviderId,
    observed: bool,
}

impl Drop for RecordingTimer {
    fn drop(&mut self) {
        if !self.observed {
            let _ = self.calls.send((self.provider.clone(), CallEnd::Dropped));
        }
    }
}

fn measured_fan_out_of(
    inspectors: Vec<MockInspector>,
) -> (
    FanOut<MockInspector, ReportedCalls>,
    mpsc::UnboundedReceiver<ReportedCall>,
) {
    let (calls, observed) = mpsc::unbounded_channel();
    let fan_out = fan_out_of(inspectors).measuring(ReportedCalls(calls));
    (fan_out, observed)
}

fn provider_id(index: usize) -> ProviderId {
    ProviderId(format!("provider-{index}"))
}

fn reported_by_provider(observed: &mut mpsc::UnboundedReceiver<ReportedCall>) -> Vec<ReportedCall> {
    let mut calls = Vec::new();
    while let Ok(call) = observed.try_recv() {
        calls.push(call);
    }
    calls.sort_by(|left, right| left.0.cmp(&right.0));
    calls
}

/// `required` of the providers named by `whitelisted` (indices into the fan-out).
fn quorum(required: usize, whitelisted: &[usize]) -> RpcQuorum {
    RpcQuorum {
        required: NonZeroUsize::new(required).unwrap(),
        whitelisted: whitelisted
            .iter()
            .map(|&index| provider_id(index))
            .collect(),
    }
}

fn transient() -> ResponseFn {
    err(|| ForeignChainInspectionError::RpcRequestFailed("connection refused".to_string()))
}

fn mock_answering_after(delay: Duration, response: ResponseFn) -> MockInspector {
    mock_awaiting(Arc::new(move || {
        let response = Arc::clone(&response);
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            response()
        })
    }))
}

fn mock_hanging() -> MockInspector {
    mock_awaiting(Arc::new(|| Box::pin(std::future::pending())))
}

mod measurement {
    use super::*;

    #[tokio::test]
    async fn fan_out_extract__should_report_every_provider_and_only_the_faulty_one_as_failed() {
        // Given
        let answering = mock_returning(ok(vec![1]));
        let unreachable = mock_returning(err(|| {
            ForeignChainInspectionError::RpcRequestFailed("connection refused".to_string())
        }));
        let not_finalized = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let (fan_out, mut observed) =
            measured_fan_out_of(vec![answering, unreachable, not_finalized]);

        // When
        fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await
            .unwrap();

        // Then
        assert_eq!(
            reported_by_provider(&mut observed),
            [
                (provider_id(0), CallEnd::Observed(None)),
                (
                    provider_id(1),
                    CallEnd::Observed(Some(ProviderFailure::Unreachable))
                ),
                (provider_id(2), CallEnd::Observed(None)),
            ]
        );
    }

    #[tokio::test]
    async fn fan_out_extract__should_report_a_dropped_call_when_the_caller_gives_up() {
        // Given
        let (asked, mut was_asked) = mpsc::unbounded_channel();
        let (fan_out, mut observed) = measured_fan_out_of(vec![mock_never_answering(asked)]);
        let quorum = any_single_provider(&fan_out);
        let mut extract =
            Box::pin(fan_out.extract_with_quorum(&quorum, INSPECTION_TIMEOUT, (), (), vec![]));
        tokio::select! {
            _ = &mut extract => panic!("the provider never answers"),
            _ = was_asked.recv() => {}
        }

        // When
        drop(extract);

        // Then
        let call = tokio::time::timeout(Duration::from_secs(5), observed.recv())
            .await
            .expect("the abandoned call must be observed");
        assert_matches!(call, Some((_, CallEnd::Dropped)));
    }
}

mod agreeing_verdicts {
    use super::*;

    #[rstest]
    #[case::all_inspectors_agree_on_extracted_values(
        vec![ok(vec![1, 2, 3]); 3],
        Verdict::Extracted(vec![1, 2, 3]),
    )]
    #[case::built_from_a_single_inspector(vec![ok(vec![7])], Verdict::Extracted(vec![7]))]
    #[case::all_inspectors_agree_on_transaction_failed(
        vec![verdict(|| Verdict::TransactionFailed); 3],
        Verdict::TransactionFailed,
    )]
    #[case::fielded_verdicts_are_identical(
        vec![non_canonical(2); 2],
        non_canonical_verdict(2),
    )]
    #[case::every_error_kind_is_tolerated_when_one_inspector_extracts(
        vec![
            err(|| ForeignChainInspectionError::NotFinalized),
            ok(vec![7]),
            err(|| ForeignChainInspectionError::RpcRequestRejected("HTTP status 401".to_string())),
        ],
        Verdict::Extracted(vec![7]),
    )]
    #[case::every_error_kind_is_tolerated_when_another_inspector_rules_the_tx_out(
        vec![
            err(|| ForeignChainInspectionError::MalformedRpcResponse("garbage".to_string())),
            verdict(|| Verdict::TransactionFailed),
            err(|| ForeignChainInspectionError::NotFinalized),
        ],
        Verdict::TransactionFailed,
    )]
    #[tokio::test]
    async fn fan_out__should_return_the_agreed_verdict(
        #[case] responses: Vec<ResponseFn>,
        #[case] expected: Verdict<u32>,
    ) {
        // Given
        let fan_out = fan_out_of(responses.into_iter().map(mock_returning).collect());

        // When
        let result = fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await;

        // Then
        assert_eq!(result.unwrap(), expected);
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
        let result = fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await;

        // Then: mockall verifies call counts on drop.
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![1, 2]));
    }
}

mod inspectors_disagree {
    use super::*;

    #[rstest]
    // Agreement is unanimity, not majority
    #[case::one_of_three_disagrees(vec![ok(vec![1, 2, 3]), ok(vec![9, 9, 9]), ok(vec![1, 2, 3])])]
    #[case::successes_differ_in_length(vec![ok(vec![1, 2, 3]), ok(vec![1, 2])])]
    // Vec equality is order-sensitive, so a permutation must be a mismatch
    #[case::successes_are_permutations(vec![ok(vec![1, 2, 3]), ok(vec![3, 2, 1])])]
    #[case::different_verdict_variants(vec![
        verdict(|| Verdict::TransactionFailed),
        verdict(|| Verdict::LogIndexOutOfBounds),
    ])]
    #[case::verdicts_share_a_variant_but_differ_in_fields(vec![non_canonical(2), non_canonical(3)])]
    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_inspectors_disagree(
        #[case] responses: Vec<ResponseFn>,
    ) {
        // Given
        let fan_out = fan_out_of(responses.into_iter().map(mock_returning).collect());

        // When
        let result = fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }
}

mod split_extracted_and_failing {
    use super::*;

    #[rstest]
    #[case::transaction_failed(Verdict::TransactionFailed)]
    #[case::transaction_not_found(Verdict::TransactionNotFound)]
    #[case::non_canonical_block(non_canonical_verdict(2))]
    #[case::log_index_out_of_bounds(Verdict::LogIndexOutOfBounds)]
    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_some_extract_and_others_rule_the_tx_out(
        #[case] ruling_out: Verdict<u32>,
    ) {
        // Given: one extraction, one failing verdict, one tolerated error. The error does not
        // mask the substantive disagreement.
        let extracting = mock_returning(ok(vec![1]));
        let failing = mock_returning(verdict(move || ruling_out.clone()));
        let erring = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![extracting, failing, erring]);

        // When
        let result = fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await;

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
        let result = fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await;

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
        let result = fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await;

        // Then
        let err = result.expect_err("expected fan-out to return an error");
        assert!(
            !matches!(err, ForeignChainInspectionError::InspectorResponseMismatch),
            "error disagreement must not be observed as mismatch, got: {err:?}",
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
        let result = fan_out
            .extract_with_quorum(
                &any_single_provider(&fan_out),
                INSPECTION_TIMEOUT,
                (),
                (),
                vec![],
            )
            .await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }
}

mod quorum {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_accept_the_verdict_when_exactly_the_quorum_of_whitelisted_providers_agree()
     {
        // Given
        let fan_out = fan_out_of(vec![
            mock_returning(ok(vec![1])),
            mock_returning(ok(vec![1])),
            mock_returning(transient()),
        ]);

        // When
        let result = fan_out
            .extract_with_quorum(&quorum(2, &[0, 1, 2]), INSPECTION_TIMEOUT, (), (), vec![])
            .await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![1]));
    }

    #[rstest]
    #[case::whitelisted_provider_fails(vec![ok(vec![1]), transient()], quorum(2, &[0, 1]), 1)]
    #[case::agreeing_provider_outside_the_whitelist_does_not_make_up_for_the_failed_one(
        vec![ok(vec![1]), transient(), ok(vec![1])],
        quorum(2, &[0, 1]),
        1,
    )]
    #[case::verdict_reached_only_outside_the_whitelist(
        vec![ok(vec![1]), transient()],
        quorum(1, &[1]),
        0,
    )]
    #[tokio::test]
    async fn fan_out__should_return_sub_quorum_when_too_few_whitelisted_providers_agree(
        #[case] responses: Vec<ResponseFn>,
        #[case] required_quorum: RpcQuorum,
        #[case] expected_agreeing: usize,
    ) {
        // Given
        let fan_out = fan_out_of(responses.into_iter().map(mock_returning).collect());

        // When
        let result = fan_out
            .extract_with_quorum(&required_quorum, INSPECTION_TIMEOUT, (), (), vec![])
            .await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::SubQuorum {
                agreeing,
                required,
            }) if agreeing == expected_agreeing && required == required_quorum.required
        );
    }

    #[rstest]
    #[case::provider_outside_the_whitelist_vetoes_the_verdict(vec![
        ok(vec![1]),
        ok(vec![1]),
        ok(vec![9]),
    ])]
    #[case::disagreement_instead_of_sub_quorum(vec![ok(vec![1]), ok(vec![9])])]
    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_providers_disagree_under_a_quorum(
        #[case] responses: Vec<ResponseFn>,
    ) {
        // Given
        let fan_out = fan_out_of(responses.into_iter().map(mock_returning).collect());

        // When
        let result = fan_out
            .extract_with_quorum(&quorum(2, &[0, 1]), INSPECTION_TIMEOUT, (), (), vec![])
            .await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }

    #[tokio::test]
    async fn fan_out__should_propagate_the_provider_error_when_nobody_reaches_a_verdict() {
        // Given
        let fan_out = fan_out_of(vec![
            mock_returning(transient()),
            mock_returning(transient()),
        ]);

        // When
        let result = fan_out
            .extract_with_quorum(&quorum(1, &[0, 1]), INSPECTION_TIMEOUT, (), (), vec![])
            .await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::RpcRequestFailed(_))
        );
    }
}

mod deadline {
    use super::*;

    #[rstest]
    #[case::hanging_provider_is_whitelisted(
        vec![mock_returning(ok(vec![1])), mock_returning(ok(vec![1])), mock_hanging()],
        quorum(2, &[0, 1, 2]),
        Ok(Verdict::Extracted(vec![1])),
    )]
    #[case::hanging_provider_is_not_whitelisted(
        vec![mock_returning(ok(vec![1])), mock_returning(ok(vec![1])), mock_hanging()],
        quorum(2, &[0, 1]),
        Ok(Verdict::Extracted(vec![1])),
    )]
    #[case::disagreeing_answer_after_the_deadline_is_ignored(
        vec![
            mock_returning(ok(vec![1])),
            mock_answering_after(INSPECTION_TIMEOUT * 2, ok(vec![9])),
        ],
        quorum(1, &[0]),
        Ok(Verdict::Extracted(vec![1])),
    )]
    #[case::disagreeing_answer_before_the_deadline_vetoes(
        vec![
            mock_returning(ok(vec![1])),
            mock_returning(ok(vec![1])),
            mock_answering_after(INSPECTION_TIMEOUT / 2, ok(vec![9])),
            mock_hanging(),
        ],
        quorum(2, &[0, 1]),
        Err(ForeignChainInspectionError::InspectorResponseMismatch),
    )]
    #[case::whitelisted_provider_misses_the_deadline(
        vec![mock_returning(ok(vec![1])), mock_hanging()],
        quorum(2, &[0, 1]),
        Err(ForeignChainInspectionError::SubQuorum {
            agreeing: 1,
            required: NonZeroUsize::new(2).unwrap(),
        }),
    )]
    #[case::every_provider_hangs(
        vec![mock_hanging(), mock_hanging()],
        quorum(1, &[0, 1]),
        Err(ForeignChainInspectionError::SubQuorum {
            agreeing: 0,
            required: NonZeroUsize::MIN,
        }),
    )]
    #[case::errored_provider_outranks_the_deadline(
        vec![mock_returning(transient()), mock_hanging()],
        quorum(1, &[0, 1]),
        Err(ForeignChainInspectionError::RpcRequestFailed("connection refused".to_string())),
    )]
    #[tokio::test(start_paused = true)]
    async fn fan_out__should_judge_only_the_answers_that_arrive_before_the_deadline(
        #[case] inspectors: Vec<MockInspector>,
        #[case] required_quorum: RpcQuorum,
        #[case] expected: Result<Verdict<u32>, ForeignChainInspectionError>,
    ) {
        // Given
        let fan_out = fan_out_of(inspectors);

        // When
        let result = fan_out
            .extract_with_quorum(&required_quorum, INSPECTION_TIMEOUT, (), (), vec![])
            .await;

        // Then
        assert_eq!(
            result.map_err(|error| error.to_string()),
            expected.map_err(|error| error.to_string()),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fan_out__should_judge_as_soon_as_the_last_provider_returns() {
        // Given
        let last_answer = INSPECTION_TIMEOUT / 5;
        let fan_out = fan_out_of(vec![
            mock_returning(ok(vec![1])),
            mock_answering_after(last_answer, ok(vec![1])),
        ]);
        let start = tokio::time::Instant::now();

        // When
        let result = fan_out
            .extract_with_quorum(&quorum(2, &[0, 1]), INSPECTION_TIMEOUT, (), (), vec![])
            .await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![1]));
        assert_eq!(start.elapsed(), last_answer);
    }

    #[tokio::test(start_paused = true)]
    async fn fan_out__should_report_a_dropped_call_for_a_provider_that_misses_the_deadline() {
        // Given
        let (fan_out, mut observed) =
            measured_fan_out_of(vec![mock_returning(ok(vec![1])), mock_hanging()]);

        // When
        fan_out
            .extract_with_quorum(&quorum(1, &[0]), INSPECTION_TIMEOUT, (), (), vec![])
            .await
            .unwrap();
        // An aborted task drops its timer only when the runtime next schedules it.
        tokio::task::yield_now().await;

        // Then
        assert_eq!(
            reported_by_provider(&mut observed),
            [
                (provider_id(0), CallEnd::Observed(None)),
                (provider_id(1), CallEnd::Dropped),
            ]
        );
    }
}
