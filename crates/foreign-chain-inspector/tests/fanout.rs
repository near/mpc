//! Integration tests for [`FanOut`].
//!
//! The mock is generated locally with `mockall::mock!` so the production trait
//! definition stays clean and `mockall` is only pulled in as a dev-dep. The
//! `impl Clone for Inspector` block makes the mock satisfy [`FanOut`]'s
//! `Inspector: Clone` bound; mockall doesn't deep-clone expectations, so the
//! factory below sets the same `expect_extract` behaviour on every clone.

#![expect(non_snake_case)]

use std::sync::Arc;

use assert_matches::assert_matches;
use foreign_chain_inspector::{
    BlockConfirmations, FanOut, ForeignChainInspectionError, ForeignChainInspector, HexBytes,
    Verdict,
};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::ProviderId;

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

/// Builds a mock that returns [`response()`] whenever `extract` is called, and
/// whose [`clone()`] produces another mock with the same behaviour.
///
/// [`FanOut::extract`] calls [`clone()`] on the inspector and only `extract` on the
/// resulting clone; the inverse never happens. We allow `times(0..)` on both
/// expectations so a single helper covers both "original" and "cloned" roles
/// without surprising the test author with expectation failures on drop.
fn mock_returning(response: ResponseFn) -> MockInspector {
    let mut m = MockInspector::new();
    let for_extract = Arc::clone(&response);
    m.expect_extract()
        .returning(move |_, _, _| Box::pin(std::future::ready(for_extract())))
        .times(0..);
    m.expect_clone()
        .returning(move || mock_returning(Arc::clone(&response)))
        .times(0..);
    m
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

/// Sugar for a [`ResponseFn`] that always extracts `values`.
fn ok(values: Vec<u32>) -> ResponseFn {
    Arc::new(move || Ok(Verdict::Extracted(values.clone())))
}

/// Sugar for a [`ResponseFn`] that always returns the verdict `make()`.
fn verdict(make: impl Fn() -> Verdict<u32> + Send + Sync + 'static) -> ResponseFn {
    Arc::new(move || Ok(make()))
}

/// Sugar for a [`ResponseFn`] that always returns `Err(make())`. The closure
/// rebuilds the error on every call because [`ForeignChainInspectionError`] is
/// not [`Clone`].
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
    async fn fan_out__should_succeed_with_empty_values_when_all_inspectors_return_empty() {
        // Given
        let make = || mock_returning(ok(vec![]));
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(Vec::<u32>::new()));
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
    async fn fan_out__should_succeed_when_many_inspectors_agree() {
        // Given: five inspectors all returning the same values.
        let make = || mock_returning(ok(vec![10, 20, 30]));
        let fan_out = fan_out_of(vec![make(), make(), make(), make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![10, 20, 30]));
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
        // Given
        let extracting = mock_returning(ok(vec![1]));
        let failing = mock_returning(verdict(|| Verdict::TransactionFailed));
        let fan_out = fan_out_of(vec![extracting, failing]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_extracted_plus_failing_verdict_plus_error() {
        // Given: one extraction, one failing verdict, one tolerated error. The verdict
        // split still dominates: errors don't mask the substantive disagreement.
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
    async fn fan_out__should_return_log_index_out_of_bounds_when_all_inspectors_agree() {
        // Given
        let make = || mock_returning(verdict(|| Verdict::LogIndexOutOfBounds));
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::LogIndexOutOfBounds));
    }

    #[tokio::test]
    async fn fan_out__should_return_the_verdict_when_single_inspector_rules_the_tx_out() {
        // Given
        let only = mock_returning(verdict(|| Verdict::TransactionFailed));
        let fan_out = fan_out_of(vec![only]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::TransactionFailed));
    }

    #[tokio::test]
    async fn fan_out__should_treat_same_verdict_variant_with_different_inner_fields_as_agreement() {
        // Given: two NonCanonicalBlock verdicts with different inner fields. They share a
        // discriminant, so the fan-out must consider them agreeing.
        let non_canonical = |block_number: u64| {
            mock_returning(verdict(move || Verdict::NonCanonicalBlock {
                block_number,
                receipt_hash: HexBytes(vec![1]),
                canonical_hash: HexBytes(vec![2]),
            }))
        };
        let fan_out = fan_out_of(vec![non_canonical(1), non_canonical(2)]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::NonCanonicalBlock { .. }));
    }

    #[tokio::test]
    async fn fan_out__should_return_the_verdict_when_errors_are_also_present() {
        // Given: two inspectors rule the transaction out, one fails to reach a verdict.
        // Errors are tolerated, so the verdict agreement wins.
        let failing = || mock_returning(verdict(|| Verdict::TransactionFailed));
        let erring = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![failing(), erring, failing()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::TransactionFailed));
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
    async fn fan_out__should_return_mismatch_when_verdict_variants_disagree_among_three() {
        // Given: three different failing verdicts.
        let a = mock_returning(verdict(|| Verdict::TransactionFailed));
        let b = mock_returning(verdict(|| Verdict::LogIndexOutOfBounds));
        let c = mock_returning(verdict(|| Verdict::TransactionNotFound));
        let fan_out = fan_out_of(vec![a, b, c]);

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
        // Given: two different errors. The fan-out does not gate errors on variant
        // agreement — they are not verdicts — so the result must be one of them and
        // must not be InspectorResponseMismatch.
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
    async fn fan_out__should_propagate_the_error_when_single_inspector_fails() {
        // Given
        let only = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![only]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::NotFinalized));
    }

    #[tokio::test]
    async fn fan_out__should_propagate_not_enough_block_confirmations_when_all_inspectors_agree() {
        // Given
        let make = || {
            mock_returning(err(|| {
                ForeignChainInspectionError::NotEnoughBlockConfirmations {
                    expected: BlockConfirmations::from(10_u64),
                    got: BlockConfirmations::from(3_u64),
                }
            }))
        };
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::NotEnoughBlockConfirmations { .. })
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
    async fn fan_out__should_tolerate_an_error_when_some_inspectors_extract() {
        // Given: two inspectors extract; one fails to reach a verdict. The error is
        // tolerated when there is a verdict.
        let extracting = || mock_returning(ok(vec![42]));
        let erring = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![extracting(), erring, extracting()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![42]));
    }

    #[tokio::test]
    async fn fan_out__should_tolerate_errors_when_only_one_inspector_extracts() {
        // Given
        let extracting = mock_returning(ok(vec![99]));
        let erring = || mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![erring(), extracting, erring()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![99]));
    }

    #[tokio::test]
    async fn fan_out__should_tolerate_a_provider_fault_when_another_inspector_extracts() {
        // Given: a refusal is the provider's own fault, deterministic or not.
        let rejected = mock_returning(err(|| {
            ForeignChainInspectionError::RpcRequestRejected("HTTP status 401".to_string())
        }));
        let extracting = mock_returning(ok(vec![7]));
        let fan_out = fan_out_of(vec![rejected, extracting]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Verdict::Extracted(vec![7]));
    }

    #[tokio::test]
    async fn fan_out__should_tolerate_a_provider_fault_when_another_inspector_reaches_a_verdict() {
        // Given: a malformed answer is the provider's fault; the verdict must win.
        let malformed = mock_returning(err(|| {
            ForeignChainInspectionError::MalformedRpcResponse("garbage".to_string())
        }));
        let failing = mock_returning(verdict(|| Verdict::TransactionFailed));
        let fan_out = fan_out_of(vec![malformed, failing]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Ok(Verdict::TransactionFailed));
    }
}
