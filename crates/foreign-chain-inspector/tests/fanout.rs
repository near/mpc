//! Integration tests for [`FanOut`].
//!
//! The mock is generated locally with `mockall::mock!` so the production trait
//! definition stays clean and `mockall` is only pulled in as a dev-dep. The
//! `impl Clone for Inspector` block makes the mock satisfy `FanOut`'s
//! `Inspector: Clone` bound; mockall doesn't deep-clone expectations, so the
//! factory below sets the same `expect_extract` behaviour on every clone.

#![expect(non_snake_case)]

use std::{io, sync::Arc};

use assert_matches::assert_matches;
use foreign_chain_inspector::{
    BlockConfirmations, FanOut, ForeignChainInspectionError, ForeignChainInspector,
};
use near_mpc_bounded_collections::NonEmptyVec;

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
        ) -> impl Future<Output = Result<Vec<u32>, ForeignChainInspectionError>> + Send;
    }

    impl Clone for Inspector {
        fn clone(&self) -> Self;
    }
}

type ResponseFn =
    Arc<dyn Fn() -> Result<Vec<u32>, ForeignChainInspectionError> + Send + Sync + 'static>;

/// Builds a mock that returns `response()` whenever `extract` is called, and
/// whose `clone()` produces another mock with the same behaviour.
///
/// `FanOut::extract` calls `clone()` on the inspector and only `extract` on the
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

/// Sugar for a `ResponseFn` that always returns `Ok(values)`.
fn ok(values: Vec<u32>) -> ResponseFn {
    Arc::new(move || Ok(values.clone()))
}

/// Sugar for a `ResponseFn` that always returns `Err(make())`. The closure
/// rebuilds the error on every call because `ForeignChainInspectionError` is
/// not `Clone`.
fn err(make: impl Fn() -> ForeignChainInspectionError + Send + Sync + 'static) -> ResponseFn {
    Arc::new(move || Err(make()))
}

fn fan_out_of(inspectors: Vec<MockInspector>) -> FanOut<MockInspector> {
    let inspectors: NonEmptyVec<MockInspector> = inspectors
        .try_into()
        .expect("test must provide at least one inspector");
    FanOut::new(inspectors)
}

mod all_succeed {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_extracted_values_when_all_inspectors_agree() {
        // Given
        let make = || mock_returning(ok(vec![1, 2, 3]));
        let fan_out = fan_out_of(vec![make(), make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn fan_out__should_succeed_with_empty_values_when_all_inspectors_return_empty() {
        // Given
        let make = || mock_returning(ok(vec![]));
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), Vec::<u32>::new());
    }

    #[tokio::test]
    async fn fan_out__should_succeed_when_built_from_a_single_inspector() {
        // Given: the smallest valid NonEmptyVec — a single inspector.
        let only = mock_returning(ok(vec![7]));
        let fan_out = fan_out_of(vec![only]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), vec![7]);
    }

    #[tokio::test]
    async fn fan_out__should_succeed_when_many_inspectors_agree() {
        // Given: five inspectors all returning the same values.
        let make = || mock_returning(ok(vec![10, 20, 30]));
        let fan_out = fan_out_of(vec![make(), make(), make(), make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), vec![10, 20, 30]);
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
        assert_eq!(result.unwrap(), vec![1, 2]);
    }
}

mod disagree_success {
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

mod split_success_and_non_transient {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_some_succeed_and_others_fail_non_transiently() {
        // Given
        let succeeding = mock_returning(ok(vec![1]));
        let failing = mock_returning(err(|| ForeignChainInspectionError::TransactionFailed));
        let fan_out = fan_out_of(vec![succeeding, failing]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_success_plus_non_transient_plus_transient() {
        // Given: one success, one non-transient failure, one transient failure.
        // The success/non-transient split still dominates: transient errors don't
        // mask the substantive disagreement.
        let succeeding = mock_returning(ok(vec![1]));
        let non_transient = mock_returning(err(|| ForeignChainInspectionError::TransactionFailed));
        let transient = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![succeeding, non_transient, transient]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }
}

mod non_transient_agree {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_propagate_transaction_failed_when_all_inspectors_agree() {
        // Given
        let make = || mock_returning(err(|| ForeignChainInspectionError::TransactionFailed));
        let fan_out = fan_out_of(vec![make(), make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::TransactionFailed));
    }

    #[tokio::test]
    async fn fan_out__should_propagate_log_index_out_of_bounds_when_all_inspectors_agree() {
        // Given
        let make = || mock_returning(err(|| ForeignChainInspectionError::LogIndexOutOfBounds));
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::LogIndexOutOfBounds)
        );
    }

    #[tokio::test]
    async fn fan_out__should_propagate_non_transient_when_single_inspector_fails() {
        // Given
        let only = mock_returning(err(|| ForeignChainInspectionError::TransactionFailed));
        let fan_out = fan_out_of(vec![only]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::TransactionFailed));
    }

    #[tokio::test]
    async fn fan_out__should_treat_same_non_transient_variant_with_different_inner_fields_as_agreement()
     {
        // Given: two EventLogFailedBorshSerialization errors wrapping different
        // inner `io::Error`s. They share a discriminant, so the fan-out must
        // consider them agreeing.
        let a = mock_returning(err(|| {
            ForeignChainInspectionError::EventLogFailedBorshSerialization(io::Error::other("first"))
        }));
        let b = mock_returning(err(|| {
            ForeignChainInspectionError::EventLogFailedBorshSerialization(io::Error::new(
                io::ErrorKind::NotFound,
                "second",
            ))
        }));
        let fan_out = fan_out_of(vec![a, b]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::EventLogFailedBorshSerialization(_))
        );
    }

    #[tokio::test]
    async fn fan_out__should_propagate_non_transient_when_transient_errors_are_also_present() {
        // Given: two inspectors report TransactionFailed (non-transient), one
        // reports NotFinalized (transient). Transient errors are tolerated, so
        // the non-transient agreement wins.
        let non_transient =
            || mock_returning(err(|| ForeignChainInspectionError::TransactionFailed));
        let transient = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![non_transient(), transient, non_transient()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::TransactionFailed));
    }
}

mod non_transient_disagree {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_return_mismatch_when_inspectors_report_different_non_transient_variants()
     {
        // Given
        let a = mock_returning(err(|| ForeignChainInspectionError::TransactionFailed));
        let b = mock_returning(err(|| ForeignChainInspectionError::LogIndexOutOfBounds));
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
    async fn fan_out__should_return_mismatch_when_non_transient_variants_disagree_among_three() {
        // Given: three different non-transient variants.
        let a = mock_returning(err(|| ForeignChainInspectionError::TransactionFailed));
        let b = mock_returning(err(|| ForeignChainInspectionError::LogIndexOutOfBounds));
        let c = mock_returning(err(|| {
            ForeignChainInspectionError::EventLogFailedBorshSerialization(io::Error::other("borsh"))
        }));
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

mod all_transient {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_propagate_transient_when_all_inspectors_fail_with_same_transient_variant()
     {
        // Given
        let make = || mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![make(), make()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::NotFinalized));
    }

    #[tokio::test]
    async fn fan_out__should_propagate_a_transient_when_transient_variants_disagree() {
        // Given: two different transient variants. The fan-out does not gate
        // transient errors on variant agreement, so the result must be transient
        // and must not be InspectorResponseMismatch.
        let a = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let b = mock_returning(err(|| {
            ForeignChainInspectionError::NotEnoughBlockConfirmations {
                expected: BlockConfirmations::from(10_u64),
                got: BlockConfirmations::from(3_u64),
            }
        }));
        let fan_out = fan_out_of(vec![a, b]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        let err = result.expect_err("expected fan-out to return an error");
        assert!(
            err.is_transient(),
            "expected a transient error, got: {err:?}",
        );
        assert!(
            !matches!(err, ForeignChainInspectionError::InspectorResponseMismatch),
            "transient disagreement must not be reported as mismatch, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn fan_out__should_propagate_transient_when_single_inspector_fails_transiently() {
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
}

mod tolerate_transient {
    use super::*;

    #[tokio::test]
    async fn fan_out__should_tolerate_transient_when_some_inspectors_succeed() {
        // Given: two inspectors succeed; one fails transiently. The transient
        // failure is tolerated when there is a substantive verdict.
        let succeeding = || mock_returning(ok(vec![42]));
        let transient = mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![succeeding(), transient, succeeding()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), vec![42]);
    }

    #[tokio::test]
    async fn fan_out__should_tolerate_transient_when_only_one_inspector_succeeds() {
        // Given
        let succeeding = mock_returning(ok(vec![99]));
        let make_transient = || mock_returning(err(|| ForeignChainInspectionError::NotFinalized));
        let fan_out = fan_out_of(vec![make_transient(), succeeding, make_transient()]);

        // When
        let result = fan_out.extract((), (), vec![]).await;

        // Then
        assert_eq!(result.unwrap(), vec![99]);
    }
}
