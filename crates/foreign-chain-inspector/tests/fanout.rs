//! Integration tests for [`FanOut`].
//!
//! The mock is generated locally with `mockall::mock!` so the production trait
//! definition stays clean and `mockall` is only pulled in as a dev-dep. The
//! `impl Clone for Inspector` block makes the mock satisfy `FanOut`'s
//! `Inspector: Clone` bound; mockall doesn't deep-clone expectations, so the
//! factory below sets the same `expect_extract` behaviour on every clone.

#![expect(non_snake_case)]

use std::sync::Arc;

use assert_matches::assert_matches;
use foreign_chain_inspector::{FanOut, ForeignChainInspectionError, ForeignChainInspector};
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

fn fan_out_of(inspectors: Vec<MockInspector>) -> FanOut<MockInspector> {
    let inspectors: NonEmptyVec<MockInspector> = inspectors
        .try_into()
        .expect("test must provide at least one inspector");
    FanOut::new(inspectors)
}

#[tokio::test]
async fn fan_out__should_return_extracted_values_when_all_inspectors_agree() {
    // Given
    let make = || mock_returning(Arc::new(|| Ok(vec![1, 2, 3])));
    let fan_out = fan_out_of(vec![make(), make(), make()]);

    // When
    let result = fan_out.extract((), (), vec![]).await;

    // Then
    assert_eq!(result.unwrap(), vec![1, 2, 3]);
}

#[tokio::test]
async fn fan_out__should_return_mismatch_error_when_inspectors_disagree() {
    // Given: two inspectors agree on [1, 2, 3], one disagrees with [9, 9, 9].
    let agreeing = || mock_returning(Arc::new(|| Ok(vec![1, 2, 3])));
    let disagreeing = mock_returning(Arc::new(|| Ok(vec![9, 9, 9])));
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
async fn fan_out__should_propagate_inner_error_when_any_inspector_fails() {
    // Given: two inspectors succeed; one fails with NotFinalized.
    let succeeding = || mock_returning(Arc::new(|| Ok(vec![42])));
    let failing = mock_returning(Arc::new(|| Err(ForeignChainInspectionError::NotFinalized)));
    let fan_out = fan_out_of(vec![succeeding(), failing, succeeding()]);

    // When
    let result = fan_out.extract((), (), vec![]).await;

    // Then
    assert_matches!(result, Err(ForeignChainInspectionError::NotFinalized));
}

#[tokio::test]
async fn fan_out__should_succeed_when_built_from_a_single_inspector() {
    // Given: the smallest valid NonEmptyVec — a single inspector.
    let only = mock_returning(Arc::new(|| Ok(vec![7])));
    let fan_out = fan_out_of(vec![only]);

    // When
    let result = fan_out.extract((), (), vec![]).await;

    // Then
    assert_eq!(result.unwrap(), vec![7]);
}
