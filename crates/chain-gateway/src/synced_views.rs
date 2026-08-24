use near_account_id::AccountId;
use near_contract_transport::{ObservedState, ViewArgs, ViewContract};

use crate::primitives::IsSyncing;

/// Gates every read on the node having caught up, so a view cannot answer from a
/// partially synced state.
pub(crate) struct SyncedViews<G, V> {
    gate: G,
    views: V,
}

impl<G, V> SyncedViews<G, V> {
    pub(crate) fn new(gate: G, views: V) -> Self {
        Self { gate, views }
    }
}

impl<G, V> ViewContract for SyncedViews<G, V>
where
    G: IsSyncing,
    V: ViewContract + Sync,
{
    type Error = V::Error;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState, Self::Error> {
        self.gate.wait_for_full_sync().await;
        self.views.view_contract(contract_id, view_args).await
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use near_contract_transport::test_utils::{RecordingViewer, TestViewError};
    use near_contract_transport::{ObservedState, ViewArgs, ViewContract};

    use super::SyncedViews;
    use crate::primitives::IsSyncing;

    /// Reports syncing until told otherwise, and counts how often it was asked.
    #[derive(Clone, Default)]
    struct FakeSync {
        syncing: Arc<AtomicBool>,
        failures_left: Arc<AtomicUsize>,
    }

    impl FakeSync {
        fn syncing() -> Self {
            Self {
                syncing: Arc::new(AtomicBool::new(true)),
                failures_left: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn synced() -> Self {
            Self::default()
        }

        /// Fails the first `count` polls, then reports synced.
        fn failing(count: usize) -> Self {
            Self {
                syncing: Arc::new(AtomicBool::new(false)),
                failures_left: Arc::new(AtomicUsize::new(count)),
            }
        }

        fn finish_syncing(&self) {
            self.syncing.store(false, Ordering::SeqCst);
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("cannot reach the node")]
    struct SyncUnavailable;

    impl IsSyncing for FakeSync {
        type Error = SyncUnavailable;

        async fn is_syncing(&self) -> Result<bool, Self::Error> {
            if self
                .failures_left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
            {
                return Err(SyncUnavailable);
            }
            Ok(self.syncing.load(Ordering::SeqCst))
        }
    }

    fn viewer() -> RecordingViewer<TestViewError> {
        RecordingViewer::answering(Ok(ObservedState {
            observed_at: 7.into(),
            value: b"read".to_vec(),
        }))
    }

    #[tokio::test]
    async fn view_contract__should_read_once_the_node_is_synced() {
        // Given
        let views = viewer();
        let gated = SyncedViews::new(FakeSync::synced(), views.clone());

        // When
        let observed = gated
            .view_contract(&"a.testnet".parse().unwrap(), ViewArgs::no_args("m"))
            .await
            .expect("a synced node should answer");

        // Then
        assert_eq!(observed.value, b"read");
        assert_eq!(views.calls().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn view_contract__should_not_read_while_the_node_is_syncing() {
        // Given
        let views = viewer();
        let gate = FakeSync::syncing();
        let gated = SyncedViews::new(gate.clone(), views.clone());
        let read = tokio::spawn(async move {
            gated
                .view_contract(&"a.testnet".parse().unwrap(), ViewArgs::no_args("m"))
                .await
        });

        // When: well past the poll interval, but still syncing
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Then
        assert!(!read.is_finished(), "the read must wait for sync");
        assert!(
            views.calls().is_empty(),
            "the backend must not be read while syncing"
        );

        gate.finish_syncing();
        read.await.unwrap().expect("the read should succeed");
        assert_eq!(views.calls().len(), 1);
    }

    /// A failed sync poll is not evidence of being synced, so the gate holds.
    #[tokio::test(start_paused = true)]
    async fn view_contract__should_keep_waiting_when_the_sync_check_fails() {
        // Given
        let views = viewer();
        let gated = SyncedViews::new(FakeSync::failing(3), views.clone());

        // When
        let observed = gated
            .view_contract(&"a.testnet".parse().unwrap(), ViewArgs::no_args("m"))
            .await;

        // Then
        observed.expect("it should retry past the failures and then read");
        assert_eq!(views.calls().len(), 1);
    }
}
