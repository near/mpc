//! This file contains the primitives we need to interact with the NEAR blockchain:
//!     - IsSyncing --> checks whether the node is fully synced
//!     - FetchLatestFinalBlockInfo-> fetches height and hash of the latest final block
//!     - SubmitSignedTransaction --> submits a signed transaction to the blockchain
//!
//! View calls go through [`near_contract_transport::ViewContract`].
use crate::types::LatestFinalBlockInfo;
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::future::Future;
use std::time::Duration;

/// Low-level trait for checking indexer sync status.
pub(crate) trait IsSyncing: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Returns whether the node is currently syncing.
    fn is_syncing(&self) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    const INTERVAL: Duration = Duration::from_millis(500);
    /// Polls [`is_syncing`](Self::is_syncing) until the node is fully synced.
    fn wait_for_full_sync(&self) -> impl Future<Output = ()> + Send {
        async {
            let mut attempt = 0u32;
            loop {
                match self.is_syncing().await {
                    Ok(false) => return,
                    Ok(true) => {
                        if attempt.is_multiple_of(120) {
                            tracing::info!("has been syncing for: {} seconds", attempt / 2);
                        }
                        attempt += 1;
                    }
                    Err(err) => {
                        tracing::warn!(err = %err, "error while waiting for sync");
                    }
                }
                tokio::time::sleep(Self::INTERVAL).await;
            }
        }
    }
}

pub(crate) async fn view_when_synced<T, F: Future<Output = T>>(
    sync: &impl IsSyncing,
    view: impl FnOnce() -> F,
) -> T {
    sync.wait_for_full_sync().await;
    view().await
}

pub(crate) trait FetchLatestFinalBlockInfo: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn fetch_latest_final_block_info(
        &self,
    ) -> impl Future<Output = Result<LatestFinalBlockInfo, Self::Error>> + Send;
}

/// note: this is the only trait that exposes NEAR internals, but it's only used crate-internally
pub(crate) trait SubmitSignedTransaction: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{IsSyncing, view_when_synced};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    struct MockSync {
        syncing: Arc<Mutex<bool>>,
    }

    impl IsSyncing for MockSync {
        type Error = Infallible;
        async fn is_syncing(&self) -> Result<bool, Self::Error> {
            Ok(*self.syncing.lock().unwrap())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn view_when_synced__should_not_start_view_until_synced() {
        // Given
        let syncing = Arc::new(Mutex::new(true));
        let sync = MockSync {
            syncing: syncing.clone(),
        };
        let view_started = Arc::new(AtomicBool::new(false));
        let started = view_started.clone();
        let handle = tokio::spawn(async move {
            view_when_synced(&sync, move || {
                started.store(true, Ordering::SeqCst);
                async { 42 }
            })
            .await
        });

        // When
        tokio::time::sleep(MockSync::INTERVAL * 2).await;
        let started_while_syncing = view_started.load(Ordering::SeqCst);
        *syncing.lock().unwrap() = false;

        // Then
        assert!(!started_while_syncing);
        assert_eq!(handle.await.unwrap(), 42);
    }
}
