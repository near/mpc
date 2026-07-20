//! This file contains the primitives we need to interact with the NEAR blockchain:
//!     - IsSyncing --> checks whether the node is fully synced
//!     - FetchLatestFinalBlockInfo-> fetches height and hash of the latest final block
//!     - SubmitSignedTransaction --> submits a signed transaction to the blockchain
//!
//! View calls go through `near_contract_transport::ViewContract`.
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
