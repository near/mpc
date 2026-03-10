//! This file contains the primitives we need to interact with the NEAR blockchain:
//!     - CheckSync --> checks whether the node is fully synced
//!     - QueryViewFunction --> can call view methods on a contract
//!     - TODO(#2342): LatestFinalBlockInfoFecher --> fetches height and hash of the latest final block
//!     - TODO(#2342): SignedTransactionSubmitter --> submits  asigned transaction to the blockchain
use crate::types::RawObservedState;
use near_account_id::AccountId;
use std::future::Future;
use std::time::Duration;

/// Low-level trait for checking indexer sync status.
pub trait CheckSync: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Returns whether the node is currently syncing.
    fn is_syncing(&self) -> impl Future<Output = Result<bool, Self::Error>> + Send;

    const INTERVAL: Duration = Duration::from_millis(500);
    /// Polls [`is_syncing`](Self::is_syncing) until the node is fully synced.
    fn wait_for_full_sync(&self) -> impl Future<Output = ()> + Send {
        async {
            loop {
                match self.is_syncing().await {
                    Ok(false) => return,
                    Ok(true) => {
                        tracing::info!("waiting for full sync");
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

pub trait QueryViewFunction: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn query_view_function(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> impl Future<Output = Result<RawObservedState, Self::Error>> + Send;
}
