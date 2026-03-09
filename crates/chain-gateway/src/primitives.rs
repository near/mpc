//! This file contains the primitives we need to interact with the NEAR blockchain:
//!     - SyncChecker --> checks whether the node is fully synced
//!     - ViewFunctionQuerySubmitter --> can call view methods on a contract
//!     - TODO(#2342): LatestFinalBlockInfoFecher --> fetches height and hash of the latest final block
//!     - TODO(#2342): SignedTransactionSubmitter --> submits  asigned transaction to the blockchain
use crate::types::RawObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use std::time::Duration;

/// Low-level trait for checking indexer sync status.
#[async_trait]
pub trait SyncChecker: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Returns whether the node is currently syncing.
    async fn is_syncing(&self) -> Result<bool, Self::Error>;

    const INTERVAL: Duration = Duration::from_millis(500);
    /// Polls [`is_syncing`](Self::is_syncing) until the node is fully synced.
    async fn wait_for_full_sync(&self) {
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

#[async_trait]
pub trait ViewFunctionQuerySubmitter: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<RawObservedState, Self::Error>;
}
