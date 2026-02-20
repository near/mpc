//! This file contains the primitives we need to interact with the NEAR blockchain:
//!     - SyncChecker --> checks whether the node is fully synced
//!     - LatestFinalBlockInfoFecher --> fetches height and hash of the latest final block
//!     - SignedTransactionSubmitter --> submits  asigned transaction to the blockchain
//!     - ViewFunctionQueroier --> can call view methods on a contract
use crate::types::{LatestFinalBlockInfo, RawObservedState};
use async_trait::async_trait;
use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::time::Duration;

/// Low-level trait for checking indexer sync status.
#[async_trait]
pub trait SyncChecker: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Returns whether the node is currently syncing.
    async fn is_syncing(&self) -> Result<bool, Self::Error>;

    /// Polls [`is_syncing`](Self::is_syncing) until the node is fully synced.
    async fn wait_for_full_sync(&self) {
        const INTERVAL: Duration = Duration::from_millis(500);
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
            tokio::time::sleep(INTERVAL).await;
        }
    }
}

#[async_trait]
pub trait LatestFinalBlockInfoFetcher: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn latest_final_block(&self) -> Result<LatestFinalBlockInfo, Self::Error>;
}

/// note: this is the only trait that exposes NEAR internals, but it's only used by tests
#[async_trait]
pub trait SignedTransactionSubmitter: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait ViewFunctionQuerier: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<RawObservedState, Self::Error>;
}

// todo: test wait_for_full_sync
