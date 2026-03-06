use crate::types::{LatestFinalBlockInfo, ObservedState, RawObservedState};
use async_trait::async_trait;
use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::time::Duration;

/// Low-level trait for checking indexer sync status.
#[async_trait]
pub(crate) trait SyncChecker: Send + Sync + Clone + 'static {
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
pub(crate) trait LatestFinalBlockInfoFetcher: Send + Sync + Clone + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn latest_final_block(&self) -> Result<LatestFinalBlockInfo, Self::Error>;
}

#[async_trait]
pub(crate) trait SignedTransactionSubmitter: Send + Sync + Clone + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error>;
}

#[async_trait]
pub(crate) trait ViewFunctionQuerier: Send + Sync + Clone + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<RawObservedState, Self::Error>;
}

pub(crate) trait HasSyncChecker {
    type C: SyncChecker;
    fn get_checker(&self) -> &Self::C;
}

pub(crate) trait HasViewFunctionQuerier {
    type V: ViewFunctionQuerier;
    fn view_querier(&self) -> &Self::V;
}
pub(crate) trait HasLatestFinalBlockInfoFetcher {
    type F: LatestFinalBlockInfoFetcher;
    fn fetcher(&self) -> &Self::F;
}

pub(crate) trait HasSignedTransactionSubmitter {
    type S: SignedTransactionSubmitter;
    fn submitter(&self) -> &Self::S;
}

#[async_trait]
impl<T> SyncChecker for T
where
    T: HasSyncChecker + Send + Sync + Clone + 'static,
{
    type Error = <T::C as SyncChecker>::Error;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.get_checker().is_syncing().await
    }
}

#[async_trait]
impl<T> ViewFunctionQuerier for T
where
    T: HasViewFunctionQuerier + Send + Sync + Clone + 'static,
{
    type Error = <T::V as ViewFunctionQuerier>::Error;

    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, Self::Error> {
        self.view_querier()
            .view_function_query(contract_id, method_name, args)
            .await
    }
}
