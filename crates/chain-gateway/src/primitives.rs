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
