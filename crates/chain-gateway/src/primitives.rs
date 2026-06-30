//! This file contains the primitives we need to interact with the NEAR blockchain:
//!     - IsSyncing --> checks whether the node is fully synced
//!     - QueryViewFunction --> can call view methods on a contract
//!     - FetchLatestFinalBlockInfo-> fetches height and hash of the latest final block
//!     - SubmitSignedTransaction --> submits  asigned transaction to the blockchain
use crate::types::LatestFinalBlockInfo;
use crate::types::ObservedState;
use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::future::Future;
use std::time::Duration;

/// Snapshot of the node's sync progress relative to its peers.
pub(crate) struct SyncStatus {
    /// Whether the node currently reports itself as syncing.
    pub syncing: bool,
    /// Height of the node's local head.
    pub head_height: u64,
    /// Highest block height advertised by a connected peer, if any.
    pub max_peer_height: Option<u64>,
}

/// How far behind the highest peer the local head may be while still counting
/// as caught up. Absorbs peers advancing a block or two between polls; the
/// `syncing` flag carries the steady state.
const SYNC_HEIGHT_TOLERANCE: u64 = 5;

impl SyncStatus {
    /// Whether the node is fully synced to the network head.
    ///
    /// The `syncing` flag alone is insufficient: on a freshly state-syncing
    /// node (or one returning from long downtime) it reads `false` during the
    /// startup window before the node has learned it is behind, which would pin
    /// the streamer's `LatestSynced` cursor at a stale head it can never reach.
    /// We also require the head to be within [`SYNC_HEIGHT_TOLERANCE`] of the
    /// highest connected peer. While no peer reports a height we cannot confirm
    /// we are caught up, so we keep waiting.
    fn is_caught_up(&self) -> bool {
        if self.syncing {
            return false;
        }
        match self.max_peer_height {
            None => false,
            Some(peer_height) => {
                peer_height.saturating_sub(self.head_height) <= SYNC_HEIGHT_TOLERANCE
            }
        }
    }
}

/// Low-level trait for checking indexer sync status.
pub(crate) trait IsSyncing: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    /// Returns the node's current sync progress relative to its peers.
    fn sync_status(&self) -> impl Future<Output = Result<SyncStatus, Self::Error>> + Send;

    const INTERVAL: Duration = Duration::from_millis(500);
    /// Polls [`sync_status`](Self::sync_status) until the node has caught up to
    /// the network head.
    fn wait_for_full_sync(&self) -> impl Future<Output = ()> + Send {
        async {
            let mut attempt = 0u32;
            loop {
                match self.sync_status().await {
                    Ok(status) if status.is_caught_up() => return,
                    Ok(_) => {
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

pub(crate) trait QueryViewFunction: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn query_view_function(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> impl Future<Output = Result<ObservedState, Self::Error>> + Send;
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
    use super::{SYNC_HEIGHT_TOLERANCE, SyncStatus};

    #[test]
    fn is_caught_up__should_be_false_while_node_reports_syncing() {
        // Given
        let status = SyncStatus {
            syncing: true,
            head_height: 257_000_000,
            max_peer_height: Some(257_000_000),
        };

        // When
        let caught_up = status.is_caught_up();

        // Then
        assert!(!caught_up);
    }

    /// The #3623 wedge: at fresh boot the node sits at genesis with `syncing`
    /// transiently `false` before it has learned a peer is far ahead.
    #[test]
    fn is_caught_up__should_be_false_at_genesis_before_sync_starts() {
        // Given
        let status = SyncStatus {
            syncing: false,
            head_height: 42_376_888,
            max_peer_height: Some(257_409_058),
        };

        // When
        let caught_up = status.is_caught_up();

        // Then
        assert!(!caught_up);
    }

    /// Same wedge after long downtime: the stale head is far above genesis but
    /// still far below the peers.
    #[test]
    fn is_caught_up__should_be_false_with_stale_head_far_above_genesis() {
        // Given
        let status = SyncStatus {
            syncing: false,
            head_height: 200_000_000,
            max_peer_height: Some(257_409_058),
        };

        // When
        let caught_up = status.is_caught_up();

        // Then
        assert!(!caught_up);
    }

    /// Until a peer advertises a height we cannot confirm we are caught up.
    #[test]
    fn is_caught_up__should_be_false_when_no_peer_height_known() {
        // Given
        let status = SyncStatus {
            syncing: false,
            head_height: 257_409_058,
            max_peer_height: None,
        };

        // When
        let caught_up = status.is_caught_up();

        // Then
        assert!(!caught_up);
    }

    #[test]
    fn is_caught_up__should_be_true_when_head_reaches_peer_height() {
        // Given
        let peer_head = 257_409_058;
        let status = SyncStatus {
            syncing: false,
            head_height: peer_head,
            max_peer_height: Some(peer_head),
        };

        // When
        let caught_up = status.is_caught_up();

        // Then
        assert!(caught_up);
    }

    /// Peers may advance a few blocks between polls; being within the tolerance
    /// still counts as caught up.
    #[test]
    fn is_caught_up__should_be_true_within_tolerance_of_peer_height() {
        // Given
        let peer_head = 257_409_058;
        let status = SyncStatus {
            syncing: false,
            head_height: peer_head - SYNC_HEIGHT_TOLERANCE,
            max_peer_height: Some(peer_head),
        };

        // When
        let caught_up = status.is_caught_up();

        // Then
        assert!(caught_up);
    }

    /// A node slightly ahead of the peers it currently sees is caught up.
    #[test]
    fn is_caught_up__should_be_true_when_head_above_peer_height() {
        // Given
        let peer_head = 257_409_058;
        let status = SyncStatus {
            syncing: false,
            head_height: peer_head + 10,
            max_peer_height: Some(peer_head),
        };

        // When
        let caught_up = status.is_caught_up();

        // Then
        assert!(caught_up);
    }
}
