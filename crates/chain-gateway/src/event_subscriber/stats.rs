use crate::{primitives::FetchLatestFinalBlockInfo, types::BlockHeight};

#[derive(Debug, Clone)]
pub struct IndexerStats {
    pub blocks_processed_count: u64,
    pub last_processed_block_height: BlockHeight,
}

impl IndexerStats {
    pub(crate) fn new() -> Self {
        IndexerStats {
            blocks_processed_count: 0,
            last_processed_block_height: 0.into(),
        }
    }
}

/// Periodically logs indexer progress stats.
/// Based on [`indexer_logger`](../../node/src/indexer/stats.rs) in the `mpc-node` crate,
/// but uses a `watch` channel instead of a `Mutex` to read stats, since blocks are no longer
/// processed by multiple threads.
pub async fn indexer_logger(
    stats_rx: tokio::sync::watch::Receiver<IndexerStats>,
    info_fetcher: impl FetchLatestFinalBlockInfo,
) {
    let interval_secs = 10;
    let mut prev_blocks_processed_count: u64 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        if stats_rx.has_changed().is_err() {
            tracing::info!(
                target: "chain gateway",
                "indexer stats sender closed, shutting down indexer logger");
            return;
        }
        let stats_copy = stats_rx.borrow().clone();

        let block_processing_speed: f64 = (stats_copy
            .blocks_processed_count
            .saturating_sub(prev_blocks_processed_count)
            as f64)
            / (interval_secs as f64);

        let blocks_behind = match info_fetcher.fetch_latest_final_block_info().await {
            Ok(block_info) => {
                let tip: u64 = block_info.observed_at.into();
                let processed: u64 = stats_copy.last_processed_block_height.into();
                format!("{}", tip.saturating_sub(processed))
            }
            Err(_) => "∞".to_string(),
        };

        tracing::info!(
            target: "chain gateway",
            "# {} | Blocks done: {}. Bps {:.2} b/s, block remaining: {}",
            stats_copy.last_processed_block_height,
            stats_copy.blocks_processed_count,
            block_processing_speed,
            blocks_behind,
        );
        prev_blocks_processed_count = stats_copy.blocks_processed_count;
    }
}
