use crate::primitives::LatestFinalBlockInfoFetcher;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct IndexerStats {
    pub block_heights_processing: std::collections::BTreeSet<u64>,
    pub blocks_processed_count: u64,
    pub last_processed_block_height: u64,
}

impl IndexerStats {
    pub(crate) fn new() -> Self {
        IndexerStats {
            block_heights_processing: std::collections::BTreeSet::new(),
            blocks_processed_count: 0,
            last_processed_block_height: 0,
        }
    }
}

// todo: take a RwLock instead
pub async fn indexer_logger(
    stats: Arc<Mutex<IndexerStats>>,
    info_fetcher: impl LatestFinalBlockInfoFetcher,
) {
    let interval_secs = 10;
    let mut prev_blocks_processed_count: u64 = 0;

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        let stats_lock = stats.lock().await;
        let stats_copy = stats_lock.clone();
        drop(stats_lock);

        let block_processing_speed: f64 = ((stats_copy.blocks_processed_count
            - prev_blocks_processed_count) as f64)
            / (interval_secs as f64);

        let time_to_catch_the_tip_duration = if block_processing_speed > 0.0 {
            if let Ok(block_height) = info_fetcher
                .latest_final_block()
                .await
                .map(|value| Into::<u64>::into(value.observed_at))
            {
                let blocks_behind = if block_height > stats_copy.last_processed_block_height {
                    block_height - stats_copy.last_processed_block_height
                } else {
                    0 // We're ahead of the chain tip, no catching up needed
                };

                Some(std::time::Duration::from_millis(
                    ((blocks_behind as f64 / block_processing_speed) * 1000f64) as u64,
                ))
            } else {
                None
            }
        } else {
            None
        };

        tracing::info!(
            target: "chain gateway",
            "# {} | Blocks processing: {}| Blocks done: {}. Bps {:.2} b/s {}",
            stats_copy.last_processed_block_height,
            stats_copy.block_heights_processing.len(),
            stats_copy.blocks_processed_count,
            block_processing_speed,
            if let Some(duration) = time_to_catch_the_tip_duration.filter(|d| d.as_secs() > 0) {
                format!(
                    " | {} to catch up the tip",
                    humantime::format_duration(duration)
                )
            } else {
                "".to_string()
            }
        );
        prev_blocks_processed_count = stats_copy.blocks_processed_count;
    }
}
