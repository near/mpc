use crate::{near_internals_wrapper::ViewClientWrapper, stats::IndexerStats};
use std::sync::Arc;
use tokio::sync::Mutex;

// todo: rename this method?
pub(crate) async fn indexer_logger(
    stats: Arc<Mutex<IndexerStats>>,
    view_client: Arc<ViewClientWrapper>,
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
            if let Ok(block_height) = view_client
                .latest_final_block()
                .await
                .map(|block| block.header.height)
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
