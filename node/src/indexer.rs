use futures::StreamExt;
use near_indexer_primitives::types;
use near_o11y::WithSpanContextExt;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub(crate) struct IndexerStats {
    pub block_heights_processing: std::collections::BTreeSet<u64>,
    pub blocks_processed_count: u64,
    pub last_processed_block_height: u64,
}

impl IndexerStats {
    pub fn new() -> Self {
        Self {
            block_heights_processing: std::collections::BTreeSet::new(),
            blocks_processed_count: 0,
            last_processed_block_height: 0,
        }
    }
}

pub(crate) async fn indexer_logger(
    stats: Arc<Mutex<IndexerStats>>,
    view_client: actix::Addr<near_client::ViewClientActor>,
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
            if let Ok(block_height) = fetch_latest_block(&view_client).await {
                Some(std::time::Duration::from_millis(
                    (((block_height - stats_copy.last_processed_block_height) as f64
                        / block_processing_speed)
                        * 1000f64) as u64,
                ))
            } else {
                None
            }
        } else {
            None
        };

        tracing::info!(
            target: "indexer",
            "# {} | Blocks processing: {}| Blocks done: {}. Bps {:.2} b/s {}",
            stats_copy.last_processed_block_height,
            stats_copy.block_heights_processing.len(),
            stats_copy.blocks_processed_count,
            block_processing_speed,
            if let Some(duration) = time_to_catch_the_tip_duration {
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

async fn fetch_latest_block(
    client: &actix::Addr<near_client::ViewClientActor>,
) -> anyhow::Result<u64> {
    let block = client
        .send(
            near_client::GetBlock(types::BlockReference::Finality(types::Finality::Final))
                .with_span_context(),
        )
        .await??;
    Ok(block.header.height)
}

pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
) {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| handle_message(streamer_message, Arc::clone(&stats)))
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(_handle_message) = handle_messages.next().await {}
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    // Block
    let block_json = serde_json::to_value(streamer_message.block)
        .expect("Failed to serializer BlockView to JSON");
    tracing::debug!(target: "indexer", "{}", block_json);

    // Shards
    for shard in streamer_message.shards.iter() {
        let shard_json =
            serde_json::to_value(shard).expect("Failed to serialize IndexerShard to JSON");
        tracing::debug!(target: "indexer", "{}", shard_json);
    }

    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.remove(&block_height);
    stats_lock.blocks_processed_count += 1;
    stats_lock.last_processed_block_height = block_height;
    drop(stats_lock);
    Ok(())
}
