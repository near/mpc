use crate::indexer::stats::IndexerStats;
use futures::StreamExt;
use near_indexer_primitives::types::AccountId;
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
) {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(streamer_message, Arc::clone(&stats), &mpc_contract_id)
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(_handle_message) = handle_messages.next().await {}
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: &AccountId,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    for shard in streamer_message.shards {
        for receipt_outcome in shard.receipt_execution_outcomes {
            let outcome = receipt_outcome.execution_outcome.outcome;
            if outcome.executor_id == *mpc_contract_id {
                tracing::info!(target: "near-indexer", "got action targeting {}", mpc_contract_id);
            }
        }
    }

    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.remove(&block_height);
    stats_lock.blocks_processed_count += 1;
    stats_lock.last_processed_block_height = block_height;
    drop(stats_lock);
    Ok(())
}
