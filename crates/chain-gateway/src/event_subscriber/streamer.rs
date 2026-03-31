mod block_processor;
mod config;

use block_processor::listen_blocks;
use config::StreamerConfig;
use near_indexer::StreamerMessage;

use crate::{errors::ChainGatewayError, primitives::FetchLatestFinalBlockInfo};

use super::{
    block_events::BlockUpdate,
    stats::{IndexerStats, indexer_logger},
    subscriber::BlockEventSubscriber,
};

pub(crate) async fn start(
    block_event_subscriber: BlockEventSubscriber,
    stream: tokio::sync::mpsc::Receiver<StreamerMessage>,
    info_fetcher: impl FetchLatestFinalBlockInfo,
) -> Result<tokio::sync::mpsc::Receiver<BlockUpdate>, ChainGatewayError> {
    let StreamerConfig {
        buffer_size,
        block_events,
    } = block_event_subscriber.into();
    let (stats_tx, stats_rx) = tokio::sync::watch::channel(IndexerStats::new());
    let (block_tx, block_rx) = tokio::sync::mpsc::channel(buffer_size);

    tokio::spawn(async move {
        if let Err(err) = listen_blocks(stream, block_events, stats_tx, block_tx).await {
            tracing::error!(target: "chain gateway", "block event listener stopped: {err}");
        }
    });
    tokio::spawn(indexer_logger(stats_rx, info_fetcher));

    Ok(block_rx)
}
