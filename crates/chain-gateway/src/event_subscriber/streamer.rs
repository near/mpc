mod block_processor;
mod config;

use block_processor::listen_blocks;
pub(crate) use config::StreamerConfig;
use near_indexer::StreamerMessage;

use crate::{
    errors::ChainGatewayError, event_subscriber::consts::DEFAULT_NUMBER_OF_TRACKED_BLOCKS,
    primitives::FetchLatestFinalBlockInfo,
};

use super::{
    block_events::BlockUpdate,
    stats::{IndexerStats, indexer_logger},
    subscriber::BlockEventSubscriptions,
};

pub(crate) struct StartedStreamer {
    pub(crate) config: StreamerConfig,
    pub(crate) block_tx: tokio::sync::mpsc::Sender<BlockUpdate>,
    pub(crate) block_rx: tokio::sync::mpsc::Receiver<BlockUpdate>,
}

pub(crate) async fn start(
    block_event_subscriber: BlockEventSubscriptions,
    stream: tokio::sync::mpsc::Receiver<StreamerMessage>,
    info_fetcher: impl FetchLatestFinalBlockInfo,
) -> Result<StartedStreamer, ChainGatewayError> {
    let config: StreamerConfig = block_event_subscriber.into();
    let (block_tx, block_rx) = tokio::sync::mpsc::channel(config.buffer_size);
    spawn_feed(config.clone(), stream, info_fetcher, block_tx.clone());
    Ok(StartedStreamer {
        config,
        block_tx,
        block_rx,
    })
}

pub(crate) fn reconnect(
    config: StreamerConfig,
    stream: tokio::sync::mpsc::Receiver<StreamerMessage>,
    info_fetcher: impl FetchLatestFinalBlockInfo,
    block_tx: tokio::sync::mpsc::Sender<BlockUpdate>,
) {
    spawn_feed(config, stream, info_fetcher, block_tx);
}

fn spawn_feed(
    config: StreamerConfig,
    stream: tokio::sync::mpsc::Receiver<StreamerMessage>,
    info_fetcher: impl FetchLatestFinalBlockInfo,
    block_tx: tokio::sync::mpsc::Sender<BlockUpdate>,
) {
    let number_of_tracked_blocks = DEFAULT_NUMBER_OF_TRACKED_BLOCKS.max(
        config
            .buffer_size
            .try_into()
            .expect("usize is expected to fit into u64"),
    );
    let (stats_tx, stats_rx) = tokio::sync::watch::channel(IndexerStats::new());

    tokio::spawn(async move {
        if let Err(err) = listen_blocks(
            stream,
            config.block_events,
            stats_tx,
            block_tx,
            number_of_tracked_blocks,
        )
        .await
        {
            tracing::error!(target: "chain gateway", "block event listener stopped: {err}");
        }
    });
    tokio::spawn(indexer_logger(stats_rx, info_fetcher));
}
