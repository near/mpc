use super::IndexerState;
use super::handler::extract_message;
use super::updates::{ChainBatch, ConsumerStarts};
use anyhow::{Context, ensure};
use mpc_node_config::{IndexerConfig, SyncMode};
use near_indexer_client::{Checkpoint, Client, Finality, Header};
use near_indexer_primitives::StreamerMessage;
use near_indexer_primitives::types::Finality as NodeFinality;
use near_indexer_primitives::views::{QueryResponse, QueryResponseKind, StatusResponse};
use near_jsonrpc_node::types::query::{
    QueryResponseKind as RpcQueryResponseKind, RpcQueryRequest, RpcQueryResponse,
};
use near_kit::rpc::{RpcClient, RpcError};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const MAX_ANCESTRY: usize = 10_000;

// Retry read availability failures without changing the acknowledged checkpoint.
// Schema, ancestry, missing historical data, and unsupported endpoint errors remain fatal.
async fn retry_read<T, F, Fut>(mut read: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut delay = Duration::from_millis(500);
    let started = std::time::Instant::now();
    loop {
        match read().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                let rpc_error = error.chain().find_map(|cause| {
                    cause.downcast_ref::<RpcError>().or_else(|| {
                        match cause.downcast_ref::<near_indexer_client::Error>() {
                            Some(near_indexer_client::Error::Rpc(error)) => Some(error),
                            _ => None,
                        }
                    })
                });
                let retryable = rpc_error.is_some_and(|error| match error {
                    RpcError::Rpc { data, .. } => data
                        .as_ref()
                        .and_then(|data| data.get("name"))
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| {
                            matches!(
                                name,
                                "BUSY" | "INTERNAL_ERROR" | "NOT_SYNCED_YET" | "TIMEOUT_ERROR"
                            ) || (name == "DATA_UNAVAILABLE"
                                && started.elapsed() < Duration::from_secs(30))
                        }),
                    _ => error.is_retryable(),
                });
                if !retryable {
                    tracing::error!(?rpc_error, ?error, "HTTP indexer read failed");
                    return Err(error);
                }
                tracing::warn!(
                    ?rpc_error,
                    ?error,
                    ?delay,
                    "HTTP indexer read unavailable; retrying acknowledged cursor"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(10));
            }
        }
    }
}

pub(super) async fn query(
    rpc: &RpcClient,
    query: RpcQueryRequest,
) -> anyhow::Result<QueryResponse> {
    let response: RpcQueryResponse = rpc.call("query", query).await?;
    let RpcQueryResponseKind::CallResult(result) = response.kind else {
        anyhow::bail!("unexpected contract query response");
    };
    Ok(QueryResponse {
        kind: QueryResponseKind::CallResult(result),
        block_height: response.block_height,
        block_hash: response.block_hash,
    })
}

pub(super) async fn sync_info(rpc: &RpcClient) -> anyhow::Result<(bool, u64)> {
    let status: StatusResponse = rpc.call("status", json!({})).await?;
    Ok((
        status.sync_info.syncing,
        status.sync_info.latest_block_height,
    ))
}

pub(crate) fn configured_url(config: &IndexerConfig) -> anyhow::Result<Option<String>> {
    match std::env::var("MPC_NEAR_RPC_URL") {
        Ok(url) => {
            ensure!(!url.is_empty(), "MPC_NEAR_RPC_URL must not be empty");
            Ok(Some(url))
        }
        Err(std::env::VarError::NotPresent) => {
            if let Some(url) = &config.rpc_url {
                ensure!(!url.is_empty(), "indexer.rpc_url must not be empty");
                Ok(Some(url.clone()))
            } else if cfg!(feature = "embedded-node") {
                Ok(None)
            } else {
                anyhow::bail!(
                    "indexer.rpc_url or MPC_NEAR_RPC_URL is required for the HTTP indexer"
                )
            }
        }
        Err(error) => Err(error).context("MPC_NEAR_RPC_URL is required for the HTTP indexer"),
    }
}

#[derive(Serialize, Deserialize)]
struct Resume {
    chain_id: String,
    genesis_hash: near_indexer_primitives::CryptoHash,
    finality: Finality,
    checkpoint: Checkpoint,
}

fn load_checkpoint(
    path: &Path,
    chain_id: &str,
    genesis_hash: near_indexer_primitives::CryptoHash,
    finality: Finality,
) -> anyhow::Result<Option<Checkpoint>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let resume: Resume =
        serde_json::from_slice(&bytes).context("invalid HTTP indexer checkpoint")?;
    ensure!(
        resume.chain_id == chain_id
            && resume.genesis_hash == genesis_hash
            && resume.finality == finality,
        "HTTP indexer checkpoint chain/finality mismatch"
    );
    Ok(Some(resume.checkpoint))
}

fn persist_checkpoint(
    path: &Path,
    chain_id: &str,
    genesis_hash: near_indexer_primitives::CryptoHash,
    finality: Finality,
    checkpoint: Checkpoint,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("checkpoint has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(
        &mut file,
        &Resume {
            chain_id: chain_id.to_owned(),
            genesis_hash,
            finality,
            checkpoint,
        },
    )?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

async fn header(rpc: &RpcClient, params: serde_json::Value) -> anyhow::Result<Header> {
    #[derive(Deserialize)]
    struct Block {
        header: Header,
    }
    let block: Block =
        retry_read(|| async { Ok(rpc.call("block", params.clone()).await?) }).await?;
    Ok(block.header)
}

async fn replay_anchor(
    rpc: &RpcClient,
    mut current: Header,
    cutoff: u64,
) -> anyhow::Result<Option<Checkpoint>> {
    if cutoff == current.height {
        return Ok(None);
    }
    for _ in 0..MAX_ANCESTRY {
        if current.height < cutoff
            || current.prev_hash == near_indexer_client::CryptoHash::default()
        {
            return Ok(Some(current.checkpoint()));
        }
        let parent = header(rpc, json!({"block_id": current.prev_hash})).await?;
        ensure!(
            parent.hash == current.prev_hash && parent.height < current.height,
            "invalid replay ancestry"
        );
        current = parent;
    }
    anyhow::bail!(
        "HTTP indexer replay exceeds {MAX_ANCESTRY} blocks; use an explicit closer start or retained archival history"
    )
}

struct HttpFeed {
    rpc: RpcClient,
    client: Client,
    state: Arc<IndexerState>,
    config: IndexerConfig,
    finality: Finality,
    chain_id: String,
    genesis_hash: near_indexer_primitives::CryptoHash,
    checkpoint_path: PathBuf,
    #[cfg(feature = "network-hardship-simulation")]
    process_blocks_receiver: tokio::sync::watch::Receiver<bool>,
}

// The initial lower bound survives cancellation before the first acknowledgement
// is recorded, so a new consumer cannot skip requests from that first batch.
fn replay_cutoff(
    mode: &SyncMode,
    head: u64,
    last_ack: Option<Checkpoint>,
    replay_from: &mut Option<u64>,
) -> u64 {
    if let Some(checkpoint) = last_ack {
        return checkpoint
            .height
            .saturating_sub(crate::requests::queue::REQUEST_EXPIRATION_BLOCKS);
    }
    *replay_from.get_or_insert_with(|| match mode {
        SyncMode::Block(args) => args.height,
        _ => head,
    })
}

fn require_final_checkpoint(
    finality: Finality,
    previous: Option<Checkpoint>,
    mut ancestry: impl Iterator<Item = Checkpoint>,
) -> anyhow::Result<()> {
    if finality == Finality::Final
        && let Some(previous) = previous
    {
        ensure!(
            ancestry.any(|checkpoint| checkpoint == previous),
            "HTTP replay would replace or omit the saved finalized checkpoint"
        );
    }
    Ok(())
}

fn send_batch(
    sender: &mpsc::UnboundedSender<ChainBatch>,
    blocks: Vec<super::handler::ChainBlockUpdate>,
    previous: Option<Checkpoint>,
    next: Checkpoint,
) -> anyhow::Result<Option<oneshot::Receiver<()>>> {
    ensure!(
        previous.is_none_or(|previous| next.height >= previous.height),
        "HTTP head decreased; MPC cannot restore expired requests. Wait for the serving endpoint to catch up or explicitly resynchronize the consumer"
    );
    let (acknowledge, received) = oneshot::channel();
    Ok(sender
        .send(ChainBatch {
            blocks,
            head: Some((
                near_indexer_primitives::CryptoHash(next.hash.0),
                next.height,
            )),
            acknowledge: Some(acknowledge),
        })
        .ok()
        .map(|()| received))
}

impl HttpFeed {
    async fn consume(
        &self,
        sender: mpsc::UnboundedSender<ChainBatch>,
        last_ack: &mut Option<Checkpoint>,
        replay_from: &mut Option<u64>,
    ) -> anyhow::Result<()> {
        let head = header(&self.rpc, json!({"finality": self.finality})).await?;
        let cutoff = replay_cutoff(&self.config.sync_mode, head.height, *last_ack, replay_from);
        ensure!(
            cutoff <= head.height,
            "requested start height is above the current chain head"
        );
        let anchor = replay_anchor(&self.rpc, head, cutoff).await?;
        let mut update =
            retry_read(|| async { Ok(self.client.update_to(anchor.as_ref(), head.hash).await?) })
                .await?;
        require_final_checkpoint(
            self.finality,
            *last_ack,
            update
                .blocks
                .iter()
                .map(|block| Checkpoint {
                    hash: block.message.block.header.hash,
                    height: block.message.block.header.height,
                })
                .chain(std::iter::once(update.next_checkpoint)),
        )?;
        #[cfg(feature = "network-hardship-simulation")]
        let mut process_blocks_receiver = self.process_blocks_receiver.clone();
        loop {
            #[cfg(feature = "network-hardship-simulation")]
            while !*process_blocks_receiver.borrow() {
                process_blocks_receiver.changed().await?;
            }
            let next = update.next_checkpoint;
            let processed_count = update.blocks.len();
            let mut blocks = Vec::with_capacity(update.blocks.len());
            for block in update.blocks {
                let message: StreamerMessage =
                    serde_json::from_value(serde_json::to_value(block.message)?)
                        .context("HTTP message is incompatible with the MPC protocol types")?;
                blocks.push(extract_message(message, &self.state.mpc_contract_id));
            }
            let Some(received) = send_batch(&sender, blocks, *last_ack, next)? else {
                return Ok(());
            };
            if received.await.is_err() {
                return Ok(());
            }
            persist_checkpoint(
                &self.checkpoint_path,
                &self.chain_id,
                self.genesis_hash,
                self.finality,
                next,
            )?;
            *last_ack = Some(next);
            {
                let mut stats = self.state.stats.lock().await;
                stats.last_processed_block_height = next.height;
                stats.blocks_processed_count += processed_count as u64;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            update =
                retry_read(|| async { Ok(self.client.poll(last_ack.as_ref()).await?) }).await?;
        }
    }
}

pub(super) async fn listen_http_blocks(
    url: String,
    home: PathBuf,
    config: IndexerConfig,
    state: Arc<IndexerState>,
    mut starts: ConsumerStarts,
    #[cfg(feature = "network-hardship-simulation")]
    process_blocks_receiver: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let finality = match config.finality {
        NodeFinality::Final => Finality::Final,
        NodeFinality::None => Finality::Optimistic,
        NodeFinality::DoomSlug => {
            anyhow::bail!("HTTP indexer supports optimistic or final finality")
        }
    };
    let rpc = RpcClient::new(&url);
    let status: StatusResponse =
        retry_read(|| async { Ok(rpc.call("status", json!({})).await?) }).await?;
    let checkpoint_path = home.join("http-indexer-checkpoint.json");
    let mut last_ack = if matches!(config.sync_mode, SyncMode::Interruption) {
        load_checkpoint(
            &checkpoint_path,
            &status.chain_id,
            status.genesis_hash,
            finality,
        )?
    } else {
        None
    };
    let feed = HttpFeed {
        rpc,
        client: Client::new(RpcClient::new(url), finality, MAX_ANCESTRY),
        state,
        config,
        finality,
        chain_id: status.chain_id,
        genesis_hash: status.genesis_hash,
        checkpoint_path,
        #[cfg(feature = "network-hardship-simulation")]
        process_blocks_receiver,
    };
    let mut sender = match starts.recv().await {
        Some(sender) => sender,
        None => return Ok(()),
    };
    let mut replay_from = None;
    loop {
        tokio::select! {
            biased;
            next = starts.recv() => match next { Some(next) => sender = next, None => return Ok(()) },
            result = feed.consume(sender.clone(), &mut last_ack, &mut replay_from) => {
                result?;
                sender = match starts.recv().await { Some(sender) => sender, None => return Ok(()) };
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    #[tokio::test]
    async fn replay_cutoff__should_retain_first_batch_when_restart_wins_ack_race() {
        // Given
        let mut replay_from = None;
        let first = replay_cutoff(&SyncMode::Latest, 100, None, &mut replay_from);
        let (acknowledge, mut acknowledged) = oneshot::channel();
        acknowledge.send(()).unwrap();
        let mut last_ack = None;

        // When
        tokio::select! {
            biased;
            _ = std::future::ready(()) => {},
            _ = &mut acknowledged => last_ack = Some(Checkpoint { hash: near_indexer_client::CryptoHash([1; 32]), height: 100 }),
        }
        let restarted = replay_cutoff(&SyncMode::Latest, 101, last_ack, &mut replay_from);

        // Then
        assert_eq!(first, 100);
        assert_eq!(last_ack, None);
        assert_eq!(restarted, 100);
    }

    #[test]
    fn send_batch__should_reject_decreasing_head_before_delivery() {
        // Given
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let previous = Checkpoint {
            hash: near_indexer_client::CryptoHash([1; 32]),
            height: 105,
        };
        let lower = Checkpoint {
            hash: near_indexer_client::CryptoHash([2; 32]),
            height: 104,
        };
        let same_height = Checkpoint {
            hash: near_indexer_client::CryptoHash([3; 32]),
            height: 105,
        };

        // When
        let rejected = send_batch(&sender, vec![], Some(previous), lower);

        // Then
        rejected.unwrap_err();
        assert_matches!(
            receiver.try_recv().err(),
            Some(mpsc::error::TryRecvError::Empty)
        );
        let acknowledgement = send_batch(&sender, vec![], Some(previous), same_height).unwrap();
        assert!(acknowledgement.is_some());
        assert_eq!(
            receiver.try_recv().unwrap().head,
            Some((near_indexer_primitives::CryptoHash([3; 32]), 105))
        );
    }

    #[test]
    fn final_checkpoint__should_reject_replaced_or_missing_saved_ancestry() {
        // Given
        let previous = Checkpoint {
            hash: near_indexer_client::CryptoHash([1; 32]),
            height: 105,
        };
        let replaced = Checkpoint {
            hash: near_indexer_client::CryptoHash([2; 32]),
            height: 105,
        };

        // When
        let matching =
            require_final_checkpoint(Finality::Final, Some(previous), [previous].into_iter());
        let conflicting =
            require_final_checkpoint(Finality::Final, Some(previous), [replaced].into_iter());
        let missing = require_final_checkpoint(Finality::Final, Some(previous), [].into_iter());
        let optimistic =
            require_final_checkpoint(Finality::Optimistic, Some(previous), [replaced].into_iter());

        // Then
        matching.unwrap();
        conflicting.unwrap_err();
        missing.unwrap_err();
        optimistic.unwrap();
    }

    #[test]
    fn checkpoint__should_reject_another_chain_or_finality() {
        // Given
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("checkpoint.json");
        let genesis = near_indexer_primitives::CryptoHash([1; 32]);
        let checkpoint = Checkpoint {
            hash: near_indexer_client::CryptoHash([2; 32]),
            height: 100,
        };
        persist_checkpoint(&path, "localnet", genesis, Finality::Final, checkpoint).unwrap();

        // When
        let restored = load_checkpoint(&path, "localnet", genesis, Finality::Final).unwrap();
        let wrong_chain = load_checkpoint(&path, "testnet", genesis, Finality::Final);
        let wrong_genesis = load_checkpoint(
            &path,
            "localnet",
            near_indexer_primitives::CryptoHash([3; 32]),
            Finality::Final,
        );
        let wrong_finality = load_checkpoint(&path, "localnet", genesis, Finality::Optimistic);

        // Then
        assert_eq!(restored, Some(checkpoint));
        wrong_chain.unwrap_err();
        wrong_genesis.unwrap_err();
        wrong_finality.unwrap_err();
    }

    #[tokio::test]
    async fn retry_read__should_retry_busy_but_reject_missing_history() {
        // Given
        let attempts = std::sync::atomic::AtomicUsize::new(0);

        // When
        let value = retry_read(|| async {
            if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return Err(near_indexer_client::Error::from(RpcError::Rpc {
                    code: -32000,
                    message: "temporarily busy".to_owned(),
                    data: Some(json!({"name": "BUSY"})),
                })
                .into());
            }
            Ok(42)
        })
        .await
        .unwrap();
        let missing = retry_read(|| async {
            Err::<(), _>(
                RpcError::Rpc {
                    code: -32000,
                    message: "missing historical block".to_owned(),
                    data: Some(json!({"name": "UNKNOWN_BLOCK"})),
                }
                .into(),
            )
        })
        .await;

        // Then
        assert_eq!(value, 42);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
        missing.unwrap_err();
    }
}
