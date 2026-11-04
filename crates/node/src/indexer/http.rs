use super::IndexerState;
use super::handler::{ChainBlockUpdate, extract_message};
use super::updates::{ChainBatch, ConsumerStarts};
use crate::durable_fs::write_file_durably;
use crate::home_paths::http_indexer_checkpoint_file;
use crate::metrics;
use crate::requests::queue::REQUEST_EXPIRATION_BLOCKS;
use crate::tracking::AutoAbortTask;
use anyhow::{Context, ensure};
use mpc_node_config::{IndexerConfig, SyncMode};
use near_indexer_client::near_kit::rpc::{RetryConfig, RpcClient, RpcError};
use near_indexer_client::{
    Backoff, Checkpoint, Client, CryptoHash, ErrorKind, Failure, Finality, Header, RetryPolicy,
};
use near_indexer_primitives::types::Finality as NodeFinality;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// How far below the head a replay starts. A request expires
/// [`REQUEST_EXPIRATION_BLOCKS`] below this node's head, so nothing older is
/// needed; the margin keeps requests that a peer slightly ahead may still answer.
const REPLAY_WINDOW_BLOCKS: u64 = REQUEST_EXPIRATION_BLOCKS + 50;
/// Bounds the blocks held in memory and applied per acknowledged batch.
const MAX_BATCH_BLOCKS: usize = 32;
/// Bounds a poll's rollback plus apply headers. A head more than
/// [`REPLAY_WINDOW_BLOCKS`] ahead is re-anchored before planning, so only a
/// deep fork can reach this.
const MAX_PLAN_HEADERS: usize = 1_000;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long a stopping feed waits for its latest checkpoint to be persisted.
const CHECKPOINT_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
enum ReadError {
    #[error(transparent)]
    Client(#[from] near_indexer_client::Error),
    #[error("indexer message does not match the node's NEAR types: {0:#}")]
    Mismatch(anyhow::Error),
}

impl From<RpcError> for ReadError {
    fn from(error: RpcError) -> Self {
        Self::Client(error.into())
    }
}

/// What a failed read was for, in logs and metrics.
#[derive(Clone, Copy, Debug)]
enum Request {
    Status,
    Head,
    Parent(CryptoHash),
    Block { height: u64, hash: CryptoHash },
    Plan { from: Checkpoint },
}

impl Request {
    fn label(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Head => "head",
            Self::Parent(_) => "parent",
            Self::Block { .. } => "block",
            Self::Plan { .. } => "plan",
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status => write!(f, "node status"),
            Self::Head => write!(f, "head header"),
            Self::Parent(hash) => write!(f, "header of block {hash}"),
            Self::Block { height, hash } => write!(f, "block {height} ({hash})"),
            Self::Plan { from } => {
                write!(f, "ancestry after block {} ({})", from.height, from.hash)
            }
        }
    }
}

fn remedy(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::LimitExceeded => {
            "the block's indexer response exceeds the RPC node's size cap, a compile-time \
             constant of 32 MiB in nearcore 2.14; serve this block from an RPC node built \
             with a larger cap"
        }
        ErrorKind::DataUnavailable | ErrorKind::IncompleteData => {
            "the RPC node lacks this block's execution data; check that it tracks all \
             shards, saves outcomes and state changes, and retains the history"
        }
        ErrorKind::Unsupported => {
            "the RPC node does not serve EXPERIMENTAL_indexer_block; check \
             rpc.enable_indexer_rpc, save_tx_outcomes and save_state_changes"
        }
        _ => "check the RPC node; the indexer does not skip blocks",
    }
}

/// Paces and reports the attempts at one failing request.
struct Attempts {
    first_failure: Instant,
    backoff: Backoff,
}

impl Attempts {
    fn start() -> Self {
        Self {
            first_failure: Instant::now(),
            backoff: RetryPolicy::default().backoff(),
        }
    }

    /// The delay before the next attempt after a failure classified here.
    fn next(&mut self, failure: Failure) -> Duration {
        self.backoff.next_delay(failure)
    }

    /// Logs and counts a failed `request`, returning the delay before the next attempt.
    fn record(&mut self, request: Request, error: &ReadError) -> Duration {
        let (label, failure, delay, remedy) = match error {
            ReadError::Client(error) => {
                let retry = self.backoff.next(error, self.first_failure.elapsed());
                (
                    retry.kind.as_str(),
                    retry.failure,
                    retry.delay,
                    remedy(retry.kind),
                )
            }
            ReadError::Mismatch(_) => (
                "type_mismatch",
                Failure::Persistent,
                self.backoff.next_delay(Failure::Persistent),
                "the RPC node serves data the node's NEAR types cannot represent; check its \
                 nearcore version",
            ),
        };
        metrics::MPC_HTTP_INDEXER_READ_FAILURES_TOTAL
            .with_label_values(&[request.label(), label])
            .inc();
        match failure {
            Failure::Transient => tracing::warn!(
                %request,
                error = %redacted(error),
                ?delay,
                "HTTP indexer read failed; retrying"
            ),
            Failure::Persistent => tracing::error!(
                %request,
                error = %redacted(error),
                ?delay,
                remedy,
                "HTTP indexer read keeps failing; retrying the same request"
            ),
        }
        delay
    }
}

/// Renders an error without the request URL, which may carry an API key.
fn redacted(error: &ReadError) -> String {
    if let ReadError::Client(near_indexer_client::Error::Rpc(rpc)) = error
        && let RpcError::Http(_) = rpc.as_ref()
    {
        return match std::error::Error::source(rpc.as_ref()).and_then(std::error::Error::source) {
            Some(cause) => format!("http transport error: {cause:?}"),
            None => "http transport error".to_owned(),
        };
    }
    error.to_string()
}

/// Repeats `read` until it succeeds. The node cannot skip a block, so no error
/// is final; persistent ones are logged as errors naming `request`.
async fn retry<T, F, Fut>(request: Request, mut read: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ReadError>>,
{
    let mut backoff = None;
    loop {
        match read().await {
            Ok(value) => return value,
            Err(error) => {
                let delay = backoff
                    .get_or_insert_with(Attempts::start)
                    .record(request, &error);
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Identifies the chain and finality a checkpoint belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ChainIdentity {
    chain_id: String,
    genesis_hash: CryptoHash,
    finality: Finality,
}

#[derive(Serialize, Deserialize)]
struct SavedCheckpoint {
    #[serde(flatten)]
    identity: ChainIdentity,
    checkpoint: Checkpoint,
}

fn read_checkpoint(path: &Path, identity: &ChainIdentity) -> anyhow::Result<Option<Checkpoint>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("failed to read the HTTP indexer checkpoint"),
    };
    let saved: SavedCheckpoint =
        serde_json::from_slice(&bytes).context("invalid HTTP indexer checkpoint")?;
    ensure!(
        saved.identity == *identity,
        "the HTTP indexer checkpoint belongs to another chain or finality"
    );
    Ok(Some(saved.checkpoint))
}

fn write_checkpoint(
    path: &Path,
    identity: &ChainIdentity,
    checkpoint: Checkpoint,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&SavedCheckpoint {
        identity: identity.clone(),
        checkpoint,
    })?;
    write_file_durably(path, &bytes).context("failed to persist the HTTP indexer checkpoint")
}

async fn load_checkpoint(
    path: PathBuf,
    identity: ChainIdentity,
) -> anyhow::Result<Option<Checkpoint>> {
    tokio::task::spawn_blocking(move || read_checkpoint(&path, &identity)).await?
}

/// The lowest height a replay delivers: the request window before the last
/// acknowledgement, or the start sampled when listening began, but never more
/// than [`REPLAY_WINDOW_BLOCKS`] below `head`.
fn replay_cutoff(head: u64, last_ack: Option<Checkpoint>, start: u64) -> u64 {
    let floor = match last_ack {
        Some(checkpoint) => checkpoint.height.saturating_sub(REQUEST_EXPIRATION_BLOCKS),
        None => start,
    };
    floor.max(head.saturating_sub(REPLAY_WINDOW_BLOCKS))
}

/// The lowest head the node follows. A lower head may already have expired
/// requests in the pending queues, so the node waits for the endpoint instead.
fn required_head(last_ack: Option<Checkpoint>, start: u64) -> u64 {
    last_ack.map_or(start, |checkpoint| checkpoint.height)
}

/// Whether catching up from `cursor` would only deliver expired requests, so
/// the consumer skips ahead to a fresh replay window instead.
fn must_reanchor(cursor: Checkpoint, head: u64) -> bool {
    head.saturating_sub(cursor.height) > REPLAY_WINDOW_BLOCKS
}

/// Whether `next` replaces `last_ack` as the durable checkpoint. A replay
/// re-delivers blocks below the last acknowledgement without moving it back.
fn advances(last_ack: Option<Checkpoint>, next: Checkpoint) -> bool {
    last_ack.is_none_or(|previous| next != previous && next.height >= previous.height)
}

/// A final replay may never replace or omit the last acknowledged final block
/// at or above `cutoff`. One below `cutoff` is not replayed, so not checked.
fn require_final_checkpoint(
    finality: Finality,
    previous: Option<Checkpoint>,
    cutoff: u64,
    mut replayed: impl Iterator<Item = Checkpoint>,
) -> anyhow::Result<()> {
    if finality == Finality::Final
        && let Some(previous) = previous
        && previous.height >= cutoff
    {
        ensure!(
            replayed.any(|checkpoint| checkpoint == previous),
            "HTTP replay would replace or omit the saved finalized checkpoint"
        );
    }
    Ok(())
}

/// Sends a batch, or `None` if the consumer is gone.
fn send_batch(
    sender: &mpsc::UnboundedSender<ChainBatch>,
    blocks: Vec<ChainBlockUpdate>,
    next: Checkpoint,
    discontinuous: bool,
) -> Option<oneshot::Receiver<()>> {
    let (acknowledge, acknowledged) = oneshot::channel();
    let batch = ChainBatch {
        blocks,
        head: Some((
            near_indexer_primitives::CryptoHash(next.hash.0),
            next.height,
        )),
        discontinuous,
        acknowledge: Some(acknowledge),
    };
    sender.send(batch).ok().map(|()| acknowledged)
}

/// Converts the client's crates.io message into the nearcore types the node
/// extracts from. Both serialize to the RPC's JSON schema.
fn to_node_message(
    message: near_indexer_client::StreamerMessage,
) -> anyhow::Result<near_indexer_primitives::StreamerMessage> {
    serde_json::from_value(serde_json::to_value(message)?)
        .context("indexer message does not match the node's NEAR types")
}

/// Headers from `cutoff` up to `head`, oldest first, without genesis.
async fn replay_headers(client: &Client, head: Header, cutoff: u64) -> Vec<Header> {
    let mut headers = vec![];
    let mut current = head;
    while current.height >= cutoff && current.prev_hash != CryptoHash::default() {
        headers.push(current);
        let child = current;
        current = retry(Request::Parent(child.prev_hash), || async {
            Ok(client.parent(&child).await?)
        })
        .await;
    }
    headers.reverse();
    headers
}

struct HttpFeed {
    client: Client,
    state: Arc<IndexerState>,
    finality: Finality,
    checkpoints: CheckpointWriter,
    /// The lowest height to deliver before anything is acknowledged, fixed
    /// when listening starts.
    start: u64,
    #[cfg(feature = "network-hardship-simulation")]
    process_blocks_receiver: tokio::sync::watch::Receiver<bool>,
}

impl HttpFeed {
    /// Feeds each consumer that starts until no consumer can start any more.
    async fn follow(
        &self,
        mut starts: ConsumerStarts,
        mut last_ack: Option<Checkpoint>,
    ) -> anyhow::Result<()> {
        let Some(mut sender) = starts.recv().await else {
            return Ok(());
        };
        loop {
            tokio::select! {
                biased;
                next = starts.recv() => match next {
                    Some(next) => sender = next,
                    None => return Ok(()),
                },
                result = self.consume(sender.clone(), &mut last_ack) => {
                    result?;
                    sender = match starts.recv().await {
                        Some(sender) => sender,
                        None => return Ok(()),
                    };
                }
            }
        }
    }

    /// Replays the request window to one consumer, then follows the head until
    /// the consumer goes away.
    async fn consume(
        &self,
        sender: mpsc::UnboundedSender<ChainBatch>,
        last_ack: &mut Option<Checkpoint>,
    ) -> anyhow::Result<()> {
        let finality = self.finality;
        let mut cursor: Option<Checkpoint> = None;
        let mut backoff: Option<Attempts> = None;
        #[cfg(feature = "network-hardship-simulation")]
        let mut process_blocks_receiver = self.process_blocks_receiver.clone();
        loop {
            #[cfg(feature = "network-hardship-simulation")]
            while !*process_blocks_receiver.borrow() {
                process_blocks_receiver.changed().await?;
            }
            let head = retry(Request::Head, || async { Ok(self.client.head().await?) }).await;
            let required = required_head(*last_ack, self.start);
            if head.height < required {
                let delay = backoff
                    .get_or_insert_with(Attempts::start)
                    .next(Failure::Transient);
                tracing::warn!(
                    head = head.height,
                    required,
                    ?delay,
                    "the RPC node's head is below what this node already processed; waiting for it to catch up"
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            let (headers, discontinuous) = match cursor {
                Some(cursor) if cursor == head.checkpoint() => {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
                Some(cursor) if !must_reanchor(cursor, head.height) => {
                    match self.client.plan(Some(&cursor), head).await {
                        Ok(plan) => (plan.apply, false),
                        Err(error) => {
                            let delay = backoff
                                .get_or_insert_with(Attempts::start)
                                .record(Request::Plan { from: cursor }, &error.into());
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    }
                }
                _ => {
                    let cutoff = replay_cutoff(head.height, *last_ack, self.start);
                    if let Some(cursor) = cursor {
                        metrics::MPC_HTTP_INDEXER_REANCHORS_TOTAL.inc();
                        tracing::warn!(
                            from = cursor.height,
                            to = cutoff,
                            "the HTTP indexer fell further behind than requests live; skipping to the replay window"
                        );
                    }
                    let headers = replay_headers(&self.client, head, cutoff).await;
                    if let Err(error) = require_final_checkpoint(
                        finality,
                        *last_ack,
                        cutoff,
                        headers.iter().map(Header::checkpoint),
                    ) {
                        let delay = backoff
                            .get_or_insert_with(Attempts::start)
                            .next(Failure::Persistent);
                        tracing::error!(%error, ?delay, "HTTP indexer replay rejected; retrying");
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    (headers, true)
                }
            };
            backoff = None;
            if !self
                .deliver(&sender, headers, discontinuous, last_ack, &mut cursor)
                .await?
            {
                return Ok(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Applies `headers` in acknowledged batches of at most [`MAX_BATCH_BLOCKS`],
    /// publishing a checkpoint after each. Returns `false` once the consumer is gone.
    async fn deliver(
        &self,
        sender: &mpsc::UnboundedSender<ChainBatch>,
        headers: Vec<Header>,
        mut discontinuous: bool,
        last_ack: &mut Option<Checkpoint>,
        cursor: &mut Option<Checkpoint>,
    ) -> anyhow::Result<bool> {
        for chunk in headers.chunks(MAX_BATCH_BLOCKS) {
            let Some(last) = chunk.last() else {
                continue;
            };
            let mut blocks = Vec::with_capacity(chunk.len());
            for header in chunk {
                let request = Request::Block {
                    height: header.height,
                    hash: header.hash,
                };
                let message = retry(request, || async {
                    let block = self.client.fetch_block(header).await?;
                    to_node_message(block.message).map_err(ReadError::Mismatch)
                })
                .await;
                blocks.push(extract_message(message, &self.state.mpc_contract_id));
            }
            let next = last.checkpoint();
            let Some(acknowledged) = send_batch(sender, blocks, next, discontinuous) else {
                return Ok(false);
            };
            if acknowledged.await.is_err() {
                return Ok(false);
            }
            discontinuous = false;
            *cursor = Some(next);
            if advances(*last_ack, next) {
                self.checkpoints.publish(next);
                *last_ack = Some(next);
            }
            let mut stats = self.state.stats.lock().await;
            stats.last_processed_block_height = next.height;
            stats.blocks_processed_count = stats
                .blocks_processed_count
                .saturating_add(u64::try_from(chunk.len())?);
        }
        Ok(true)
    }
}

/// Persists the latest published checkpoint in a background task, so
/// delivery never waits for the disk. Checkpoints published during a slow
/// write coalesce into the next one, and writes run one at a time, so an older
/// checkpoint never replaces a newer one.
struct CheckpointWriter {
    latest: watch::Sender<Option<Checkpoint>>,
    task: AutoAbortTask<()>,
}

impl CheckpointWriter {
    /// `saved` is the checkpoint already persisted, which is not written again.
    fn spawn(store: impl PersistCheckpoint, saved: Option<Checkpoint>) -> Self {
        let (latest, receiver) = watch::channel(saved);
        let task = tokio::spawn(write_latest(store, saved, receiver)).into();
        Self { latest, task }
    }

    fn publish(&self, checkpoint: Checkpoint) {
        self.latest.send_replace(Some(checkpoint));
    }

    /// Waits up to `timeout` for the last published checkpoint to be persisted,
    /// then stops the writer.
    async fn flush(self, timeout: Duration) {
        let Self { latest, mut task } = self;
        drop(latest);
        match tokio::time::timeout(timeout, &mut task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(%error, "the HTTP indexer checkpoint writer failed");
            }
            Err(_) => tracing::warn!(
                ?timeout,
                "the latest HTTP indexer checkpoint was not persisted in time; the next start \
                 replays from an older one"
            ),
        }
    }
}

/// Persists each checkpoint `latest` holds that differs from the last one
/// persisted, starting from `saved`, until its sender is dropped and nothing is
/// left to persist. A failed write is retried with whatever checkpoint is
/// latest by then.
async fn write_latest(
    store: impl PersistCheckpoint,
    saved: Option<Checkpoint>,
    mut latest: watch::Receiver<Option<Checkpoint>>,
) {
    let mut persisted = saved;
    let mut failures: Option<Backoff> = None;
    loop {
        let pending = *latest.borrow_and_update();
        if let Some(checkpoint) = pending
            && pending != persisted
        {
            if let Err(error) = store.persist(checkpoint).await {
                metrics::MPC_HTTP_INDEXER_CHECKPOINT_WRITE_FAILURES_TOTAL.inc();
                let delay = failures
                    .get_or_insert_with(|| RetryPolicy::default().backoff())
                    .next_delay(Failure::Transient);
                tracing::error!(
                    height = checkpoint.height,
                    error = format!("{error:#}"),
                    ?delay,
                    "failed to persist the HTTP indexer checkpoint; retrying with the latest one"
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            persisted = pending;
            failures = None;
        }
        if latest.changed().await.is_err() {
            return;
        }
    }
}

/// Durably stores the feed's checkpoint.
trait PersistCheckpoint: Send + Sync + 'static {
    fn persist(&self, checkpoint: Checkpoint) -> impl Future<Output = anyhow::Result<()>> + Send;
}

/// The checkpoint file in the node's home directory.
struct CheckpointFile {
    path: PathBuf,
    identity: ChainIdentity,
}

impl PersistCheckpoint for CheckpointFile {
    async fn persist(&self, checkpoint: Checkpoint) -> anyhow::Result<()> {
        let path = self.path.clone();
        let identity = self.identity.clone();
        tokio::task::spawn_blocking(move || write_checkpoint(&path, &identity, checkpoint)).await?
    }
}

/// Where a feed starts, read before it waits for its first consumer.
struct FeedStart {
    client: Client,
    identity: ChainIdentity,
    last_ack: Option<Checkpoint>,
    start: u64,
}

async fn connect(
    rpc_url: &url::Url,
    checkpoint_path: &Path,
    config: &IndexerConfig,
    finality: Finality,
) -> anyhow::Result<FeedStart> {
    // Every read is retried per request below; near-kit's own retries would stack on top.
    let rpc = RpcClient::with_retry_config(rpc_url.as_str(), RetryConfig::none());
    let status = retry(Request::Status, || async { Ok(rpc.status().await?) }).await;
    let identity = ChainIdentity {
        chain_id: status.chain_id,
        genesis_hash: CryptoHash(status.genesis_hash.into()),
        finality,
    };
    let last_ack = match config.sync_mode {
        SyncMode::Interruption => {
            load_checkpoint(checkpoint_path.to_path_buf(), identity.clone()).await?
        }
        SyncMode::Latest | SyncMode::Block(_) => None,
    };
    let client = Client::new(rpc, finality, MAX_PLAN_HEADERS);
    let start = match (&config.sync_mode, last_ack) {
        (SyncMode::Block(args), _) => args.height,
        (_, Some(checkpoint)) => checkpoint.height,
        (_, None) => {
            retry(Request::Head, || async { Ok(client.head().await?) })
                .await
                .height
        }
    };
    Ok(FeedStart {
        client,
        identity,
        last_ack,
        start,
    })
}

/// Feeds every consumer that [`super::updates::BlockUpdateReceiver::restart`]
/// starts. Samples the start position before waiting for the first consumer,
/// and returns on a fatal error, once no consumer can start any more, or once
/// `shutdown` is cancelled. Before returning, it waits up to
/// [`CHECKPOINT_FLUSH_TIMEOUT`] for the latest checkpoint to be persisted.
pub(super) async fn listen_http_blocks(
    rpc_url: url::Url,
    home_dir: PathBuf,
    config: IndexerConfig,
    state: Arc<IndexerState>,
    starts: ConsumerStarts,
    shutdown: CancellationToken,
    #[cfg(feature = "network-hardship-simulation")]
    process_blocks_receiver: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let finality = match config.finality {
        NodeFinality::Final => Finality::Final,
        NodeFinality::None => Finality::Optimistic,
        NodeFinality::DoomSlug => {
            anyhow::bail!("the HTTP indexer supports only optimistic or final finality")
        }
    };
    let checkpoint_path = http_indexer_checkpoint_file(&home_dir);
    let Some(connected) = shutdown
        .run_until_cancelled(connect(&rpc_url, &checkpoint_path, &config, finality))
        .await
    else {
        return Ok(());
    };
    let FeedStart {
        client,
        identity,
        last_ack,
        start,
    } = connected?;
    let checkpoints = CheckpointWriter::spawn(
        CheckpointFile {
            path: checkpoint_path,
            identity,
        },
        last_ack,
    );
    let feed = HttpFeed {
        client,
        state,
        finality,
        checkpoints,
        start,
        #[cfg(feature = "network-hardship-simulation")]
        process_blocks_receiver,
    };
    let result = shutdown
        .run_until_cancelled(feed.follow(starts, last_ack))
        .await
        .unwrap_or(Ok(()));
    feed.checkpoints.flush(CHECKPOINT_FLUSH_TIMEOUT).await;
    result
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        ChainIdentity, Checkpoint, CheckpointFile, CheckpointWriter, CryptoHash, Finality,
        PersistCheckpoint, REPLAY_WINDOW_BLOCKS, ReadError, Request, advances, must_reanchor,
        read_checkpoint, remedy, replay_cutoff, replay_headers, require_final_checkpoint,
        required_head, retry, send_batch, to_node_message, write_checkpoint,
    };
    use near_indexer_client::near_kit::rpc::{
        BoxFuture, RetryConfig, RpcClient, RpcError, RpcTransport, TransportResponse,
    };
    use near_indexer_client::{Client, Header};
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{Semaphore, mpsc};
    use tokio::time::Instant;

    fn checkpoint(byte: u8, height: u64) -> Checkpoint {
        Checkpoint {
            hash: CryptoHash([byte; 32]),
            height,
        }
    }

    fn rpc_error(name: &str) -> ReadError {
        RpcError::Rpc {
            code: -32000,
            message: "Server error".to_owned(),
            data: Some(json!({"name": name, "info": {}})),
        }
        .into()
    }

    /// `EXPERIMENTAL_indexer_block` response captured from a local test chain,
    /// shared with near-indexer-client's own schema tests.
    const INDEXER_BLOCK_WITH_RECEIPTS: &str =
        include_str!("fixtures/indexer-block-with-receipts.json");

    #[test]
    fn to_node_message__should_preserve_a_real_indexer_block() {
        // Given
        let block: near_indexer_client::IndexerBlock =
            serde_json::from_str(INDEXER_BLOCK_WITH_RECEIPTS).unwrap();
        let expected = serde_json::to_value(&block.message).unwrap();

        // When
        let message = to_node_message(block.message).unwrap();

        // Then
        assert_eq!(serde_json::to_value(&message).unwrap(), expected);
        assert!(
            message
                .shards
                .iter()
                .any(|shard| !shard.receipt_execution_outcomes.is_empty())
        );
    }

    #[test]
    fn replay_cutoff__should_replay_the_request_window_before_a_recent_acknowledgement() {
        // When
        let cutoff = replay_cutoff(1_000, Some(checkpoint(1, 990)), 0);

        // Then
        assert_eq!(cutoff, 790);
    }

    #[test]
    fn replay_cutoff__should_stay_within_the_window_below_the_head_after_a_long_gap() {
        // Given
        let last_ack = checkpoint(1, 1_000_000);
        let head = 1_050_000;

        // When
        let cutoff = replay_cutoff(head, Some(last_ack), 0);

        // Then
        assert_eq!(cutoff, head - REPLAY_WINDOW_BLOCKS);
    }

    #[test]
    fn replay_cutoff__should_start_at_the_position_sampled_when_listening_began() {
        // Given
        let listened_at = 100;

        // When
        let cutoff = replay_cutoff(150, None, listened_at);

        // Then
        assert_eq!(cutoff, listened_at);
    }

    #[test]
    fn replay_cutoff__should_clamp_a_configured_block_far_below_the_head() {
        // When
        let near = replay_cutoff(1_000, None, 950);
        let far = replay_cutoff(1_000, None, 42);

        // Then
        assert_eq!(near, 950);
        assert_eq!(far, 1_000 - REPLAY_WINDOW_BLOCKS);
    }

    #[test]
    fn required_head__should_wait_for_the_acknowledged_height_or_the_start() {
        // When
        let acknowledged = required_head(Some(checkpoint(1, 105)), 7);
        let fresh = required_head(None, 7);

        // Then
        assert_eq!(acknowledged, 105);
        assert_eq!(fresh, 7);
    }

    #[test]
    fn must_reanchor__should_skip_a_gap_longer_than_the_replay_window() {
        // Given
        let cursor = checkpoint(1, 1_000_000);

        // When
        let long_gap = must_reanchor(cursor, 1_050_000);
        let window = must_reanchor(cursor, 1_000_000 + REPLAY_WINDOW_BLOCKS);

        // Then
        assert!(long_gap);
        assert!(!window);
    }

    #[test]
    fn advances__should_never_move_the_checkpoint_below_the_last_acknowledgement() {
        // Given
        let last_ack = checkpoint(1, 105);

        // When
        let replayed_below = advances(Some(last_ack), checkpoint(2, 100));
        let unchanged = advances(Some(last_ack), last_ack);
        let replaced = advances(Some(last_ack), checkpoint(3, 105));
        let higher = advances(Some(last_ack), checkpoint(4, 106));
        let first = advances(None, checkpoint(5, 1));

        // Then
        assert!(!replayed_below);
        assert!(!unchanged);
        assert!(replaced);
        assert!(higher);
        assert!(first);
    }

    #[test]
    fn send_batch__should_carry_the_head_and_discontinuity() {
        // Given
        let (sender, mut receiver) = mpsc::unbounded_channel();

        // When
        let sent = send_batch(&sender, vec![], checkpoint(3, 105), true);
        let batch = receiver.try_recv().unwrap();
        drop(receiver);
        let closed = send_batch(&sender, vec![], checkpoint(4, 106), false);

        // Then
        assert!(sent.is_some());
        assert_eq!(
            batch.head,
            Some((near_indexer_primitives::CryptoHash([3; 32]), 105))
        );
        assert!(batch.discontinuous);
        assert!(closed.is_none());
    }

    #[test]
    fn require_final_checkpoint__should_reject_replaced_or_missing_saved_ancestry() {
        // Given
        let previous = checkpoint(1, 105);
        let replaced = checkpoint(2, 105);

        // When
        let matching =
            require_final_checkpoint(Finality::Final, Some(previous), 100, [previous].into_iter());
        let conflicting =
            require_final_checkpoint(Finality::Final, Some(previous), 100, [replaced].into_iter());
        let missing =
            require_final_checkpoint(Finality::Final, Some(previous), 100, [].into_iter());
        let optimistic = require_final_checkpoint(
            Finality::Optimistic,
            Some(previous),
            100,
            [replaced].into_iter(),
        );

        // Then
        matching.unwrap();
        conflicting.unwrap_err();
        missing.unwrap_err();
        optimistic.unwrap();
    }

    #[test]
    fn require_final_checkpoint__should_skip_a_checkpoint_below_the_replay() {
        // When
        let skipped = require_final_checkpoint(
            Finality::Final,
            Some(checkpoint(1, 105)),
            106,
            [checkpoint(2, 106)].into_iter(),
        );

        // Then
        skipped.unwrap();
    }

    #[test]
    fn read_checkpoint__should_reject_another_chain_or_finality() {
        // Given
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("checkpoint.json");
        let identity = ChainIdentity {
            chain_id: "localnet".to_owned(),
            genesis_hash: CryptoHash([1; 32]),
            finality: Finality::Final,
        };
        let saved = checkpoint(2, 100);
        write_checkpoint(&path, &identity, saved).unwrap();
        let with = |change: fn(&mut ChainIdentity)| {
            let mut other = identity.clone();
            change(&mut other);
            other
        };

        // When
        let restored = read_checkpoint(&path, &identity).unwrap();
        let wrong_chain = read_checkpoint(&path, &with(|i| i.chain_id = "testnet".to_owned()));
        let wrong_genesis = read_checkpoint(&path, &with(|i| i.genesis_hash = CryptoHash([3; 32])));
        let wrong_finality = read_checkpoint(&path, &with(|i| i.finality = Finality::Optimistic));

        // Then
        assert_eq!(restored, Some(saved));
        wrong_chain.unwrap_err();
        wrong_genesis.unwrap_err();
        wrong_finality.unwrap_err();
    }

    #[test]
    fn read_checkpoint__should_start_fresh_without_a_saved_checkpoint() {
        // Given
        let home = tempfile::tempdir().unwrap();
        let identity = ChainIdentity {
            chain_id: "localnet".to_owned(),
            genesis_hash: CryptoHash([1; 32]),
            finality: Finality::Optimistic,
        };

        // When
        let restored = read_checkpoint(&home.path().join("absent.json"), &identity).unwrap();

        // Then
        assert_eq!(restored, None);
    }

    const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
    /// Permits enough for every write a test makes.
    const OPEN: usize = 1_000;

    /// Records every write. Each write first waits for a permit from `gate`,
    /// then fails while `failures` remain.
    #[derive(Clone)]
    struct FakeStore {
        gate: Arc<Semaphore>,
        failures: Arc<AtomicUsize>,
        attempted: Arc<Mutex<Vec<Checkpoint>>>,
        persisted: Arc<Mutex<Vec<Checkpoint>>>,
    }

    impl FakeStore {
        fn new(permits: usize, failures: usize) -> Self {
            Self {
                gate: Arc::new(Semaphore::new(permits)),
                failures: Arc::new(AtomicUsize::new(failures)),
                attempted: Arc::default(),
                persisted: Arc::default(),
            }
        }

        fn open(&self) {
            self.gate.add_permits(OPEN);
        }

        fn attempted(&self) -> Vec<Checkpoint> {
            self.attempted.lock().unwrap().clone()
        }

        fn persisted(&self) -> Vec<Checkpoint> {
            self.persisted.lock().unwrap().clone()
        }

        async fn must_wait_for_attempts(&self, count: usize) {
            for _ in 0..1_000 {
                if self.attempted().len() >= count {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("the writer did not attempt {count} writes");
        }
    }

    impl PersistCheckpoint for FakeStore {
        async fn persist(&self, checkpoint: Checkpoint) -> anyhow::Result<()> {
            self.attempted.lock().unwrap().push(checkpoint);
            self.gate.acquire().await?.forget();
            let failed = self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            anyhow::ensure!(!failed, "disk full");
            self.persisted.lock().unwrap().push(checkpoint);
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn checkpoint_writer__should_coalesce_checkpoints_published_during_a_slow_write() {
        // Given
        let store = FakeStore::new(0, 0);
        let writer = CheckpointWriter::spawn(store.clone(), None);
        writer.publish(checkpoint(1, 101));
        store.must_wait_for_attempts(1).await;

        // When
        for height in 102..=105 {
            writer.publish(checkpoint(2, height));
        }
        store.open();
        writer.flush(FLUSH_TIMEOUT).await;

        // Then
        assert_eq!(store.persisted(), [checkpoint(1, 101), checkpoint(2, 105)]);
    }

    #[tokio::test(start_paused = true)]
    async fn checkpoint_writer__should_retry_a_failed_write_with_the_latest_checkpoint() {
        // Given
        let store = FakeStore::new(OPEN, 1);
        let writer = CheckpointWriter::spawn(store.clone(), None);
        writer.publish(checkpoint(1, 101));
        store.must_wait_for_attempts(1).await;
        let failed_at = Instant::now();

        // When
        writer.publish(checkpoint(2, 102));
        writer.flush(FLUSH_TIMEOUT).await;

        // Then
        assert_eq!(store.attempted(), [checkpoint(1, 101), checkpoint(2, 102)]);
        assert_eq!(store.persisted(), [checkpoint(2, 102)]);
        assert_eq!(failed_at.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn checkpoint_writer__should_never_persist_an_older_checkpoint_after_a_newer_one() {
        // Given
        let store = FakeStore::new(0, 2);
        let writer = CheckpointWriter::spawn(store.clone(), None);

        // When
        for height in 101..=110 {
            writer.publish(checkpoint(1, height));
            tokio::task::yield_now().await;
            store.gate.add_permits(1);
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        store.open();
        writer.flush(FLUSH_TIMEOUT).await;

        // Then
        let heights: Vec<_> = store.attempted().iter().map(|c| c.height).collect();
        assert!(heights.is_sorted_by(|a, b| a < b), "{heights:?}");
        assert_eq!(store.persisted().last(), Some(&checkpoint(1, 110)));
    }

    #[tokio::test(start_paused = true)]
    async fn checkpoint_writer__should_persist_the_pending_checkpoint_on_flush() {
        // Given
        let store = FakeStore::new(0, 0);
        let writer = CheckpointWriter::spawn(store.clone(), None);
        writer.publish(checkpoint(1, 101));
        store.must_wait_for_attempts(1).await;
        writer.publish(checkpoint(2, 102));

        // When
        let flush = tokio::spawn(writer.flush(FLUSH_TIMEOUT));
        store.open();
        flush.await.unwrap();

        // Then
        assert_eq!(store.persisted(), [checkpoint(1, 101), checkpoint(2, 102)]);
    }

    #[tokio::test(start_paused = true)]
    async fn checkpoint_writer__should_stop_waiting_for_a_stuck_write_after_the_flush_timeout() {
        // Given
        let store = FakeStore::new(0, 0);
        let writer = CheckpointWriter::spawn(store.clone(), None);
        writer.publish(checkpoint(1, 101));
        store.must_wait_for_attempts(1).await;
        let started = Instant::now();

        // When
        writer.flush(FLUSH_TIMEOUT).await;

        // Then
        assert_eq!(started.elapsed(), FLUSH_TIMEOUT);
        assert!(store.persisted().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn checkpoint_writer__should_skip_the_checkpoint_already_saved() {
        // Given
        let saved = checkpoint(1, 101);
        let store = FakeStore::new(OPEN, 0);
        let writer = CheckpointWriter::spawn(store.clone(), Some(saved));

        // When
        writer.publish(saved);
        writer.flush(FLUSH_TIMEOUT).await;

        // Then
        assert!(store.attempted().is_empty());
    }

    #[tokio::test]
    async fn checkpoint_file__should_persist_a_checkpoint_the_next_start_reads() {
        // Given
        let home = tempfile::tempdir().unwrap();
        let identity = ChainIdentity {
            chain_id: "localnet".to_owned(),
            genesis_hash: CryptoHash([1; 32]),
            finality: Finality::Final,
        };
        let file = CheckpointFile {
            path: home.path().join("checkpoint.json"),
            identity: identity.clone(),
        };

        // When
        file.persist(checkpoint(2, 100)).await.unwrap();

        // Then
        assert_eq!(
            read_checkpoint(&file.path, &identity).unwrap(),
            Some(checkpoint(2, 100))
        );
    }

    #[test]
    fn remedy__should_name_the_size_cap_for_an_oversized_block() {
        // Given
        let error = near_indexer_client::Error::from(RpcError::Rpc {
            code: -32000,
            message: "Server error".to_owned(),
            data: Some(json!({"name": "LIMIT_EXCEEDED"})),
        });

        // When
        let remedy = remedy(error.kind());

        // Then
        assert!(remedy.contains("size cap"), "{remedy}");
    }

    #[tokio::test(start_paused = true)]
    async fn retry__should_keep_retrying_a_block_error_instead_of_failing() {
        // Given
        let attempts = AtomicUsize::new(0);
        let started = Instant::now();

        // When
        let value = retry(Request::Head, || async {
            match attempts.fetch_add(1, Ordering::SeqCst) {
                0 => Err(rpc_error("LIMIT_EXCEEDED")),
                1 => Err(rpc_error("BUSY")),
                _ => Ok(42),
            }
        })
        .await;

        // Then
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(started.elapsed(), Duration::from_millis(1_500));
    }

    #[tokio::test(start_paused = true)]
    async fn retry__should_measure_the_data_grace_period_from_the_first_failure() {
        // Given
        let attempts = AtomicUsize::new(0);
        let started = Instant::now();

        // When
        retry(Request::Head, || async {
            if attempts.fetch_add(1, Ordering::SeqCst) < 8 {
                return Err(rpc_error("DATA_UNAVAILABLE"));
            }
            Ok(())
        })
        .await;

        // Then
        // Seven transient waits (0.5 + 1 + 2 + 4 + 8 + 10 + 10 s) pass the 30 s
        // grace, so the eighth failure waits a persistent 60 s, not 10 s.
        assert_eq!(attempts.load(Ordering::SeqCst), 9);
        assert_eq!(started.elapsed(), Duration::from_millis(95_500));
    }

    /// Serves `block` headers for a chain whose block at height `h` has a hash
    /// encoding `h`, counting the requests.
    struct SyntheticChain {
        requests: AtomicUsize,
    }

    fn must_hash(height: u64) -> CryptoHash {
        let mut bytes = [1; 32];
        bytes[..8].copy_from_slice(&height.to_le_bytes());
        CryptoHash(bytes)
    }

    fn must_header(height: u64) -> Header {
        Header {
            hash: must_hash(height),
            prev_hash: must_hash(height - 1),
            height,
            last_final_block: must_hash(height - 2),
        }
    }

    impl RpcTransport for SyntheticChain {
        fn post_json(
            &self,
            _url: &str,
            body: Vec<u8>,
        ) -> BoxFuture<'_, Result<TransportResponse, RpcError>> {
            Box::pin(async move {
                self.requests.fetch_add(1, Ordering::SeqCst);
                let request: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["method"], "block");
                let hash: CryptoHash =
                    serde_json::from_value(request["params"]["block_id"].clone()).unwrap();
                let height = u64::from_le_bytes(hash.0[..8].try_into().unwrap());
                let header = must_header(height);
                let result = json!({"header": {
                    "hash": header.hash,
                    "prev_hash": header.prev_hash,
                    "height": header.height,
                    "last_final_block": header.last_final_block,
                }});
                Ok(TransportResponse {
                    status: 200,
                    body: serde_json::to_vec(
                        &json!({"jsonrpc": "2.0", "id": request["id"], "result": result}),
                    )
                    .unwrap(),
                })
            })
        }
    }

    #[tokio::test]
    async fn replay_headers__should_walk_only_the_window_after_a_gap_far_beyond_the_old_limit() {
        // Given
        let chain = Arc::new(SyntheticChain {
            requests: AtomicUsize::new(0),
        });
        let rpc = RpcClient::with_transport_and_retry_config(
            "http://fixture.invalid",
            chain.clone(),
            RetryConfig::none(),
        );
        let client = Client::new(rpc, Finality::Final, 1);
        let last_ack = checkpoint(1, 1_000_000);
        let head = must_header(1_050_000);
        let cutoff = replay_cutoff(head.height, Some(last_ack), 0);

        // When
        let headers = replay_headers(&client, head, cutoff).await;

        // Then
        let heights: Vec<_> = headers.iter().map(|header| header.height).collect();
        let expected: Vec<_> = (head.height - REPLAY_WINDOW_BLOCKS..=head.height).collect();
        assert_eq!(heights, expected);
        assert_eq!(
            chain.requests.load(Ordering::SeqCst),
            usize::try_from(REPLAY_WINDOW_BLOCKS + 1).unwrap()
        );
    }
}
