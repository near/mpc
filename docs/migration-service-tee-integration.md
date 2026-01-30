# Migration Service TEE integration

This documents outlines the design and efforts for running the migration and backup service inside a trusted execution environment (c.f. [migration-service](migration-service.md) for more details on the migration and backup service, as well as for the motivation of running it inside a TEE).

## Introduction

The backup service will want to submit proof to the blockchain that it's running inside a TEE. Further, it will need to track the MPC contract state, such that it can act autonomously without intervention by the node operator (currently, backups and migrations require a lot of manual intervention by the node operators).
For that reason, the design discussion can be split in two tracks:

1. Indexer integration with the migration and backup service. Similar to how the MPC nodes keep track of the Contract state by running an indexer, the migration and backup service will do the same.
2. TEE integration under the assumption that the migration and backup service is running an indexer.

It seems possible to work on both of these tracks in parallel, if we agree on the indexer an MPC contract API beforehand.

## Indexer

### Background and Motivation

The node is already running an indexer. It makes sense to re-use the existing logic for the following reasons:
- Generally, it is preferred to re-use code where applicable;
- The indexer exposes some Near internals, which have experienced breaking changes in the past. It would thus be good to only have to maintain one place where we depend on these internals.
- There exist larger plans for the indexer. It is quite useful to have a standalone binary that is capable of monitoring the MPC contract and recognizing transactions related to the MPC network. We could use it as a tool for monitoring our production deployments.

On a high-level, we expect to be doing the following:

1. Clean up the indexer API in the MPC node, such that it will be easy to separate it from the node. We **should not** nearcore internals - we would like to have a single point of failure in case nearcore decides to change the indexer API.
2. Move the indexer code into its own crate.
3. Add the indexer crate as a dependency to the migration and backup service.

As a first step, we need to agree on an indexer API.

### Proposed Indexer API

This is the current IndexerAPI:

```rust
/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#155): This would be the interface to abstract away having an indexer
/// running in a separate process.
pub struct IndexerAPI<TransactionSender> {
    /// Provides the current contract state as well as updates to it.
    pub contract_state_receiver: watch::Receiver<ContractState>,
    /// Provides block updates (signature requests and other relevant receipts).
    /// It is in a mutex, because the logical "owner" of this receiver can
    /// change over time (specifically, when we transition from the Running
    /// state to a Resharing state to the Running state again, two different
    /// tasks would successively "own" the receiver).
    /// We do not want to re-create the channel, because while resharing is
    /// happening we want to buffer the signature requests.
    pub block_update_receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ChainBlockUpdate>>>,
    /// Handle to transaction processor.
    pub txn_sender: TransactionSender,
    /// Watcher that keeps track of allowed [`DockerImageHash`]es on the contract.
    pub allowed_docker_images_receiver: watch::Receiver<Vec<MpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,
}
```

Note that it consist of the following:
- view functions (for finalized contract state):
    - `contract_state_receiver`
    - `allowed_docker_images_receiver`
    - `allowed_launcher_compose_receiver`
    - `attested_nodes_receiver`
    - `my_migration_info_receiver`
- view streams (for monitoring non-finalized transactions related to the contract)
    - `block_update_receiver`
- write functions (sending transactions)
    - `txn_sender`

Not all users of the indexer crate will be interested in all of these capabilities. Monitoring our production deployments might not need the ability to send any transactions, while the backup and migration service does not care about block updates.

Thus, it seems sensible to offer separate API's for:
- state view
- block stream 
- transaction sender


#### State View

The indexer should offer a convenient method for viewing and subscribing to MPC contract state. While it would be sufficient to only expose a simple view function like the following:

```rust
#[async_trait::async_trait]
trait MpcContractStateView {
    async fn get<T: DeserializeOwned>(
        &self,
        endpoint: MpcContractEndpoint,
    ) -> anyhow::Result<(BlockHeight, T)>;
}
```

we might need re-write a lot of the monitoring and subscription logic on the consumer side. Hence, it makes sense to additionally expose a subscriber logic:

```rust
#[async_trait::async_trait]
trait MpcContractStateSubscriber {
    async fn subscribe<T: DeserializeOwned + PartialEq + Send + 'static>(
        &self,
        endpoint: MpcContractEndpoint,
        subscriber_policy: SubscriberPolicy,
    ) -> anyhow::Result<Oneshot<watch::Receiver<(BlockHeight,T)>>>;
}
```

Alternatively, if we are concerned about having `tokio::watch` and `oneshot` channels in our API, we could return a struct with the following traits:

```rust
#[async_trait::async_trait]
trait ContractStateStream<T> {
    /// is synchronous, contains the last seen value
    fn latest(&self) -> (BlockHeight, &T);
    /// must be cancellation safe
    /// returned BlockHeight is monotonically increasing
    async fn next(&mut self) -> (BlockHeight, &T);
}

#[async_trait::async_trait]
trait MpcContractStateSubscriber {
    async fn subscribe<T: DeserializeOwned + PartialEq + Send + 'static>(
        &self,
        endpoint: MpcContractEndpoint,
        subscriber_policy: SubscriberPolicy,
    ) -> anyhow::Result<Box<dyn ContractStateStream<T> + Send>>;
}
```

where `SubscriberPolicy` details how the indexer should query new contract state (e.g. exponential backoff, interval, etc), the behavior on error etc.
It could look something like this:

```rust
pub struct SubscriberPolicy {
    // poll strategy to use for bootstrapping (until we receive the first result)
    pub bootstrap: PollStrategy,
    // poll statey to use for updates
    pub updates: PollStrategy,
}

pub struct PollStrategy {
    /// duration between two consecutive polls
    pub poll_interval: Duration,
    pub on_failure: FailurePolicy,
}

/// Defines the behavior on failure
pub enum FailurePolicy {
    /// Abort the stream immediately on error
    FailFast,
    /// Retry after applying a backoff strategy
    Retry {
        backoff: BackoffStrategy,
    },
}

/// Defines the timeout between consecutive attempts
pub enum BackoffStrategy {
    Fixed(Duration),
    Exponential {
        initial: Duration,
        max: Duration,
    },
}
```

#### BlockStream

For the next few months, the only expected user of block streams is the MPC node. This might change in the future if we use the indexer crate for monitoring and testing our MPC code, but for now, it seems safe to just port the existing design to the indexer until we have a better idea of what changes we would want from it.

```Rust
// c.f. https://github.com/near/mpc/issues/236 for start_block_height
trait MpcEventSubscriber {
    async fn subscribe(interval: Duration, channel_size: usize, start_block_height) -> anyhow::Result<mpsc::Receiver<ChainBlockUpdate>>;
}

pub struct ChainBlockUpdate {
    pub block: BlockViewLite,
    pub signature_requests: Vec<SignatureRequestFromChain>,
    pub completed_signatures: Vec<SignatureId>,
    pub ckd_requests: Vec<CKDRequestFromChain>,
    pub completed_ckds: Vec<CKDId>,
}
```

##### Transaction Sender

Similarly, it's probably fine for the first iteration to keep the existing `TransactionSender` trait:

```rust
pub trait TransactionSender: Clone + Send + Sync {
    fn send(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> impl Future<Output = Result<(), TransactionProcessorError>> + Send;

    fn send_and_wait(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> impl Future<Output = Result<TransactionStatus, TransactionProcessorError>> + Send;
}
```

### Implementation

Some pre-conditions must be met:
1. We need to refactor the node, such that the Indexer's view methods only transmit types part of the contract interface. C.f. https://github.com/near/mpc/issues/1184
2. we can then construct what is currently `IndexerAPI` from our traits (WIP):

```rust
fn make_indexer_api(indexer_config: IndexerConfig) -> IndexerAPI<MpcTransactionSender> {
    let indexer = crate::indexer::new(indexer_config);
    let policy = DEFAULT_POLICY;

    let contract_state_receiver =
        subscribe_as_watch::<ContractState>(
            &indexer.state,
            CONTRACT_STATE_ENDPOINT,
            policy.clone(),
        )?;

    let allowed_docker_images_receiver =
        subscribe_as_watch::<Vec<MpcDockerImageHash>>(
            &indexer.state,
            ALLOWED_IMAGE_HASHES_ENDPOINT,
            policy.clone(),
        )?;

    let allowed_launcher_compose_receiver =
        subscribe_as_watch::<Vec<LauncherDockerComposeHash>>(
            &indexer.state,
            ALLOWED_LAUNCHER_COMPOSE_HASHES_ENDPOINT,
            policy.clone(),
        )?;

    let attested_nodes_receiver =
        subscribe_as_watch::<Vec<NodeId>>(
            &indexer.state,
            TEE_ACCOUNTS_ENDPOINT,
            policy.clone(),
        )?;

    let my_migration_info_receiver =
        subscribe_as_watch::<MigrationInfo>(
            &indexer.state,
            MIGRATION_INFO_ENDPOINT,
            policy,
        )?;

    let block_update_receiver =
        indexer.events.subscribe(
            DEFAULT_EVENT_INTERVAL,
            DEFAULT_CHANNEL_SIZE,
            START_BLOCK_HEIGHT,
        )?;

    let txn_sender = indexer.make_sender();

    IndexerAPI {
        contract_state_receiver,
        allowed_docker_images_receiver,
        allowed_launcher_compose_receiver,
        attested_nodes_receiver,
        my_migration_info_receiver,
        block_update_receiver,
        txn_sender,
    }
}

async fn subscribe_as_watch<T>(
    subscriber: &impl MpcContractStateSubscriber,
    endpoint: MpcContractEndpoint,
    policy: SubscriberPolicy,
) -> anyhow::Result<watch::Receiver<(BlockHeight, T)>>
where
    T: DeserializeOwned + PartialEq + Send + 'static,
{
    let mut stream = subscriber
        .subscribe::<T>(endpoint, policy)
        .await?;

    let (height, value) = stream.latest();
    let (tx, rx) = watch::channel((height, value.clone()));

    tokio::spawn(async move {
        let mut stream = stream;
        loop {
            let (height, value) = stream.next().await;
            if tx.send((height, value.clone())).is_err() {
                // Receiver dropped → stop task
                break;
            }
        }
    });

    Ok(rx)
}

```


## Smart contract & Backup service changes

Note: WIP

