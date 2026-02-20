# Chain Gateway

This crate spawns and interacts with an in-process neard node. It provides three subsystems for blockchain interaction:

- **State Viewer:** query and subscribe to arbitrary view methods on NEAR smart contracts.
- **Block Events:** filter finalized blocks for matching transactions/receipts and receive them as a stream. *(planned — not yet implemented)*
- **Transaction Sender:** submit signed transactions to the NEAR blockchain.

```rust
use chain_gateway::chain_gateway::start_with_streamer;

let (chain_gateway, stream) = start_with_streamer(near_indexer_config).await?;

let viewer = chain_gateway.viewer();           // StateViewer
let tx_sender = chain_gateway.transaction_sender(); // TransactionSender
```

```mermaid
---
title: MPC Orchestration
---
flowchart TB

subgraph CHAIN[Chain Gateway]
    direction TB
    TX_SUBSCRIBER[**Block Event Subscriber**<br/><br/>
        **Filters** non-finalized NEAR blocks for specific transactions
        **Returns** matching args in a stream
    ]

    CONTRACT_STATE_VIEWER[**State Viewer**<br/><br/>
        **Queries** view functions of smart contracts
        **Returns** the result to the MPC Context
    ]

    TX_SENDER[**Transaction Sender**<br/><br/>
        **Submits** transaction to the neard node
        **Returns** transaction hash
    ]

    subgraph NEARD[**Neard node**]
        direction TB
        BLOCK_STREAMER[**Streamer**]

        VIEW_CLIENT[**View Client**]

        RPC_HANDLER[**RPC Handler**]

    end
end

subgraph NEAR[NEAR Blockchain]
    direction TB

    subgraph MEMPOOL[NEAR Mempool]
    end

    subgraph CONTRACT[MPC Smart Contract]
        direction TB
        CONTRACT_VIEW[
        <b>Read Methods</b>
        ]

        CONTRACT_WRITE[
        <b>Write Methods</b>
        ]


    end

end


%% Chain Gateway --> Neard Node
TX_SUBSCRIBER --> BLOCK_STREAMER
CONTRACT_STATE_VIEWER --> VIEW_CLIENT
TX_SENDER --> RPC_HANDLER

%% Neard --> Smart Contract
RPC_HANDLER --> MEMPOOL
MEMPOOL -.-> CONTRACT_WRITE
VIEW_CLIENT --> CONTRACT_VIEW
BLOCK_STREAMER --> MEMPOOL

%% ------------------------
%% Styling
%% ------------------------

classDef core stroke:#1b5e20,stroke-width:4px;
classDef indexer stroke:#2563eb,stroke-width:4px;
classDef near stroke:#7c3aed,stroke-width:4px;
classDef contract stroke:#d97706,stroke-width:2px;
classDef mempool stroke:#0f766e,stroke-width:2px;
classDef chain stroke-width:2px;

class NEAR near;
class CONTRACT contract;
class MEMPOOL mempool;
class CHAIN chain;
```

## API

### State Viewer

`StateViewer` provides one-shot view calls and polling-based subscriptions to contract state.
It is generic over `ContractViewer`, which is the testing seam — production code uses `NearContractViewer`
(backed by the real nearcore actor system), while unit tests can substitute a `FakeViewer`.

```rust
/// Testing seam: abstracts the raw contract view call.
#[async_trait]
pub trait ContractViewer: Send + Sync + Clone + 'static {
    async fn view_raw(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ViewOutput, ChainGatewayError>;
}

/// External API for querying contract state.
/// Defaults to NearContractViewer (the real NEAR viewer).
pub struct StateViewer<V = NearContractViewer> { /* ... */ }

impl<V: ContractViewer> StateViewer<V> {
    /// One-shot view call. Serializes `args` as JSON, deserializes the response as `Res`.
    pub async fn view<Arg: Serialize, Res: DeserializeOwned>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<(BlockHeight, Res), ChainGatewayError>;

    /// Subscribe to a view method (with arguments). Polls every 200ms.
    pub async fn subscribe<Arg: Serialize, Res: DeserializeOwned + Send + Clone>(
        &self,
        contract_id: AccountId,
        method_name: &str,
        args: &Arg,
    ) -> Result<impl ContractStateStream<Res>, ChainGatewayError>;

    /// Subscribe to a view method with no arguments (`{}`). Polls every 200ms.
    pub async fn subscribe_no_args<Res: DeserializeOwned + Send + Clone>(
        &self,
        contract_id: AccountId,
        method_name: &str,
    ) -> impl ContractStateStream<Res>;
}
```

The `ContractStateStream` trait provides a watch-like interface for observing contract state changes:

```rust
#[async_trait]
pub trait ContractStateStream<Res> {
    /// Returns the last value observed on chain and the block height at which it last changed.
    fn latest(&mut self) -> Result<(BlockHeight, Res), ChainGatewayError>;

    /// Waits until the observed value changes.
    async fn changed(&mut self) -> Result<(), ChainGatewayError>;

    /// Waits for the next state change and returns the new value.
    async fn next(&mut self) -> Result<(BlockHeight, Res), ChainGatewayError>;
}
```


### Block Event Subscriber

> **Status: not yet implemented.** Block event handling currently lives in
> `node::indexer::handler::listen_blocks()`, which consumes the raw `StreamerMessage` channel
> returned by `start_with_streamer()`. The API below is the planned design for when this
> functionality is moved into chain-gateway.

```rust
impl BlockEventSubscriber {
    pub fn new(subscription_replay: SubscriptionReplay) -> Self;

    /// Configure queue size between producer and consumer.
    /// we can define overflow behavior later, by default we could just stop producing (neard indexer will consume unlimited amount of memory).
    pub fn buffer_size(&mut self, n: usize) -> Self;

    /// Add a subscription and get a unique identifier for it.
    /// Can be called multiple times before build().
    /// the identifier can be used to match a return value to the given subscription id.
    pub fn add_subscription(&mut self, filter: SubscriptionFilter) -> SubscriptionId;

    /// Finalise and start streaming.
    pub async fn start(&mut self) -> Result<tokio::sync::mpsc::Receiver<BlockUpdate>, BuilderError>;
}

/// an identifier for a subscription
pub struct SubscriptionId(pub u64);

/// Filter - can be easily extended later
pub enum SubscriptionFilter {
    /// Filter for events where a receipt outcome was executed by `transaction_outcome_executor_id` and called `method_name`.
    ExecutorFunctionCall {
        transaction_outcome_executor_id: AccountId,
        method_name: String,
    },
    /// Filter for events where a receipt was addressed to `receipt_receiver_id` and called `method_name`.
    ReceiverFunctionCall {
        receipt_receiver_id: AccountId,
        method_name: String,
    },
}

/// we want to offer the possibility to re-play blocks if necessary (c.f. [#236](https://github.com/near/mpc/issues/236))
pub enum SubscriptionReplay {
    /// no replay, start once indexer has caught up to the current block height
    None,
    /// Start at a specific height
    BlockHeight(u64),
}

```

Example usage:
```rust

let mut subscriber = BlockEventSubscriber::new(SubscriptionReplay::None);

let signature_requests_id = subscriber.add_subscription(
    SubscriptionFilter::ExecutorFunctionCall {
        transaction_outcome_executor_id: "v1.signer".parse()?,
        method_name: "sign".to_string(),
    }
);

let ckd_request_id = subscriber.add_subscription(
    SubscriptionFilter::ExecutorFunctionCall {
        transaction_outcome_executor_id: "v1.signer".parse()?,
        method_name: "request_app_private_key".to_string(),
    }
);

let mut block_stream_receiver : tokio::sync::mpsc::Receiver<BlockUpdate> = subscriber.start().await?;

while let Some(update) = block_stream_receiver.recv().await {
    for matched in update.events {
        match matched.id {
            id if id == signature_requests_id => { /* handle signature request */ }
            id if id == ckd_request_id => { /* handle ckd request */ }
            _ => {}
        }
    }
}

```

Specific types (c.f. [Appendix](#current-block-update) and `indexer/handler.rs` for justification).
```rust
/// The BlockUpdate returned by the Chain indexer. Similar to the current `BlockUpdate`
pub struct BlockUpdate {
    pub ctx: BlockContext,
    pub events: Vec<MatchedEvent>,
}

/// Context for a single block
pub struct BlockContext {
    pub hash: CryptoHash,
    pub height: u64,
    pub prev_hash: CryptoHash,
    pub last_final_block: CryptoHash,
    pub block_entropy: [u8; 32],
    pub block_timestamp_nanosec: u64,
}

pub struct MatchedEvent {
    /// this is needed such that the caller can identify the filter
    pub id: SubscriptionId,
    /// any data associated with that event
    pub event_data: EventData,
}

/// this can be extended if required
pub enum EventData {
    ExecutorFunctionCall(ExecutorFunctionCallEventData),
    ReceiverFunctionCall(ReceiverFunctionCallEventData),
}

/// This event is associated to a transaction that matched a specific (transaction_outcome_executor_id: AccountId, method_name: String) pattern.
struct ExecutorFunctionCallEventData {
    /// the receipt_id of the receipt this event came from
    receipt_id: CryptoHash,
    /// predecessor_id who signed the transaction
    predecessor_id : AccountId,
    /// the receipt that will hold the outcome of this receipt
    next_receipt_id: CryptoHash,
    /// raw bytes used for function call. Could probably also be a String.
    args_raw: Vec<u8>,
}

/// This event is associated to a transaction that matched a specific SubscriptionFilter
struct ReceiverFunctionCallEventData {
    // the receipt id for the matched transaction
    receipt_id: CrpytoHash,
}
```


### Transaction Sender

```rust

pub struct TransactionSender<V>
where
    V: LatestFinalBlock,
{
    /// rpc handler for sending txs to the chain (internal type, c.f. indexer.rs)
    rpc_handler: IndexerRpcHandler,
    /// method to the view client to query the latest final block (needed for nonce computation)
    view_client: V,
}

/// we could probably make this a trait for testing?
impl<V> TransactionSender<V>
where
    V: LatestFinalBlock
{
    /// creates a function call transaction for contract `receiver_id` with method `method_name` and args `args`
    /// returns the CryptoHash for the receipt, such that the execution outcome can be tracked
    pub async fn submit_function_call_tx(
        &self,
        /// Key with which this transaction should be signed
        signer: TransactionSigner,
        /// contract on which this method should be called
        receiver_id: AccountId,
        /// method name to call
        method_name: String,
        /// arguments for the method
        args: Vec<u8>,
        /// deposit amount
        deposit: Near,
        /// gas to attach
        gas: Gas,
    ) -> Result<CryptoHash, TxSignerError>;
}

/// we will implement this for the view client
trait LatestFinalBlock {
    async fn latest_final_block(&self) -> Result<BlockView, Error>;
}
```

Additionally, we will expose the following types and methods (omitting internals, c.f. tx_signer.rs)
```rust
pub struct TransactionSigner {
    signing_key: SigningKey,
    account_id: AccountId,
    nonce: Mutex<u64>,
}

impl TransactionSigner {
    pub fn from_key(account_id: AccountId, signing_key: SigningKey) -> Self {
        TransactionSigner {
            account_id,
            signing_key,
            nonce: Mutex::new(0),
        }
    }
    /// might be good to expose
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}
```

## Testing

- **Unit tests** use a `FakeViewer` implementing the `ContractViewer` trait to test subscription
  logic without a real NEAR node (see `src/state_viewer/subscription.rs`).
- **Integration tests** start a full in-process NEAR node with a WAT contract embedded in genesis,
  exercising the complete path through the actor system (see `tests/state_viewer_integration.rs`).
