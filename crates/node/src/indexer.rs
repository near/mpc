use crate::mpc_state::MpcState;

use self::stats::IndexerStats;
use chain_gateway::ChainGateway;
use handler::ChainBlockUpdate;
use near_account_id::AccountId;
use near_async::{
    messaging::CanSendAsync, multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle,
};
use near_client::{RpcHandlerActor, Status, client_actor::ClientActor};
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::types::BlockHeight;
use near_mpc_contract_interface::client::MpcContractHandle;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};
use types::ChainSendTransactionRequest;

pub mod configs;
pub mod foreign_chain;
pub mod handler;
pub mod migrations;
pub mod near_data_wipe;
pub mod participants;
pub mod real;
pub mod stats;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;

#[cfg(test)]
pub mod fake;

pub(crate) struct IndexerState {
    contract: MpcContractHandle<ChainGateway>,
    gateway: ChainGateway,
    /// For querying blockchain sync status.
    client: IndexerClient,
    /// For sending txs to the chain.
    rpc_handler: IndexerRpcHandler,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
    /// Stores runtime indexing statistics.
    stats: Arc<Mutex<IndexerStats>>,
}

impl IndexerState {
    pub fn new(
        gateway: ChainGateway,
        client: TokioRuntimeHandle<ClientActor>,
        rpc_handler: MultithreadRuntimeHandle<RpcHandlerActor>,
        mpc_contract_id: AccountId,
    ) -> Self {
        Self {
            contract: MpcContractHandle::new(gateway.clone(), mpc_contract_id.clone()),
            gateway,
            client: IndexerClient { client },
            rpc_handler: IndexerRpcHandler { rpc_handler },
            mpc_contract_id,
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }
}

#[derive(Clone)]
struct IndexerClient {
    client: TokioRuntimeHandle<ClientActor>,
}

const INTERVAL: Duration = Duration::from_millis(500);

/// Consecutive non-syncing polls with head progress before the node counts as caught up.
const REQUIRED_STABLE_POLLS: u32 = 4;

impl IndexerClient {
    /// Polls sync status, yielding `(syncing, head_height)`, or `None` on a
    /// failed request.
    async fn sync_info(&self) -> Option<(bool, BlockHeight)> {
        let status_request = Status {
            is_health_check: false,
            detailed: false,
        };
        let Ok(Ok(status)) = self
            .client
            .send_async(
                near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(status_request),
            )
            .await
        else {
            return None;
        };
        Some((
            status.sync_info.syncing,
            status.sync_info.latest_block_height,
        ))
    }

    async fn ensure_head_follows_tip(&self) {
        let mut progress = SyncProgress::default();
        loop {
            tokio::time::sleep(INTERVAL).await;
            if let Some((syncing, head_height)) = self.sync_info().await
                && progress.observe(syncing, head_height)
            {
                return;
            }
        }
    }
}

/// Reports caught-up only after [`REQUIRED_STABLE_POLLS`] consecutive
/// non-syncing polls over which the head advances.
#[derive(Default)]
struct SyncProgress {
    run_start_head: Option<BlockHeight>,
    run_polls: u32,
}

impl SyncProgress {
    fn observe(&mut self, syncing: bool, head_height: BlockHeight) -> bool {
        if syncing {
            self.run_start_head = None;
            self.run_polls = 0;
            return false;
        }
        match self.run_start_head {
            None => {
                self.run_start_head = Some(head_height);
                self.run_polls = 1;
                false
            }
            Some(start_head) => {
                self.run_polls += 1;
                self.run_polls >= REQUIRED_STABLE_POLLS && head_height > start_head
            }
        }
    }
}

// #[derive(Debug)]
struct IndexerRpcHandler {
    rpc_handler: MultithreadRuntimeHandle<RpcHandlerActor>,
}

impl IndexerRpcHandler {
    /// Creates, signs, and submits a function call with the given method and serialized arguments.
    async fn submit_tx(&self, transaction: SignedTransaction) -> anyhow::Result<()> {
        let response = self
            .rpc_handler
            .send_async(near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            })
            .await?;

        match response {
            // We're not a validator, so we should always be routing the transaction.
            near_client::ProcessTxResponse::RequestRouted => Ok(()),
            _ => {
                anyhow::bail!("unexpected ProcessTxResponse: {:?}", response);
            }
        }
    }
}

/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#592): abstract away having an indexer running in a separate process
pub struct IndexerAPI<TransactionSender> {
    /// The contract-derived state the node runs against.
    pub mpc_state: MpcState,
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
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{BlockHeight, REQUIRED_STABLE_POLLS, SyncProgress};

    fn first_caught_up_poll(samples: &[(bool, BlockHeight)]) -> Option<usize> {
        let mut progress = SyncProgress::default();
        samples
            .iter()
            .position(|&(syncing, head)| progress.observe(syncing, head))
    }

    #[test]
    fn observe__should_never_report_caught_up_while_syncing() {
        // Given
        let samples: Vec<_> = (0..10).map(|i| (true, 42_000_000 + i)).collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_never_report_caught_up_with_static_head_at_genesis() {
        // Given
        let genesis = 42_376_888;
        let samples: Vec<_> = (0..10).map(|_| (false, genesis)).collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_not_report_caught_up_before_required_polls() {
        // Given
        let samples: Vec<_> = (0..REQUIRED_STABLE_POLLS - 1)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_report_caught_up_after_sustained_progress() {
        // Given
        let samples: Vec<_> = (0..REQUIRED_STABLE_POLLS)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        let expected = usize::try_from(REQUIRED_STABLE_POLLS).unwrap() - 1;
        assert_eq!(caught_up_at, Some(expected));
    }

    #[test]
    fn observe__should_wait_for_head_to_advance_past_run_start() {
        // Given
        let head = 257_000_000;
        let mut samples: Vec<_> = (0..REQUIRED_STABLE_POLLS + 2)
            .map(|_| (false, head))
            .collect();
        samples.push((false, head + 1));

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, Some(samples.len() - 1));
    }

    #[test]
    fn observe__should_reset_run_when_syncing_resumes() {
        // Given
        let pre = [
            (false, 42_000_000),
            (false, 42_000_001),
            (false, 42_000_002),
        ];
        let resync = [(true, 100_000_000)];
        let post: Vec<_> = (0..REQUIRED_STABLE_POLLS)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();
        let samples: Vec<_> = pre.iter().chain(&resync).chain(&post).copied().collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        let expected =
            pre.len() + resync.len() + usize::try_from(REQUIRED_STABLE_POLLS).unwrap() - 1;
        assert_eq!(caught_up_at, Some(expected));
    }
}
