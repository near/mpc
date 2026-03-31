use near_indexer::IndexerExecutionOutcomeWithReceipt;
use near_indexer_primitives::{
    CryptoHash,
    types::FunctionArgs,
    views::{ActionView, ExecutionStatusView, ReceiptEnumView, ReceiptView},
};

use crate::{
    errors::ChainGatewayError,
    event_subscriber::{
        block_events::{
            BlockContext, BlockUpdate, EventData, ExecutorFunctionCallSuccessWithPromiseData,
            MatchedEvent, ReceiverFunctionCallData,
        },
        stats::IndexerStats,
    },
};

use super::config::{BlockEvents, ReceiptExecutorEventIdsByMethodNames};

pub(super) async fn listen_blocks(
    mut stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    block_events: BlockEvents,
    stats_tx: tokio::sync::watch::Sender<IndexerStats>,
    block_update_sender: tokio::sync::mpsc::Sender<BlockUpdate>,
) -> Result<(), ChainGatewayError> {
    let mut blocks_processed_count: u64 = 0;
    // Note: the mpc-node indexer (handler.rs) uses `buffer_unordered` for concurrent
    // block processing. We deliberately use sequential processing here because:
    //   1. `process_block` is synchronous — there is no async work to overlap.
    //   2. `buffer_unordered` does not preserve ordering, yet consumers expect
    //      block updates in block-height order.
    //   3. There is no performance gain in concurrent processing here, especially if we use
    //      bounded channels.
    loop {
        let streamer_message = stream
            .recv()
            .await
            .ok_or(ChainGatewayError::BlockEventIndexerDropped)?;
        let block_height = streamer_message.block.header.height;
        // TODO(#2626): we can ignore blocks that are older than a specific block height. This
        // requires some care on the node side, which is why we will only do so after we integrated
        // the chain-gateway struct with the node.
        let block_update = process_block(streamer_message, &block_events);
        // Send every block. Some consumers might require this.
        // Note that a timeout here is not requried. The `stream` channel from the nearcore indxer
        // is of buffer size 100 and the near node will simply pause sending blocks
        // in case the buffer is full.
        block_update_sender
            .send(block_update)
            .await
            .map_err(|_| ChainGatewayError::BlockEventReceiverDropped)?;
        blocks_processed_count = blocks_processed_count.saturating_add(1);
        stats_tx.send_modify(|s| {
            s.blocks_processed_count = blocks_processed_count;
            s.last_processed_block_height = block_height.into();
        });
    }
}

fn process_block(
    streamer_message: near_indexer_primitives::StreamerMessage,
    block_events: &BlockEvents,
) -> BlockUpdate {
    let mut processed_events = vec![];
    for shard in streamer_message.shards {
        for outcome in &shard.receipt_execution_outcomes {
            // TODO(#2639): This matches the current behavior in the mpc-node.
            // But we should investigate if receiver_id and executor_id are always a
            // match. If so, we can simplify and gain a minor performance improvement.
            block_events.process_receipt(&mut processed_events, outcome);
        }
    }
    let context = BlockContext {
        hash: streamer_message.block.header.hash,
        height: streamer_message.block.header.height.into(),
        prev_hash: streamer_message.block.header.prev_hash,
        block_entropy: streamer_message.block.header.random_value,
        block_timestamp_nanosec: streamer_message.block.header.timestamp_nanosec,
        last_final_block: streamer_message.block.header.last_final_block,
    };
    BlockUpdate {
        context,
        events: processed_events,
    }
}

impl BlockEvents {
    // Constructs and appends all events matching this receipt to processed_events.
    fn process_receipt(
        &self,
        processed_events: &mut Vec<MatchedEvent>,
        outcome: &IndexerExecutionOutcomeWithReceipt,
    ) {
        // First, check if the executor or receiver of this receipt matches one of the events we
        // are monitoring.
        let execution_outcome = &outcome.execution_outcome;
        let receipt = &outcome.receipt;

        let executor_event_candidates: Option<(
            &ReceiptExecutorEventIdsByMethodNames,
            &CryptoHash,
        )> = {
            if let ExecutionStatusView::SuccessReceiptId(next_receipt_id) =
                &execution_outcome.outcome.status
            {
                let executor_id = &execution_outcome.outcome.executor_id;
                self.receipt_executor_events
                    .get(executor_id)
                    .map(|methods| (methods, next_receipt_id))
            } else {
                None
            }
        };

        let receiver_event_candidates = self.receipt_receiver_events.get(&receipt.receiver_id);

        if executor_event_candidates.is_none() && receiver_event_candidates.is_none() {
            // This receipt does not match any of our executor or receipt receiver filters.
            // We return early and avoid extracting function call args.
            return;
        }

        // It does match one of our events, so now, we extract the function call args and match on
        // the method name.
        // Note: readability would be better if we extracted the methods earlier, but performance
        // would suffer, as we would be extracting function call args for receipts that are of no
        // interest to us.
        let Some((args, contract_method_name)) = try_extract_function_call_args(receipt) else {
            return;
        };

        // Extract ids of receiver events that match this receipt.
        let receiver_event_ids =
            receiver_event_candidates.and_then(|candidates| candidates.get(contract_method_name));

        if let Some(receiver_event_ids) = receiver_event_ids {
            let is_success = matches!(
                execution_outcome.outcome.status,
                ExecutionStatusView::SuccessValue(_) | ExecutionStatusView::SuccessReceiptId(_)
            );

            for event_id in receiver_event_ids {
                processed_events.push(MatchedEvent {
                    id: *event_id,
                    event_data: EventData::ReceiverFunctionCall(ReceiverFunctionCallData {
                        receipt_id: receipt.receipt_id,
                        is_success,
                    }),
                });
            }
        }

        // Extract ids of executor events that match this receipt. If we don't have any, we can
        // return here, as our work is done.
        let Some((executor_event_ids, next_receipt_id)) = executor_event_candidates else {
            return;
        };
        let Some(executor_event_ids) = executor_event_ids.get(contract_method_name) else {
            return;
        };

        for event_id in executor_event_ids {
            processed_events.push(MatchedEvent {
                id: *event_id,
                event_data: EventData::ExecutorFunctionCallSuccessWithPromise(
                    ExecutorFunctionCallSuccessWithPromiseData {
                        receipt_id: receipt.receipt_id,
                        predecessor_id: receipt.predecessor_id.clone(),
                        next_receipt_id: *next_receipt_id,
                        args_raw: args.to_vec(),
                    },
                ),
            });
        }
    }
}

fn try_extract_function_call_args(receipt: &ReceiptView) -> Option<(&FunctionArgs, &String)> {
    let ReceiptEnumView::Action { ref actions, .. } = receipt.receipt else {
        return None;
    };
    if actions.len() != 1 {
        return None;
    }
    let ActionView::FunctionCall {
        ref method_name,
        ref args,
        ..
    } = actions[0]
    else {
        return None;
    };

    tracing::debug!(target: "chain indexer", "found `{}` function call", method_name);

    Some((args, method_name))
}
