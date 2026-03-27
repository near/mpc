use std::time::Duration;

use near_indexer::IndexerExecutionOutcomeWithReceipt;
use near_indexer_primitives::{
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

use super::config::{BlockEventIdsByContractIds, BlockEvents};

pub(super) async fn listen_blocks(
    mut stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    block_events: BlockEvents,
    stats_tx: tokio::sync::watch::Sender<IndexerStats>,
    block_update_sender: tokio::sync::mpsc::Sender<BlockUpdate>,
    backpressure_timeout: Duration,
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
        // Only send if we have something the consumer is interested in.
        if !block_update.events.is_empty() {
            tokio::time::timeout(backpressure_timeout, block_update_sender.send(block_update))
                .await
                .map_err(|_| ChainGatewayError::BlockEventBufferFull)?
                .map_err(|_| ChainGatewayError::BlockEventReceiverDropped)?;
        }
        blocks_processed_count = blocks_processed_count.saturating_add(1);
        stats_tx.send_modify(|s| {
            s.blocks_processed_count = blocks_processed_count;
            s.last_processed_block_height = block_height.into();
        });
    }
}

fn filter_executor_function_calls(
    res: &mut Vec<MatchedEvent>,
    executor_filters: &BlockEventIdsByContractIds,
    outcome: &IndexerExecutionOutcomeWithReceipt,
) {
    let execution_outcome = &outcome.execution_outcome;
    let ExecutionStatusView::SuccessReceiptId(next_receipt_id) = execution_outcome.outcome.status
    else {
        return;
    };
    let receipt = outcome.receipt.clone();
    let executor_id = &execution_outcome.outcome.executor_id;
    let Some(filter_methods_for_executor) = executor_filters.filter_methods_for(executor_id) else {
        return;
    };
    let Some((args, contract_method_name)) = try_extract_function_call_args(&receipt) else {
        return;
    };
    let Some(filter_ids) = filter_methods_for_executor.filter_ids_for(contract_method_name) else {
        return;
    };
    for filter_id in filter_ids {
        res.push(MatchedEvent {
            id: *filter_id,
            event_data: EventData::ExecutorFunctionCallSuccessWithPromise(
                ExecutorFunctionCallSuccessWithPromiseData {
                    receipt_id: receipt.receipt_id,
                    predecessor_id: receipt.predecessor_id.clone(),
                    next_receipt_id,
                    args_raw: args.to_vec(),
                },
            ),
        });
    }
}

fn filter_receipt_function_calls(
    res: &mut Vec<MatchedEvent>,
    receiver_filters: &BlockEventIdsByContractIds,
    outcome: &IndexerExecutionOutcomeWithReceipt,
) {
    let receipt = &outcome.receipt;
    let Some(methods_filter) = receiver_filters.filter_methods_for(&receipt.receiver_id) else {
        return;
    };

    let Some((_, contract_method_name)) = try_extract_function_call_args(receipt) else {
        return;
    };
    let Some(filter_ids) = methods_filter.filter_ids_for(contract_method_name) else {
        return;
    };

    let is_success = matches!(
        outcome.execution_outcome.outcome.status,
        ExecutionStatusView::SuccessValue(_) | ExecutionStatusView::SuccessReceiptId(_)
    );

    for filter_id in filter_ids {
        res.push(MatchedEvent {
            id: *filter_id,
            event_data: EventData::ReceiverFunctionCall(ReceiverFunctionCallData {
                receipt_id: receipt.receipt_id,
                is_success,
            }),
        });
    }
}

fn process_block(
    streamer_message: near_indexer_primitives::StreamerMessage,
    block_events: &BlockEvents,
) -> BlockUpdate {
    let mut filtered_events = vec![];
    for shard in streamer_message.shards {
        for outcome in &shard.receipt_execution_outcomes {
            filter_executor_function_calls(
                &mut filtered_events,
                &block_events.executor_filters,
                outcome,
            );
            filter_receipt_function_calls(
                &mut filtered_events,
                &block_events.receipt_receiver_filters,
                outcome,
            );
        }
    }
    let context = BlockContext {
        hash: streamer_message.block.header.hash,
        height: streamer_message.block.header.height.into(),
        prev_hash: streamer_message.block.header.prev_hash,
        block_entropy: streamer_message.block.header.random_value.into(),
        block_timestamp_nanosec: streamer_message.block.header.timestamp_nanosec,
        last_final_block: streamer_message.block.header.last_final_block,
    };
    BlockUpdate {
        context,
        events: filtered_events,
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

    tracing::debug!(target: "mpc", "found `{}` function call", method_name);

    Some((args, method_name))
}
