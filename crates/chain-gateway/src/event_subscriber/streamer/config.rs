use std::collections::BTreeMap;

use derive_more::{Deref, DerefMut};
use near_account_id::AccountId;

use crate::event_subscriber::{
    block_events::BlockEventId,
    subscriber::{BlockEventFilter, BlockEventSubscriber},
};

pub(super) struct StreamerConfig {
    pub(super) block_events: BlockEvents,
    pub(super) buffer_size: usize,
}

// helper struct for efficient access
pub(super) struct BlockEvents {
    pub(super) receipt_executor_events: ReceiptExecutorEventIdsByContractIds,
    pub(super) receipt_receiver_events: ReceiptReceiverEventIdsByContractIds,
}

#[derive(Default, Deref, DerefMut)]
pub(super) struct ReceiptReceiverEventIdsByContractIds(
    BTreeMap<AccountId, ReceiptReceiverEventIdsByMethodNames>,
);

#[derive(Default, Deref, DerefMut)]
pub(super) struct ReceiptReceiverEventIdsByMethodNames(BTreeMap<String, Vec<BlockEventId>>);

#[derive(Default, Deref, DerefMut)]
pub(super) struct ReceiptExecutorEventIdsByContractIds(
    BTreeMap<AccountId, ReceiptExecutorEventIdsByMethodNames>,
);

#[derive(Default, Deref, DerefMut)]
pub(super) struct ReceiptExecutorEventIdsByMethodNames(BTreeMap<String, Vec<BlockEventId>>);

impl From<BlockEventSubscriber> for StreamerConfig {
    fn from(value: BlockEventSubscriber) -> Self {
        let mut receipt_executor_events = ReceiptExecutorEventIdsByContractIds::default();
        let mut receipt_receiver_events = ReceiptReceiverEventIdsByContractIds::default();
        for (id, filter) in value.subscriptions {
            match filter {
                BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
                    transaction_outcome_executor_id,
                    method_name,
                } => {
                    receipt_executor_events
                        .entry(transaction_outcome_executor_id)
                        .or_default()
                        .entry(method_name)
                        .or_default()
                        .push(id);
                }
                BlockEventFilter::ReceiverFunctionCall {
                    receipt_receiver_id,
                    method_name,
                } => {
                    receipt_receiver_events
                        .entry(receipt_receiver_id)
                        .or_default()
                        .entry(method_name)
                        .or_default()
                        .push(id);
                }
            }
        }

        let block_events = BlockEvents {
            receipt_executor_events,
            receipt_receiver_events,
        };

        let buffer_size = value.buffer_size;
        StreamerConfig {
            block_events,
            buffer_size,
        }
    }
}
