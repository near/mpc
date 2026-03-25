use std::{collections::BTreeMap, time::Duration};

use near_account_id::AccountId;

use crate::event_subscriber::{
    block_events::BlockEventId,
    subscriber::{BlockEventFilter, BlockEventSubscriber},
};

pub(super) struct StreamerConfig {
    pub(super) block_events: BlockEvents,
    pub(super) buffer_size: usize,
    pub(super) backpressure_timeout: Duration,
}

// helper struct for efficient access
pub(super) struct BlockEvents {
    pub(super) executor_filters: BlockEventIdsByContractIds,
    pub(super) receipt_receiver_filters: BlockEventIdsByContractIds,
}

// helper struct for efficient access
pub(super) struct BlockEventIdsByContractIds(BTreeMap<AccountId, BlockEventIdsByMethodNames>);

// helper struct for efficient access
pub(super) struct BlockEventIdsByMethodNames(BTreeMap<String, Vec<BlockEventId>>);

impl BlockEventIdsByMethodNames {
    pub(crate) fn filter_ids_for(&self, method_name: &str) -> Option<&Vec<BlockEventId>> {
        self.0.get(method_name)
    }
}

impl BlockEventIdsByContractIds {
    pub(crate) fn filter_methods_for(
        &self,
        contract: &AccountId,
    ) -> Option<&BlockEventIdsByMethodNames> {
        self.0.get(contract)
    }
}

impl From<BlockEventSubscriber> for StreamerConfig {
    fn from(value: BlockEventSubscriber) -> Self {
        let mut executor_filters: BTreeMap<AccountId, BTreeMap<String, Vec<BlockEventId>>> =
            BTreeMap::new();
        let mut receipt_receiver_filters: BTreeMap<AccountId, BTreeMap<String, Vec<BlockEventId>>> =
            BTreeMap::new();
        for (id, filter) in value.subscriptions {
            match filter {
                BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
                    transaction_outcome_executor_id,
                    method_name,
                } => {
                    executor_filters
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
                    receipt_receiver_filters
                        .entry(receipt_receiver_id)
                        .or_default()
                        .entry(method_name)
                        .or_default()
                        .push(id);
                }
            }
        }

        let block_events = BlockEvents {
            executor_filters: BlockEventIdsByContractIds(
                executor_filters
                    .into_iter()
                    .map(|(k, v)| (k, BlockEventIdsByMethodNames(v)))
                    .collect(),
            ),
            receipt_receiver_filters: BlockEventIdsByContractIds(
                receipt_receiver_filters
                    .into_iter()
                    .map(|(k, v)| (k, BlockEventIdsByMethodNames(v)))
                    .collect(),
            ),
        };

        let buffer_size = value.buffer_size;
        let backpressure_timeout = value.backpressure_timeout;
        StreamerConfig {
            block_events,
            buffer_size,
            backpressure_timeout,
        }
    }
}
