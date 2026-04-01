use near_account_id::AccountId;

use super::block_events::BlockEventId;

pub struct BlockEventSubscriber {
    pub(super) subscriptions: Vec<(BlockEventId, BlockEventFilter)>,
    next_id: BlockEventId,
    pub(super) buffer_size: usize,
}

impl BlockEventSubscriber {
    pub fn new(buffer_size: usize) -> Self {
        BlockEventSubscriber {
            subscriptions: vec![],
            next_id: 0.into(),
            buffer_size,
        }
    }

    /// Add a filter and get a unique identifier for it.
    /// The identifier can be used to match a return value to the given filter.
    pub fn subscribe(&mut self, filter: BlockEventFilter) -> BlockEventId {
        let filter_id = self.next_id;
        self.subscriptions.push((filter_id, filter));
        self.next_id = filter_id.overflowing_add(1).0.into();
        filter_id
    }
}

/// Filters, can be extended if necessary
pub enum BlockEventFilter {
    /// Filters for executions of method `method_name` on `transaction_outcome_executor_id`
    /// that spawn a promise (execution status == `SuccessReceiptId`).
    ///
    /// Calls to `transaction_outcome_executor_id.method_name`, that do not spawn a promise will be
    /// ignored.
    ///
    /// If a transaction matches this filter, then [`super::block_events::ExecutorFunctionCallSuccessWithPromiseData`] will be extracted
    /// and placed in the [`super::block_events::BlockUpdate`]
    ///
    /// When to use:
    /// Use this for tracking calls across blocks. The MPC node uses this to filter out signature
    /// requests and keep track of the yield index for resolving the request.
    ExecutorFunctionCallSuccessWithPromise {
        transaction_outcome_executor_id: AccountId,
        method_name: String,
    },

    /// Filters for calls to `receipt_receiver_id.method_name`, regardless if they spawn a
    /// promise, have been successful or not.
    /// If a transaction matches this filter, then [`super::block_events::ReceiverFunctionCallData`] will be extracted
    /// and placed in the [`super::block_events::BlockUpdate`].
    ///
    /// When to use:
    /// Use this if one just wants to track calls to a specific method on a specific contract
    /// without the additional data of [`super::block_events::ExecutorFunctionCallSuccessWithPromiseData`].
    /// The MPC node uses this to track calls to private contract methods.
    ReceiverFunctionCall {
        receipt_receiver_id: AccountId,
        method_name: String,
    },
}
