use crate::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use crate::types::LatestFinalBlockInfo;
use near_account_id::AccountId;
use near_contract_transport::{
    ObserveContract, ObservedState, Observations, ViewArgs, ViewContract, publish_if_changed,
};
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Notify, watch};

#[derive(Clone)]
pub struct MockChainState {
    sync_response: Arc<Mutex<Result<bool, MockError>>>,
    view_state: Arc<Mutex<MockViewState>>,
    latest_final_block: Arc<Mutex<Result<LatestFinalBlockInfo, MockError>>>,
    signed_transaction_submitter_state: Arc<Mutex<MockSignedTransactionSubmitterState>>,
    read_notify: Arc<Notify>,
}

pub struct MockViewState {
    pub response: Result<ObservedState, MockError>,
    /// Consulted before [`response`](MockViewState::response), so a test that
    /// watches two view methods can give each its own payload.
    pub responses_by_method: HashMap<String, Result<ObservedState, MockError>>,
    pub submitted: Vec<Call>,
    /// One sender per observed view method, so a `set_view_response*` call
    /// reaches subscribers immediately instead of on the next poll.
    observers: HashMap<String, watch::Sender<Result<ObservedState, MockError>>>,
}

impl MockViewState {
    fn response_for(&self, method_name: &str) -> Result<ObservedState, MockError> {
        self.responses_by_method
            .get(method_name)
            .unwrap_or(&self.response)
            .clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub contract_id: AccountId,
    pub method_name: String,
    pub args: Vec<u8>,
}

pub struct MockSignedTransactionSubmitterState {
    pub response: Result<(), MockError>,
    pub submitted: Vec<SignedTransaction>,
}

impl MockChainState {
    pub fn builder() -> MockChainStateBuilder {
        MockChainStateBuilder::new()
    }

    pub fn set_sync_response(&self, value: Result<bool, MockError>) {
        *self.sync_response.lock().unwrap() = value;
    }

    /// Update the view function query response, waking every observer that has
    /// no method-specific response of its own.
    pub async fn set_view_response(&self, value: Result<ObservedState, MockError>) {
        let mut inner = self.view_state.lock().unwrap();
        inner.response = value;
        let overridden: Vec<String> = inner.responses_by_method.keys().cloned().collect();
        for (method_name, sender) in &inner.observers {
            if !overridden.contains(method_name) {
                publish_if_changed(sender, inner.response.clone());
            }
        }
    }

    /// Update the response served for `method_name` only, waking its observer.
    pub async fn set_view_response_for(
        &self,
        method_name: impl Into<String>,
        value: Result<ObservedState, MockError>,
    ) {
        let method_name = method_name.into();
        let mut inner = self.view_state.lock().unwrap();
        inner
            .responses_by_method
            .insert(method_name.clone(), value.clone());
        if let Some(sender) = inner.observers.get(&method_name) {
            publish_if_changed(sender, value);
        }
    }

    /// Wait for the next view_contract call (polls submitted.len() every 10ms).
    pub async fn await_next_view_call(&self, max_wait_duration: Duration) -> Result<(), MockError> {
        tokio::time::timeout(max_wait_duration, self.read_notify.notified())
            .await
            .map_err(|_| MockError::Timeout)
    }

    /// Returns a snapshot of all recorded view function calls.
    pub async fn view_calls(&self) -> Vec<Call> {
        let inner = self.view_state.lock().unwrap();
        inner.submitted.clone()
    }

    /// Returns a snapshot of all recorded signed transactions.
    pub async fn signed_transactions(&self) -> Vec<SignedTransaction> {
        let inner = self.signed_transaction_submitter_state.lock().unwrap();
        inner.submitted.clone()
    }
}

pub struct MockChainStateBuilder {
    sync_response: Result<bool, MockError>,
    view_response: Result<ObservedState, MockError>,
    responses_by_method: HashMap<String, Result<ObservedState, MockError>>,
    latest_final_block: Result<LatestFinalBlockInfo, MockError>,
    signed_transaction_submitter_response: Result<(), MockError>,
}

impl Default for MockChainStateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MockChainStateBuilder {
    pub fn new() -> Self {
        Self {
            sync_response: Err(MockError::NotInitialized),
            view_response: Err(MockError::NotInitialized),
            responses_by_method: HashMap::new(),
            latest_final_block: Err(MockError::NotInitialized),
            signed_transaction_submitter_response: Err(MockError::NotInitialized),
        }
    }

    pub fn with_syncing_status(mut self, s: Result<bool, MockError>) -> Self {
        self.sync_response = s;
        self
    }

    pub fn with_latest_block(mut self, b: Result<LatestFinalBlockInfo, MockError>) -> Self {
        self.latest_final_block = b;
        self
    }

    pub fn with_signed_transaction_submitter_response(mut self, r: Result<(), MockError>) -> Self {
        self.signed_transaction_submitter_response = r;
        self
    }

    pub fn with_view_response(mut self, r: Result<ObservedState, MockError>) -> Self {
        self.view_response = r;
        self
    }

    /// Serve `r` for `method_name` only, overriding
    /// [`with_view_response`](Self::with_view_response) for that method.
    pub fn with_view_response_for(
        mut self,
        method_name: impl Into<String>,
        r: Result<ObservedState, MockError>,
    ) -> Self {
        self.responses_by_method.insert(method_name.into(), r);
        self
    }

    pub fn build(self) -> MockChainState {
        MockChainState {
            sync_response: Arc::new(Mutex::new(self.sync_response)),
            view_state: Arc::new(Mutex::new(MockViewState {
                response: self.view_response,
                responses_by_method: self.responses_by_method,
                submitted: Vec::new(),
                observers: HashMap::new(),
            })),
            read_notify: Arc::new(Notify::new()),
            latest_final_block: Arc::new(Mutex::new(self.latest_final_block)),
            signed_transaction_submitter_state: Arc::new(Mutex::new(
                MockSignedTransactionSubmitterState {
                    response: self.signed_transaction_submitter_response,
                    submitted: Vec::new(),
                },
            )),
        }
    }
}

//impl IsSyncing for MockChainState {
//    type Error = MockError;
//    async fn is_syncing(&self) -> Result<bool, Self::Error> {
//        self.sync_response.lock().unwrap().clone()
//    }
//}

/// Publishes rather than being polled, so a `set_view_response*` call wakes
/// subscribers at once and a test never waits out an interval. Deliberately does
/// not implement [`PollInterval`](near_contract_transport::PollInterval): the
/// two are mutually exclusive.
impl ObserveContract for MockChainState {
    async fn observe(
        &self,
        contract_id: AccountId,
        view_args: ViewArgs,
    ) -> Observations<Self::Error> {
        let mut inner = self.view_state.lock().unwrap();
        let current = inner.response_for(&view_args.method_name);
        inner.submitted.push(Call {
            contract_id,
            method_name: view_args.method_name.clone(),
            args: view_args.args,
        });
        let receiver = inner
            .observers
            .entry(view_args.method_name)
            .or_insert_with(|| watch::channel(current).0)
            .subscribe();
        Observations::pushed(receiver)
    }
}

impl ViewContract for MockChainState {
    type Error = MockError;
    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState, Self::Error> {
        let mut inner = self.view_state.lock().unwrap();
        let response = inner.response_for(&view_args.method_name);
        inner.submitted.push(Call {
            contract_id: contract_id.clone(),
            method_name: view_args.method_name,
            args: view_args.args,
        });
        drop(inner);
        self.read_notify.notify_waiters();
        response
    }
}

impl FetchLatestFinalBlockInfo for MockChainState {
    type Error = MockError;
    async fn fetch_latest_final_block_info(&self) -> Result<LatestFinalBlockInfo, Self::Error> {
        self.latest_final_block.lock().unwrap().clone()
    }
}

impl SubmitSignedTransaction for MockChainState {
    type Error = MockError;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error> {
        let mut inner = self.signed_transaction_submitter_state.lock().unwrap();
        inner.submitted.push(transaction);
        inner.response.clone()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MockError {
    #[error("failed to sync")]
    SyncError,
    #[error("failed to fetch latest final block")]
    LatestFinalBlockError,
    #[error("mock field not initialized")]
    NotInitialized,
    #[error("mock view client error")]
    ViewClientError,
    #[error("timed out")]
    Timeout,
    #[error("rpc error")]
    RpcError,
}
