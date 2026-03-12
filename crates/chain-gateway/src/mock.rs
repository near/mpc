use crate::primitives::{IsSyncing, QueryViewFunction};
use crate::types::ObservedState;
use near_account_id::AccountId;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;

#[derive(Clone)]
pub struct MockChainState {
    sync_response: Arc<Mutex<Result<bool, MockError>>>,
    query_view_function_submitter_state: Arc<Mutex<MockQueryViewFunctionState>>,
    read_notify: Arc<Notify>,
}

pub struct MockQueryViewFunctionState {
    pub response: Result<ObservedState, MockError>,
    pub submitted: Vec<Call>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub contract_id: AccountId,
    pub method_name: String,
    pub args: Vec<u8>,
}

impl MockChainState {
    pub fn builder() -> MockChainStateBuilder {
        MockChainStateBuilder::new()
    }

    pub fn set_sync_response(&self, value: Result<bool, MockError>) {
        *self.sync_response.lock().unwrap() = value;
    }

    /// Update the view function query response.
    pub async fn set_view_response(&self, value: Result<ObservedState, MockError>) {
        let mut inner = self.query_view_function_submitter_state.lock().unwrap();
        inner.response = value;
    }

    /// Wait for the next query_view_function call (polls submitted.len() every 10ms).
    pub async fn await_next_view_call(&self, max_wait_duration: Duration) -> Result<(), MockError> {
        tokio::time::timeout(max_wait_duration, self.read_notify.notified())
            .await
            .map_err(|_| MockError::Timeout)
    }

    /// Returns a snapshot of all recorded view function calls.
    pub async fn view_calls(&self) -> Vec<Call> {
        let inner = self.query_view_function_submitter_state.lock().unwrap();
        inner.submitted.clone()
    }
}

pub struct MockChainStateBuilder {
    sync_response: Result<bool, MockError>,
    query_view_function_response: Result<ObservedState, MockError>,
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
            query_view_function_response: Err(MockError::NotInitialized),
        }
    }

    pub fn with_syncing_status(mut self, s: Result<bool, MockError>) -> Self {
        self.sync_response = s;
        self
    }

    pub fn with_query_view_function_response(
        mut self,
        r: Result<ObservedState, MockError>,
    ) -> Self {
        self.query_view_function_response = r;
        self
    }

    pub fn build(self) -> MockChainState {
        MockChainState {
            sync_response: Arc::new(Mutex::new(self.sync_response)),
            query_view_function_submitter_state: Arc::new(Mutex::new(MockQueryViewFunctionState {
                response: self.query_view_function_response,
                submitted: Vec::new(),
            })),
            read_notify: Arc::new(Notify::new()),
        }
    }
}

impl IsSyncing for MockChainState {
    type Error = MockError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.sync_response.lock().unwrap().clone()
    }
}

impl QueryViewFunction for MockChainState {
    type Error = MockError;
    async fn query_view_function(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<ObservedState, Self::Error> {
        let mut inner = self.query_view_function_submitter_state.lock().unwrap();
        inner.submitted.push(Call {
            contract_id: contract_id.clone(),
            method_name: method_name.to_string(),
            args: args.to_vec(),
        });
        let response = inner.response.clone();
        drop(inner);
        self.read_notify.notify_waiters();
        response
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MockError {
    #[error("Failed to sync")]
    SyncError,
    #[error("mock field not initialized")]
    NotInitialized,
    #[error("mock rpc error")]
    RpcError,
    #[error("timed out")]
    Timeout,
}
