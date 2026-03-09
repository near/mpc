use crate::primitives::{SyncChecker, ViewFunctionQuerySubmitter};
use crate::state_viewer::{ContractStateSubscriber, ContractViewer, MethodViewer};
use crate::types::RawObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MockChainState {
    pub sync_response: Arc<RwLock<Result<bool, MockError>>>,
    pub view_function_querier_state: Arc<Mutex<MockViewFunctionQuerySubmitterState>>,
}

pub struct MockViewFunctionQuerySubmitterState {
    pub response: Result<RawObservedState, MockError>,
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

    /// Update the view function query response.
    pub async fn set_view_response(&self, value: Result<RawObservedState, MockError>) {
        let mut inner = self.view_function_querier_state.lock().await;
        inner.response = value;
    }

    /// Wait for the next view_function_query call (polls submitted.len() every 5ms).
    pub async fn await_next_view_call(&self, max_wait_duration: Duration) -> Result<(), MockError> {
        tokio::time::timeout(max_wait_duration, async {
            let baseline = {
                let inner = self.view_function_querier_state.lock().await;
                inner.submitted.len()
            };
            loop {
                let inner = self.view_function_querier_state.lock().await;
                if inner.submitted.len() > baseline {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| MockError::Timeout)
    }

    /// Returns a snapshot of all recorded view function calls.
    pub async fn view_calls(&self) -> Vec<Call> {
        let inner = self.view_function_querier_state.lock().await;
        inner.submitted.clone()
    }
}

pub struct MockChainStateBuilder {
    sync_response: Result<bool, MockError>,
    view_function_query_response: Result<RawObservedState, MockError>,
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
            view_function_query_response: Err(MockError::NotInitialized),
        }
    }

    pub fn with_syncing_status(mut self, s: Result<bool, MockError>) -> Self {
        self.sync_response = s;
        self
    }

    pub fn with_view_function_query_response(
        mut self,
        r: Result<RawObservedState, MockError>,
    ) -> Self {
        self.view_function_query_response = r;
        self
    }

    pub fn build(self) -> MockChainState {
        MockChainState {
            sync_response: Arc::new(RwLock::new(self.sync_response)),
            view_function_querier_state: Arc::new(Mutex::new(
                MockViewFunctionQuerySubmitterState {
                    response: self.view_function_query_response,
                    submitted: Vec::new(),
                },
            )),
        }
    }
}

#[async_trait]
impl SyncChecker for MockChainState {
    type Error = MockError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.sync_response.read().unwrap().clone()
    }
}

#[async_trait]
impl ViewFunctionQuerySubmitter for MockChainState {
    type Error = MockError;
    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<RawObservedState, Self::Error> {
        let mut inner = self.view_function_querier_state.lock().await;
        inner.submitted.push(Call {
            contract_id: contract_id.clone(),
            method_name: method_name.to_string(),
            args: args.to_vec(),
        });
        inner.response.clone()
    }
}

impl ContractViewer for MockChainState {}
impl MethodViewer for MockChainState {}
impl ContractStateSubscriber for MockChainState {}

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
