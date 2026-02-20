use crate::primitives::{
    LatestFinalBlockInfoFetcher, SignedTransactionSubmitter, SyncChecker, ViewFunctionQuerier,
};
use crate::state_viewer::{ContractStateSubscriber, ContractViewer, MethodViewer};
use crate::transaction_sender::FunctionCallSubmitter;
use crate::types::{LatestFinalBlockInfo, RawObservedState};
use async_trait::async_trait;
use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MockChainState {
    pub sync_response: Arc<RwLock<Result<bool, MockError>>>,
    pub latest_final_block: Arc<RwLock<Result<LatestFinalBlockInfo, MockError>>>,
    pub signed_transaction_submitter_state: Arc<Mutex<MockSignedTransactionSubmitterState>>,
    pub view_function_querier_state: Arc<Mutex<MockViewFunctionQuerierState>>,
}

pub struct MockSignedTransactionSubmitterState {
    pub response: Result<(), MockError>,
    pub submitted: Vec<SignedTransaction>,
}

pub struct MockViewFunctionQuerierState {
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
    pub async fn await_next_view_call(&self) {
        let baseline = {
            let inner = self.view_function_querier_state.lock().await;
            inner.submitted.len()
        };
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let inner = self.view_function_querier_state.lock().await;
            if inner.submitted.len() > baseline {
                return;
            }
        }
    }

    /// Returns a snapshot of all recorded view function calls.
    pub async fn view_calls(&self) -> Vec<Call> {
        let inner = self.view_function_querier_state.lock().await;
        inner.submitted.clone()
    }

    /// Returns a snapshot of all recorded signed transactions.
    pub async fn signed_transactions(&self) -> Vec<SignedTransaction> {
        let inner = self.signed_transaction_submitter_state.lock().await;
        inner.submitted.clone()
    }
}

pub struct MockChainStateBuilder {
    sync_response: Result<bool, MockError>,
    latest_final_block: Result<LatestFinalBlockInfo, MockError>,
    signed_transaction_submitter_response: Result<(), MockError>,
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
            latest_final_block: Err(MockError::NotInitialized),
            signed_transaction_submitter_response: Err(MockError::NotInitialized),
            view_function_query_response: Err(MockError::NotInitialized),
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
            latest_final_block: Arc::new(RwLock::new(self.latest_final_block)),
            signed_transaction_submitter_state: Arc::new(Mutex::new(
                MockSignedTransactionSubmitterState {
                    response: self.signed_transaction_submitter_response,
                    submitted: Vec::new(),
                },
            )),
            view_function_querier_state: Arc::new(Mutex::new(MockViewFunctionQuerierState {
                response: self.view_function_query_response,
                submitted: Vec::new(),
            })),
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
impl ViewFunctionQuerier for MockChainState {
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

#[async_trait]
impl LatestFinalBlockInfoFetcher for MockChainState {
    type Error = MockError;
    async fn latest_final_block(&self) -> Result<LatestFinalBlockInfo, Self::Error> {
        self.latest_final_block.read().unwrap().clone()
    }
}

#[async_trait]
impl SignedTransactionSubmitter for MockChainState {
    type Error = MockError;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error> {
        let mut inner = self.signed_transaction_submitter_state.lock().await;
        inner.submitted.push(transaction);
        inner.response.clone()
    }
}

impl ContractViewer for MockChainState {}
impl MethodViewer for MockChainState {}
impl ContractStateSubscriber for MockChainState {}
impl FunctionCallSubmitter for MockChainState {}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MockError {
    #[error("Failed to sync")]
    SyncError,
    #[error("Failed to fetch latest final block")]
    LatestFinalBlockError,
    #[error("mock field not initialized")]
    NotInitialized,
    #[error("mock rpc error")]
    RpcError,
}

#[derive(Clone)]
pub struct MockLatestFinalBlockInfoFetcher {
    pub response: Arc<RwLock<Result<LatestFinalBlockInfo, MockError>>>,
}

#[async_trait]
impl LatestFinalBlockInfoFetcher for MockLatestFinalBlockInfoFetcher {
    type Error = MockError;

    async fn latest_final_block(&self) -> Result<LatestFinalBlockInfo, Self::Error> {
        self.response.read().unwrap().clone()
    }
}
