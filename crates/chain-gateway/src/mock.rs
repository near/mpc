use crate::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use crate::types::LatestFinalBlockInfo;
use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_kit_primitives::Viewer;
use near_kit_primitives::rpc::{BlockReference, ViewFunctionResult};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;

/// What a view answers with: the raw result, or an error.
pub type ViewResponse = Result<ViewFunctionResult, MockError>;

/// A view the mock was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewCall {
    pub contract_id: AccountId,
    pub method_name: String,
    pub args: Vec<u8>,
}

#[derive(Clone)]
pub struct MockChainState {
    views: Arc<Mutex<MockViews>>,
    view_called: Arc<Notify>,
    latest_final_block: Arc<Mutex<Result<LatestFinalBlockInfo, MockError>>>,
    signed_transaction_submitter_state: Arc<Mutex<MockSignedTransactionSubmitterState>>,
}

struct MockViews {
    response: ViewResponse,
    responses_by_method: HashMap<String, ViewResponse>,
    calls: Vec<ViewCall>,
}

pub struct MockSignedTransactionSubmitterState {
    pub response: Result<(), MockError>,
    pub submitted: Vec<SignedTransaction>,
}

impl MockChainState {
    /// How often tests poll the mock's views.
    pub const POLL_INTERVAL: Duration = Duration::from_millis(10);

    pub fn builder() -> MockChainStateBuilder {
        MockChainStateBuilder::new()
    }

    /// Update the response of every view without a method-specific one.
    pub fn set_view_response(&self, value: ViewResponse) {
        self.views.lock().unwrap().response = value;
    }

    pub fn set_view_response_for_method(
        &self,
        method_name: impl Into<String>,
        value: ViewResponse,
    ) {
        let mut views = self.views.lock().unwrap();
        views.responses_by_method.insert(method_name.into(), value);
    }

    /// Wait for the next view call
    pub async fn await_next_view_call(&self, max_wait_duration: Duration) -> Result<(), MockError> {
        tokio::time::timeout(max_wait_duration, self.view_called.notified())
            .await
            .map_err(|_| MockError::Timeout)
    }

    /// Returns a snapshot of all recorded view function calls.
    pub fn view_calls(&self) -> Vec<ViewCall> {
        self.views.lock().unwrap().calls.clone()
    }

    /// Returns a snapshot of all recorded signed transactions.
    pub fn signed_transactions(&self) -> Vec<SignedTransaction> {
        let inner = self.signed_transaction_submitter_state.lock().unwrap();
        inner.submitted.clone()
    }
}

pub struct MockChainStateBuilder {
    view_response: ViewResponse,
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
            view_response: Err(MockError::NotInitialized),
            latest_final_block: Err(MockError::NotInitialized),
            signed_transaction_submitter_response: Err(MockError::NotInitialized),
        }
    }

    pub fn with_latest_block(mut self, b: Result<LatestFinalBlockInfo, MockError>) -> Self {
        self.latest_final_block = b;
        self
    }

    pub fn with_signed_transaction_submitter_response(mut self, r: Result<(), MockError>) -> Self {
        self.signed_transaction_submitter_response = r;
        self
    }

    pub fn with_view_response(mut self, r: ViewResponse) -> Self {
        self.view_response = r;
        self
    }

    pub fn build(self) -> MockChainState {
        MockChainState {
            views: Arc::new(Mutex::new(MockViews {
                response: self.view_response,
                responses_by_method: HashMap::new(),
                calls: Vec::new(),
            })),
            view_called: Arc::new(Notify::new()),
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

impl Viewer for MockChainState {
    type ViewError = MockError;

    async fn view_function(
        &self,
        contract_id: &AccountId,
        method: &str,
        args: &[u8],
        _block: BlockReference,
    ) -> ViewResponse {
        let response = {
            let mut views = self.views.lock().unwrap();
            views.calls.push(ViewCall {
                contract_id: contract_id.clone(),
                method_name: method.to_string(),
                args: args.to_vec(),
            });
            views
                .responses_by_method
                .get(method)
                .unwrap_or(&views.response)
                .clone()
        };
        self.view_called.notify_waiters();
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
    #[error("failed to fetch latest final block")]
    LatestFinalBlockError,
    #[error("mock field not initialized")]
    NotInitialized,
    #[error("timed out")]
    Timeout,
    #[error("rpc error")]
    RpcError,
    #[error("view failed: {0}")]
    View(&'static str),
}
