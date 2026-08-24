use crate::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use crate::types::LatestFinalBlockInfo;
use near_account_id::AccountId;
use near_contract_transport::test_utils::{RecordingViewer, ViewRequest};
use std::collections::HashMap;
use std::future::Future;
use near_contract_transport::{ObserveContract, ObservedState, Observations, ViewArgs, ViewContract};
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Clone)]
pub struct MockChainState {
    sync_response: Arc<Mutex<Result<bool, MockError>>>,
    views: RecordingViewer<MockError>,
    latest_final_block: Arc<Mutex<Result<LatestFinalBlockInfo, MockError>>>,
    signed_transaction_submitter_state: Arc<Mutex<MockSignedTransactionSubmitterState>>,
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
        self.views.set_response(value);
    }

    /// Update the response served for `method_name` only, waking its observer.
    pub async fn set_view_response_for(
        &self,
        method_name: impl Into<String>,
        value: Result<ObservedState, MockError>,
    ) {
        self.views.set_response_for(method_name, value);
    }

    /// Returns a snapshot of all recorded view function calls.
    pub async fn view_calls(&self) -> Vec<ViewRequest> {
        self.views.calls()
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
        let views = RecordingViewer::answering(self.view_response);
        for (method_name, response) in self.responses_by_method {
            views.set_response_for(method_name, response);
        }

        MockChainState {
            sync_response: Arc::new(Mutex::new(self.sync_response)),
            views,
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
    fn observe(
        &self,
        contract_id: AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Observations<Self::Error>> + Send {
        self.views.observe(contract_id, view_args)
    }
}

impl ViewContract for MockChainState {
    type Error = MockError;
    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState, Self::Error>> + Send {
        self.views.view_contract(contract_id, view_args)
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
