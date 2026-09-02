use crate::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use crate::types::LatestFinalBlockInfo;
use near_account_id::AccountId;
use near_contract_transport::{HasPollInterval, PollInterval, SerializedObservation};
use near_contract_transport::{ViewArgs, ViewContract};
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;

#[derive(Clone)]
pub struct MockChainState {
    view: MockViewContract,
    latest_final_block: Arc<Mutex<Result<LatestFinalBlockInfo, MockError>>>,
    signed_transaction_submitter_state: Arc<Mutex<MockSignedTransactionSubmitterState>>,
}

impl HasPollInterval for MockChainState {
    fn poll_interval(&self) -> PollInterval {
        self.view.poll_interval()
    }
}

struct ViewState {
    response: Result<SerializedObservation, MockViewError>,
    calls: Vec<Call>,
    responses_by_method: HashMap<String, Result<SerializedObservation, MockViewError>>,
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

    /// Update the view function query response.
    pub fn set_view_response(&self, value: Result<SerializedObservation, MockViewError>) {
        self.view.set_response(value);
    }

    pub fn set_view_response_for_method(
        &self,
        method_name: impl Into<String>,
        value: Result<SerializedObservation, MockViewError>,
    ) {
        self.view.set_view_response_for_method(method_name, value)
    }

    /// Wait for the next view_contract call
    pub async fn await_next_view_call(&self, max_wait_duration: Duration) -> Result<(), MockError> {
        self.view
            .await_next_call(max_wait_duration)
            .await
            .map_err(|_| MockError::Timeout)
    }

    /// Returns a snapshot of all recorded view function calls.
    pub fn view_calls(&self) -> Vec<Call> {
        self.view.calls()
    }

    /// Returns a snapshot of all recorded signed transactions.
    pub fn signed_transactions(&self) -> Vec<SignedTransaction> {
        let inner = self.signed_transaction_submitter_state.lock().unwrap();
        inner.submitted.clone()
    }
}

pub struct MockChainStateBuilder {
    view_response: Result<SerializedObservation, MockViewError>,
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
            view_response: Err(MockViewError("not initialized")),
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

    pub fn with_view_response(mut self, r: Result<SerializedObservation, MockViewError>) -> Self {
        self.view_response = r;
        self
    }

    pub fn build(self) -> MockChainState {
        MockChainState {
            view: MockViewContract::new(self.view_response),
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

impl ViewContract for MockChainState {
    type Error = MockViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        self.view.view_contract(contract_id, view_args).await
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
}

#[derive(Clone)]
pub struct MockViewContract {
    state: Arc<Mutex<ViewState>>,
    call_notify: Arc<Notify>,
}

impl MockViewContract {
    pub fn new(response: Result<SerializedObservation, MockViewError>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ViewState {
                responses_by_method: HashMap::new(),
                response,
                calls: Vec::new(),
            })),
            call_notify: Arc::new(Notify::new()),
        }
    }

    pub fn set_response(&self, response: Result<SerializedObservation, MockViewError>) {
        self.state.lock().unwrap().response = response;
    }

    pub async fn await_next_call(
        &self,
        max_wait_duration: Duration,
    ) -> Result<(), tokio::time::error::Elapsed> {
        tokio::time::timeout(max_wait_duration, self.call_notify.notified()).await
    }

    /// Returns a snapshot of all recorded view function calls.
    pub fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn set_view_response_for_method(
        &self,
        method_name: impl Into<String>,
        value: Result<SerializedObservation, MockViewError>,
    ) {
        let mut inner = self.state.lock().unwrap();
        inner.responses_by_method.insert(method_name.into(), value);
    }
}

impl ViewContract for MockViewContract {
    type Error = MockViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        let response = {
            let mut state = self.state.lock().unwrap();
            let response = state
                .responses_by_method
                .get(&view_args.method_name)
                .unwrap_or(&state.response)
                .clone();
            state.calls.push(Call {
                contract_id: contract_id.clone(),
                method_name: view_args.method_name,
                args: view_args.args,
            });
            response
        };
        self.call_notify.notify_waiters();
        response
    }
}

impl HasPollInterval for MockViewContract {
    fn poll_interval(&self) -> PollInterval {
        PollInterval::new(Duration::from_millis(10)).expect("non-zero")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("mock view error: {0}")]
pub struct MockViewError(pub &'static str);
