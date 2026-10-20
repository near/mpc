use crate::primitives::{FetchLatestFinalBlockInfo, SubmitSignedTransaction};
use crate::types::LatestFinalBlockInfo;
use near_account_id::AccountId;
use near_contract_transport::{
    HasPollInterval, PollInterval, SerializedObservation, ViewArgs, ViewContract,
    mock::{Call, MockViewContract, MockViewError},
};
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

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
