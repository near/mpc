use crate::primitives::{
    LatestFinalBlockInfoFetcher, SignedTransactionSubmitter, SyncChecker, ViewFunctionQuerier,
};
use crate::types::{LatestFinalBlockInfo, RawObservedState};
use async_trait::async_trait;
use near_account_id::AccountId;
use near_indexer::near_primitives::transaction::SignedTransaction;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::sync::Mutex;

// todo: make a nice builder pattern
// MochChainStateBuilder.with_sync_status(synced=true/false).with_latest_block(Ok(res)).with_signed_transaction_submitter_response(resp).wth_veiw_function_query_response(resp)
// and then easy MockChainStateVerifier.build(allowed_function_calls).
//
pub struct MockChainState {
    sync_checker: MockSyncChecker,
    latest_final_block_fetcher: MockLatestFinalBlockInfoFetcher,
    signed_transaction_submitter: MockSignedTransactionSubmitter,
    view_function_querier: MockViewFunctionQuerier,
}

#[async_trait]
impl SyncChecker for MockChainState {
    type Error = MockError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.sync_checker.is_syncing().await
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
        self.view_function_querier
            .view_function_query(contract_id, method_name, args)
            .await
    }
}

#[async_trait]
impl LatestFinalBlockInfoFetcher for MockChainState {
    type Error = MockError;
    async fn latest_final_block(&self) -> Result<LatestFinalBlockInfo, Self::Error> {
        self.latest_final_block_fetcher.latest_final_block().await
    }
}

#[async_trait]
impl SignedTransactionSubmitter for MockChainState {
    type Error = MockError;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error> {
        self.signed_transaction_submitter
            .submit_signed_transaction(transaction)
            .await
    }
}

#[derive(Debug, Error, Clone)]
pub enum MockError {
    #[error("Failed to sync")]
    SyncError,
    #[error("Failed to fetch latest final block")]
    LatestFinalBlockError,
}

pub struct MockSyncChecker {
    pub response: Arc<RwLock<Result<bool, MockError>>>,
}

#[async_trait]
impl SyncChecker for MockSyncChecker {
    type Error = MockError;
    async fn is_syncing(&self) -> Result<bool, Self::Error> {
        self.response.read().unwrap().clone()
    }
}

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

pub struct MockSignedTransactionSubmitterState {
    pub response: Result<(), MockError>,
    pub submitted: Vec<SignedTransaction>,
}

pub struct MockSignedTransactionSubmitter {
    pub inner: Mutex<MockSignedTransactionSubmitterState>,
}

#[async_trait]
impl SignedTransactionSubmitter for MockSignedTransactionSubmitter {
    type Error = MockError;
    async fn submit_signed_transaction(
        &self,
        transaction: SignedTransaction,
    ) -> Result<(), Self::Error> {
        let mut inner = self.inner.lock().await;
        inner.submitted.push(transaction);
        inner.response.clone()
    }
}

pub struct MockViewFunctionQuerierState {
    pub response: Result<RawObservedState, MockError>,
    pub submitted: Vec<Call>,
}

pub struct MockViewFunctionQuerier {
    pub inner: Mutex<MockViewFunctionQuerierState>,
}

#[async_trait]
impl ViewFunctionQuerier for MockViewFunctionQuerier {
    type Error = MockError;
    async fn view_function_query(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<RawObservedState, Self::Error> {
        let mut inner = self.inner.lock().await;
        inner.submitted.push(Call {
            contract_id: contract_id.clone(),
            method_name: method_name.to_string(),
            args: args.to_vec(),
        });
        inner.response.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub contract_id: AccountId,
    pub method_name: String,
    pub args: Vec<u8>,
}

//pub(crate) trait SignedTransactionSubmitter: Send + Sync + 'static {
//    type Error: std::error::Error + Send + Sync + 'static;
//    async fn submit_signed_transaction(
//        &self,
//        transaction: SignedTransaction,
//    ) -> Result<(), Self::Error>;
//}
//
//#[async_trait]
//pub(crate) trait ViewFunctionQuerier: Send + Sync + 'static {
//    type Error: std::error::Error + Send + Sync + 'static;
//    async fn view_function_query(
//        &self,
//        contract_id: &AccountId,
//        method_name: &str,
//        args: &[u8],
//    ) -> Result<RawObservedState, Self::Error>;
//}

/////
///// # Example
/////
///// ```
///// # #[cfg(feature = "test-utils")]
///// # #[tokio::main]
///// # async fn main() {
///// use chain_gateway::state_viewer::mock_viewer::{MockViewer, Call};
///// use chain_gateway::types::{ObservedState, RawObservedState};
///// use chain_gateway::state_viewer::ContractViewer;
///// use std::error::Error;
/////
///// let viewer = MockViewer::new(
/////     Call {
/////         contract_id: "contract.near".parse().unwrap(),
/////         method_name: "get_state".into(),
/////         args: b"{}".to_vec(),
/////     },
/////     Ok(ObservedState {
/////         observed_at: 42.into(),
/////         value: br#""hello""#.to_vec(),
/////     }.into()),
///// );
/////
///// let res = viewer
/////     .view(
/////         &"contract.near".parse().unwrap(),
/////         "get_state",
/////         b"{}",
/////     )
/////     .await
/////     .unwrap();
/////
///// assert_eq!(res.value, br#""hello""#.to_vec());
///// assert_eq!(viewer.num_expected_calls().await, 1);
///// assert_eq!(viewer.num_unexpected_calls().await, 0);
///// let err = viewer
/////     .view(
/////         &"contract.near".parse().unwrap(),
/////         "get_statee",
/////         b"{}",
/////     )
/////     .await
/////     .unwrap_err();
/////
///// assert!(err.source().unwrap().to_string().contains("unexpected mock call"));
///// assert_eq!(viewer.num_unexpected_calls().await, 1);
///// assert_eq!(viewer.total_number_calls().await, 2);
///// # }
///// ```
//#[derive(Clone)]
//pub struct MockViewer {
//    expected_call: Call,
//    inner: Arc<Mutex<MockViewerState>>,
//}
//
//impl ContractViewer for MockViewer {}
//
//#[async_trait]
//impl SyncChecker for MockViewer {
//    type Error = std::io::Error;
//    async fn is_syncing(&self) -> Result<bool, Self::Error> {
//        return Ok(false);
//    }
//}
//
//#[derive(Debug, Clone, PartialEq, Eq)]
//pub struct Call {
//    pub contract_id: AccountId,
//    pub method_name: String,
//    pub args: Vec<u8>,
//}
//
//struct MockViewerState {
//    pub num_expected_calls: usize,
//    pub num_unexpected_calls: usize,
//    pub current_value: Result<RawObservedState, ChainGatewayError>,
//}
//
//#[async_trait]
//impl ViewFunctionQuerier for MockViewer {
//    type Error = ChainGatewayError;
//    async fn view_function_query(
//        &self,
//        contract_id: &AccountId,
//        method_name: &str,
//        args: &[u8],
//    ) -> Result<RawObservedState, Self::Error> {
//        let call = Call {
//            contract_id: contract_id.clone(),
//            method_name: method_name.to_string(),
//            args: args.to_vec(),
//        };
//        let expected = call == self.expected_call;
//
//        let mut inner = self.inner.lock().await;
//        if expected {
//            inner.num_expected_calls += 1;
//            inner.current_value.clone()
//        } else {
//            inner.num_unexpected_calls += 1;
//            // todo: make this proper
//            Err(ChainGatewayError::MonitoringClosed)
//        }
//    }
//}
//
//// todo: make custom error types
//impl MockViewer {
//    pub fn new(expected_call: Call, value: Result<RawObservedState, ChainGatewayError>) -> Self {
//        Self {
//            expected_call,
//            inner: Arc::new(Mutex::new(MockViewerState {
//                num_unexpected_calls: 0,
//                num_expected_calls: 0,
//                current_value: value,
//            })),
//        }
//    }
//
//    pub async fn set_val(&self, value: Result<RawObservedState, ChainGatewayError>) {
//        self.inner.lock().await.current_value = value;
//    }
//
//    pub async fn num_expected_calls(&self) -> usize {
//        self.inner.lock().await.num_expected_calls
//    }
//
//    pub async fn num_unexpected_calls(&self) -> usize {
//        self.inner.lock().await.num_unexpected_calls
//    }
//
//    pub async fn total_number_calls(&self) -> usize {
//        let inner = self.inner.lock().await;
//        inner.num_unexpected_calls + inner.num_expected_calls
//    }
//
//    pub async fn await_next_call(&self) {
//        const POLL_INTERVAL: Duration = Duration::from_millis(100);
//        let start = self.total_number_calls().await;
//        while self.total_number_calls().await == start {
//            tokio::time::sleep(POLL_INTERVAL).await
//        }
//    }
//}
