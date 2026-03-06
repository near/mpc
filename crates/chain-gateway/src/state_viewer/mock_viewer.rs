use crate::errors::{ChainGatewayError, ChainGatewayOp};
use crate::state_viewer::ContractViewer;
use crate::types::RawObservedState;
use async_trait::async_trait;
use near_account_id::AccountId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::HasContractViewer;

///
/// # Example
///
/// ```
/// # #[cfg(feature = "test-utils")]
/// # #[tokio::main]
/// # async fn main() {
/// use chain_gateway::state_viewer::mock_viewer::{MockViewer, Call};
/// use chain_gateway::types::{ObservedState, RawObservedState};
/// use chain_gateway::state_viewer::ContractViewer;
/// use std::error::Error;
///
/// let viewer = MockViewer::new(
///     Call {
///         contract_id: "contract.near".parse().unwrap(),
///         method_name: "get_state".into(),
///         args: b"{}".to_vec(),
///     },
///     Ok(ObservedState {
///         observed_at: 42.into(),
///         value: br#""hello""#.to_vec(),
///     }.into()),
/// );
///
/// let res = viewer
///     .view(
///         &"contract.near".parse().unwrap(),
///         "get_state",
///         b"{}",
///     )
///     .await
///     .unwrap();
///
/// assert_eq!(res.value, br#""hello""#.to_vec());
/// assert_eq!(viewer.num_expected_calls().await, 1);
/// assert_eq!(viewer.num_unexpected_calls().await, 0);
/// let err = viewer
///     .view(
///         &"contract.near".parse().unwrap(),
///         "get_statee",
///         b"{}",
///     )
///     .await
///     .unwrap_err();
///
/// assert!(err.source().unwrap().to_string().contains("unexpected mock call"));
/// assert_eq!(viewer.num_unexpected_calls().await, 1);
/// assert_eq!(viewer.total_number_calls().await, 2);
/// # }
/// ```
#[derive(Clone)]
pub struct MockViewer {
    expected_call: Call,
    inner: Arc<Mutex<MockViewerState>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub contract_id: AccountId,
    pub method_name: String,
    pub args: Vec<u8>,
}

struct MockViewerState {
    pub num_expected_calls: usize,
    pub num_unexpected_calls: usize,
    pub current_value: Result<RawObservedState, ChainGatewayError>,
}

#[async_trait]
impl ContractViewer for MockViewer {
    async fn view(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: &[u8],
    ) -> Result<RawObservedState, ChainGatewayError> {
        let call = Call {
            contract_id: contract_id.clone(),
            method_name: method_name.to_string(),
            args: args.to_vec(),
        };
        let expected = call == self.expected_call;

        let mut inner = self.inner.lock().await;
        if expected {
            inner.num_expected_calls += 1;
            inner.current_value.clone()
        } else {
            inner.num_unexpected_calls += 1;
            Err(ChainGatewayError::ViewClient {
                op: ChainGatewayOp::ViewCall {
                    account_id: contract_id.to_string(),
                    method_name: method_name.to_string(),
                },
                source: Arc::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unexpected mock call",
                )),
            })
        }
    }
}

impl HasContractViewer for MockViewer {
    type Viewer = Self;
    fn get_viewer(&self) -> &Self::Viewer {
        self
    }
}

impl MockViewer {
    pub fn new(expected_call: Call, value: Result<RawObservedState, ChainGatewayError>) -> Self {
        Self {
            expected_call,
            inner: Arc::new(Mutex::new(MockViewerState {
                num_unexpected_calls: 0,
                num_expected_calls: 0,
                current_value: value,
            })),
        }
    }

    pub async fn set_val(&self, value: Result<RawObservedState, ChainGatewayError>) {
        self.inner.lock().await.current_value = value;
    }

    pub async fn num_expected_calls(&self) -> usize {
        self.inner.lock().await.num_expected_calls
    }

    pub async fn num_unexpected_calls(&self) -> usize {
        self.inner.lock().await.num_unexpected_calls
    }

    pub async fn total_number_calls(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.num_unexpected_calls + inner.num_expected_calls
    }

    pub async fn await_next_call(&self) {
        const POLL_INTERVAL: Duration = Duration::from_millis(100);
        let start = self.total_number_calls().await;
        while self.total_number_calls().await == start {
            tokio::time::sleep(POLL_INTERVAL).await
        }
    }
}
