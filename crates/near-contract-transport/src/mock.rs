use near_account_id::AccountId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;

use crate::{HasPollInterval, PollInterval, SerializedObservation, ViewArgs, ViewContract};

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
