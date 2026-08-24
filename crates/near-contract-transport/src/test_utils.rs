//! A programmable [`ViewContract`] double, shared so each crate does not grow
//! its own.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use near_account_id::AccountId;
use tokio::sync::{Notify, watch};

use crate::monitoring::{Observations, publish_if_changed};
use crate::subscription::ViewError;
use crate::traits::{ObserveContract, ViewContract};
use crate::types::{ObservedState, ViewArgs};

/// One recorded view request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRequest {
    pub contract_id: AccountId,
    pub method_name: String,
    pub args: Vec<u8>,
}

/// Answers view calls with canned responses and records what it was asked.
///
/// Publishes rather than polls: [`set_response`](Self::set_response) and
/// [`set_response_for`](Self::set_response_for) wake subscribers at once, so a
/// test never waits out an interval. Pass it to
/// [`poll_observations`](crate::poll_observations) to exercise the polling path
/// instead.
pub struct RecordingViewer<E> {
    state: Arc<Mutex<ViewerState<E>>>,
    read_notify: Arc<Notify>,
}

impl<E> Clone for RecordingViewer<E> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            read_notify: Arc::clone(&self.read_notify),
        }
    }
}

struct ViewerState<E> {
    response: Result<ObservedState, E>,
    responses_by_method: HashMap<String, Result<ObservedState, E>>,
    calls: Vec<ViewRequest>,
    observers: HashMap<String, watch::Sender<Result<ObservedState, E>>>,
}

impl<E: Clone> ViewerState<E> {
    fn response_for(&self, method_name: &str) -> Result<ObservedState, E> {
        self.responses_by_method
            .get(method_name)
            .unwrap_or(&self.response)
            .clone()
    }
}

impl<E> RecordingViewer<E> {
    /// Answers every method with `response` until told otherwise.
    pub fn answering(response: Result<ObservedState, E>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ViewerState {
                response,
                responses_by_method: HashMap::new(),
                calls: Vec::new(),
                observers: HashMap::new(),
            })),
            read_notify: Arc::new(Notify::new()),
        }
    }

    /// Every view request received so far, in order.
    pub fn calls(&self) -> Vec<ViewRequest> {
        self.state.lock().unwrap().calls.clone()
    }

    /// Resolves once another view call arrives, or `false` on timeout. Only the
    /// polling path calls repeatedly; a subscription reads once at `observe`.
    pub async fn await_next_call(&self, within: Duration) -> bool {
        tokio::time::timeout(within, self.read_notify.notified())
            .await
            .is_ok()
    }
}

impl<E: Clone + PartialEq> RecordingViewer<E> {
    /// Answer every method without its own response with `value`, waking their
    /// observers.
    pub fn set_response(&self, value: Result<ObservedState, E>) {
        let mut state = self.state.lock().unwrap();
        state.response = value;
        let overridden: Vec<String> = state.responses_by_method.keys().cloned().collect();
        for (method_name, sender) in &state.observers {
            if !overridden.contains(method_name) {
                publish_if_changed(sender, state.response.clone());
            }
        }
    }

    /// Answer `method_name` with `value`, waking its observer.
    pub fn set_response_for(&self, method_name: impl Into<String>, value: Result<ObservedState, E>) {
        let method_name = method_name.into();
        let mut state = self.state.lock().unwrap();
        state
            .responses_by_method
            .insert(method_name.clone(), value.clone());
        if let Some(sender) = state.observers.get(&method_name) {
            publish_if_changed(sender, value);
        }
    }
}

impl<E: Clone + Send + Sync + 'static> ViewContract for RecordingViewer<E> {
    type Error = E;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<ObservedState, Self::Error> {
        let response = {
            let mut state = self.state.lock().unwrap();
            let response = state.response_for(&view_args.method_name);
            state.calls.push(ViewRequest {
                contract_id: contract_id.clone(),
                method_name: view_args.method_name,
                args: view_args.args,
            });
            response
        };
        self.read_notify.notify_waiters();
        response
    }
}

impl<E: ViewError> ObserveContract for RecordingViewer<E> {
    async fn observe(
        &self,
        contract_id: AccountId,
        view_args: ViewArgs,
    ) -> Observations<Self::Error> {
        let mut state = self.state.lock().unwrap();
        let current = state.response_for(&view_args.method_name);
        state.calls.push(ViewRequest {
            contract_id,
            method_name: view_args.method_name.clone(),
            args: view_args.args,
        });
        let receiver = state
            .observers
            .entry(view_args.method_name)
            .or_insert_with(|| watch::channel(current).0)
            .subscribe();
        Observations::pushed(receiver)
    }
}
