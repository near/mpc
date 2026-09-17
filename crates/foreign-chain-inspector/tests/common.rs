use foreign_chain_inspector::FanOut;
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::ProviderId;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use jsonrpsee::core::{
    client::BatchResponse,
    client::{ClientT, error::Error as RpcClientError},
    params::BatchRequestBuilder,
};
use serde::{Deserialize, Serialize};

/// A client that always returns a hard-coded response.
/// Useful for tests.
/// Note: We have to hold a closure and not just the response
/// because [`RpcClientError`] does not implement [`Clone`].
#[derive(Clone)]
pub struct FixedResponseRpcClient<RespFn> {
    response_fn: RespFn,
}

impl<RespFn> FixedResponseRpcClient<RespFn> {
    pub fn new(response_fn: RespFn) -> Self {
        Self { response_fn }
    }
}

pub fn mock_client_from_fixed_response(
    response: impl serde::Serialize + Clone,
) -> FixedResponseRpcClient<impl Fn() -> Result<serde_json::Value, RpcClientError>> {
    FixedResponseRpcClient {
        response_fn: move || Ok(serde_json::to_value(response.clone()).unwrap()),
    }
}

impl<RespFn> ClientT for FixedResponseRpcClient<RespFn>
where
    RespFn: Fn() -> Result<serde_json::Value, RpcClientError> + Sync,
{
    async fn request<R, Params>(&self, _method: &str, _params: Params) -> Result<R, RpcClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        serde_json::from_value((self.response_fn)()?).map_err(RpcClientError::ParseError)
    }

    async fn notification<Params>(
        &self,
        _method: &str,
        _params: Params,
    ) -> Result<(), RpcClientError> {
        unimplemented!("notification() not used in tests")
    }

    async fn batch_request<'a, R>(
        &self,
        _batch: BatchRequestBuilder<'a>,
    ) -> Result<BatchResponse<'a, R>, RpcClientError>
    where
        R: serde::de::DeserializeOwned + std::fmt::Debug + 'a,
    {
        unimplemented!("batch_request() not used in tests")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub result: T,
    pub id: u64,
}

/// Builds a mock RPC client that returns pre-configured responses in call order.
///
/// Each call to the resulting client pops the next response from the queue, regardless
/// of method name or params. Useful for tests of flows that issue a deterministic sequence
/// of RPC calls. Panics if the client is called more times than responses were configured;
/// excess responses are silently ignored.
#[derive(Default)]
pub struct SequentialResponseMockClientBuilder {
    responses: Vec<QueuedResponse>,
}

#[derive(Clone)]
enum QueuedResponse {
    Value(serde_json::Value),
    Error(fn() -> RpcClientError),
}

impl SequentialResponseMockClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_response(mut self, response: impl serde::Serialize) -> Self {
        let value = serde_json::to_value(&response).unwrap();
        self.responses.push(QueuedResponse::Value(value));
        self
    }

    pub fn with_error(mut self, error: fn() -> RpcClientError) -> Self {
        self.responses.push(QueuedResponse::Error(error));
        self
    }

    pub fn build(
        self,
    ) -> FixedResponseRpcClient<
        impl Fn() -> Result<serde_json::Value, RpcClientError> + Clone + Send + Sync + 'static,
    > {
        let call_count = Arc::new(AtomicUsize::new(0));
        let responses = Arc::new(self.responses);
        FixedResponseRpcClient::new(move || {
            let count = call_count.fetch_add(1, Ordering::SeqCst);
            let response = responses.get(count).unwrap_or_else(|| {
                panic!(
                    "mock client received call #{} but only {} responses were configured",
                    count + 1,
                    responses.len(),
                )
            });
            match response {
                QueuedResponse::Value(value) => Ok(value.clone()),
                QueuedResponse::Error(make_error) => Err(make_error()),
            }
        })
    }
}

pub fn fan_out_of<Inspector>(inspectors: Vec<Inspector>) -> FanOut<Inspector> {
    let named: Vec<(ProviderId, Inspector)> = inspectors
        .into_iter()
        .enumerate()
        .map(|(index, inspector)| (ProviderId(format!("provider-{index}")), inspector))
        .collect();
    let inspectors: NonEmptyVec<(ProviderId, Inspector)> = named
        .try_into()
        .expect("test must provider at least one inspector");
    FanOut::new(inspectors)
}
