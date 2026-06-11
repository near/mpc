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
/// because `RpcClientError` does not implement `Clone`.
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
    responses: Vec<serde_json::Value>,
}

impl SequentialResponseMockClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_response(mut self, response: impl serde::Serialize) -> Self {
        self.responses
            .push(serde_json::to_value(&response).unwrap());
        self
    }

    pub fn build(
        self,
    ) -> FixedResponseRpcClient<impl Fn() -> Result<serde_json::Value, RpcClientError> + Sync> {
        let call_count = AtomicUsize::new(0);
        let total = self.responses.len();
        FixedResponseRpcClient::new(move || {
            let count = call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.responses.get(count).cloned().unwrap_or_else(|| {
                panic!(
                    "mock client received call #{} but only {} responses were configured",
                    count + 1,
                    total,
                )
            }))
        })
    }
}
