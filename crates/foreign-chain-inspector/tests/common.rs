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
