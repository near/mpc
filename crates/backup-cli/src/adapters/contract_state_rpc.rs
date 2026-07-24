use anyhow::Context as _;
use near_account_id::AccountId;
use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
use near_jsonrpc_client::methods::query::{RpcQueryError, RpcQueryRequest};
use near_jsonrpc_client::{JsonRpcClient, auth};
use near_jsonrpc_primitives::types::query::{QueryResponseKind, RpcQueryResponse};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::ProtocolContractState;
use near_primitives::types::{BlockReference, Finality, FunctionArgs};
use near_primitives::views::QueryRequest;

use crate::ports::ContractStateReader;

/// Reads the MPC contract's `state` view method from a NEAR JSON-RPC endpoint.
pub struct RpcContractStateReader {
    client: JsonRpcClient,
    mpc_contract_account_id: AccountId,
}

impl RpcContractStateReader {
    pub fn new(
        rpc_url: &str,
        api_key: Option<String>,
        mpc_contract_account_id: AccountId,
    ) -> anyhow::Result<Self> {
        let client = JsonRpcClient::connect(rpc_url);
        let client = match api_key {
            Some(key) => {
                client.header(auth::Authorization::bearer(key).context("invalid RPC api key")?)
            }
            None => client,
        };
        Ok(Self {
            client,
            mpc_contract_account_id,
        })
    }
}

impl ContractStateReader for RpcContractStateReader {
    type Error = anyhow::Error;

    async fn get_contract_state(&self) -> Result<ProtocolContractState, Self::Error> {
        let request = RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: self.mpc_contract_account_id.clone(),
                method_name: method_names::STATE.to_string(),
                args: FunctionArgs::from(b"{}".to_vec()),
            },
        };
        parse_state_response(self.client.call(request).await)
    }
}

/// An uninitialized contract rejects the `state` call with a "Calling default not
/// allowed." error; that case maps to `NotInitialized` rather than an error.
fn parse_state_response(
    response: Result<RpcQueryResponse, JsonRpcError<RpcQueryError>>,
) -> anyhow::Result<ProtocolContractState> {
    match response {
        Ok(response) => match response.kind {
            QueryResponseKind::CallResult(result) => serde_json::from_slice(&result.result)
                .with_context(|| {
                    format!(
                        "failed to deserialize contract state: {}",
                        String::from_utf8_lossy(&result.result)
                    )
                }),
            other => anyhow::bail!("unexpected query response kind: {other:?}"),
        },
        Err(JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcQueryError::ContractExecutionError { vm_error, .. },
        ))) if vm_error.contains("Calling default not allowed.") => {
            Ok(ProtocolContractState::NotInitialized)
        }
        Err(err) => Err(anyhow::anyhow!("state view call failed: {err:?}")),
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use near_primitives::hash::CryptoHash;
    use near_primitives::views::CallResult;

    fn call_result_response(bytes: Vec<u8>) -> RpcQueryResponse {
        RpcQueryResponse {
            kind: QueryResponseKind::CallResult(CallResult {
                result: bytes,
                logs: vec![],
            }),
            block_height: 0,
            block_hash: CryptoHash::default(),
        }
    }

    #[test]
    fn parse_state_response__should_deserialize_running_state_from_call_result() {
        // Given
        let fixture = include_str!("../../assets/contract_state.json");
        let response = call_result_response(fixture.as_bytes().to_vec());

        // When
        let state = parse_state_response(Ok(response)).unwrap();

        // Then
        assert_matches!(state, ProtocolContractState::Running(_));
    }

    #[test]
    fn parse_state_response__should_error_on_undeserializable_call_result() {
        // Given
        let response = call_result_response(b"not json".to_vec());

        // When
        let result = parse_state_response(Ok(response));

        // Then
        let err = result.expect_err("garbage bytes should fail to deserialize");
        assert!(
            err.to_string()
                .contains("failed to deserialize contract state")
        );
    }
}
