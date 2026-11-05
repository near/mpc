use std::sync::Arc;

use crate::account::{OperatingAccessKey, OperatingAccount};
use crate::rpc::NearRpcClients;
use near_contract_transport::{
    CallContract, FunctionCallArgs, ObservedState, SerializedObservation, ViewArgs, ViewContract,
};
use near_jsonrpc_client::errors::JsonRpcError;
use near_jsonrpc_client::methods::query::{RpcQueryError, RpcQueryRequest};
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_primitives::types::{AccountId, BlockReference, Finality, FunctionArgs};
use near_primitives::views::{QueryRequest, TxExecutionStatus};
use tokio::sync::Mutex;

pub(crate) trait CallMpcContract {
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller>;
}

impl CallMpcContract for OperatingAccount {
    /// The returned handle logs each call and waits for transaction to be final
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller> {
        MpcContractHandle::new(
            DevnetCaller::new(
                self.any_access_key_handle(),
                self.rpc_client(),
                TxExecutionStatus::Final,
                Verbosity::Verbose,
            ),
            contract_id.clone(),
        )
    }
}

#[derive(Clone)]
pub struct DevnetCaller {
    key: Arc<Mutex<OperatingAccessKey>>,
    client: Arc<NearRpcClients>,
    wait_until: TxExecutionStatus,
    verbosity: Verbosity,
}

#[derive(Clone)]
pub enum Verbosity {
    Verbose,
    Quiet,
}

impl DevnetCaller {
    pub(crate) fn new(
        key: Arc<Mutex<OperatingAccessKey>>,
        client: Arc<NearRpcClients>,
        wait_until: TxExecutionStatus,
        verbosity: Verbosity,
    ) -> Self {
        Self {
            key,
            client,
            wait_until,
            verbosity,
        }
    }

    pub(crate) fn with_verbosity(self, verbosity: Verbosity) -> Self {
        Self { verbosity, ..self }
    }
}

pub trait WithVerbosity {
    fn with_verbosity(self, verbosity: Verbosity) -> Self;
}

impl WithVerbosity for MpcContractHandle<DevnetCaller> {
    fn with_verbosity(self, verbosity: Verbosity) -> Self {
        self.map_caller(|caller| caller.with_verbosity(verbosity))
    }
}

impl CallContract for DevnetCaller {
    type Output = RpcTransactionResponse;
    type Error = anyhow::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.key
            .lock()
            .await
            .submit_tx_to_call_function(
                contract_id,
                &call_args.method_name,
                &call_args.args,
                call_args.gas.as_tgas(),
                call_args.deposit.as_yoctonear(),
                self.wait_until.clone(),
                matches!(self.verbosity, Verbosity::Verbose),
            )
            .await
    }
}

impl ViewContract for DevnetCaller {
    type Error = DevnetViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        let request = RpcQueryRequest {
            block_reference: BlockReference::Finality(view_finality(&self.wait_until)),
            request: QueryRequest::CallFunction {
                account_id: contract_id.clone(),
                method_name: view_args.method_name,
                args: FunctionArgs::from(view_args.args),
            },
        };
        let response = self.client.submit(request).await?;
        let QueryResponseKind::CallResult(result) = response.kind else {
            return Err(DevnetViewError::UnexpectedResponse);
        };
        Ok(ObservedState {
            observed_at: response.block_height.into(),
            value: result.result,
        })
    }
}

/// Below [`TxExecutionStatus::Final`], a call returns before the blocks holding its effects
/// are final, so only an optimistic view is guaranteed to observe them.
fn view_finality(wait_until: &TxExecutionStatus) -> Finality {
    match wait_until {
        TxExecutionStatus::Final => Finality::Final,
        TxExecutionStatus::None
        | TxExecutionStatus::Included
        | TxExecutionStatus::ExecutedOptimistic
        | TxExecutionStatus::IncludedFinal
        | TxExecutionStatus::Executed => Finality::None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DevnetViewError {
    /// [`JsonRpcError`] is neither [`Clone`] nor [`PartialEq`], so only its rendering is kept.
    #[error("{0}")]
    Rpc(String),
    #[error("the RPC answered a function call query with another kind of response")]
    UnexpectedResponse,
}

impl From<JsonRpcError<RpcQueryError>> for DevnetViewError {
    fn from(err: JsonRpcError<RpcQueryError>) -> Self {
        Self::Rpc(err.to_string())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::types::RpcConfig;
    use ed25519_dalek::SigningKey;
    use httpmock::prelude::*;
    use near_primitives::hash::CryptoHash;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::assert_matches;

    const CONTRACT_ID: &str = "mpc.test.near";

    async fn must_make_caller(server: &MockServer, wait_until: TxExecutionStatus) -> DevnetCaller {
        let client = Arc::new(
            NearRpcClients::new(vec![RpcConfig {
                url: server.base_url(),
                rate_limit: 100,
                max_concurrency: 1,
                api_key: None,
            }])
            .await,
        );
        let key = OperatingAccessKey::new(
            CONTRACT_ID.parse().unwrap(),
            SigningKey::generate(&mut OsRng),
            CryptoHash::default(),
            client.clone(),
        );
        DevnetCaller::new(
            Arc::new(Mutex::new(key)),
            client,
            wait_until,
            Verbosity::Quiet,
        )
    }

    async fn mock_call_function(server: &MockServer, finality: &str) {
        server
            .mock_async(|when, then| {
                when.method(POST).json_body_includes(
                    json!({
                        "method": "query",
                        "params": {
                            "request_type": "call_function",
                            "finality": finality,
                            "account_id": CONTRACT_ID,
                            "method_name": "config",
                            "args_base64": "e30=",
                        },
                    })
                    .to_string(),
                );
                then.status(200).json_body(json!({
                    "jsonrpc": "2.0",
                    "id": "dontcare",
                    "result": {
                        "result": [1, 2, 3],
                        "logs": [],
                        "block_height": 7,
                        "block_hash": "11111111111111111111111111111111",
                    },
                }));
            })
            .await;
    }

    #[tokio::test]
    async fn view_contract__should_return_call_result_observed_at_final_block() {
        // Given
        let server = MockServer::start_async().await;
        mock_call_function(&server, "final").await;
        let caller = must_make_caller(&server, TxExecutionStatus::Final).await;

        // When
        let observed = caller
            .view_contract(&CONTRACT_ID.parse().unwrap(), ViewArgs::no_args("config"))
            .await;

        // Then
        assert_eq!(
            observed,
            Ok(ObservedState {
                observed_at: 7.into(),
                value: vec![1, 2, 3],
            })
        );
    }

    #[tokio::test]
    async fn view_contract__should_read_optimistic_block_when_calls_return_before_final() {
        // Given
        let server = MockServer::start_async().await;
        mock_call_function(&server, "optimistic").await;
        let caller = must_make_caller(&server, TxExecutionStatus::ExecutedOptimistic).await;

        // When
        let observed = caller
            .view_contract(&CONTRACT_ID.parse().unwrap(), ViewArgs::no_args("config"))
            .await;

        // Then
        assert_eq!(
            observed,
            Ok(ObservedState {
                observed_at: 7.into(),
                value: vec![1, 2, 3],
            })
        );
    }

    #[tokio::test]
    async fn view_contract__should_return_rpc_error_when_rpc_fails() {
        // Given
        let server = MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(POST);
                then.status(503);
            })
            .await;
        let caller = must_make_caller(&server, TxExecutionStatus::Final).await;

        // When
        let observed = caller
            .view_contract(&CONTRACT_ID.parse().unwrap(), ViewArgs::no_args("config"))
            .await;

        // Then
        assert_matches!(observed, Err(DevnetViewError::Rpc(_)));
    }
}
