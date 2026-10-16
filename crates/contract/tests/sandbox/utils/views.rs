use near_contract_transport::{
    HasPollInterval, ObservedState, PollInterval, SerializedObservation, ViewArgs, ViewContract,
};
use near_jsonrpc_client::{JsonRpcClient, methods::query::RpcQueryRequest};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::types::BlockReference;
use near_primitives::views::QueryRequest;
use near_workspaces::{AccountId, Worker, network::Sandbox};
use std::time::Duration;

/// Queries the sandbox RPC directly: near-workspaces' `view` drops the block height of the
/// response, which [`ObservedState`] needs.
#[derive(Clone)]
pub struct SandboxViewer(JsonRpcClient);

impl SandboxViewer {
    pub fn new(worker: &Worker<Sandbox>) -> Self {
        Self(JsonRpcClient::connect(worker.rpc_addr()))
    }
}

impl HasPollInterval for SandboxViewer {
    fn poll_interval(&self) -> PollInterval {
        PollInterval::new(Duration::from_millis(100)).expect("non-zero")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SandboxViewError(String);

impl ViewContract for SandboxViewer {
    type Error = SandboxViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        let response = self
            .0
            .call(RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: QueryRequest::CallFunction {
                    account_id: contract_id.clone(),
                    method_name: view_args.method_name,
                    args: view_args.args.into(),
                },
            })
            .await
            .map_err(|err| SandboxViewError(err.to_string()))?;
        let QueryResponseKind::CallResult(result) = response.kind else {
            return Err(SandboxViewError(
                "view query did not return a call result".to_string(),
            ));
        };
        Ok(ObservedState {
            observed_at: response.block_height.into(),
            value: result.result,
        })
    }
}
