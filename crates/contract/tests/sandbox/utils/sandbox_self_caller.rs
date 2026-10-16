use crate::sandbox::utils::transactions::SandboxCaller;
use near_contract_transport::{
    CallContract, FunctionCallArgs, HasPollInterval, ObservedState, PollInterval,
    SerializedObservation, ViewArgs, ViewContract,
};
use near_jsonrpc_client::{JsonRpcClient, methods::query::RpcQueryRequest};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::types::BlockReference;
use near_primitives::views::QueryRequest;
use near_workspaces::{
    Account, AccountId, Contract, Worker, network::Sandbox, result::ExecutionFinalResult,
};
use std::time::Duration;

/// The deployed MPC contract as a caller: calls are signed by the contract's own key, views go
/// to the sandbox RPC directly because near-workspaces' `view` drops the block height that
/// [`ObservedState`] needs.
#[derive(Clone)]
pub struct SandboxSelfCaller {
    contract: Contract,
    rpc: JsonRpcClient,
}

impl SandboxSelfCaller {
    pub fn new(worker: &Worker<Sandbox>, contract: Contract) -> Self {
        Self {
            contract,
            rpc: JsonRpcClient::connect(worker.rpc_addr()),
        }
    }

    pub fn as_account(&self) -> &Account {
        self.contract.as_account()
    }

    pub async fn view_code(&self) -> near_workspaces::Result<Vec<u8>> {
        self.contract.view_code().await
    }
}

impl CallContract for SandboxSelfCaller {
    type Output = ExecutionFinalResult;
    type Error = near_workspaces::error::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        SandboxCaller(self.contract.as_account())
            .call_contract(contract_id, call_args)
            .await
    }
}

impl HasPollInterval for SandboxSelfCaller {
    fn poll_interval(&self) -> PollInterval {
        PollInterval::new(Duration::from_millis(100)).expect("non-zero")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SandboxViewError(String);

impl ViewContract for SandboxSelfCaller {
    type Error = SandboxViewError;

    async fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> Result<SerializedObservation, Self::Error> {
        let response = self
            .rpc
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
