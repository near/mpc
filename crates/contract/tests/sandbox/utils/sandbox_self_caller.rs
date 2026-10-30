use crate::sandbox::utils::transactions::{SandboxCaller, SandboxSendError};
use near_jsonrpc_client::{JsonRpcClient, methods::query::RpcQueryRequest};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_kit_primitives::protocol::Action;
use near_kit_primitives::rpc::{BlockReference as KitBlockReference, ViewFunctionResult};
use near_kit_primitives::{CryptoHash, TxSender, Viewer};
use near_primitives::types::BlockReference;
use near_primitives::views::QueryRequest;
use near_workspaces::{
    Account, AccountId, Contract, Worker, network::Sandbox, result::ExecutionFinalResult,
};
use std::time::Duration;

/// How often the sandbox tests poll contract views.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The deployed MPC contract as a backend: calls are signed by the contract's own key, views go
/// to the sandbox RPC directly because near-workspaces' `view` drops the block height.
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

impl TxSender for SandboxSelfCaller {
    type Output = ExecutionFinalResult;
    type SendError = SandboxSendError;

    fn account_id(&self) -> &AccountId {
        self.contract.id()
    }

    async fn send(
        &self,
        receiver_id: AccountId,
        actions: Vec<Action>,
    ) -> Result<ExecutionFinalResult, SandboxSendError> {
        SandboxCaller(self.as_account().clone())
            .send(receiver_id, actions)
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SandboxViewError(String);

/// Every view reads the latest (optimistic) block, whatever block it asks for: near-kit
/// defaults views to final, which can lag the transactions the tests just executed.
impl Viewer for SandboxSelfCaller {
    type ViewError = SandboxViewError;

    async fn view_function(
        &self,
        contract_id: &AccountId,
        method: &str,
        args: &[u8],
        _block: KitBlockReference,
    ) -> Result<ViewFunctionResult, SandboxViewError> {
        let response = self
            .rpc
            .call(RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: QueryRequest::CallFunction {
                    account_id: contract_id.clone(),
                    method_name: method.to_string(),
                    args: args.to_vec().into(),
                },
            })
            .await
            .map_err(|err| SandboxViewError(err.to_string()))?;
        let QueryResponseKind::CallResult(result) = response.kind else {
            return Err(SandboxViewError(
                "view query did not return a call result".to_string(),
            ));
        };
        Ok(ViewFunctionResult::new(
            result.result,
            response.block_height,
            CryptoHash::from_bytes(response.block_hash.0),
        )
        .with_logs(result.logs))
    }
}
