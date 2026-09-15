use near_contract_transport::{ObservedState, SerializedObservation, ViewArgs, ViewContract};
use near_jsonrpc_client::{JsonRpcClient, methods::query::RpcQueryRequest};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_primitives::types::BlockReference;
use near_primitives::views::QueryRequest;
use near_workspaces::{AccountId, Worker, network::Sandbox};

pub(crate) trait ViewMpcContract {
    fn view_mpc(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<SandboxViewer>;
}

impl ViewMpcContract for Worker<Sandbox> {
    fn view_mpc(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<SandboxViewer> {
        MpcContractHandle::new(
            SandboxViewer(JsonRpcClient::connect(self.rpc_addr())),
            contract_id.clone(),
        )
    }
}

#[derive(Clone)]
pub struct SandboxViewer(pub JsonRpcClient);

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
