use near_contract_transport::{
    CallContract, FunctionCallArgs, ObservedState, SerializedObservation, ViewArgs, ViewContract,
};
use near_jsonrpc_client::{JsonRpcClient, methods::query::RpcQueryRequest};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_mpc_contract_interface::client::{MpcContractHandle, MpcContractHandleError};
use near_primitives::types::{BlockReference, Finality};
use near_primitives::views::QueryRequest;
use near_sdk::Gas;
use near_workspaces::{
    Account, AccountId, Contract, Worker, network::Sandbox, operations::TransactionStatus,
    result::ExecutionFinalResult,
};
use serde::Serialize;
use std::future::Future;

pub(crate) trait CallMpcContract {
    fn call_mpc(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<SandboxCaller<'_>>;
    fn call_mpc_async(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<AsyncSandboxCaller<'_>>;
}

impl CallMpcContract for Account {
    fn call_mpc(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<SandboxCaller<'_>> {
        MpcContractHandle::new(SandboxCaller(self), contract_id.clone())
    }

    fn call_mpc_async(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<AsyncSandboxCaller<'_>> {
        MpcContractHandle::new(AsyncSandboxCaller(self), contract_id.clone())
    }
}

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
                block_reference: BlockReference::Finality(Finality::Final),
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

pub struct SandboxCaller<'a>(pub &'a Account);

impl CallContract for SandboxCaller<'_> {
    type Output = ExecutionFinalResult;
    type Error = near_workspaces::error::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.0
            .call(contract_id, &call_args.method_name)
            .args(call_args.args)
            .gas(call_args.gas)
            .deposit(call_args.deposit)
            .transact()
            .await
    }
}

/// Different to [`SandboxCaller`], in that it doesn't wait for the transaction to complete, but
/// returns a [`TransactionStatus`] which can be awaited.
pub struct AsyncSandboxCaller<'a>(pub &'a Account);

impl CallContract for AsyncSandboxCaller<'_> {
    type Output = TransactionStatus;
    type Error = near_workspaces::error::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.0
            .call(contract_id, &call_args.method_name)
            .args(call_args.args)
            .gas(call_args.gas)
            .deposit(call_args.deposit)
            .transact_async()
            .await
    }
}

pub async fn execute_async_transactions(
    accounts: &[Account],
    contract: &Contract,
    function_name: &str,
    json_args: &impl Serialize,
    attached_gas: Gas,
) -> anyhow::Result<()> {
    let mut transactions = vec![];
    for account in accounts.iter() {
        let result = account
            .call(contract.id(), function_name)
            .gas(attached_gas)
            .args_json(json_args)
            .transact_async()
            .await?;
        transactions.push(result);
    }
    for transaction in transactions {
        let result = transaction.await?;
        all_receipts_successful(result)?;
    }
    Ok(())
}

/// Issues `call` once per account against `contract`, keeping every transaction in flight
/// before awaiting any of them, then fails if any receipt failed.
///
/// ```ignore
/// execute_async_handle_calls(&accounts, &contract, |handle| async move {
///     handle.vote_update(id).await
/// })
/// ```
pub async fn execute_async_handle_calls<'a, F, Fut>(
    accounts: &'a [Account],
    contract: &Contract,
    call: F,
) -> anyhow::Result<()>
where
    F: Fn(MpcContractHandle<AsyncSandboxCaller<'a>>) -> Fut,
    Fut: Future<
        Output = Result<TransactionStatus, MpcContractHandleError<near_workspaces::error::Error>>,
    >,
{
    let mut transactions = vec![];
    for account in accounts {
        let handle = account.call_mpc_async(contract.id());
        transactions.push(call(handle).await?);
    }
    for transaction in transactions {
        let result = transaction.await?;
        all_receipts_successful(result)?;
    }
    Ok(())
}

/// Returns an error if any of the outcomes in [`ExecutionFinalResult`] failed
pub fn all_receipts_successful(result: ExecutionFinalResult) -> anyhow::Result<()> {
    anyhow::ensure!(
        result.outcomes().iter().all(|o| !o.is_failure()),
        "execution should have succeeded: {result:#?}"
    );
    Ok(())
}
