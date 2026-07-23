use near_contract_transport::{CallContract, FunctionCallArgs};
use near_mpc_contract_interface::client::{MpcContractHandle, MpcContractHandleError};
use near_sdk::Gas;
use near_workspaces::{
    Account, AccountId, Contract, operations::TransactionStatus, result::ExecutionFinalResult,
};
use serde::Serialize;
use std::future::Future;

pub(crate) trait CallMpcContract {
    fn call_mpc_async<'a>(
        &'a self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<AsyncSandboxCaller<'a>>;
    fn call_mpc<'a>(
        &'a self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<SandboxCaller<'a>>;
}

impl CallMpcContract for Account {
    fn call_mpc<'a>(
        &'a self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<SandboxCaller<'a>> {
        MpcContractHandle::new(SandboxCaller(self), contract_id.clone())
    }
    fn call_mpc_async<'a>(
        &'a self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractHandle<AsyncSandboxCaller<'a>> {
        MpcContractHandle::new(AsyncSandboxCaller(self), contract_id.clone())
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

/// Executes parallel contract calls on [`Contract`].
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
