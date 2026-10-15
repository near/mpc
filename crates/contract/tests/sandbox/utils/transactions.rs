use crate::sandbox::utils::sandbox_mpc_contract::SandboxMpcContract;
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_mpc_contract_interface::client::{MpcContractHandle, MpcContractHandleError};
use near_workspaces::{
    Account, AccountId, operations::TransactionStatus, result::ExecutionFinalResult,
};
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

/// Calls the MPC contract as the contract account itself (e.g. for `#[private]` methods).
pub(crate) trait CallMpcContractAsSelf {
    fn call_mpc(&self) -> MpcContractHandle<SandboxCaller<'_>>;
}

impl CallMpcContractAsSelf for SandboxMpcContract {
    fn call_mpc(&self) -> MpcContractHandle<SandboxCaller<'_>> {
        self.as_account().call_mpc(self.id())
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

/// Issues `call` once per account against `contract`, keeping every transaction in flight
/// before awaiting any of them, then fails if any receipt failed.
///
/// ```ignore
/// execute_async_handle_calls(&accounts, &contract, |handle| async move {
///     handle.vote_contract_update(update_hash).await
/// })
/// ```
pub async fn execute_async_handle_calls<'a, F, Fut>(
    accounts: &'a [Account],
    contract: &SandboxMpcContract,
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
