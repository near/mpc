use near_contract_transport::{CallContract, FunctionCallArgs};
use near_sdk::Gas;
use near_workspaces::{Account, AccountId, Contract, result::ExecutionFinalResult};
use serde::Serialize;

/// The sandbox-test [`CallContract`] backend: transacts as the wrapped
/// [`Account`] via near-workspaces.
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

/// Returns an error if any of the outcomes in [`ExecutionFinalResult`] failed
pub fn all_receipts_successful(result: ExecutionFinalResult) -> anyhow::Result<()> {
    anyhow::ensure!(
        result.outcomes().iter().all(|o| !o.is_failure()),
        "execution should have succeeded: {result:#?}"
    );
    Ok(())
}
