use mpc_call_args::FunctionCallArgs;
use near_sdk::Gas;
use near_workspaces::{Account, Contract, operations::CallTransaction, result::ExecutionFinalResult};
use serde::Serialize;

/// Builds a [`CallTransaction`] from a [`call_args`](near_mpc_contract_interface::call_args) builder,
/// so tests share the node's gas/deposit/encoding. Caller drives it (`.transact()`, assertions).
pub fn call_from_args(account: &Account, contract: &Contract, call: FunctionCallArgs) -> CallTransaction {
    account
        .call(contract.id(), &call.method_name)
        .args(call.args)
        .gas(call.gas)
        .deposit(call.deposit)
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
