use crate::sandbox::utils::sandbox_mpc_contract::SandboxMpcContract;
use near_kit_primitives::protocol::{Action, FunctionCallAction};
use near_kit_primitives::{Contract as _, ContractError, TxSender};
use near_mpc_contract_interface::contract::{MpcContract, MpcContractClient};
use near_workspaces::operations::{CallTransaction, TransactionStatus};
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId};
use std::future::Future;

pub(crate) trait CallMpcContract {
    fn call_mpc(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractClient<SandboxCaller>;
    fn call_mpc_async(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractClient<AsyncSandboxCaller>;
}

impl CallMpcContract for Account {
    fn call_mpc(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractClient<SandboxCaller> {
        MpcContract::client(SandboxCaller(self.clone()), contract_id.clone())
    }

    fn call_mpc_async(
        &self,
        contract_id: &near_account_id::AccountId,
    ) -> MpcContractClient<AsyncSandboxCaller> {
        MpcContract::client(AsyncSandboxCaller(self.clone()), contract_id.clone())
    }
}

/// Sends each call as its own transaction from the account and waits for it to complete.
#[derive(Clone)]
pub struct SandboxCaller(pub Account);

/// Different to [`SandboxCaller`], in that it doesn't wait for the transaction to complete, but
/// returns a [`TransactionStatus`] which can be awaited.
#[derive(Clone)]
pub struct AsyncSandboxCaller(pub Account);

/// The near-workspaces call for the one function call a typed client sends.
fn function_call(
    account: &Account,
    receiver_id: &AccountId,
    actions: &[Action],
) -> Result<CallTransaction, SandboxSendError> {
    let [Action::FunctionCall(call)] = actions else {
        return Err(SandboxSendError::NotOneFunctionCall(actions.len()));
    };
    let FunctionCallAction {
        method_name,
        args,
        gas,
        deposit,
    } = call;
    Ok(account
        .call(receiver_id, method_name)
        .args(args.clone())
        .gas(Gas::from_gas(gas.as_gas()))
        .deposit(NearToken::from_yoctonear(deposit.as_yoctonear())))
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxSendError {
    #[error("the sandbox callers send exactly one function call, got {0} actions")]
    NotOneFunctionCall(usize),
    #[error(transparent)]
    Workspaces(#[from] near_workspaces::error::Error),
}

impl TxSender for SandboxCaller {
    type Output = ExecutionFinalResult;
    type SendError = SandboxSendError;

    fn account_id(&self) -> &AccountId {
        self.0.id()
    }

    async fn send(
        &self,
        receiver_id: AccountId,
        actions: Vec<Action>,
    ) -> Result<ExecutionFinalResult, SandboxSendError> {
        Ok(function_call(&self.0, &receiver_id, &actions)?
            .transact()
            .await?)
    }
}

impl TxSender for AsyncSandboxCaller {
    type Output = TransactionStatus;
    type SendError = SandboxSendError;

    fn account_id(&self) -> &AccountId {
        self.0.id()
    }

    async fn send(
        &self,
        receiver_id: AccountId,
        actions: Vec<Action>,
    ) -> Result<TransactionStatus, SandboxSendError> {
        Ok(function_call(&self.0, &receiver_id, &actions)?
            .transact_async()
            .await?)
    }
}

/// Issues `call` once per account against `contract`, keeping every transaction in flight
/// before awaiting any of them, then fails if any receipt failed.
///
/// ```ignore
/// execute_async_handle_calls(&accounts, &contract, |client| {
///     client.vote_contract_update(args).into_future()
/// })
/// ```
pub async fn execute_async_handle_calls<F, Fut>(
    accounts: &[Account],
    contract: &SandboxMpcContract,
    call: F,
) -> anyhow::Result<()>
where
    F: Fn(MpcContractClient<AsyncSandboxCaller>) -> Fut,
    Fut: Future<Output = Result<TransactionStatus, ContractError<SandboxSendError>>>,
{
    let mut transactions = vec![];
    for account in accounts {
        let client = account.call_mpc_async(contract.id());
        transactions.push(call(client).await?);
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
