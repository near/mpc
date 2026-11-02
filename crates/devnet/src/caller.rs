use std::sync::Arc;

use crate::account::{OperatingAccessKey, OperatingAccount};
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_kit_primitives::protocol::Action;
use near_kit_primitives::{Contract as _, TxSender};
use near_mpc_contract_interface::contract::{MpcContract, MpcContractClient};
use near_primitives::types::AccountId;
use near_primitives::views::TxExecutionStatus;
use tokio::sync::Mutex;

pub(crate) trait CallMpcContract {
    /// The returned client logs each call and waits for transaction to be final
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractClient<DevnetCaller> {
        self.call_mpc_with_verbosity(contract_id, Verbosity::Verbose)
    }

    fn call_mpc_with_verbosity(
        &self,
        contract_id: &AccountId,
        verbosity: Verbosity,
    ) -> MpcContractClient<DevnetCaller>;
}

impl CallMpcContract for OperatingAccount {
    fn call_mpc_with_verbosity(
        &self,
        contract_id: &AccountId,
        verbosity: Verbosity,
    ) -> MpcContractClient<DevnetCaller> {
        MpcContract::client(
            DevnetCaller::new(
                self.account_id().clone(),
                self.any_access_key_handle(),
                TxExecutionStatus::Final,
                verbosity,
            ),
            contract_id.clone(),
        )
    }
}

#[derive(Clone)]
pub struct DevnetCaller {
    account_id: AccountId,
    key: Arc<Mutex<OperatingAccessKey>>,
    wait_until: TxExecutionStatus,
    verbosity: Verbosity,
}

#[derive(Clone, Copy)]
pub enum Verbosity {
    Verbose,
    Quiet,
}

impl DevnetCaller {
    pub(crate) fn new(
        account_id: AccountId,
        key: Arc<Mutex<OperatingAccessKey>>,
        wait_until: TxExecutionStatus,
        verbosity: Verbosity,
    ) -> Self {
        Self {
            account_id,
            key,
            wait_until,
            verbosity,
        }
    }
}

/// Sends one function call per transaction, through the account's access key.
impl TxSender for DevnetCaller {
    type Output = RpcTransactionResponse;
    type SendError = anyhow::Error;

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    async fn send(
        &self,
        receiver_id: AccountId,
        actions: Vec<Action>,
    ) -> Result<Self::Output, Self::SendError> {
        let [Action::FunctionCall(call)] = actions.as_slice() else {
            anyhow::bail!("DevnetCaller sends exactly one function call, got {actions:?}");
        };
        self.key
            .lock()
            .await
            .submit_tx_to_call_function(
                &receiver_id,
                &call.method_name,
                &call.args,
                call.gas.as_tgas(),
                call.deposit.as_yoctonear(),
                self.wait_until.clone(),
                matches!(self.verbosity, Verbosity::Verbose),
            )
            .await
    }
}
