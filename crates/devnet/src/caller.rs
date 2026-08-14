use std::sync::Arc;

use crate::account::{OperatingAccessKey, OperatingAccount};
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_primitives::types::AccountId;
use near_primitives::views::TxExecutionStatus;
use tokio::sync::Mutex;

pub(crate) trait CallMpcContract {
    /// Handle submitting as this account, waiting for the transaction to be
    /// final and logging each call.
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller>;

    /// As [`Self::call_mpc`], but silent: for calls whose arguments are a
    /// contract blob rather than anything readable.
    fn call_mpc_quiet(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller>;
}

impl CallMpcContract for OperatingAccount {
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller> {
        handle(self, contract_id, true)
    }

    fn call_mpc_quiet(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller> {
        handle(self, contract_id, false)
    }
}

fn handle(
    account: &OperatingAccount,
    contract_id: &AccountId,
    verbose: bool,
) -> MpcContractHandle<DevnetCaller> {
    MpcContractHandle::new(
        DevnetCaller::new(
            account.any_access_key_arc(),
            TxExecutionStatus::Final,
            verbose,
        ),
        contract_id.clone(),
    )
}

/// The devnet [`CallContract`] backend: submits through one of an operating
/// account's access keys.
pub struct DevnetCaller {
    key: Arc<Mutex<OperatingAccessKey>>,
    wait_until: TxExecutionStatus,
    verbose: bool,
}

impl DevnetCaller {
    pub fn new(
        key: Arc<Mutex<OperatingAccessKey>>,
        wait_until: TxExecutionStatus,
        verbose: bool,
    ) -> Self {
        Self {
            key,
            wait_until,
            verbose,
        }
    }
}

impl CallContract for DevnetCaller {
    type Output = RpcTransactionResponse;
    type Error = anyhow::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.key
            .lock()
            .await
            .submit_tx_to_call_function(
                contract_id,
                &call_args.method_name,
                &call_args.args,
                call_args.gas.as_tgas(),
                call_args.deposit.as_yoctonear(),
                self.wait_until.clone(),
                self.verbose,
            )
            .await
    }
}
