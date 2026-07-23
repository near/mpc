use std::sync::Arc;

use crate::account::OperatingAccessKey;
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_primitives::types::AccountId;
use near_primitives::views::TxExecutionStatus;
use tokio::sync::Mutex;

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
