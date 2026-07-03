use std::sync::Arc;

use mpc_call_args::FunctionCallArgs;
use near_account_id::AccountId;
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_mpc_contract_interface::call_args::{CallContract, CallError};
use near_primitives::views::TxExecutionStatus;
use tokio::sync::Mutex;

use crate::account::OperatingAccessKey;

/// Local newtype implementing the foreign [`CallContract`] trait for a devnet
/// access key (orphan rule). Locks the key's mutex inside `call_contract` so the
/// trait's `&self` method can drive the `&mut self` transaction submitter, and
/// can be cloned into the per-participant `join_all` voting loops.
#[derive(Clone)]
pub struct DevnetCaller {
    key: Arc<Mutex<OperatingAccessKey>>,
    verbose: bool,
}

impl DevnetCaller {
    pub fn new(key: Arc<Mutex<OperatingAccessKey>>) -> Self {
        Self { key, verbose: true }
    }

    pub fn verbose(key: Arc<Mutex<OperatingAccessKey>>, verbose: bool) -> Self {
        Self { key, verbose }
    }
}

impl CallContract for DevnetCaller {
    type Output = RpcTransactionResponse;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<RpcTransactionResponse, CallError> {
        let mut key = self.key.lock().await;
        key.submit_tx_to_call_function(
            contract_id,
            &call_args.method_name,
            &call_args.args,
            call_args.gas.as_tgas(),
            call_args.deposit.as_yoctonear(),
            TxExecutionStatus::Final,
            self.verbose,
        )
        .await
        .map_err(|e| CallError::Call(e.into()))
    }
}
