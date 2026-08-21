use std::sync::Arc;

use crate::account::{OperatingAccessKey, OperatingAccount};
use crate::tx::SubmittedTx;
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_primitives::types::AccountId;
use near_primitives::views::TxExecutionStatus;
use tokio::sync::Mutex;

pub(crate) trait CallMpcContract {
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller>;
}

impl CallMpcContract for OperatingAccount {
    /// The returned handle logs each call and waits for transaction to be final
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller> {
        MpcContractHandle::new(
            DevnetCaller::new(
                self.any_access_key_handle(),
                TxExecutionStatus::Final,
                Verbosity::Verbose,
            ),
            contract_id.clone(),
        )
    }
}

pub struct DevnetCaller {
    key: Arc<Mutex<OperatingAccessKey>>,
    wait_until: TxExecutionStatus,
    verbosity: Verbosity,
}

pub enum Verbosity {
    Verbose,
    Quiet,
}

impl DevnetCaller {
    pub(crate) fn new(
        key: Arc<Mutex<OperatingAccessKey>>,
        wait_until: TxExecutionStatus,
        verbosity: Verbosity,
    ) -> Self {
        Self {
            key,
            wait_until,
            verbosity,
        }
    }

    pub(crate) fn with_verbosity(self, verbosity: Verbosity) -> Self {
        Self { verbosity, ..self }
    }
}

pub trait WithVerbosity {
    fn with_verbosity(self, verbosity: Verbosity) -> Self;
}

impl WithVerbosity for MpcContractHandle<DevnetCaller> {
    fn with_verbosity(self, verbosity: Verbosity) -> Self {
        self.map_caller(|caller| caller.with_verbosity(verbosity))
    }
}

impl CallContract for DevnetCaller {
    type Output = SubmittedTx;
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
                matches!(self.verbosity, Verbosity::Verbose),
            )
            .await
    }
}
