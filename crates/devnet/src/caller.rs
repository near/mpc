use std::marker::PhantomData;
use std::sync::Arc;

use crate::account::{OperatingAccessKey, OperatingAccount};
use crate::tx::{Final, WaitLevel};
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_primitives::types::AccountId;
use tokio::sync::Mutex;

pub(crate) trait CallMpcContract {
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller<Final>>;
}

impl CallMpcContract for OperatingAccount {
    /// The returned handle logs each call and waits for transaction to be final
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller<Final>> {
        self.any_access_key_handle().call_mpc(contract_id)
    }
}

impl CallMpcContract for Arc<Mutex<OperatingAccessKey>> {
    /// Binds one specific access key, so callers driving many keys concurrently pick
    /// which one signs.
    fn call_mpc(&self, contract_id: &AccountId) -> MpcContractHandle<DevnetCaller<Final>> {
        MpcContractHandle::new(
            DevnetCaller::new(self.clone(), Verbosity::Verbose),
            contract_id.clone(),
        )
    }
}

pub struct DevnetCaller<W> {
    key: Arc<Mutex<OperatingAccessKey>>,
    verbosity: Verbosity,
    _wait_level: PhantomData<fn() -> W>,
}

pub enum Verbosity {
    Verbose,
    Quiet,
}

impl DevnetCaller<Final> {
    pub(crate) fn new(key: Arc<Mutex<OperatingAccessKey>>, verbosity: Verbosity) -> Self {
        Self {
            key,
            verbosity,
            _wait_level: PhantomData,
        }
    }
}

impl<W> DevnetCaller<W> {
    pub(crate) fn with_verbosity(self, verbosity: Verbosity) -> Self {
        Self { verbosity, ..self }
    }

    pub(crate) fn with_finality<U: WaitLevel>(self) -> DevnetCaller<U> {
        DevnetCaller {
            key: self.key,
            verbosity: self.verbosity,
            _wait_level: PhantomData,
        }
    }
}

pub trait WithVerbosity {
    fn with_verbosity(self, verbosity: Verbosity) -> Self;
}

impl<W> WithVerbosity for MpcContractHandle<DevnetCaller<W>> {
    fn with_verbosity(self, verbosity: Verbosity) -> Self {
        self.map_caller(|caller| caller.with_verbosity(verbosity))
    }
}

/// Allows to change the status a transaction is awaited to before a call returns.
/// Note that the return type of the contract handle changes with the finality.
pub trait WithFinality {
    fn with_finality<U: WaitLevel>(self) -> MpcContractHandle<DevnetCaller<U>>;
}

impl<W> WithFinality for MpcContractHandle<DevnetCaller<W>> {
    fn with_finality<U: WaitLevel>(self) -> MpcContractHandle<DevnetCaller<U>> {
        self.map_caller(DevnetCaller::with_finality)
    }
}

impl<W: WaitLevel> CallContract for DevnetCaller<W> {
    type Output = W::Response;
    type Error = anyhow::Error;

    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.key
            .lock()
            .await
            .submit_tx_to_call_function::<W>(
                contract_id,
                &call_args.method_name,
                &call_args.args,
                call_args.gas.as_tgas(),
                call_args.deposit.as_yoctonear(),
                matches!(self.verbosity, Verbosity::Verbose),
            )
            .await
    }
}
