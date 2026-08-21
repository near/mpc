use std::marker::PhantomData;

use near_contract_transport::{CallContract, FunctionCallArgs};
use near_kit::WaitLevel;
use near_mpc_contract_interface::client::MpcContractHandle;

/// A [`near_kit::Near`] client bound to a specific account
pub struct NearKitCaller<T> {
    pub(crate) inner: near_kit::Near,
    pub(crate) _wait_level: PhantomData<fn() -> T>,
}

pub trait CallMpc: Sized {
    fn call_mpc(self, contract_id: &near_account_id::AccountId) -> MpcContractHandle<Self>;
}

impl<T> CallMpc for NearKitCaller<T> {
    fn call_mpc(self, contract_id: &near_account_id::AccountId) -> MpcContractHandle<Self> {
        MpcContractHandle::new(self, contract_id.clone())
    }
}

impl<T> CallContract for NearKitCaller<T>
where
    T: WaitLevel,
{
    type Output = T::Response;
    type Error = near_kit::Error;

    async fn call_contract(
        &self,
        contract_id: &near_kit::AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<Self::Output, Self::Error> {
        self.inner
            .call(contract_id, &call_args.method_name)
            .args_raw(call_args.args)
            .gas(call_args.gas)
            .deposit(call_args.deposit)
            .wait_until::<T>()
            .await
    }
}

impl<T> NearKitCaller<T> {
    pub(crate) fn with_wait_level<U: WaitLevel>(self) -> NearKitCaller<U> {
        NearKitCaller {
            inner: self.inner,
            _wait_level: PhantomData,
        }
    }
}

/// Allows to change the finality level the transaction is required to achieve before
/// a call returns.
/// Note that return type of the contract handle may change depending on the wait level.
pub trait WithWaitLevel {
    fn with_wait_level<U: WaitLevel>(self) -> MpcContractHandle<NearKitCaller<U>>;
}

impl<T> WithWaitLevel for MpcContractHandle<NearKitCaller<T>> {
    fn with_wait_level<U: WaitLevel>(self) -> MpcContractHandle<NearKitCaller<U>> {
        self.map_caller(NearKitCaller::with_wait_level)
    }
}
