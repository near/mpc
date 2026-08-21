use std::future::Future;

use near_account_id::AccountId;

use crate::FunctionCallArgs;
use crate::ViewArgs;
use crate::types::ObservedState;

pub trait CallContract {
    /// Backend-specific successful call outcome.
    type Output;
    type Error;

    fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;
}

impl<T: CallContract> CallContract for &T {
    type Output = T::Output;
    type Error = T::Error;

    fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send {
        T::call_contract(self, contract_id, call_args)
    }
}

/// A backend executing NEAR view calls against a contract.
///
/// Implementors wire [`ViewArgs`] to their transport (nearcore view client,
/// RPC, test double), convert the transport's observation height into
/// [`BlockHeight`](crate::BlockHeight), and surface its native error as
/// [`Error`](ViewContract::Error).
pub trait ViewContract {
    type Error;

    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState<Vec<u8>>, Self::Error>> + Send;
}

impl<T: ViewContract> ViewContract for &T {
    type Error = T::Error;

    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState<Vec<u8>>, Self::Error>> + Send {
        T::view_contract(self, contract_id, view_args)
    }
}
