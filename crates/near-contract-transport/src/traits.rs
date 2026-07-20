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
/// RPC, test double) and surface the transport's native error as
/// [`Error`](ViewContract::Error).
pub trait ViewContract {
    type Error;
    /// Height witness: [`BlockHeight`] where the backend reports the
    /// observation height, `()` where it cannot.
    ///
    /// [`BlockHeight`]: crate::BlockHeight
    type ObservedAt;

    fn view_contract(
        &self,
        contract_id: &AccountId,
        view_args: ViewArgs,
    ) -> impl Future<Output = Result<ObservedState<Vec<u8>, Self::ObservedAt>, Self::Error>> + Send;
}
