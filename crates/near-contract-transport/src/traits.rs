use std::future::Future;

use near_account_id::AccountId;

use crate::ViewArgs;
use crate::types::ObservedState;

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
