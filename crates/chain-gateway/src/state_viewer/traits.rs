use borsh::BorshDeserialize;
use near_account_id::AccountId;
use near_contract_transport::{ViewArgs, ViewContract};
use serde::de::DeserializeOwned;

use crate::state_viewer::view_call::ViewCall;

pub trait ViewExt: ViewContract + Clone + Sized {
    fn view_json<T>(&self, contract_id: AccountId, args: ViewArgs) -> ViewCall<Self, T>
    where
        T: DeserializeOwned,
    {
        ViewCall::json(self.clone(), contract_id, args)
    }

    fn view_borsh<T>(&self, contract_id: AccountId, args: ViewArgs) -> ViewCall<Self, T>
    where
        T: BorshDeserialize,
    {
        ViewCall::borsh(self.clone(), contract_id, args)
    }
}

impl<V: ViewContract + Clone> ViewExt for V {}
