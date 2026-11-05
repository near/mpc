use near_contract_transport::NearKitCaller;
use near_mpc_contract_interface::client::MpcContractHandle;

pub trait CallMpc: Sized {
    fn call_mpc(self, contract_id: &near_account_id::AccountId) -> MpcContractHandle<Self>;
}

impl<T> CallMpc for NearKitCaller<T> {
    fn call_mpc(self, contract_id: &near_account_id::AccountId) -> MpcContractHandle<Self> {
        MpcContractHandle::new(self, contract_id.clone())
    }
}
