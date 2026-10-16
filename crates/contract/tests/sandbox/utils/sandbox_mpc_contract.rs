use crate::sandbox::utils::sandbox_self_caller::SandboxSelfCaller;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_workspaces::{Account, Contract, Worker, network::Sandbox};

pub type SandboxMpcContract = MpcContractHandle<SandboxSelfCaller>;

/// What the typed interface does not cover: the contract's own account, key included.
pub trait SandboxMpcContractExt {
    fn from_deployed(worker: &Worker<Sandbox>, contract: Contract) -> Self;
    fn as_account(&self) -> &Account;
    fn view_code(&self) -> impl Future<Output = near_workspaces::Result<Vec<u8>>>;
}

impl SandboxMpcContractExt for SandboxMpcContract {
    fn from_deployed(worker: &Worker<Sandbox>, contract: Contract) -> Self {
        let contract_id = contract.id().clone();
        MpcContractHandle::new(SandboxSelfCaller::new(worker, contract), contract_id)
    }

    fn as_account(&self) -> &Account {
        self.caller().as_account()
    }

    async fn view_code(&self) -> near_workspaces::Result<Vec<u8>> {
        self.caller().view_code().await
    }
}
