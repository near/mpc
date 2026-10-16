use crate::sandbox::utils::views::SandboxViewer;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_workspaces::{Account, AccountId, Contract, Worker, network::Sandbox};
use std::ops::Deref;

/// The MPC contract deployed in a sandbox. Derefs to its typed view handle;
/// [`as_account`](Self::as_account) is the contract's own [`Account`], key included, for
/// whatever the typed interface does not cover.
pub struct SandboxMpcContract {
    handle: MpcContractHandle<SandboxViewer>,
    account: Contract,
}

impl SandboxMpcContract {
    pub fn new(worker: &Worker<Sandbox>, account: Contract) -> Self {
        Self {
            handle: MpcContractHandle::new(SandboxViewer::new(worker), account.id().clone()),
            account,
        }
    }

    pub fn id(&self) -> &AccountId {
        self.account.id()
    }

    pub fn as_account(&self) -> &Account {
        self.account.as_account()
    }

    pub async fn view_code(&self) -> near_workspaces::Result<Vec<u8>> {
        self.account.view_code().await
    }
}

impl Deref for SandboxMpcContract {
    type Target = MpcContractHandle<SandboxViewer>;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}
