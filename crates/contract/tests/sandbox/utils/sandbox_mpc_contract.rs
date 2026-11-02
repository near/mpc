use crate::sandbox::utils::sandbox_self_caller::SandboxSelfCaller;
use near_kit_primitives::Contract as _;
use near_mpc_contract_interface::contract::{MpcContract, MpcContractClient};
use near_workspaces::{Account, AccountId, Contract, Worker, network::Sandbox};
use std::ops::Deref;

/// The deployed MPC contract: its typed client, plus what the typed interface does not cover,
/// the contract's own account, key included. The generated client does not hand its backend
/// back, so the caller is kept beside it.
#[derive(Clone)]
pub struct SandboxMpcContract {
    client: MpcContractClient<SandboxSelfCaller>,
    caller: SandboxSelfCaller,
}

impl SandboxMpcContract {
    pub fn from_deployed(worker: &Worker<Sandbox>, contract: Contract) -> Self {
        let contract_id = contract.id().clone();
        let caller = SandboxSelfCaller::new(worker, contract);
        Self {
            client: MpcContract::client(caller.clone(), contract_id),
            caller,
        }
    }

    pub fn id(&self) -> &AccountId {
        self.client.contract_id()
    }

    pub fn as_account(&self) -> &Account {
        self.caller.as_account()
    }

    pub async fn view_code(&self) -> near_workspaces::Result<Vec<u8>> {
        self.caller.view_code().await
    }
}

impl Deref for SandboxMpcContract {
    type Target = MpcContractClient<SandboxSelfCaller>;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}
