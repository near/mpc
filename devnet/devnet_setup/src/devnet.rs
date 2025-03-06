use crate::account::OperatingAccounts;
use crate::rpc::NearRpcClients;
use crate::types::{DevnetSetupRepository, LoadtestSetup, MpcNetworkSetup};
use near_jsonrpc_client::methods;
use std::collections::HashMap;
use std::sync::Arc;

pub struct OperatingDevnetSetup {
    pub accounts: OperatingAccounts,
    pub mpc_setups: HashMap<String, MpcNetworkSetup>,
    pub loadtest_setups: HashMap<String, LoadtestSetup>,
}

impl OperatingDevnetSetup {
    const SETUP_FILENAME: &str = "devnet_setup.json";

    pub async fn load(client: Arc<NearRpcClients>) -> Self {
        if !std::fs::exists(Self::SETUP_FILENAME).unwrap() {
            std::fs::write(
                Self::SETUP_FILENAME,
                serde_json::to_string(&DevnetSetupRepository::default()).unwrap(),
            )
            .unwrap();
        }
        let setup_data = std::fs::read_to_string(Self::SETUP_FILENAME).unwrap();
        let setup: DevnetSetupRepository = serde_json::from_str(&setup_data).unwrap();

        let recent_block_hash = client
            .lease()
            .await
            .call(methods::block::RpcBlockRequest {
                block_reference: near_primitives::types::BlockReference::Finality(
                    near_primitives::types::Finality::Final,
                ),
            })
            .await
            .unwrap()
            .header
            .hash;

        let accounts = OperatingAccounts::new(setup.accounts, recent_block_hash, client);
        Self {
            accounts,
            mpc_setups: setup.mpc_setups,
            loadtest_setups: setup.loadtest_setups,
        }
    }
}

impl Drop for OperatingDevnetSetup {
    fn drop(&mut self) {
        let setup = DevnetSetupRepository {
            accounts: self.accounts.to_data(),
            mpc_setups: self.mpc_setups.clone(),
            loadtest_setups: self.loadtest_setups.clone(),
        };
        let setup_data = serde_json::to_string(&setup).unwrap();
        if std::fs::exists(OperatingDevnetSetup::SETUP_FILENAME).unwrap() {
            std::fs::rename(
                OperatingDevnetSetup::SETUP_FILENAME,
                format!("{}.bak", OperatingDevnetSetup::SETUP_FILENAME),
            )
            .unwrap();
        }
        std::fs::write(OperatingDevnetSetup::SETUP_FILENAME, setup_data).unwrap();
    }
}
