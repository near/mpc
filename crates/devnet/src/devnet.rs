use crate::account::OperatingAccounts;
use crate::rpc::NearRpcClients;
use crate::types::{DevnetSetupRepository, LoadtestSetup, MpcNetworkSetup};
use futures::FutureExt;
use near_jsonrpc_client::methods;
use near_primitives::types::{BlockReference, Finality};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Live state of the setup for the entire devnet.
/// Upon dropping, saves the state to devnet_setup.yaml
pub struct OperatingDevnetSetup {
    pub accounts: OperatingAccounts,
    pub mpc_setups: HashMap<String, MpcNetworkSetup>,
    pub loadtest_setups: HashMap<String, LoadtestSetup>,
}

impl OperatingDevnetSetup {
    const SETUP_FILENAME: &str = "devnet_setup.yaml";

    /// Load the setup from disk.
    pub async fn load(client: Arc<NearRpcClients>) -> Self {
        if !std::fs::exists(Self::SETUP_FILENAME).unwrap() {
            std::fs::write(
                Self::SETUP_FILENAME,
                serde_yaml::to_string(&DevnetSetupRepository::default()).unwrap(),
            )
            .unwrap();
        }
        let setup_data = std::fs::read_to_string(Self::SETUP_FILENAME).unwrap();
        let setup: DevnetSetupRepository = serde_yaml::from_str(&setup_data).unwrap();
        // Retry the initial block fetch: a transient RPC failure (e.g. a 429
        // from a rate-limited provider) shouldn't kill an otherwise long-
        // running CLI invocation.
        let recent_block_hash = tokio::time::timeout(
            Duration::from_secs(30),
            client.with_retry(5, |rpc| {
                async move {
                    rpc.call(methods::block::RpcBlockRequest {
                        block_reference: BlockReference::Finality(Finality::Final),
                    })
                    .await
                    .map_err(anyhow::Error::from)
                }
                .boxed()
            }),
        )
        .await
        .expect("Timed out while waiting for block finality; expected RPC node to be reachable and responsive within 30 seconds.")
        .expect("Failed to fetch a recent block hash from the RPC after retries.")
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
        let setup_data = serde_yaml::to_string(&setup).unwrap();
        if std::fs::exists(OperatingDevnetSetup::SETUP_FILENAME).unwrap() {
            // Make a backup, just in case the CLI crashed and saved some invalid middle state.
            std::fs::rename(
                OperatingDevnetSetup::SETUP_FILENAME,
                format!("{}.bak", OperatingDevnetSetup::SETUP_FILENAME),
            )
            .unwrap();
        }
        std::fs::write(OperatingDevnetSetup::SETUP_FILENAME, setup_data).unwrap();
    }
}
