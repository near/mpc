use base64::Engine;
use chain_gateway::{
    ChainGateway, NodeHandle,
    event_subscriber::{block_events::BlockUpdate, subscriber::BlockEventSubscriber},
};
use near_indexer::near_primitives::types::Finality;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use super::accounts::{Contract, TestAccount};

pub struct LocalNode {
    pub home_dir: TempDir,
    pub ports: PortsConfig,
    pub chain_gateway: ChainGateway,
    pub node_handle: NodeHandle,
    pub block_update_receiver: Option<tokio::sync::mpsc::Receiver<BlockUpdate>>,
}

#[derive(Clone)]
pub struct PortsConfig {
    pub network_port: u16,
    pub rpc_port: u16,
}

pub(crate) struct LocalNodeBuilder {
    home_dir: TempDir,
    ports: Option<PortsConfig>,
}

impl LocalNodeBuilder {
    pub(crate) async fn start(self, streamer_config: Option<BlockEventSubscriber>) -> LocalNode {
        let indexer_config = near_indexer::IndexerConfig {
            home_dir: self.home_dir.path().to_path_buf(),
            sync_mode: near_indexer::SyncModeEnum::LatestSynced,
            await_for_node_synced: near_indexer::AwaitForNodeSyncedEnum::WaitForFullSync,
            finality: Finality::Final,
            validate_genesis: true,
        };

        let (chain_gateway, node_handle, block_update_receiver) =
            chain_gateway::chain_gateway::ChainGateway::start(indexer_config, streamer_config)
                .await
                .expect("chain_gateway::start should succeed");

        let Self { home_dir, ports } = self;

        LocalNode {
            home_dir,
            ports: ports.unwrap(),
            chain_gateway,
            node_handle,
            block_update_receiver,
        }
    }
    pub(crate) fn new(node_name: &str, home_dir: TempDir) -> Self {
        let account_id = format!("{}.near", node_name);
        near_indexer::indexer_init_configs(
            &home_dir.path().to_path_buf(),
            near_indexer::InitConfigArgs {
                chain_id: Some("localnet".to_string()),
                account_id: Some(account_id.clone()),
                test_seed: Some(account_id.clone()),
                num_shards: 1,
                fast: true,
                genesis: None,
                download_genesis: false,
                download_genesis_url: None,
                download_records_url: None,
                download_config: None,
                download_config_url: None,
                boot_nodes: None,
                max_gas_burnt_view: None,
            },
        )
        .expect("indexer_init_configs should succeed");
        let node = LocalNodeBuilder {
            home_dir,
            ports: None,
        };
        let ports_config = PortsConfig::from_os();
        node.with_ports_config(ports_config.clone())
    }

    fn with_ports_config(mut self, ports: PortsConfig) -> Self {
        let PortsConfig {
            network_port,
            rpc_port,
        } = ports;
        let mut config = self.config();
        config["network"]["addr"] = serde_json::json!(format!("127.0.0.1:{network_port}"));
        config["rpc"]["addr"] = serde_json::json!(format!("127.0.0.1:{rpc_port}"));
        self.write_config(&config);
        self.ports = Some(ports);
        self
    }

    /// Copy genesis.json from another node's home directory.
    ///
    /// This ensures both nodes share the same genesis hash and are on the
    /// same chain, which is required for P2P sync to work.
    /// For localnet chains, `indexer_init_configs` ignores the `genesis` param
    /// and always generates a fresh genesis, so we must overwrite the file after init.
    pub(crate) fn with_genesis_from(self, source: &LocalNode) -> Self {
        std::fs::copy(
            source.home_dir.path().join("genesis.json"),
            self.home_dir.path().join("genesis.json"),
        )
        .expect("copy genesis.json from source node");
        self
    }

    /// Set boot_nodes in config.json.
    pub(crate) fn with_boot_nodes(self, boot_node: &str) -> Self {
        let mut config = self.config();
        config["network"]["boot_nodes"] = serde_json::json!(boot_node);
        self.write_config(&config);
        self
    }
    /// Remove `validator_key.json` to make a node non-validator.
    pub(crate) fn without_validator_key(self) -> Self {
        let validator_key_path = self.home_dir.path().join("validator_key.json");
        std::fs::remove_file(&validator_key_path).expect("remove validator_key.json");
        self
    }

    /// Set `consensus.min_num_peers` in config.json.
    ///
    /// For multi-node setups, setting this to 1 on the validator ensures it waits
    /// for at least one peer connection (with full handshake + AccountAnnounce)
    /// before producing blocks, guaranteeing P2P routing tables are populated.
    pub(crate) fn with_consensus_min_peers(self, min_peers: u64) -> Self {
        let mut config = self.config();
        config["consensus"]["min_num_peers"] = serde_json::json!(min_peers);
        self.write_config(&config);
        self
    }

    /// Inject a contract account into genesis.json before the node starts.
    ///
    /// Adds three state records: Account (with code_hash), Contract (base64 WASM),
    /// and AccessKey (FullAccess). This embeds the contract directly in genesis so
    /// we don't need to deploy via transaction.
    pub(crate) fn with_contract(self, contract: Contract, wasm: &[u8]) -> Self {
        inject_genesis_account(
            &self.home_dir.path().join("genesis.json"),
            &contract.account_id,
            &contract.public_key_str(),
            Some(wasm),
        );
        self
    }

    /// Inject a plain account (no contract code) into genesis.json before the node starts.
    ///
    /// Adds Account and AccessKey records. Use this for user accounts that only need
    /// to sign transactions, not deploy code.
    pub(crate) fn with_account(self, account: TestAccount) -> Self {
        inject_genesis_account(
            &self.home_dir.path().join("genesis.json"),
            &account.account_id,
            &account.public_key_str(),
            None,
        );
        self
    }

    fn config(&self) -> serde_json::Value {
        let config_text = std::fs::read_to_string(self.config_path()).expect("read config.json");
        let config: serde_json::Value =
            serde_json::from_str(&config_text).expect("parse config.json");
        config
    }

    fn write_config(&self, config: &serde_json::Value) {
        let updated = serde_json::to_string_pretty(&config).expect("serialize config.json");
        std::fs::write(self.config_path(), updated).expect("write config.json");
    }

    fn config_path(&self) -> PathBuf {
        self.home_dir.path().join("config.json")
    }
}

impl LocalNode {
    /// Read the node's public key from `node_key.json`.
    pub(crate) fn read_node_public_key(&self) -> String {
        let node_key_path = self.home_dir.path().join("node_key.json");
        let node_key_text = std::fs::read_to_string(&node_key_path).expect("read node_key.json");
        let node_key: serde_json::Value =
            serde_json::from_str(&node_key_text).expect("parse node_key.json");
        node_key["public_key"]
            .as_str()
            .expect("node_key.json should have public_key")
            .to_string()
    }
}

impl PortsConfig {
    fn from_os() -> Self {
        let network_port = test_port_allocator::reserve_port();
        let rpc_port = test_port_allocator::reserve_port();
        Self {
            network_port,
            rpc_port,
        }
    }
}

/// Shared helper for injecting an account into genesis.json.
///
/// When `wasm` is `Some`, the account is treated as a contract: the code hash is
/// computed from the WASM bytes and a `Contract` record is added.
/// When `wasm` is `None`, the account is a plain user account with default code hash.
fn inject_genesis_account(
    genesis_path: &Path,
    account_id: &near_account_id::AccountId,
    public_key_str: &str,
    wasm: Option<&[u8]>,
) {
    let genesis_text = std::fs::read_to_string(genesis_path).expect("read genesis.json");
    let mut genesis: serde_json::Value =
        serde_json::from_str(&genesis_text).expect("parse genesis.json");

    let existing_total_supply: u128 = genesis
        .get("total_supply")
        .unwrap()
        .as_str()
        .expect("total supply should be a string")
        .parse()
        .expect("total supply should parse as u128");
    let amount: u128 = 10000000000000000000000000;
    let total_supply = existing_total_supply + amount;
    *genesis.get_mut("total_supply").unwrap() = serde_json::json!(total_supply.to_string());

    let code_hash = match wasm {
        Some(bytes) => near_indexer::near_primitives::hash::hash(bytes).to_string(),
        None => "11111111111111111111111111111111".to_string(),
    };

    let records = genesis
        .get_mut("records")
        .expect("genesis should have records")
        .as_array_mut()
        .expect("records should be an array");

    // Account record
    records.push(serde_json::json!({
        "Account": {
            "account_id": account_id,
            "account": {
                "amount": amount.to_string(),
                "locked": "0",
                "code_hash": code_hash,
                "storage_usage": 0,
                "version": "V1"
            }
        }
    }));

    // Contract record (only for contract accounts)
    if let Some(bytes) = wasm {
        let code_base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        records.push(serde_json::json!({
            "Contract": {
                "account_id": account_id,
                "code": code_base64
            }
        }));
    }

    // AccessKey record
    records.push(serde_json::json!({
        "AccessKey": {
            "account_id": account_id,
            "public_key": public_key_str,
            "access_key": {
                "nonce": 0,
                "permission": "FullAccess"
            }
        }
    }));

    let updated = serde_json::to_string_pretty(&genesis).expect("serialize genesis.json");
    std::fs::write(genesis_path, updated).expect("write genesis.json");
}
