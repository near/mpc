use std::path::PathBuf;

use anyhow::Context;
use near_sandbox::{Sandbox, SandboxConfig};

use crate::port_allocator::E2ePortAllocator;

const GENESIS_FILE: &str = "genesis.json";
const NODE_KEY_FILE: &str = "node_key.json";

/// Wraps a NEAR sandbox node for E2E tests.
///
/// Starts a local `near-sandbox` binary process, exposes RPC and network
/// ports, and provides access to genesis.json and node_key.json so MPC node
/// indexers can sync blocks via P2P.
///
/// The inner [`Sandbox`] kills the process and removes its temp directory on drop.
pub struct NearSandbox {
    sandbox: Sandbox,
    network_port: u16,
}

impl NearSandbox {
    pub async fn start(ports: &E2ePortAllocator, version: &str) -> anyhow::Result<Self> {
        let rpc_port = ports.near_node_rpc_port();
        let network_port = ports.near_node_network_port();

        tracing::info!(rpc_port, network_port, version, "starting NEAR sandbox");

        // Set chain_id to "sandbox" so MPC nodes recognize this as a local
        // network (is_localnet() returns true). Without this, `near-sandbox
        // init` generates a random chain_id like "test-chain-XXXXX".
        let config = SandboxConfig {
            rpc_port: Some(rpc_port),
            net_port: Some(network_port),
            additional_genesis: Some(serde_json::json!({"chain_id": "sandbox"})),
            ..Default::default()
        };

        let sandbox = Sandbox::start_sandbox_with_config_and_version(config, version)
            .await
            .map_err(|e| anyhow::anyhow!("failed to start sandbox: {e}"))?;

        tracing::info!(
            rpc_url = %sandbox.rpc_addr,
            genesis = %sandbox.home_dir.path().join(GENESIS_FILE).display(),
            "NEAR sandbox ready"
        );

        Ok(Self {
            sandbox,
            network_port,
        })
    }

    pub fn rpc_url(&self) -> String {
        self.sandbox.rpc_addr.clone()
    }

    pub fn genesis_path(&self) -> PathBuf {
        self.sandbox.home_dir.path().join(GENESIS_FILE)
    }

    pub fn boot_nodes(&self) -> anyhow::Result<String> {
        let node_key_path = self.sandbox.home_dir.path().join(NODE_KEY_FILE);
        let content = std::fs::read_to_string(&node_key_path)
            .with_context(|| format!("failed to read {}", node_key_path.display()))?;
        let parsed: serde_json::Value =
            serde_json::from_str(&content).context("failed to parse node_key.json")?;
        let public_key = parsed["public_key"]
            .as_str()
            .context("missing public_key in node_key.json")?;
        Ok(format!("{public_key}@127.0.0.1:{}", self.network_port))
    }

    pub fn chain_id(&self) -> anyhow::Result<String> {
        let genesis = self.genesis_path();
        let content = std::fs::read_to_string(&genesis)
            .with_context(|| format!("failed to read {}", genesis.display()))?;
        let parsed: serde_json::Value =
            serde_json::from_str(&content).context("failed to parse genesis.json")?;
        parsed["chain_id"]
            .as_str()
            .map(|s| s.to_string())
            .context("missing chain_id in genesis.json")
    }
}
