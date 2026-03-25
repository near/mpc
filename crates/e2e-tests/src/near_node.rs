use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::port_allocator::E2ePortAllocator;

/// Wraps a NEAR node process with controlled ports.
///
/// The NEAR node is the single validator that all mpc-node indexers
/// connect to via P2P boot_nodes.
pub struct NearNode {
    sandbox: near_sandbox::Sandbox,
    rpc_port: u16,
    network_port: u16,
}

impl NearNode {
    /// Start a NEAR validator with ports from the allocator.
    pub async fn start(ports: &E2ePortAllocator) -> anyhow::Result<Self> {
        let rpc_port = ports.near_node_rpc_port();
        let network_port = ports.near_node_network_port();

        tracing::info!(rpc_port, network_port, "starting near-sandbox");

        let config = near_sandbox::SandboxConfig {
            rpc_port: Some(rpc_port),
            net_port: Some(network_port),
            ..Default::default()
        };

        let sandbox = near_sandbox::Sandbox::start_sandbox_with_config(config)
            .await
            .context("failed to start near-sandbox")?;

        tracing::info!(rpc_addr = %sandbox.rpc_addr, "near-sandbox started");

        Ok(Self {
            sandbox,
            rpc_port,
            network_port,
        })
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    pub fn network_port(&self) -> u16 {
        self.network_port
    }

    /// Path to the NEAR node home directory (contains genesis.json, node_key.json, etc.).
    pub fn home_dir(&self) -> &Path {
        self.sandbox.home_dir.path()
    }

    /// Path to genesis.json inside the NEAR node home.
    pub fn genesis_path(&self) -> PathBuf {
        self.home_dir().join("genesis.json")
    }

    /// Constructs the boot_nodes string for mpc-node NearInitConfig.
    ///
    /// Format: `"ed25519:<base58_pubkey>@127.0.0.1:<network_port>"`
    pub fn boot_nodes(&self) -> anyhow::Result<String> {
        let node_key_path = self.home_dir().join("node_key.json");
        let content = std::fs::read_to_string(&node_key_path)
            .with_context(|| format!("failed to read {}", node_key_path.display()))?;
        let parsed: serde_json::Value =
            serde_json::from_str(&content).context("failed to parse node_key.json")?;
        let public_key = parsed["public_key"]
            .as_str()
            .context("missing public_key in node_key.json")?;
        Ok(format!("{public_key}@127.0.0.1:{}", self.network_port))
    }
}
