use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};

use crate::port_allocator::E2ePortAllocator;

const CONTAINER_RPC_PORT: u16 = 3030;
const CONTAINER_NET_PORT: u16 = 3031;

/// Wraps a NEAR sandbox node for E2E tests.
///
/// Starts a Docker container running `nearprotocol/sandbox`, exposes RPC and
/// network ports, and extracts genesis.json and node_key.json so MPC node
/// indexers can sync blocks via P2P.
///
/// The container is stopped and cleaned up when this value is dropped.
pub struct NearSandbox {
    container_id: String,
    rpc_port: u16,
    network_port: u16,
    sandbox_dir: PathBuf,
}

impl NearSandbox {
    pub async fn start(
        ports: &E2ePortAllocator,
        image: &str,
        test_dir: &Path,
    ) -> anyhow::Result<Self> {
        let rpc_port = ports.near_node_rpc_port();
        let network_port = ports.near_node_network_port();

        tracing::info!(
            rpc_port,
            network_port,
            image,
            "starting NEAR sandbox Docker container"
        );

        let container_id = docker_run(rpc_port, network_port, image)?;
        tracing::info!(container_id = %container_id, "sandbox container started");

        if let Err(e) = wait_for_rpc(rpc_port).await {
            let _ = docker_rm(&container_id);
            return Err(e.context("sandbox node failed to become ready"));
        }

        let sandbox_dir = test_dir.join("sandbox");
        std::fs::create_dir_all(&sandbox_dir)
            .with_context(|| format!("failed to create {}", sandbox_dir.display()))?;

        docker_cp(&container_id, "/data/genesis.json", &sandbox_dir)?;
        docker_cp(&container_id, "/data/node_key.json", &sandbox_dir)?;

        tracing::info!(
            rpc_url = %format!("http://127.0.0.1:{rpc_port}"),
            genesis = %sandbox_dir.join("genesis.json").display(),
            "NEAR sandbox ready"
        );

        Ok(Self {
            container_id,
            rpc_port,
            network_port,
            sandbox_dir,
        })
    }

    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    pub fn genesis_path(&self) -> PathBuf {
        self.sandbox_dir.join("genesis.json")
    }

    pub fn boot_nodes(&self) -> anyhow::Result<String> {
        let node_key_path = self.sandbox_dir.join("node_key.json");
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

impl Drop for NearSandbox {
    fn drop(&mut self) {
        tracing::info!(container_id = %self.container_id, "stopping NEAR sandbox container");
        if let Err(e) = docker_rm(&self.container_id) {
            tracing::error!(error = %e, "failed to remove sandbox container");
        }
    }
}

fn docker_run(rpc_port: u16, network_port: u16, image: &str) -> anyhow::Result<String> {
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "-p",
            &format!("{rpc_port}:{CONTAINER_RPC_PORT}"),
            "-p",
            &format!("{network_port}:{CONTAINER_NET_PORT}"),
            image,
        ])
        .output()
        .context("failed to execute `docker run`")?;
    if !output.status.success() {
        bail!(
            "docker run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn docker_cp(container_id: &str, container_path: &str, host_dir: &Path) -> anyhow::Result<()> {
    let output = Command::new("docker")
        .args([
            "cp",
            &format!("{container_id}:{container_path}"),
            &host_dir.display().to_string(),
        ])
        .output()
        .with_context(|| format!("failed to execute `docker cp {container_path}`"))?;
    if !output.status.success() {
        bail!(
            "docker cp {container_path} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn docker_rm(container_id: &str) -> anyhow::Result<()> {
    let output = Command::new("docker")
        .args(["rm", "-f", container_id])
        .output()
        .context("failed to execute `docker rm`")?;
    if !output.status.success() {
        bail!(
            "docker rm failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

async fn wait_for_rpc(rpc_port: u16) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{rpc_port}/status");
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => {
                if tokio::time::Instant::now() >= deadline {
                    bail!("sandbox RPC on port {rpc_port} did not become ready within 30s");
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}
