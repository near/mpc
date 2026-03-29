use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, DownloadFromContainerOptions, RemoveContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::HostConfig;
use futures::{StreamExt, TryStreamExt};

use crate::port_allocator::E2ePortAllocator;

/// Wraps a NEAR sandbox node for E2E tests.
///
/// Starts a Docker container running `nearprotocol/sandbox`, exposes RPC and
/// network ports, and extracts genesis.json and node_key.json so MPC node
/// indexers can sync blocks via P2P.
///
/// The container is stopped and cleaned up when this value is dropped.
pub struct NearSandbox {
    docker: Docker,
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

        let docker =
            Docker::connect_with_local_defaults().context("failed to connect to Docker")?;

        // Ensure the image is available locally (CI runners may not have it cached).
        pull_image(&docker, image).await?;

        // Use host networking so nearcore P2P works without Docker bridge
        // NAT issues. Requires "Enable host networking" in Docker Desktop
        // on macOS/Windows.
        let host_config = HostConfig {
            network_mode: Some("host".to_string()),
            auto_remove: Some(true),
            ..Default::default()
        };

        let container = docker
            .create_container(
                Some(CreateContainerOptions::<String> {
                    ..Default::default()
                }),
                Config::<String> {
                    image: Some(image.to_string()),
                    host_config: Some(host_config),
                    entrypoint: Some(vec!["sh".to_string(), "-c".to_string()]),
                    cmd: Some(vec![format!(
                        concat!(
                            "export RUST_LOG=\"neard::cli=off,near=error,stats=error,network=error\" && ",
                            "near-sandbox --home /data init --fast ",
                            "--account-id sandbox --test-seed sandbox --chain-id sandbox 2>/dev/null; ",
                            "exec near-sandbox --home /data run ",
                            "--rpc-addr 0.0.0.0:{rpc_port} --network-addr 0.0.0.0:{network_port}"
                        ),
                        rpc_port = rpc_port,
                        network_port = network_port,
                    )]),
                    ..Default::default()
                },
            )
            .await
            .context("failed to create sandbox container")?;

        let container_id = container.id;
        docker
            .start_container::<&str>(&container_id, None)
            .await
            .context("failed to start sandbox container")?;

        tracing::info!(container_id = %container_id, "sandbox container started");

        if let Err(e) = wait_for_rpc(rpc_port).await {
            let _ = docker
                .remove_container(
                    &container_id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
            return Err(e.context("sandbox node failed to become ready"));
        }

        let sandbox_dir = test_dir.join("sandbox");
        std::fs::create_dir_all(&sandbox_dir)
            .with_context(|| format!("failed to create {}", sandbox_dir.display()))?;

        copy_from_container(&docker, &container_id, "/data/genesis.json", &sandbox_dir).await?;
        copy_from_container(&docker, &container_id, "/data/node_key.json", &sandbox_dir).await?;

        tracing::info!(
            rpc_url = %format!("http://127.0.0.1:{rpc_port}"),
            genesis = %sandbox_dir.join("genesis.json").display(),
            "NEAR sandbox ready"
        );

        Ok(Self {
            docker,
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
        // Best-effort synchronous removal via a blocking runtime.
        let docker = self.docker.clone();
        let id = self.container_id.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let _ = docker
                    .remove_container(
                        &id,
                        Some(RemoveContainerOptions {
                            force: true,
                            ..Default::default()
                        }),
                    )
                    .await;
            });
        })
        .join()
        .ok();
    }
}

/// Copy a single file from a container to a host directory.
async fn copy_from_container(
    docker: &Docker,
    container_id: &str,
    container_path: &str,
    host_dir: &Path,
) -> anyhow::Result<()> {
    let chunks: Vec<_> = docker
        .download_from_container(
            container_id,
            Some(DownloadFromContainerOptions {
                path: container_path,
            }),
        )
        .try_collect()
        .await
        .with_context(|| format!("failed to download {container_path}"))?;
    let tar_bytes: Vec<u8> = chunks.into_iter().flatten().collect();

    let mut archive = tar::Archive::new(&tar_bytes[..]);
    archive.unpack(host_dir).with_context(|| {
        format!(
            "failed to unpack {container_path} into {}",
            host_dir.display()
        )
    })?;
    Ok(())
}

async fn pull_image(docker: &Docker, image: &str) -> anyhow::Result<()> {
    let mut parts = image.splitn(2, ':');
    let from_image = parts.next().unwrap_or(image);
    let tag = parts.next().unwrap_or("latest");

    tracing::info!(image, "pulling Docker image");
    let mut stream = docker.create_image(
        Some(CreateImageOptions {
            from_image,
            tag,
            ..Default::default()
        }),
        None,
        None,
    );

    while let Some(msg) = stream.next().await {
        msg.with_context(|| format!("failed to pull image {image}"))?;
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
