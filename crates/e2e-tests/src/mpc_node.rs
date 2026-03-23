use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;
use ed25519_dalek::SigningKey;
use near_workspaces::{Account, AccountId};
use serde::Serialize;
use serde_json::json;

use crate::near_node::NearNode;
use crate::port_allocator::E2ePortAllocator;

const DUMMY_IMAGE_HASH: &str =
    "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Ports allocated for a single MPC node.
pub struct NodePorts {
    pub p2p: u16,
    pub web_ui: u16,
    pub migration_web_ui: u16,
    pub pprof: u16,
    pub near_rpc: u16,
    pub near_network: u16,
}

impl NodePorts {
    pub fn from_allocator(ports: &E2ePortAllocator, index: usize) -> Self {
        Self {
            p2p: ports.p2p_port(index),
            web_ui: ports.web_ui_port(index),
            migration_web_ui: ports.migration_web_ui_port(index),
            pprof: ports.pprof_port(index),
            near_rpc: ports.near_rpc_port(index),
            near_network: ports.near_network_port(index),
        }
    }
}

/// Arguments for constructing an [`MpcNode`].
pub struct MpcNodeConfig {
    pub node_index: usize,
    pub home_dir: PathBuf,
    pub signer_account_id: AccountId,
    pub p2p_signing_key: SigningKey,
    pub near_signer_key: SigningKey,
    pub ports: NodePorts,
    pub mpc_contract_id: AccountId,
    pub account: Account,
    pub triples_to_buffer: usize,
    pub presignatures_to_buffer: usize,
    pub rust_log: Option<String>,
}

/// Manages a single `mpc-node` OS process.
///
/// Generates the `start_config.toml` and spawns the binary. Each node runs its
/// own internal neard indexer that peers with the NEAR validator via P2P.
pub struct MpcNode {
    pub node_index: usize,
    pub home_dir: PathBuf,
    pub signer_account_id: AccountId,
    pub p2p_signing_key: SigningKey,
    /// Key used by the node to sign NEAR transactions (must have access key on account).
    pub near_signer_key: SigningKey,
    pub ports: NodePorts,

    // Blockchain connection info (for TOML config)
    pub mpc_contract_id: AccountId,
    near_node_genesis_path: PathBuf,
    near_node_boot_nodes: String,

    // Config values
    secret_store_key_hex: String,
    backup_encryption_key_hex: String,
    triples_to_buffer: usize,
    presignatures_to_buffer: usize,
    rust_log: String,

    // near-workspaces account (for voting on contract)
    pub account: Account,

    // Runtime
    process: Option<Child>,
}

impl MpcNode {
    /// Create a new MPC node config (not yet running).
    pub fn new(config: MpcNodeConfig, near_node: &NearNode) -> anyhow::Result<Self> {
        let near_node_genesis_path = near_node.genesis_path();
        let near_node_boot_nodes = near_node.boot_nodes()?;

        // Deterministic secret keys for each node
        let secret_byte = b'A'
            .checked_add(u8::try_from(config.node_index).context("node_index too large")?)
            .context("secret_byte overflow")?;
        let secret_store_key_hex = hex::encode([secret_byte; 16]);
        let backup_encryption_key_hex = hex::encode([secret_byte; 32]);

        std::fs::create_dir_all(&config.home_dir).with_context(|| {
            format!(
                "failed to create node home dir: {}",
                config.home_dir.display()
            )
        })?;

        Ok(Self {
            node_index: config.node_index,
            home_dir: config.home_dir,
            signer_account_id: config.signer_account_id,
            p2p_signing_key: config.p2p_signing_key,
            near_signer_key: config.near_signer_key,
            ports: config.ports,
            mpc_contract_id: config.mpc_contract_id,
            near_node_genesis_path,
            near_node_boot_nodes,
            secret_store_key_hex,
            backup_encryption_key_hex,
            triples_to_buffer: config.triples_to_buffer,
            presignatures_to_buffer: config.presignatures_to_buffer,
            rust_log: config.rust_log.unwrap_or_else(|| "DEBUG".to_string()),
            account: config.account,
            process: None,
        })
    }

    /// The ed25519 public key formatted as `"ed25519:<base58>"`.
    pub fn p2p_public_key_str(&self) -> String {
        let verifying_key = self.p2p_signing_key.verifying_key();
        format!(
            "ed25519:{}",
            bs58::encode(verifying_key.as_bytes()).into_string()
        )
    }

    /// The P2P URL for this node.
    pub fn p2p_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.p2p)
    }

    /// Write the `start_config.toml` and spawn the mpc-node process.
    pub fn start(&mut self, binary_path: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.process.is_none(),
            "node {} already running",
            self.node_index
        );

        self.write_secrets_json()?;
        let config_path = self.write_start_config()?;

        tracing::info!(
            node = self.node_index,
            account = %self.signer_account_id,
            p2p_port = self.ports.p2p,
            "starting mpc-node"
        );

        let stdout_file = std::fs::File::create(self.home_dir.join("stdout.log"))
            .context("failed to create stdout log")?;
        let stderr_file = std::fs::File::create(self.home_dir.join("stderr.log"))
            .context("failed to create stderr log")?;

        let child = Command::new(binary_path)
            .arg("start-with-config-file")
            .arg(&config_path)
            .env("RUST_LOG", &self.rust_log)
            .env("RUST_BACKTRACE", "1")
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn mpc-node {} (binary: {})",
                    self.node_index,
                    binary_path.display()
                )
            })?;

        self.process = Some(child);
        Ok(())
    }

    /// Stop the node.
    pub fn kill(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn is_running(&mut self) -> bool {
        match &mut self.process {
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => {
                    self.process.take();
                    false
                }
                _ => true,
            },
            None => false,
        }
    }

    /// Write `secrets.json` so the node uses our pre-generated keys instead of
    /// generating random ones. The p2p key must match what was registered on
    /// the contract, and the near signer key must have an access key on the account.
    fn write_secrets_json(&self) -> anyhow::Result<()> {
        let secrets_path = self.home_dir.join("secrets.json");

        let format_key = |key: &SigningKey| -> String {
            let keypair_bytes = key.to_keypair_bytes();
            format!("ed25519:{}", bs58::encode(keypair_bytes).into_string())
        };

        let secrets = json!({
            "p2p_private_key": format_key(&self.p2p_signing_key),
            "near_signer_key": format_key(&self.near_signer_key),
            "near_responder_keys": [format_key(&self.near_signer_key)],
        });

        std::fs::write(&secrets_path, serde_json::to_vec_pretty(&secrets)?)
            .with_context(|| format!("failed to write {}", secrets_path.display()))?;

        tracing::debug!(path = %secrets_path.display(), "wrote secrets.json");
        Ok(())
    }

    /// Build the TOML config and write it for `mpc-node start-with-config-file`.
    fn write_start_config(&self) -> anyhow::Result<PathBuf> {
        let config_path = self.home_dir.join("start_config.toml");
        let signer = self.signer_account_id.to_string();

        let config = StartConfig {
            home_dir: self.home_dir.display().to_string(),
            secrets: Secrets {
                secret_store_key_hex: self.secret_store_key_hex.clone(),
                backup_encryption_key_hex: self.backup_encryption_key_hex.clone(),
            },
            tee: Tee {
                image_hash: DUMMY_IMAGE_HASH.to_string(),
                latest_allowed_hash_file_path: "latest_allowed_hash.txt".to_string(),
                authority: TeeAuthority {
                    r#type: "local".to_string(),
                },
            },
            log: Log {
                format: "plain".to_string(),
                filter: "debug".to_string(),
            },
            near_init: NearInit {
                chain_id: "mpc-localnet".to_string(),
                boot_nodes: self.near_node_boot_nodes.clone(),
                genesis_path: self.near_node_genesis_path.display().to_string(),
                download_genesis: false,
                rpc_addr: format!("0.0.0.0:{}", self.ports.near_rpc),
                network_addr: format!("0.0.0.0:{}", self.ports.near_network),
            },
            node: Node {
                my_near_account_id: signer.clone(),
                near_responder_account_id: signer,
                number_of_responder_keys: 1,
                web_ui: format!("127.0.0.1:{}", self.ports.web_ui),
                migration_web_ui: format!("127.0.0.1:{}", self.ports.migration_web_ui),
                pprof_bind_address: format!("127.0.0.1:{}", self.ports.pprof),
                cores: 4,
                indexer: Indexer {
                    validate_genesis: true,
                    concurrency: 1,
                    mpc_contract_id: self.mpc_contract_id.to_string(),
                    finality: "optimistic".to_string(),
                    sync_mode: BTreeMap::from([("Block".to_string(), SyncModeBlock { height: 0 })]),
                },
                triple: Triple {
                    concurrency: 2,
                    desired_triples_to_buffer: self.triples_to_buffer,
                    timeout_sec: 60,
                    parallel_triple_generation_stagger_time_sec: 1,
                },
                presignature: Presignature {
                    concurrency: 2,
                    desired_presignatures_to_buffer: self.presignatures_to_buffer,
                    timeout_sec: 60,
                },
                signature: Timeout { timeout_sec: 60 },
                ckd: Timeout { timeout_sec: 60 },
                keygen: Timeout { timeout_sec: 60 },
            },
        };

        let toml_string =
            toml::to_string_pretty(&config).context("failed to serialize start config")?;
        std::fs::write(&config_path, &toml_string)
            .with_context(|| format!("failed to write {}", config_path.display()))?;

        tracing::debug!(path = %config_path.display(), "wrote start_config.toml");
        Ok(config_path)
    }
}

impl Drop for MpcNode {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// TODO(#2560): Factor `StartConfig` out of `mpc-node` into a lightweight crate so we
// can reuse it here instead of duplicating the structure.
//
// Serialization types for `start_config.toml`.
// These mirror the structure in `crates/node/src/config/start.rs` (StartConfig)
// without pulling in the full mpc-node dependency.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StartConfig {
    home_dir: String,
    secrets: Secrets,
    tee: Tee,
    log: Log,
    near_init: NearInit,
    node: Node,
}

#[derive(Serialize)]
struct Secrets {
    secret_store_key_hex: String,
    backup_encryption_key_hex: String,
}

#[derive(Serialize)]
struct Tee {
    image_hash: String,
    latest_allowed_hash_file_path: String,
    authority: TeeAuthority,
}

#[derive(Serialize)]
struct Log {
    format: String,
    filter: String,
}

#[derive(Serialize)]
struct TeeAuthority {
    r#type: String,
}

#[derive(Serialize)]
struct NearInit {
    chain_id: String,
    boot_nodes: String,
    genesis_path: String,
    download_genesis: bool,
    rpc_addr: String,
    network_addr: String,
}

#[derive(Serialize)]
struct Node {
    my_near_account_id: String,
    near_responder_account_id: String,
    number_of_responder_keys: usize,
    web_ui: String,
    migration_web_ui: String,
    pprof_bind_address: String,
    cores: usize,
    indexer: Indexer,
    triple: Triple,
    presignature: Presignature,
    signature: Timeout,
    ckd: Timeout,
    keygen: Timeout,
}

#[derive(Serialize)]
struct Indexer {
    validate_genesis: bool,
    concurrency: usize,
    mpc_contract_id: String,
    finality: String,
    sync_mode: BTreeMap<String, SyncModeBlock>,
}

#[derive(Serialize)]
struct SyncModeBlock {
    height: u64,
}

#[derive(Serialize)]
struct Triple {
    concurrency: usize,
    desired_triples_to_buffer: usize,
    timeout_sec: u64,
    parallel_triple_generation_stagger_time_sec: u64,
}

#[derive(Serialize)]
struct Presignature {
    concurrency: usize,
    desired_presignatures_to_buffer: usize,
    timeout_sec: u64,
}

#[derive(Serialize)]
struct Timeout {
    timeout_sec: u64,
}
