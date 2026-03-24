use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::Context;
use ed25519_dalek::SigningKey;
use near_mpc_crypto_types::Ed25519PublicKey;
use near_workspaces::{Account, AccountId};
use serde::Serialize;
use serde_json::json;

use crate::near_node::NearNode;
use crate::port_allocator::E2ePortAllocator;

const DUMMY_IMAGE_HASH: &str =
    "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Handle to a running `mpc-node` OS process. Always represents a live process.
/// Obtained by calling [`MpcNodeSetup::start()`].
/// The child process is killed automatically when this value is dropped.
pub struct MpcNode {
    setup: MpcNodeSetup,
    process: ProcessGuard,
}

impl MpcNode {
    /// Stop the node. Consumes self and returns the setup for potential restart.
    pub fn kill(self) -> MpcNodeSetup {
        drop(self.process);
        self.setup
    }

    /// Kill then start. New process, same config and data directory.
    pub fn restart(self) -> anyhow::Result<MpcNode> {
        self.kill().start()
    }

    pub fn is_running(&mut self) -> bool {
        !matches!(self.process.0.try_wait(), Ok(Some(_)))
    }
}

/// Guard that kills the child process on drop.
struct ProcessGuard(Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Err(e) = self.0.kill() {
            tracing::error!(error = %e, "failed to kill mpc-node process");
        }
        if let Err(e) = self.0.wait() {
            tracing::error!(error = %e, "failed to wait on mpc-node process");
        }
    }
}

/// All configuration and state needed to start an mpc-node process.
/// Represents a node that is NOT running. Can wipe DB, modify config, etc.
/// Config files (secrets.json, start_config.toml) are written on creation.
pub struct MpcNodeSetup {
    node_index: usize,
    home_dir: PathBuf,
    binary_path: PathBuf,
    signer_account_id: AccountId,
    p2p_signing_key: SigningKey,
    /// Key used by the node to sign NEAR transactions (must have access key on account).
    near_signer_key: SigningKey,
    ports: NodePorts,
    mpc_contract_id: AccountId,

    // Derived config values
    secret_store_key_hex: String,
    backup_encryption_key_hex: String,
    near_node_genesis_path: PathBuf,
    near_node_boot_nodes: String,
    triples_to_buffer: usize,
    presignatures_to_buffer: usize,

    // Config file path (written on creation)
    config_path: PathBuf,
}

impl MpcNodeSetup {
    /// Create a new node setup. Writes config files to disk immediately.
    pub fn new(args: MpcNodeSetupArgs, near_node: &NearNode) -> anyhow::Result<Self> {
        let near_node_genesis_path = near_node.genesis_path();
        let near_node_boot_nodes = near_node.boot_nodes()?;

        // Deterministic secret keys for each node
        let secret_byte = b'A'
            .checked_add(u8::try_from(args.node_index).context("node_index too large")?)
            .context("secret_byte overflow")?;
        let secret_store_key_hex = hex::encode([secret_byte; 16]);
        let backup_encryption_key_hex = hex::encode([secret_byte; 32]);

        std::fs::create_dir_all(&args.home_dir).with_context(|| {
            format!(
                "failed to create node home dir: {}",
                args.home_dir.display()
            )
        })?;

        let config_path = args.home_dir.join("start_config.toml");

        let setup = Self {
            node_index: args.node_index,
            home_dir: args.home_dir,
            binary_path: args.binary_path,
            signer_account_id: args.signer_account_id,
            p2p_signing_key: args.p2p_signing_key,
            near_signer_key: args.near_signer_key,
            ports: args.ports,
            mpc_contract_id: args.mpc_contract_id,
            secret_store_key_hex,
            backup_encryption_key_hex,
            near_node_genesis_path,
            near_node_boot_nodes,
            triples_to_buffer: args.triples_to_buffer,
            presignatures_to_buffer: args.presignatures_to_buffer,
            config_path,
        };

        setup.write_secrets_json()?;
        setup.write_start_config()?;

        Ok(setup)
    }

    /// The ed25519 public key formatted as `"ed25519:<base58>"`.
    pub fn p2p_public_key_str(&self) -> String {
        String::from(&Ed25519PublicKey::from(
            &self.p2p_signing_key.verifying_key(),
        ))
    }

    /// The P2P URL for this node.
    pub fn p2p_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.p2p)
    }

    /// Spawn the mpc-node process. Consumes self, returning an MpcNode handle.
    pub fn start(self) -> anyhow::Result<MpcNode> {
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

        let child = Command::new(&self.binary_path)
            .arg("start-with-config-file")
            .arg(&self.config_path)
            .env(
                "RUST_LOG",
                std::env::var("MPC_NODE_LOG").unwrap_or_else(|_| "DEBUG".to_string()),
            )
            .env(
                "RUST_BACKTRACE",
                std::env::var("MPC_NODE_BACKTRACE").unwrap_or_else(|_| "1".to_string()),
            )
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn mpc-node {} (binary: {})",
                    self.node_index,
                    self.binary_path.display()
                )
            })?;

        Ok(MpcNode {
            setup: self,
            process: ProcessGuard(child),
        })
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
    fn write_start_config(&self) -> anyhow::Result<()> {
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
        std::fs::write(&self.config_path, &toml_string)
            .with_context(|| format!("failed to write {}", self.config_path.display()))?;

        tracing::debug!(path = %self.config_path.display(), "wrote start_config.toml");
        Ok(())
    }
}

/// Arguments for constructing an [`MpcNodeSetup`].
pub struct MpcNodeSetupArgs {
    pub node_index: usize,
    pub home_dir: PathBuf,
    pub binary_path: PathBuf,
    pub signer_account_id: AccountId,
    pub p2p_signing_key: SigningKey,
    pub near_signer_key: SigningKey,
    pub ports: NodePorts,
    pub mpc_contract_id: AccountId,
    pub account: Account,
    pub triples_to_buffer: usize,
    pub presignatures_to_buffer: usize,
}

/// Ports allocated for a single MPC node.
pub struct NodePorts {
    p2p: u16,
    web_ui: u16,
    migration_web_ui: u16,
    pprof: u16,
    near_rpc: u16,
    near_network: u16,
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
