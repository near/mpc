use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use anyhow::Context;
use ed25519_dalek::SigningKey;
use launcher_interface::types::{TeeAuthorityConfig, TeeConfig};
use mpc_node_config::{
    BlockArgs, CKDConfig, ChainId, ConfigFile, IndexerConfig, KeygenConfig, LogConfig, LogFormat,
    NearInitConfig, PresignatureConfig, SecretsStartConfig, SignatureConfig, StartConfig, SyncMode,
    TripleConfig,
};
use near_indexer_primitives::types::Finality;
use near_kit::AccountId;
use near_mpc_crypto_types::Ed25519PublicKey;
use serde_json::json;

use crate::port_allocator::E2ePortAllocator;

const DUMMY_IMAGE_HASH: &str =
    "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

const LISTEN_BLOCKS_FILE: &str = "listen_blocks";

const TEMP_KEYS_FILE: &str = "temporary_keys";

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

    /// Reference to the underlying setup (config, paths, ports).
    pub fn setup(&self) -> &MpcNodeSetup {
        &self.setup
    }

    /// Check whether the child process has already exited (crashed).
    pub fn has_exited(&mut self) -> bool {
        self.process.has_exited()
    }

    pub fn web_address(&self) -> String {
        format!("127.0.0.1:{}", self.setup.ports.web_ui)
    }

    pub fn pprof_address(&self) -> String {
        format!("127.0.0.1:{}", self.setup.ports.pprof)
    }

    /// Scrapes the node's `/metrics` HTTP endpoint and returns the value of
    /// the named metric, parsed as `i64`. Returns `None` if the metric is not
    /// found or the node is unreachable.
    pub async fn get_metric(&self, name: &str) -> anyhow::Result<Option<i64>> {
        let url = format!("http://{}/metrics", self.web_address());
        let body = match reqwest::get(&url).await {
            Ok(resp) => resp.text().await.context("failed to read metrics body")?,
            Err(_) => return Ok(None),
        };

        for line in body.lines() {
            if line.starts_with('#') {
                continue;
            }
            // Match lines like "metric_name <value>" or "metric_name{labels} <value>"
            let metric_key = line.split([' ', '{']).next().unwrap_or("");
            if metric_key == name {
                let value_str = line.rsplit_once(' ').map(|(_, v)| v).unwrap_or("0");
                if let Ok(v) = value_str.parse::<f64>() {
                    return Ok(Some(v as i64));
                }
            }
        }
        Ok(None)
    }

    /// Writes a flag file that controls block ingestion. Requires the
    /// `network-hardship-simulation` feature on the mpc-node binary.
    pub fn set_block_ingestion(&self, active: bool) -> anyhow::Result<()> {
        let path = self.setup.home_dir.join(LISTEN_BLOCKS_FILE);
        std::fs::write(&path, if active { "true" } else { "false" })
            .with_context(|| format!("failed to write {}", path.display()))
    }
}

pub const STDERR_LOG: &str = "stderr.log";

/// Guard that kills the child process on drop.
struct ProcessGuard(Child);

impl ProcessGuard {
    fn has_exited(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(Some(_)))
    }
}

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

    // NEAR chain info (from sandbox)
    chain_id: String,
    near_genesis_path: PathBuf,
    near_boot_nodes: String,

    // Derived config values
    secret_store_key_hex: String,
    backup_encryption_key_hex: String,
    triples_to_buffer: usize,
    presignatures_to_buffer: usize,

    // Config file path (written on creation)
    config_path: PathBuf,
}

impl MpcNodeSetup {
    /// Create a new node setup. Writes config files to disk immediately.
    pub fn new(args: MpcNodeSetupArgs) -> anyhow::Result<Self> {
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
            chain_id: args.chain_id,
            near_genesis_path: args.near_genesis_path,
            near_boot_nodes: args.near_boot_nodes,
            secret_store_key_hex,
            backup_encryption_key_hex,
            triples_to_buffer: args.triples_to_buffer,
            presignatures_to_buffer: args.presignatures_to_buffer,
            config_path,
        };

        setup.write_secrets_json()?;
        setup.write_start_config()?;

        Ok(setup)
    }

    pub fn p2p_public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::from(&self.p2p_signing_key.verifying_key())
    }

    /// The P2P URL for this node.
    pub fn p2p_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.ports.p2p)
    }

    /// The NEAR account ID for this node.
    pub fn account_id(&self) -> &AccountId {
        &self.signer_account_id
    }

    /// The node's home directory (logs, config, data).
    pub fn home_dir(&self) -> &std::path::Path {
        &self.home_dir
    }

    /// Fully reset the node by wiping its home directory.
    /// SIGKILL can leave NEAR indexer data in a corrupted state that prevents
    /// restart, so the entire home directory is removed and recreated. The NEAR
    /// indexer will re-init from genesis_path/boot_nodes in start_config.toml
    /// and sync from block 0.
    ///
    /// Re-writes secrets.json and start_config.toml from the saved setup.
    pub fn reset_mpc_state(&self) -> anyhow::Result<()> {
        // Nuke and recreate the home directory. SIGKILL can leave NEAR indexer
        // data in a corrupted state that prevents restart, so we start fully
        // fresh. The NEAR indexer will re-init from genesis_path/boot_nodes in
        // start_config.toml and sync from block 0.
        if self.home_dir.exists() {
            std::fs::remove_dir_all(&self.home_dir)
                .with_context(|| format!("failed to remove {}", self.home_dir.display()))?;
        }
        std::fs::create_dir_all(&self.home_dir)
            .with_context(|| format!("failed to recreate {}", self.home_dir.display()))?;
        self.write_secrets_json()?;
        self.write_start_config()?;
        Ok(())
    }

    /// Deletes RocksDB files and temporary key state from the data directory.
    /// Safe to call because the node is not running.
    pub fn wipe_db(&self) -> anyhow::Result<()> {
        let entries = std::fs::read_dir(&self.home_dir)
            .with_context(|| format!("failed to read dir {}", self.home_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();

            let should_remove = matches!(name.as_ref(), "CURRENT" | "IDENTITY" | "LOCK" | "LOG")
                || name.starts_with("MANIFEST-")
                || name.starts_with("OPTIONS-")
                || name.ends_with(".log")
                || name.ends_with(".sst");

            if should_remove {
                std::fs::remove_file(entry.path())
                    .with_context(|| format!("failed to remove {}", entry.path().display()))?;
            }
        }

        // Also clean temporary key event state to avoid stale resharing data.
        let temp_keys = self.home_dir.join(TEMP_KEYS_FILE);
        if temp_keys.exists() {
            std::fs::remove_dir_all(&temp_keys)
                .with_context(|| format!("failed to remove {}", temp_keys.display()))?;
        }

        Ok(())
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
    /// generating random ones.
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
        let signer: near_account_id::AccountId = self.signer_account_id.to_string().parse()?;
        let mpc_contract: near_account_id::AccountId = self.mpc_contract_id.to_string().parse()?;

        let config = StartConfig {
            home_dir: self.home_dir.clone(),
            secrets: SecretsStartConfig {
                secret_store_key_hex: self.secret_store_key_hex.clone(),
                backup_encryption_key_hex: Some(self.backup_encryption_key_hex.clone()),
            },
            tee: TeeConfig {
                image_hash: DUMMY_IMAGE_HASH.parse().unwrap(),
                latest_allowed_hash_file_path: "latest_allowed_hash.txt".into(),
                authority: TeeAuthorityConfig::Local,
            },
            gcp: None,
            log: LogConfig {
                format: LogFormat::Plain,
                filter: Some("debug".to_string()),
            },
            near_init: Some(NearInitConfig {
                chain_id: ChainId::Custom(self.chain_id.clone()),
                boot_nodes: Some(self.near_boot_nodes.clone()),
                genesis_path: Some(self.near_genesis_path.clone()),
                download_config: None,
                download_config_url: None,
                download_genesis: false,
                download_genesis_url: None,
                download_genesis_records_url: None,
                rpc_addr: Some(format!("0.0.0.0:{}", self.ports.near_rpc)),
                network_addr: Some(format!("0.0.0.0:{}", self.ports.near_network)),
            }),
            node: ConfigFile {
                my_near_account_id: signer.clone(),
                near_responder_account_id: signer,
                number_of_responder_keys: 1,
                web_ui: format!("127.0.0.1:{}", self.ports.web_ui).parse()?,
                migration_web_ui: format!("127.0.0.1:{}", self.ports.migration_web_ui).parse()?,
                pprof_bind_address: format!("127.0.0.1:{}", self.ports.pprof).parse()?,
                cores: Some(4),
                indexer: IndexerConfig {
                    validate_genesis: true,
                    concurrency: std::num::NonZeroU16::new(1).unwrap(),
                    mpc_contract_id: mpc_contract,
                    finality: Finality::None,
                    sync_mode: SyncMode::Block(BlockArgs { height: 0 }),
                    port_override: None,
                },
                triple: TripleConfig {
                    concurrency: 2,
                    desired_triples_to_buffer: self.triples_to_buffer,
                    timeout_sec: 60,
                    parallel_triple_generation_stagger_time_sec: 1,
                },
                presignature: PresignatureConfig {
                    concurrency: 2,
                    desired_presignatures_to_buffer: self.presignatures_to_buffer,
                    timeout_sec: 60,
                },
                signature: SignatureConfig { timeout_sec: 60 },
                ckd: CKDConfig { timeout_sec: 60 },
                keygen: KeygenConfig { timeout_sec: 60 },
                foreign_chains: Default::default(),
            },
            quote_upload_url: mpc_node_config::default_quote_upload_url(),
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
    pub triples_to_buffer: usize,
    pub presignatures_to_buffer: usize,
    /// Chain ID from the sandbox's genesis.json.
    pub chain_id: String,
    /// Path to genesis.json on the host (copied from sandbox container).
    pub near_genesis_path: PathBuf,
    /// Boot nodes string: `"ed25519:<pubkey>@127.0.0.1:<port>"`.
    pub near_boot_nodes: String,
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
