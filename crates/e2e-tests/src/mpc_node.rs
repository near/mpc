use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;
use ed25519_dalek::SigningKey;
use near_workspaces::{Account, AccountId};
use serde_json::json;

use crate::port_allocator::E2ePortAllocator;
use crate::sandbox::SandboxNode;

const DUMMY_IMAGE_HASH: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

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

/// Manages a single `mpc-node` OS process.
///
/// Generates the `start_config.toml` and spawns the binary. Each node runs its
/// own internal neard indexer that peers with the sandbox validator via P2P.
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
    sandbox_genesis_path: PathBuf,
    sandbox_boot_nodes: String,

    // Config values
    secret_store_key_hex: String,
    backup_encryption_key_hex: String,
    triples_to_buffer: usize,
    presignatures_to_buffer: usize,

    // near-workspaces account (for voting on contract)
    pub account: Account,

    // Runtime
    process: Option<Child>,
}

impl MpcNode {
    /// Create a new MPC node config (not yet running).
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        node_index: usize,
        home_dir: PathBuf,
        signer_account_id: AccountId,
        p2p_signing_key: SigningKey,
        near_signer_key: SigningKey,
        ports: NodePorts,
        mpc_contract_id: AccountId,
        sandbox: &SandboxNode,
        account: Account,
        triples_to_buffer: usize,
        presignatures_to_buffer: usize,
    ) -> anyhow::Result<Self> {
        let sandbox_genesis_path = sandbox.genesis_path();
        let sandbox_boot_nodes = sandbox.boot_nodes()?;

        // Deterministic secret keys for each node
        let secret_byte = b'A' + node_index as u8;
        let secret_store_key_hex = hex::encode([secret_byte; 16]);
        let backup_encryption_key_hex = hex::encode([secret_byte; 32]);

        std::fs::create_dir_all(&home_dir)
            .with_context(|| format!("failed to create node home dir: {}", home_dir.display()))?;

        Ok(Self {
            node_index,
            home_dir,
            signer_account_id,
            p2p_signing_key,
            near_signer_key,
            ports,
            mpc_contract_id,
            sandbox_genesis_path,
            sandbox_boot_nodes,
            secret_store_key_hex,
            backup_encryption_key_hex,
            triples_to_buffer,
            presignatures_to_buffer,
            account,
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
            .env("RUST_LOG", "DEBUG")
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

    /// Stop the node with SIGTERM.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            // Send SIGTERM on unix, kill on other platforms
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Kill the node with SIGKILL.
    pub fn kill(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    pub fn is_running(&self) -> bool {
        self.process.is_some()
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

    /// Write the TOML config file for `mpc-node start-with-config-file`.
    fn write_start_config(&self) -> anyhow::Result<PathBuf> {
        let config_path = self.home_dir.join("start_config.toml");

        // Must match the structure in crates/node/src/config/start.rs (StartConfig).
        let toml_string = format!(
            r#"home_dir = "{home_dir}"

[secrets]
secret_store_key_hex = "{secret_store_key_hex}"
backup_encryption_key_hex = "{backup_encryption_key_hex}"

[tee]
image_hash = "{image_hash}"
latest_allowed_hash_file = "latest_allowed_hash.txt"

[tee.authority]
type = "local"

[near_init]
chain_id = "mpc-localnet"
boot_nodes = "{boot_nodes}"
genesis_path = "{genesis_path}"
download_genesis = false
rpc_addr = "0.0.0.0:{near_rpc_port}"
network_addr = "0.0.0.0:{near_network_port}"

[node]
my_near_account_id = "{signer_account_id}"
near_responder_account_id = "{signer_account_id}"
number_of_responder_keys = 1
web_ui = "127.0.0.1:{web_ui_port}"
migration_web_ui = "127.0.0.1:{migration_web_ui_port}"
pprof_bind_address = "127.0.0.1:{pprof_port}"
cores = 4

[node.indexer]
validate_genesis = true
concurrency = 1
mpc_contract_id = "{mpc_contract_id}"
finality = "optimistic"

[node.indexer.sync_mode]
Block = {{ height = 0 }}

[node.triple]
concurrency = 2
desired_triples_to_buffer = {triples_to_buffer}
timeout_sec = 60
parallel_triple_generation_stagger_time_sec = 1

[node.presignature]
concurrency = 2
desired_presignatures_to_buffer = {presignatures_to_buffer}
timeout_sec = 60

[node.signature]
timeout_sec = 60

[node.ckd]
timeout_sec = 60

[node.keygen]
timeout_sec = 60
"#,
            home_dir = self.home_dir.display(),
            secret_store_key_hex = self.secret_store_key_hex,
            backup_encryption_key_hex = self.backup_encryption_key_hex,
            image_hash = DUMMY_IMAGE_HASH,
            boot_nodes = self.sandbox_boot_nodes,
            genesis_path = self.sandbox_genesis_path.display(),
            near_rpc_port = self.ports.near_rpc,
            near_network_port = self.ports.near_network,
            signer_account_id = self.signer_account_id,
            web_ui_port = self.ports.web_ui,
            migration_web_ui_port = self.ports.migration_web_ui,
            pprof_port = self.ports.pprof,
            mpc_contract_id = self.mpc_contract_id,
            triples_to_buffer = self.triples_to_buffer,
            presignatures_to_buffer = self.presignatures_to_buffer,
        );

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
        // Dump logs on drop for debugging
        for log_name in &["stderr.log", "stdout.log"] {
            let log_path = self.home_dir.join(log_name);
            if let Ok(content) = std::fs::read_to_string(&log_path) {
                if !content.is_empty() {
                    eprintln!(
                        "=== node {} {} (FULL) ===\n{}\n=== end node {} {} ===",
                        self.node_index, log_name,
                        content,
                        self.node_index, log_name,
                    );
                }
            }
        }
    }
}
