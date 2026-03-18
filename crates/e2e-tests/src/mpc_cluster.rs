use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use ed25519_dalek::SigningKey;
use near_workspaces::types::{AccessKey, AccessKeyPermission, FunctionCallPermission};

use crate::blockchain::{self, NearBlockchain};
use crate::mpc_node::{MpcNode, NodePorts};
use crate::port_allocator::E2ePortAllocator;
use crate::sandbox::SandboxNode;

/// Configuration for starting an MPC cluster.
pub struct ClusterConfig {
    pub num_nodes: usize,
    pub threshold: u64,
    pub triples_to_buffer: usize,
    pub presignatures_to_buffer: usize,
    pub port_allocator: E2ePortAllocator,
    /// Path to the `mpc-node` binary. Defaults to `target/release/mpc-node`.
    pub binary_path: Option<PathBuf>,
    /// Path to the contract WASM. Defaults to
    /// `target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm`.
    pub wasm_path: Option<PathBuf>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            num_nodes: 2,
            threshold: 2,
            triples_to_buffer: 200,
            presignatures_to_buffer: 100,
            port_allocator: E2ePortAllocator::new(0),
            binary_path: None,
            wasm_path: None,
        }
    }
}

/// Orchestrates sandbox + blockchain + N mpc-node processes.
pub struct MpcCluster {
    pub blockchain: NearBlockchain,
    pub nodes: Vec<MpcNode>,
    _sandbox: SandboxNode,
    _temp_dir: tempfile::TempDir,
    _binary_path: PathBuf,
}

impl MpcCluster {
    /// Start a complete MPC cluster:
    /// 1. Start sandbox validator
    /// 2. Connect blockchain RPC client
    /// 3. Deploy MPC contract
    /// 4. Create node accounts with access keys
    /// 5. Initialize contract with threshold parameters
    /// 6. Submit mock TEE attestations
    /// 7. Start all mpc-node processes
    /// 8. Vote to add domains
    /// 9. Wait for Running state (nodes complete key generation)
    pub async fn start(config: ClusterConfig) -> anyhow::Result<Self> {
        let _ = tracing_subscriber::fmt().with_env_filter("INFO").try_init();

        let temp_dir = tempfile::TempDir::new().context("failed to create temp dir")?;

        // Resolve binary and WASM paths (handles git worktrees)
        let binary_path = find_artifact(
            config.binary_path,
            "target/release/mpc-node",
            "mpc-node binary",
            "cargo build -p mpc-node --release --features test-utils",
        )?;
        let wasm_path = find_artifact(
            config.wasm_path,
            "target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm",
            "contract WASM",
            "cargo near build non-reproducible-wasm --manifest-path crates/contract/Cargo.toml --locked",
        )?;

        let wasm = std::fs::read(&wasm_path)
            .with_context(|| format!("failed to read WASM: {}", wasm_path.display()))?;

        // 1. Start sandbox
        tracing::info!("starting sandbox...");
        let sandbox = SandboxNode::start(&config.port_allocator).await?;

        // 2. Connect blockchain client
        tracing::info!("connecting blockchain client...");
        let mut blockchain = NearBlockchain::from_sandbox(&sandbox).await?;

        // 3. Deploy contract
        tracing::info!("deploying MPC contract...");
        blockchain.deploy_contract(&wasm).await?;

        let contract_id = blockchain.contract_id().clone();

        // 4. Create node accounts and MPC nodes
        tracing::info!(num_nodes = config.num_nodes, "creating node accounts...");
        let mut nodes = Vec::with_capacity(config.num_nodes);
        let mut account_sign_pks = Vec::new();
        let mut p2p_urls = Vec::new();

        for i in 0..config.num_nodes {
            let p2p_signing_key = SigningKey::generate(&mut rand::thread_rng());
            let near_signer_key = SigningKey::generate(&mut rand::thread_rng());
            let account = blockchain.create_subaccount(&format!("signer_{i}")).await?;

            // Add the near_signer_key as a function-call access key on the account.
            // The mpc-node will use this key from secrets.json to submit transactions.
            let signer_pub = near_signer_key.verifying_key();
            let signer_pub_str = format!(
                "ed25519:{}",
                bs58::encode(signer_pub.as_bytes()).into_string()
            );
            let near_pub_key: near_workspaces::types::PublicKey = signer_pub_str
                .parse()
                .context("failed to parse near signer public key")?;

            let result = account
                .batch(account.id())
                .add_key(
                    near_pub_key,
                    AccessKey {
                        nonce: 0,
                        permission: AccessKeyPermission::FunctionCall(FunctionCallPermission {
                            allowance: None,
                            receiver_id: contract_id.to_string(),
                            method_names: vec![],
                        }),
                    },
                )
                .transact()
                .await
                .with_context(|| format!("failed to add access key for signer_{i}"))?;

            anyhow::ensure!(
                result.is_success(),
                "add access key failed for signer_{i}: {result:?}"
            );

            let node_home = temp_dir.path().join(format!("node_{i}"));
            let ports = NodePorts::from_allocator(&config.port_allocator, i);

            let node = MpcNode::new(
                i,
                node_home,
                account.id().clone(),
                p2p_signing_key,
                near_signer_key,
                ports,
                contract_id.clone(),
                &sandbox,
                account,
                config.triples_to_buffer,
                config.presignatures_to_buffer,
            )?;

            let sign_pk = node.p2p_public_key_str();
            let url = node.p2p_url();

            account_sign_pks.push((node.signer_account_id.clone(), sign_pk));
            p2p_urls.push(url);
            nodes.push(node);
        }

        // 5. Build threshold parameters and init contract
        tracing::info!(threshold = config.threshold, "initializing contract...");
        let params =
            blockchain::make_threshold_parameters(&account_sign_pks, &p2p_urls, config.threshold);
        blockchain.init_contract(&params).await?;

        // 6. Submit mock TEE attestations
        tracing::info!("submitting TEE attestations...");
        for node in &nodes {
            let sign_pk = node.p2p_public_key_str();
            blockchain
                .submit_attestation(&node.account, &sign_pk)
                .await?;
        }

        // Wait for contract to be in Running state after init
        blockchain
            .wait_for_running(Duration::from_secs(30))
            .await
            .context("contract did not reach Running state after init")?;

        // 7. Start all MPC node processes
        tracing::info!("starting mpc-node processes...");
        for node in &mut nodes {
            node.start(&binary_path)?;
        }

        // Give nodes a moment to initialize, then check if config.json was created
        tokio::time::sleep(Duration::from_secs(3)).await;
        for node in &nodes {
            let config_json = node.home_dir.join("config.json");
            if config_json.exists() {
                tracing::info!(node = node.node_index, "config.json exists");
            } else {
                tracing::error!(node = node.node_index, home = %node.home_dir.display(), "config.json does NOT exist!");
                // List what files are in the home dir
                if let Ok(entries) = std::fs::read_dir(&node.home_dir) {
                    for entry in entries.flatten() {
                        tracing::error!(node = node.node_index, file = %entry.file_name().to_string_lossy(), "  found file");
                    }
                }
            }
        }

        // 8. Vote to add domains
        tracing::info!("voting to add domains...");
        let domains = blockchain::default_domains(0);
        let voter_accounts: Vec<&near_workspaces::Account> =
            nodes.iter().map(|n| &n.account).collect();
        blockchain
            .vote_add_domains(&voter_accounts, &domains)
            .await?;

        // 9. Wait for Running state (nodes complete key generation via P2P)
        tracing::info!("waiting for key generation to complete...");
        blockchain
            .wait_for_running(Duration::from_secs(120))
            .await
            .context("contract did not reach Running state after key generation")?;

        tracing::info!("cluster is ready");

        Ok(Self {
            blockchain,
            nodes,
            _sandbox: sandbox,
            _temp_dir: temp_dir,
            _binary_path: binary_path,
        })
    }

    /// Submit signature requests and wait for responses.
    pub async fn send_and_await_signature_requests(
        &self,
        num_per_domain: usize,
    ) -> anyhow::Result<()> {
        self.blockchain
            .send_and_await_signature_requests(num_per_domain, Duration::from_secs(300))
            .await
    }

    /// Submit CKD requests and wait for responses.
    pub async fn send_and_await_ckd_requests(&self, num_per_domain: usize) -> anyhow::Result<()> {
        self.blockchain
            .send_and_await_ckd_requests(num_per_domain, Duration::from_secs(300))
            .await
    }

    /// Get the current contract state.
    pub async fn get_contract_state(
        &self,
    ) -> anyhow::Result<near_mpc_contract_interface::types::ProtocolContractState> {
        self.blockchain.get_state().await
    }

    /// Kill all MPC node processes.
    pub fn kill_all(&mut self) {
        for node in &mut self.nodes {
            node.kill();
        }
    }
}

impl Drop for MpcCluster {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// Find the workspace root by walking up from the crate directory.
/// In a git worktree, also discovers the main repository root as a fallback
/// for finding build artifacts.
fn find_project_root() -> anyhow::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/e2e-tests -> root is ../..
    let root = manifest_dir
        .ancestors()
        .nth(2)
        .context("failed to find project root")?
        .to_path_buf();
    Ok(root)
}

/// Find a build artifact (binary or WASM) by checking:
/// 1. Explicit path from config
/// 2. Project root's target/ (works in normal repos)
/// 3. Main repo's target/ (fallback for git worktrees)
fn find_artifact(
    explicit: Option<PathBuf>,
    relative_path: &str,
    description: &str,
    build_hint: &str,
) -> anyhow::Result<PathBuf> {
    // 1. Explicit path
    if let Some(p) = explicit {
        anyhow::ensure!(p.exists(), "{description} not found at {}", p.display());
        return Ok(p);
    }

    let project_root = find_project_root()?;

    // 2. Project root target/
    let candidate = project_root.join(relative_path);
    if candidate.exists() {
        return Ok(candidate);
    }

    // 3. Git worktree fallback: find the main repo via `.git` file
    let git_path = project_root.join(".git");
    if git_path.is_file() {
        // In a worktree, .git is a file containing "gitdir: <path>"
        if let Ok(content) = std::fs::read_to_string(&git_path) {
            if let Some(gitdir) = content.strip_prefix("gitdir: ") {
                let gitdir = PathBuf::from(gitdir.trim());
                // gitdir is usually <main_repo>/.git/worktrees/<name>
                // so the main repo root is gitdir/../../..
                if let Some(main_root) = gitdir.ancestors().nth(3) {
                    let candidate = main_root.join(relative_path);
                    if candidate.exists() {
                        return Ok(candidate);
                    }
                }
            }
        }
    }

    anyhow::bail!(
        "{description} not found. Searched:\n  - {}\nBuild it with: {build_hint}",
        project_root.join(relative_path).display(),
    )
}
