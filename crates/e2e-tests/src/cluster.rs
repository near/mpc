use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use ed25519_dalek::SigningKey;
use near_kit::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    AccountId as ContractAccountId, DomainConfig, DomainId, DomainPurpose, ParticipantId,
    ParticipantInfo, Participants, ProtocolContractState, SignatureScheme, Threshold,
    ThresholdParameters,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::json;

use crate::blockchain::{ClientHandle, DeployedContract, NearBlockchain};
use crate::mpc_node::{MpcNode, MpcNodeSetup, MpcNodeSetupArgs, NodePorts};
use crate::near_sandbox::NearSandbox;
use crate::port_allocator::E2ePortAllocator;

const DEFAULT_SANDBOX_IMAGE: &str = "nearprotocol/sandbox:2.11.0-rc.3";
const SANDBOX_ROOT_ACCOUNT: &str = "sandbox";
const SANDBOX_ROOT_SECRET_KEY: &str = "ed25519:3JoAjwLppjgvxkk6kNsu5wQj3FfUJnpBKWieC73hVTpBeA6FZiCc5tfyZL3a3tHeQJegQe4qGSv8FLsYp7TYd1r6";
// Polling interval for waiting contract state.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Configuration for creating a new [`MpcCluster`].
pub struct MpcClusterConfig {
    /// Number of MPC nodes to start.
    pub num_nodes: usize,
    /// Threshold for signing (number of nodes required).
    pub threshold: usize,
    /// Signature domains to initialize after contract setup.
    pub domains: Vec<DomainConfig>,
    /// Path to the mpc-node binary. If multiple paths, each node gets the corresponding one.
    pub binary_paths: Vec<PathBuf>,
    /// Compiled contract WASM bytes (pre-compiled by the test).
    pub contract_wasm: Vec<u8>,
    /// Port seed for the port allocator (must be unique across parallel tests).
    pub port_seed: u16,
    /// Triple buffer size per node.
    pub triples_to_buffer: usize,
    /// Presignature buffer size per node.
    pub presignatures_to_buffer: usize,
    /// Docker image for the NEAR sandbox (e.g. `"nearprotocol/sandbox:2.11.0-rc.3"`).
    pub sandbox_image: String,
    /// Root directory for all test artifacts (logs, configs, DB). If `None`, a temp dir is created.
    pub home_base: Option<PathBuf>,
}

impl MpcClusterConfig {
    /// Sensible defaults for a basic E2E test.
    ///
    /// - 3 nodes, 2-of-3 threshold
    /// - All 3 standard domains (Secp256k1, Ed25519, Bls12381)
    /// - 10 triples, 10 presignatures per node
    pub fn default_for_test(port_seed: u16, contract_wasm: Vec<u8>) -> Self {
        Self {
            num_nodes: 3,
            threshold: 2,
            domains: vec![
                DomainConfig {
                    id: DomainId(0),
                    scheme: SignatureScheme::Secp256k1,
                    purpose: Some(DomainPurpose::Sign),
                },
                DomainConfig {
                    id: DomainId(1),
                    scheme: SignatureScheme::Ed25519,
                    purpose: Some(DomainPurpose::Sign),
                },
                DomainConfig {
                    id: DomainId(2),
                    scheme: SignatureScheme::Bls12381,
                    purpose: Some(DomainPurpose::CKD),
                },
            ],
            binary_paths: vec![default_mpc_binary_path()],
            contract_wasm,
            port_seed,
            triples_to_buffer: 10,
            presignatures_to_buffer: 10,
            sandbox_image: DEFAULT_SANDBOX_IMAGE.to_string(),
            home_base: None,
        }
    }
}

fn default_mpc_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/mpc-node")
}

/// A running MPC test cluster with a deployed contract and N mpc-node processes.
///
/// Orchestrates the full test environment: Docker sandbox -> contract ->
/// accounts -> attestations -> domains -> mpc-node processes.
///
/// All nodes are killed when dropped.
pub struct MpcCluster {
    pub sandbox: NearSandbox,
    pub blockchain: NearBlockchain,
    pub contract: DeployedContract,
    pub nodes: Vec<MpcNodeState>,
    pub node_keys: Vec<SigningKey>,
    pub user_accounts: HashMap<AccountId, SigningKey>,
    pub ports: E2ePortAllocator,
    /// Held to keep the temp directory alive for the lifetime of the cluster.
    pub test_dir: tempfile::TempDir,
}

impl MpcCluster {
    /// Create the full cluster: start Docker sandbox, deploy contract,
    /// create accounts, submit attestations, add domains, spawn mpc-node
    /// binaries, and wait for Running state.
    pub async fn start(config: MpcClusterConfig) -> anyhow::Result<Self> {
        let ports = E2ePortAllocator::new(config.port_seed);
        let test_dir = create_test_dir(&config.home_base)?;

        let sandbox = NearSandbox::start(&ports, &config.sandbox_image, test_dir.path()).await?;
        let blockchain = NearBlockchain::new(
            &sandbox.rpc_url(),
            SANDBOX_ROOT_ACCOUNT,
            SANDBOX_ROOT_SECRET_KEY,
        )?;

        let contract_key = generate_deterministic_key(255);
        let contract_account: AccountId = format!("mpc.{SANDBOX_ROOT_ACCOUNT}").parse()?;
        let (node_keys, node_near_keys, node_p2p_keys) =
            generate_node_keys(u64::try_from(config.num_nodes).unwrap());

        let contract = deploy_contract(
            &blockchain,
            &contract_account,
            &contract_key,
            &config.contract_wasm,
        )
        .await?;

        create_node_accounts(&blockchain, &node_near_keys).await?;

        init_contract(
            &blockchain,
            &contract,
            &node_near_keys,
            &node_p2p_keys,
            config.threshold,
            config.num_nodes,
            &ports,
        )
        .await?;

        if !config.domains.is_empty() {
            add_initial_domains(&blockchain, &contract, &node_near_keys, &config.domains).await?;
        }

        let nodes = start_mpc_nodes(
            &config,
            &sandbox,
            &node_near_keys,
            &node_p2p_keys,
            &contract_account,
            test_dir.path(),
            &ports,
        )?;

        let user_accounts = create_user_accounts(&blockchain, 1).await?;

        tracing::info!("MPC cluster is ready");

        Ok(Self {
            sandbox,
            blockchain,
            contract,
            nodes,
            node_keys,
            user_accounts,
            ports,
            test_dir,
        })
    }

    pub fn kill_nodes(&mut self, indices: &[usize]) -> anyhow::Result<()> {
        for &idx in indices {
            if idx >= self.nodes.len() {
                anyhow::bail!(
                    "node index {idx} out of bounds (have {} nodes)",
                    self.nodes.len()
                );
            }
            let state = self.nodes.remove(idx);
            let new_state = match state {
                MpcNodeState::Running(node) => MpcNodeState::Stopped(node.kill()),
                MpcNodeState::Stopped(setup) => {
                    tracing::warn!(node = idx, "node already stopped");
                    MpcNodeState::Stopped(setup)
                }
            };
            self.nodes.insert(idx, new_state);
        }
        Ok(())
    }

    pub fn start_nodes(&mut self, indices: &[usize]) -> anyhow::Result<()> {
        for &idx in indices {
            let state = self.nodes.remove(idx);
            let new_state = match state {
                MpcNodeState::Stopped(setup) => MpcNodeState::Running(setup.start()?),
                MpcNodeState::Running(node) => {
                    tracing::warn!(node = idx, "node already running");
                    MpcNodeState::Running(node)
                }
            };
            self.nodes.insert(idx, new_state);
        }
        Ok(())
    }

    pub fn kill_all(&mut self) -> anyhow::Result<()> {
        let indices: Vec<usize> = (0..self.nodes.len()).collect();
        self.kill_nodes(&indices)
    }

    pub async fn get_contract_state(&self) -> anyhow::Result<ProtocolContractState> {
        self.contract.state().await
    }

    pub async fn wait_for_state(
        &self,
        predicate: impl Fn(&ProtocolContractState) -> bool,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        wait_for_contract_state(&self.contract, timeout, predicate).await
    }

    pub async fn add_domains(&self, domains: Vec<DomainConfig>) -> anyhow::Result<()> {
        let args = json!({ "domains": domains });
        self.call_from_all_nodes_concurrently(method_names::VOTE_ADD_DOMAINS, args)
            .await?;

        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Initializing(_)),
            Duration::from_secs(30),
        )
        .await?;

        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            Duration::from_secs(120),
        )
        .await
    }

    pub async fn start_resharing(
        &self,
        new_participants: &[usize],
        new_threshold: usize,
    ) -> anyhow::Result<()> {
        let state = self.get_contract_state().await?;
        let epoch_id = match &state {
            ProtocolContractState::Running(r) => r.keyset.epoch_id,
            _ => anyhow::bail!("cannot reshare: contract not in Running state"),
        };

        let participants =
            build_participants_from_nodes(new_participants, &self.nodes, &self.ports);
        let proposal = ThresholdParameters {
            threshold: Threshold(new_threshold as u64),
            participants,
        };

        self.call_from_all_nodes_concurrently(
            method_names::VOTE_NEW_PARAMETERS,
            json!({ "prospective_epoch_id": epoch_id, "proposal": proposal }),
        )
        .await?;

        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Resharing(_)),
            Duration::from_secs(30),
        )
        .await?;

        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            Duration::from_secs(120),
        )
        .await
    }

    pub async fn get_metric_all_nodes(&self, name: &str) -> anyhow::Result<Vec<Option<i64>>> {
        let mut results = Vec::new();
        for node in &self.nodes {
            match node {
                MpcNodeState::Running(n) => results.push(n.get_metric(name).await?),
                MpcNodeState::Stopped(_) => results.push(None),
            }
        }
        Ok(results)
    }

    pub async fn wait_for_metric_all_nodes(
        &self,
        name: &str,
        expected: i64,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let values = self.get_metric_all_nodes(name).await?;
            if values.iter().all(|v| *v == Some(expected)) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "metric {name} did not reach {expected} on all nodes within {}s (values: {values:?})",
                    timeout.as_secs()
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub fn wipe_db(&self, indices: &[usize]) -> anyhow::Result<()> {
        for &idx in indices {
            match &self.nodes[idx] {
                MpcNodeState::Stopped(setup) => setup.wipe_db()?,
                MpcNodeState::Running(_) => anyhow::bail!("cannot wipe DB for running node {idx}"),
            }
        }
        Ok(())
    }

    pub fn set_block_ingestion(&self, indices: &[usize], active: bool) -> anyhow::Result<()> {
        for &idx in indices {
            match &self.nodes[idx] {
                MpcNodeState::Running(node) => node.set_block_ingestion(active)?,
                MpcNodeState::Stopped(_) => {
                    anyhow::bail!("cannot set block ingestion for stopped node {idx}")
                }
            }
        }
        Ok(())
    }

    async fn call_from_all_nodes_concurrently(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<()> {
        let clients: Vec<_> = self
            .nodes
            .iter()
            .zip(self.node_keys.iter())
            .enumerate()
            .filter(|(_, (node, _))| matches!(node, MpcNodeState::Running(_)))
            .map(|(i, (node, key))| {
                let client = self
                    .blockchain
                    .client_for(node.account_id().as_ref(), key)?;
                Ok((i, node.account_id().clone(), client))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let futures = clients.iter().map(|(i, account, client)| {
            let args = args.clone();
            let method = method.to_string();
            async move {
                self.contract
                    .call_from(client, &method, args)
                    .await
                    .with_context(|| format!("node {i} ({account}) failed to call {method}"))
            }
        });

        futures::future::try_join_all(futures).await?;
        Ok(())
    }

    pub fn user_client(&self, account_id: &AccountId) -> anyhow::Result<ClientHandle> {
        let key = self
            .user_accounts
            .get(account_id)
            .with_context(|| format!("unknown user account: {account_id}"))?;
        self.blockchain.client_for(account_id.as_ref(), key)
    }

    pub fn default_user_account(&self) -> &AccountId {
        self.user_accounts
            .keys()
            .next()
            .expect("cluster should have at least one user account")
    }
}

impl Drop for MpcCluster {
    fn drop(&mut self) {
        if let Err(e) = self.kill_all() {
            tracing::error!(error = %e, "failed to kill all nodes during drop");
        }
    }
}

/// A node that is either running or stopped (killed).
pub enum MpcNodeState {
    Running(MpcNode),
    Stopped(MpcNodeSetup),
}

impl MpcNodeState {
    pub fn account_id(&self) -> &AccountId {
        match self {
            MpcNodeState::Running(n) => n.setup().account_id(),
            MpcNodeState::Stopped(s) => s.account_id(),
        }
    }

    pub fn p2p_public_key_str(&self) -> String {
        match self {
            MpcNodeState::Running(n) => n.setup().p2p_public_key_str(),
            MpcNodeState::Stopped(s) => s.p2p_public_key_str(),
        }
    }

    pub fn p2p_url(&self) -> String {
        match self {
            MpcNodeState::Running(n) => n.setup().p2p_url(),
            MpcNodeState::Stopped(s) => s.p2p_url(),
        }
    }
}

fn create_test_dir(home_base: &Option<PathBuf>) -> anyhow::Result<tempfile::TempDir> {
    match home_base {
        Some(base) => {
            std::fs::create_dir_all(base)?;
            Ok(tempfile::tempdir_in(base)?)
        }
        None => Ok(tempfile::tempdir()?),
    }
}

fn generate_node_keys(num_nodes: u64) -> (Vec<SigningKey>, Vec<SigningKey>, Vec<SigningKey>) {
    let mut node_keys = Vec::new();
    let mut near_keys = Vec::new();
    let mut p2p_keys = Vec::new();
    for i in 0..num_nodes {
        let near_key = generate_deterministic_key(i);
        let p2p_key = generate_deterministic_key(100 + i);
        node_keys.push(near_key.clone());
        near_keys.push(near_key);
        p2p_keys.push(p2p_key);
    }
    (node_keys, near_keys, p2p_keys)
}

async fn deploy_contract(
    blockchain: &NearBlockchain,
    contract_account: &AccountId,
    contract_key: &SigningKey,
    wasm: &[u8],
) -> anyhow::Result<DeployedContract> {
    tracing::info!(account = %contract_account, "deploying MPC contract");
    blockchain
        .create_account_and_deploy(contract_account.as_ref(), 1000, contract_key, wasm)
        .await
}

async fn create_node_accounts(
    blockchain: &NearBlockchain,
    near_keys: &[SigningKey],
) -> anyhow::Result<()> {
    for (i, key) in near_keys.iter().enumerate() {
        let account = format!("node{i}.{SANDBOX_ROOT_ACCOUNT}");
        tracing::info!(account = %account, "creating MPC node account");
        blockchain.create_account(&account, 100, key).await?;
    }
    Ok(())
}

async fn init_contract(
    blockchain: &NearBlockchain,
    contract: &DeployedContract,
    near_keys: &[SigningKey],
    p2p_keys: &[SigningKey],
    threshold: usize,
    num_nodes: usize,
    ports: &E2ePortAllocator,
) -> anyhow::Result<()> {
    let participants = build_participants(num_nodes, p2p_keys, ports);
    let params = ThresholdParameters {
        threshold: Threshold(threshold as u64),
        participants,
    };

    tracing::info!(threshold, "initializing contract");
    contract
        .call(method_names::INIT, json!({ "parameters": params }))
        .await?;

    for (i, (near_key, p2p_key)) in near_keys.iter().zip(p2p_keys.iter()).enumerate() {
        let account = format!("node{i}.{SANDBOX_ROOT_ACCOUNT}");
        let client = blockchain.client_for(&account, near_key)?;
        let pubkey =
            near_mpc_crypto_types::Ed25519PublicKey::from(p2p_key.verifying_key().to_bytes());
        contract
            .call_from(
                &client,
                method_names::SUBMIT_PARTICIPANT_INFO,
                json!({
                    "proposed_participant_attestation": { "Mock": "Valid" },
                    "tls_public_key": pubkey,
                }),
            )
            .await
            .with_context(|| format!("failed to submit attestation for node {i}"))?;
    }

    wait_for_contract_state(contract, Duration::from_secs(30), |s| {
        matches!(s, ProtocolContractState::Running(_))
    })
    .await
    .context("contract did not reach Running state after init")
}

async fn add_initial_domains(
    blockchain: &NearBlockchain,
    contract: &DeployedContract,
    near_keys: &[SigningKey],
    domains: &[DomainConfig],
) -> anyhow::Result<()> {
    tracing::info!(count = domains.len(), "adding domains");
    let args = json!({ "domains": domains });

    for (i, key) in near_keys.iter().enumerate() {
        let account = format!("node{i}.{SANDBOX_ROOT_ACCOUNT}");
        let client = blockchain.client_for(&account, key)?;
        contract
            .call_from(&client, method_names::VOTE_ADD_DOMAINS, args.clone())
            .await
            .with_context(|| format!("node {i} failed to vote add domains"))?;
    }

    wait_for_contract_state(contract, Duration::from_secs(60), |s| {
        matches!(s, ProtocolContractState::Initializing(_))
    })
    .await
    .context("contract did not reach Initializing state after domain addition")?;

    wait_for_contract_state(contract, Duration::from_secs(120), |s| {
        matches!(s, ProtocolContractState::Running(_))
    })
    .await
    .context("contract did not reach Running state after key generation")
}

fn start_mpc_nodes(
    config: &MpcClusterConfig,
    sandbox: &NearSandbox,
    near_keys: &[SigningKey],
    p2p_keys: &[SigningKey],
    contract_account: &AccountId,
    test_dir: &Path,
    ports: &E2ePortAllocator,
) -> anyhow::Result<Vec<MpcNodeState>> {
    let chain_id = sandbox.chain_id()?;
    let genesis_path = sandbox.genesis_path();
    let boot_nodes = sandbox.boot_nodes()?;

    tracing::info!(count = config.num_nodes, "starting MPC nodes");
    let mut nodes = Vec::new();
    for i in 0..config.num_nodes {
        let binary_path = if config.binary_paths.len() == 1 {
            config.binary_paths[0].clone()
        } else {
            config.binary_paths[i].clone()
        };

        let setup = MpcNodeSetup::new(MpcNodeSetupArgs {
            node_index: i,
            home_dir: test_dir.join(format!("node{i}")),
            binary_path,
            signer_account_id: format!("node{i}.{SANDBOX_ROOT_ACCOUNT}").parse()?,
            p2p_signing_key: p2p_keys[i].clone(),
            near_signer_key: near_keys[i].clone(),
            ports: NodePorts::from_allocator(ports, i),
            mpc_contract_id: contract_account.clone(),
            triples_to_buffer: config.triples_to_buffer,
            presignatures_to_buffer: config.presignatures_to_buffer,
            chain_id: chain_id.clone(),
            near_genesis_path: genesis_path.clone(),
            near_boot_nodes: boot_nodes.clone(),
        })?;
        nodes.push(MpcNodeState::Running(setup.start()?));
    }
    Ok(nodes)
}

/// Creates user accounts for test interactions under SANDBOX_ROOT_ACCOUNT.
async fn create_user_accounts(
    blockchain: &NearBlockchain,
    num_accounts: u64,
) -> anyhow::Result<HashMap<AccountId, SigningKey>> {
    let mut map = HashMap::new();
    for i in 0..num_accounts {
        let key = generate_deterministic_key(200 + i);
        let account: AccountId = format!("user{i}.{SANDBOX_ROOT_ACCOUNT}").parse()?;
        blockchain
            .create_account(account.as_ref(), 100, &key)
            .await?;
        map.insert(account, key);
    }
    Ok(map)
}

fn build_participants(
    num_nodes: usize,
    p2p_keys: &[SigningKey],
    ports: &E2ePortAllocator,
) -> Participants {
    let mut list = Vec::new();
    for (i, key) in p2p_keys.iter().enumerate().take(num_nodes) {
        let account_id = ContractAccountId(format!("node{i}.{SANDBOX_ROOT_ACCOUNT}"));
        let pubkey = near_mpc_crypto_types::Ed25519PublicKey::from(key.verifying_key().to_bytes());
        list.push((
            account_id,
            ParticipantId(i as u32),
            ParticipantInfo {
                url: format!("http://127.0.0.1:{}", ports.p2p_port(i)),
                sign_pk: String::from(&pubkey),
            },
        ));
    }
    Participants {
        next_id: ParticipantId(num_nodes as u32),
        participants: list,
    }
}

fn build_participants_from_nodes(
    indices: &[usize],
    nodes: &[MpcNodeState],
    _ports: &E2ePortAllocator,
) -> Participants {
    let mut list = Vec::new();
    for (new_idx, &old_idx) in indices.iter().enumerate() {
        list.push((
            ContractAccountId(nodes[old_idx].account_id().to_string()),
            ParticipantId(new_idx as u32),
            ParticipantInfo {
                url: nodes[old_idx].p2p_url(),
                sign_pk: nodes[old_idx].p2p_public_key_str(),
            },
        ));
    }
    Participants {
        next_id: ParticipantId(indices.len() as u32),
        participants: list,
    }
}

fn generate_deterministic_key(seed: u64) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

async fn wait_for_contract_state(
    contract: &DeployedContract,
    timeout: Duration,
    predicate: impl Fn(&ProtocolContractState) -> bool,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match contract.state().await {
            Ok(state) if predicate(&state) => return Ok(()),
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "failed to query contract state (retrying)"),
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "contract state predicate not satisfied within {}s",
                timeout.as_secs()
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
