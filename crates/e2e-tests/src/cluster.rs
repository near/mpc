use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use backon::{ConstantBuilder, Retryable};
use ed25519_dalek::SigningKey;
use near_kit::AccountId;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{
    AccountId as ContractAccountId, CKDAppPublicKey, Curve, DomainConfig, DomainId, DomainPurpose,
    Ed25519PublicKey, EpochId, ParticipantId, ParticipantInfo, Participants, Protocol,
    ProtocolContractState, Threshold, ThresholdParameters,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::json;

use crate::blockchain::{ClientHandle, DeployedContract, NearBlockchain};
use crate::mpc_node::{MpcNode, MpcNodeSetup, MpcNodeSetupArgs, NodePorts};
use crate::near_sandbox::NearSandbox;
use crate::port_allocator::E2ePortAllocator;

const DEFAULT_SANDBOX_VERSION: &str = "2.11.1";
const SANDBOX_ROOT_ACCOUNT: &str = "sandbox";
const SANDBOX_ROOT_SECRET_KEY: &str = near_sandbox::config::DEFAULT_GENESIS_ACCOUNT_PRIVATE_KEY;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const DEFAULT_TRIPLES_TO_BUFFER: usize = 20;
pub const DEFAULT_PRESIGNATURES_TO_BUFFER: usize = 10;
// Concurrent e2e tests on a shared CI runner can stretch
// triple/presignature generation past 120 s; the most pressure-sensitive
// consumer is `wait_for_presignatures` (see `parallel_sign_calls` test).
pub const CLUSTER_WAIT_TIMEOUT: Duration = Duration::from_secs(240);
const SIGN_GAS: near_kit::Gas = near_kit::Gas::from_tgas(15);
// AppPublicKeyPV does an on-chain bls12381_pairing_check (2 pairs) before yielding,
// which costs significantly more than a plain CKD or sign request.
const CKD_PV_GAS: near_kit::Gas = near_kit::Gas::from_tgas(100);
const SIGN_DEPOSIT: near_kit::NearToken = near_kit::NearToken::from_yoctonear(1);
const CONTRACT_UPDATE_DEPOSIT: near_kit::NearToken = near_kit::NearToken::from_millinear(17_000);
const CONTRACT_UPDATE_GAS: near_kit::Gas = near_kit::Gas::from_tgas(300);
const CONTRACT_DEPLOY_TIMEOUT: Duration = Duration::from_secs(15);
const PROPOSER_NODE_INDEX: usize = 0;

// Seed offsets for `generate_deterministic_key` — each range holds up to 100 keys.
const KEY_SEED_NEAR_SIGNER: u64 = 0;
const KEY_SEED_P2P: u64 = 100;
const KEY_SEED_OPERATOR: u64 = 200;
const KEY_SEED_MIGRATION_P2P: u64 = 300;
const KEY_SEED_MIGRATION_NEAR_SIGNER: u64 = 400;

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
    /// Version of the `near-sandbox` binary (e.g. `"2.6.3"`, `"2.10.4"`).
    pub sandbox_version: String,
    /// Root directory for all test artifacts (logs, configs, DB). If `None`, a temp dir is created.
    pub home_base: Option<PathBuf>,
    /// Indices (into the node array) of nodes that are initial participants.
    /// An empty vec means all nodes are participants. Set to a subset to start
    /// extra non-participant nodes (useful for resharing and attestation tests).
    pub initial_participant_indices: Vec<usize>,
    /// Per-node foreign chains configuration. If empty, all nodes get the default
    /// (empty) config. If non-empty, must have exactly `num_nodes` entries.
    pub node_foreign_chains_configs: Vec<mpc_node_config::ForeignChainsConfig>,
    /// Migration targets: each entry is a source node index. The i-th entry
    /// produces a target node at index `num_nodes + i` that shares the
    /// source's NEAR account but gets a distinct P2P key. Started with the
    /// cluster so their indexers sync before blocks accumulate (`start_near_node`
    /// blocks until synced).
    pub migration_targets: Vec<usize>,
    /// Wire format used when calling `init`. See [`ContractInitFormat`].
    pub init_format: ContractInitFormat,
}

/// JSON wire format used for the contract's `init` call.
///
/// Whenever a wire-breaking change to an `init` argument lands (e.g. the
/// `sign_pk` → `tls_public_key` rename in 3.10), a new variant is needed so
/// the cluster can still target the older production contract.
///
/// # Maintaining this enum across upgrades
///
/// - **When a new wire-breaking change to `init` lands**: add a new variant
///   (e.g. `Legacy3_10_X`) that emits the now-old shape, and update the
///   `init_contract` helper in `cluster.rs` to branch on it.
/// - **After the breaking change has rolled out to Mainnet/Testnet**: remove
///   the obsolete variant and any tests that pin to it. The `current_*()`
///   pointers in `contract-history` will already reference a binary that
///   speaks the new format, so `Current` is enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ContractInitFormat {
    /// Current `ThresholdParameters` shape (uses `tls_public_key`).
    #[default]
    Current,
    /// Pre-3.10 `ThresholdParameters` shape (uses `sign_pk`). Only the field
    /// inside `ParticipantInfo` differs; everything else is forward-compatible
    /// because the 3.9.1 contract ignores unknown JSON fields. Remove this
    /// variant once `contract_history::current_*()` no longer points at a
    /// binary that requires the legacy shape.
    Legacy3_9_1,
}

impl MpcClusterConfig {
    /// Sensible defaults for a basic E2E test.
    ///
    /// - 3 nodes, 2-of-3 threshold
    /// - All 3 standard domains (Secp256k1, Edwards25519, Bls12381)
    /// - 10 triples, 10 presignatures per node
    pub fn default_for_test(port_seed: u16, contract_wasm: Vec<u8>) -> Self {
        Self {
            num_nodes: 3,
            threshold: 2,
            domains: vec![
                DomainConfig {
                    id: DomainId(0),
                    curve: Curve::Secp256k1,
                    protocol: Protocol::CaitSith,
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(1),
                    curve: Curve::Edwards25519,
                    protocol: Protocol::Frost,
                    purpose: DomainPurpose::Sign,
                },
                DomainConfig {
                    id: DomainId(2),
                    curve: Curve::Bls12381,
                    protocol: Protocol::ConfidentialKeyDerivation,
                    purpose: DomainPurpose::CKD,
                },
            ],
            binary_paths: vec![default_mpc_binary_path()],
            contract_wasm,
            port_seed,
            triples_to_buffer: DEFAULT_TRIPLES_TO_BUFFER,
            presignatures_to_buffer: DEFAULT_PRESIGNATURES_TO_BUFFER,
            sandbox_version: DEFAULT_SANDBOX_VERSION.to_string(),
            home_base: None,
            initial_participant_indices: vec![],
            node_foreign_chains_configs: vec![],
            migration_targets: vec![],
            init_format: ContractInitFormat::Current,
        }
    }

    /// Returns the resolved participant indices.
    /// An empty `initial_participant_indices` means all nodes are participants.
    pub fn participant_indices(&self) -> Vec<usize> {
        if self.initial_participant_indices.is_empty() {
            (0..self.num_nodes).collect()
        } else {
            self.initial_participant_indices.clone()
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        for (i, &source_idx) in self.migration_targets.iter().enumerate() {
            anyhow::ensure!(
                source_idx < self.num_nodes,
                "migration_targets[{i}]: source index {source_idx} must be < num_nodes ({})",
                self.num_nodes,
            );
        }
        Ok(())
    }
}

fn default_mpc_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/mpc-node")
}

/// A running MPC test cluster with a deployed contract and N mpc-node processes.
///
/// Orchestrates the full test environment: sandbox -> contract ->
/// accounts -> attestations -> domains -> mpc-node processes.
///
/// All nodes are killed when dropped.
pub struct MpcCluster {
    pub sandbox: NearSandbox,
    pub blockchain: NearBlockchain,
    pub contract: DeployedContract,
    pub nodes: Vec<MpcNodeState>,
    pub node_keys: Vec<SigningKey>,
    /// Separate access keys used by the test to cast votes on node accounts.
    /// Disjoint from `node_keys` so the MPC node's own nonce sequence is never disturbed.
    pub operator_keys: Vec<SigningKey>,
    pub threshold: usize,
    pub user_accounts: HashMap<AccountId, SigningKey>,
    pub ports: E2ePortAllocator,
    /// Held to keep the temp directory alive for the lifetime of the cluster.
    pub test_dir: tempfile::TempDir,
}

impl MpcCluster {
    /// Create the full cluster: start sandbox, deploy contract,
    /// create accounts, submit attestations, add domains, spawn mpc-node
    /// binaries, and wait for Running state.
    pub async fn start(config: MpcClusterConfig) -> anyhow::Result<Self> {
        config.validate()?;
        let threshold = config.threshold;
        let ports = E2ePortAllocator::new(config.port_seed);
        let test_dir = create_test_dir(&config.home_base)?;

        let sandbox = NearSandbox::start(&ports, &config.sandbox_version).await?;
        let root_secret_key: near_kit::SecretKey = SANDBOX_ROOT_SECRET_KEY
            .parse()
            .context("invalid sandbox root secret key")?;
        let blockchain =
            NearBlockchain::new(&sandbox.rpc_url(), SANDBOX_ROOT_ACCOUNT, root_secret_key)?;

        let contract_key = generate_deterministic_key(255);
        let contract_account: AccountId = format!("mpc.{SANDBOX_ROOT_ACCOUNT}").parse()?;
        let (mut node_keys, node_near_keys, node_p2p_keys, mut operator_keys) =
            generate_signing_keys(u64::try_from(config.num_nodes).unwrap());

        // Pre-generate keys for migration target nodes.
        // Migration targets share the source's NEAR account and operator
        // (mirroring the production scenario of one operator managing both
        // the old and new node), but get a fresh NEAR signer key so the new
        // node's transactions are distinguishable from the source's.
        for (i, &source_idx) in config.migration_targets.iter().enumerate() {
            let target_idx = config.num_nodes + i;
            node_keys.push(generate_deterministic_key(
                KEY_SEED_MIGRATION_NEAR_SIGNER + target_idx as u64,
            ));
            operator_keys.push(operator_keys[source_idx].clone());
        }

        let contract = deploy_contract(
            &blockchain,
            &contract_account,
            &contract_key,
            &config.contract_wasm,
        )
        .await?;

        let participant_indices = config.participant_indices();

        create_node_accounts(&blockchain, &node_near_keys, &operator_keys).await?;

        init_contract(
            &blockchain,
            &contract,
            &ports,
            InitContractArgs {
                near_keys: node_near_keys.clone(),
                p2p_keys: node_p2p_keys.clone(),
                threshold: config.threshold,
                participant_indices: participant_indices.clone(),
                init_format: config.init_format,
            },
        )
        .await?;

        // Start MPC nodes BEFORE adding domains: key generation requires running nodes.
        let mut nodes = start_mpc_nodes(
            &config,
            &sandbox,
            &node_near_keys,
            &node_p2p_keys,
            &contract_account,
            test_dir.path(),
            &ports,
        )?;

        ensure_nodes_alive(&mut nodes).await?;

        if !config.domains.is_empty() {
            // Only participants can vote to add domains.
            add_initial_domains(
                &blockchain,
                &contract,
                &operator_keys,
                &participant_indices,
                &config.domains,
            )
            .await?;
        }

        let user_accounts = create_user_accounts(&blockchain, 1).await?;

        tracing::info!("MPC cluster is ready");

        Ok(Self {
            sandbox,
            blockchain,
            contract,
            nodes,
            node_keys,
            operator_keys,
            threshold,
            user_accounts,
            ports,
            test_dir,
        })
    }

    /// Kill specific nodes. `node_keys` is not affected — indices are stable
    /// because remove+insert preserves the position.
    pub fn kill_nodes(&mut self, indices: &[usize]) -> anyhow::Result<()> {
        for &idx in indices {
            anyhow::ensure!(
                idx < self.nodes.len(),
                "node index {idx} out of bounds (have {} nodes)",
                self.nodes.len()
            );
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

    /// Reset stopped nodes to a clean state and start them, waiting for each
    /// node's health endpoint before returning. This ensures the node's web
    /// server and indexer are running before proceeding.
    pub async fn reset_and_start_nodes(&mut self, indices: &[usize]) -> anyhow::Result<()> {
        for &idx in indices {
            let state = self.nodes.remove(idx);
            let new_state = match state {
                MpcNodeState::Stopped(setup) => {
                    setup.reset_mpc_state()?;
                    MpcNodeState::Running(setup.start()?)
                }
                MpcNodeState::Running(node) => {
                    tracing::warn!(node = idx, "node already running");
                    MpcNodeState::Running(node)
                }
            };
            self.nodes.insert(idx, new_state);
        }

        // Wait for all restarted nodes to be healthy.
        for &idx in indices {
            self.wait_for_node_healthy(idx).await?;
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
    ) -> anyhow::Result<ProtocolContractState> {
        wait_for_contract_state(&self.contract, timeout, predicate).await
    }

    /// Wait until the node at `idx` responds with HTTP 200 on its `/health` endpoint.
    /// Returns an error if the node is not running or does not become healthy within 120 seconds.
    pub async fn wait_for_node_healthy(&self, idx: usize) -> anyhow::Result<()> {
        let node = match &self.nodes[idx] {
            MpcNodeState::Running(n) => n,
            _ => anyhow::bail!("node {idx} is not running"),
        };
        let client = reqwest::Client::new();
        let url = format!("http://{}/health", node.web_address());
        (|| async {
            let ok = matches!(client.get(&url).send().await, Ok(r) if r.status() == 200);
            anyhow::ensure!(ok, "not yet healthy");
            tracing::info!(node = idx, "node is healthy");
            Ok(())
        })
        // 120s deadline: 120_000ms / 500ms = 240 attempts
        .retry(
            ConstantBuilder::default()
                .with_delay(POLL_INTERVAL)
                .with_max_times(240),
        )
        .await
        .with_context(|| format!("node {idx} did not become healthy within 120s"))
    }

    /// Query all accounts that have TEE attestations stored in the contract.
    pub async fn get_tee_accounts(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        self.contract.view(method_names::GET_TEE_ACCOUNTS).await
    }

    /// Vote to add domains and wait until the contract returns to the `Running`
    /// state (i.e. key generation has completed for all new domains).
    /// Use `start_add_domains` to stop waiting once `Initializing` is entered.
    pub async fn add_domains_and_wait(&self, domains: Vec<DomainConfig>) -> anyhow::Result<()> {
        self.start_add_domains(domains).await?;

        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .map(|_| ())
    }

    /// Vote to add domains and wait only until the contract enters the
    /// `Initializing` state. Does NOT wait for key generation to complete —
    /// use `add_domains_and_wait` for the full flow.
    pub async fn start_add_domains(&self, domains: Vec<DomainConfig>) -> anyhow::Result<()> {
        let args = json!({ "domains": domains });
        self.call_from_all_nodes_concurrently(method_names::VOTE_ADD_DOMAINS, args)
            .await?;

        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Initializing(_)),
            Duration::from_secs(30),
        )
        .await
        .map(|_| ())
    }

    /// Vote to cancel an in-progress keygen from a specific node.
    /// Returns the execution outcome so callers can check success/failure.
    pub async fn vote_cancel_keygen_from(
        &self,
        node_index: usize,
        next_domain_id: u64,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let client = self.operator_client_for(node_index)?;
        self.contract
            .call_from(
                &client,
                method_names::VOTE_CANCEL_KEYGEN,
                json!({ "next_domain_id": next_domain_id }),
            )
            .await
            .with_context(|| format!("node {node_index} failed to send cancel keygen vote"))
    }

    /// Vote for resharing and wait until the contract enters Resharing state.
    /// Does NOT wait for resharing to complete — use `start_resharing_and_wait`.
    pub async fn start_resharing(
        &self,
        new_participants: &[usize],
        new_threshold: usize,
    ) -> anyhow::Result<()> {
        self.wait_for_participant_attestations(new_participants)
            .await?;

        let state = self.get_contract_state().await?;
        let (prospective_epoch_id, current_participants) = match &state {
            ProtocolContractState::Running(r) => {
                let base = r
                    .previously_cancelled_resharing_epoch_id
                    .unwrap_or(r.keyset.epoch_id);
                (EpochId(base.0 + 1), &r.parameters.participants)
            }
            _ => anyhow::bail!("cannot reshare: contract not in Running state"),
        };

        let participants =
            build_participants_from_nodes(new_participants, &self.nodes, current_participants);
        let proposal = ThresholdParameters {
            threshold: Threshold(new_threshold as u64),
            participants,
        };

        tracing::info!(?prospective_epoch_id, new_threshold, "voting for resharing");
        let args = json!({ "prospective_epoch_id": prospective_epoch_id, "proposal": proposal });
        self.vote_resharing(current_participants, args).await?;

        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Resharing(_)),
            Duration::from_secs(30),
        )
        .await
        .map(|_| ())
    }

    /// Full resharing: vote, wait for Resharing, then wait for Running.
    pub async fn start_resharing_and_wait(
        &self,
        new_participants: &[usize],
        new_threshold: usize,
    ) -> anyhow::Result<()> {
        self.start_resharing(new_participants, new_threshold)
            .await?;
        self.wait_for_state(
            |s| matches!(s, ProtocolContractState::Running(_)),
            CLUSTER_WAIT_TIMEOUT,
        )
        .await
        .map(|_| ())
    }

    /// Poll until all proposed participants have TEE attestations on-chain.
    async fn wait_for_participant_attestations(
        &self,
        node_indices: &[usize],
    ) -> anyhow::Result<()> {
        let required: Vec<String> = node_indices
            .iter()
            .map(|&idx| self.nodes[idx].account_id().to_string())
            .collect();
        (|| async {
            let tee_accounts = self.get_tee_accounts().await?;
            let have: std::collections::HashSet<String> = tee_accounts
                .iter()
                .filter_map(|v| v.get("account_id")?.as_str().map(String::from))
                .collect();
            anyhow::ensure!(
                required.iter().all(|a| have.contains(a)),
                "not all proposed participants have TEE attestations (need: {required:?}, have: {have:?})"
            );
            Ok(())
        })
        // 120s deadline: 120_000ms / 500ms = 240 attempts
        .retry(ConstantBuilder::default().with_delay(POLL_INTERVAL).with_max_times(240))
        .await
    }

    /// Vote for resharing from all running nodes: current participants first,
    /// then candidates. The contract requires threshold participant votes
    /// before candidates can vote.
    async fn vote_resharing(
        &self,
        current_participants: &Participants,
        args: serde_json::Value,
    ) -> anyhow::Result<()> {
        let current_accounts: std::collections::HashSet<_> = current_participants
            .participants
            .iter()
            .map(|(a, _, _)| a.to_string())
            .collect();

        let mut participants_first: Vec<usize> = Vec::new();
        let mut candidates_second: Vec<usize> = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
            if !matches!(node, MpcNodeState::Running(_)) {
                continue;
            }
            let acct: &str = node.account_id().as_ref();
            if current_accounts.contains(acct) {
                participants_first.push(i);
            } else {
                candidates_second.push(i);
            }
        }

        for i in participants_first.iter().chain(candidates_second.iter()) {
            let client = self.operator_client_for(*i)?;
            let outcome = self
                .contract
                .call_from(&client, method_names::VOTE_NEW_PARAMETERS, args.clone())
                .await
                .with_context(|| format!("node {i} failed to send resharing vote"))?;
            if !outcome.is_success() {
                tracing::warn!(
                    node = i,
                    failure = ?outcome.failure_message(),
                    "resharing vote failed"
                );
            } else {
                tracing::debug!(node = i, "resharing vote succeeded");
            }
        }
        Ok(())
    }

    /// Vote to cancel an active resharing from a specific node.
    /// Returns the execution outcome so callers can check success/failure.
    pub async fn vote_cancel_resharing_from(
        &self,
        node_index: usize,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let client = self.operator_client_for(node_index)?;
        self.contract
            .call_from(&client, method_names::VOTE_CANCEL_RESHARING, json!({}))
            .await
            .with_context(|| format!("node {node_index} failed to send cancel resharing vote"))
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
        predicate: impl Fn(i64) -> bool,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let max_times = (timeout.as_millis() / POLL_INTERVAL.as_millis()) as usize;
        (|| async {
            let values = self.get_metric_all_nodes(name).await?;
            anyhow::ensure!(
                values.iter().all(|v| v.is_some_and(&predicate)),
                "metric {name} predicate not satisfied on all nodes (values: {values:?})"
            );
            Ok(())
        })
        .retry(
            ConstantBuilder::default()
                .with_delay(POLL_INTERVAL)
                .with_max_times(max_times),
        )
        .await
        .with_context(|| {
            format!(
                "metric {name} predicate not satisfied within {}s",
                timeout.as_secs()
            )
        })
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

    /// Send a sign request from the given user account and return the outcome.
    pub async fn send_sign_request(
        &self,
        domain_id: DomainId,
        payload: serde_json::Value,
        account_id: &AccountId,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let client = self.user_client(account_id)?;
        let args = json!({
            "request": {
                "domain_id": domain_id,
                "path": "test",
                "payload_v2": payload,
            }
        });
        self.contract
            .call_from_with_deposit(&client, method_names::SIGN, args, SIGN_GAS, SIGN_DEPOSIT)
            .await
    }

    /// Send a CKD (Confidential Key Derivation) request from the given user account.
    ///
    /// Gas is derived from the `CKDAppPublicKey` variant.
    pub async fn send_ckd_request(
        &self,
        domain_id: DomainId,
        app_public_key: CKDAppPublicKey,
        account_id: &AccountId,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let gas = match app_public_key {
            CKDAppPublicKey::AppPublicKey(_) => SIGN_GAS,
            CKDAppPublicKey::AppPublicKeyPV(_) => CKD_PV_GAS,
        };
        let client = self.user_client(account_id)?;
        let args = json!({
            "request": {
                "domain_id": domain_id,
                "derivation_path": "test",
                "app_public_key": app_public_key,
            }
        });
        self.contract
            .call_from_with_deposit(
                &client,
                method_names::REQUEST_APP_PRIVATE_KEY,
                args,
                gas,
                SIGN_DEPOSIT,
            )
            .await
    }

    /// View migration info from the contract.
    pub async fn view_migration_info<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
    ) -> anyhow::Result<T> {
        self.contract.view(method_names::MIGRATION_INFO).await
    }

    /// Build a [`ClientHandle`] for the operator key of the given node.
    pub fn operator_client_for(&self, node_index: usize) -> anyhow::Result<ClientHandle> {
        let node = &self.nodes[node_index];
        self.blockchain
            .client_for(node.account_id().as_ref(), &self.operator_keys[node_index])
    }

    /// Register backup service info for a node.
    pub async fn register_backup_service(
        &self,
        node_index: usize,
        backup_service_info: serde_json::Value,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let client = self.operator_client_for(node_index)?;
        self.contract
            .call_from(
                &client,
                method_names::REGISTER_BACKUP_SERVICE,
                json!({ "backup_service_info": backup_service_info }),
            )
            .await
    }
    /// View the foreign chains the contract accepts requests for.
    pub async fn view_foreign_chains_supported_by_contract(
        &self,
    ) -> anyhow::Result<near_mpc_contract_interface::types::SupportedForeignChains> {
        self.contract
            .view(method_names::GET_SUPPORTED_FOREIGN_CHAINS)
            .await
    }

    /// View the per-node foreign chain configurations registered with the contract.
    pub async fn view_foreign_chain_configurations(
        &self,
    ) -> anyhow::Result<near_mpc_contract_interface::types::ForeignChainSupportByNode> {
        self.contract
            .view(method_names::GET_FOREIGN_CHAIN_SUPPORT_BY_NODE)
            .await
    }

    /// Register foreign chain support on the contract for a specific node.
    pub async fn register_foreign_chain_config(
        &self,
        node_index: usize,
        foreign_chain_support: &near_mpc_contract_interface::types::SupportedForeignChains,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let node = &self.nodes[node_index];
        let client = self
            .blockchain
            .client_for(node.account_id().as_ref(), &self.operator_keys[node_index])?;
        self.contract
            .call_from(
                &client,
                method_names::REGISTER_FOREIGN_CHAIN_SUPPORT,
                json!({
                    "foreign_chain_support": serde_json::to_value(foreign_chain_support)?,
                }),
            )
            .await
    }

    /// Start node migration for a specific node.
    pub async fn start_node_migration(
        &self,
        node_index: usize,
        destination_node_info: serde_json::Value,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let client = self.operator_client_for(node_index)?;
        self.contract
            .call_from(
                &client,
                method_names::START_NODE_MIGRATION,
                json!({ "destination_node_info": destination_node_info }),
            )
            .await
    }

    /// Send a verify_foreign_transaction request from the default user account.
    pub async fn send_verify_foreign_transaction(
        &self,
        request: &near_mpc_contract_interface::types::VerifyForeignTransactionRequestArgs,
    ) -> anyhow::Result<near_kit::FinalExecutionOutcome> {
        let user = self.default_user_account().clone();
        let client = self.user_client(&user)?;
        self.contract
            .call_from_with_deposit(
                &client,
                method_names::VERIFY_FOREIGN_TRANSACTION,
                json!({ "request": serde_json::to_value(request)? }),
                SIGN_GAS,
                SIGN_DEPOSIT,
            )
            .await
    }

    /// Propose a contract code update and cast votes until `vote_update` reports
    /// the threshold reached. Pair with [`Self::assert_deployed_code`]: the deploy
    /// and `migrate()` promise runs asynchronously, and a panicking `migrate`
    /// rolls the deploy back without changing the threshold-reached signal.
    pub async fn propose_and_vote_contract_update(&self, new_wasm: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.nodes.is_empty(),
            "cannot propose contract update with no nodes"
        );

        let propose_args = ProposeUpdateArgsBorsh {
            code: Some(new_wasm),
            config: None,
        };
        let proposer_client = self.operator_client_for(PROPOSER_NODE_INDEX)?;
        let outcome = self
            .contract
            .call_from_borsh_with_deposit(
                &proposer_client,
                method_names::PROPOSE_UPDATE,
                propose_args,
                CONTRACT_UPDATE_GAS,
                CONTRACT_UPDATE_DEPOSIT,
            )
            .await
            .context("failed to call propose_update")?;
        anyhow::ensure!(
            outcome.is_success(),
            "propose_update failed: {:?}",
            outcome.failure_message()
        );
        let proposal_id: UpdateId = outcome
            .json()
            .context("propose_update did not return a JSON UpdateId")?;

        for (i, _) in self.nodes.iter().enumerate() {
            let client = self.operator_client_for(i)?;
            let vote_outcome = self
                .contract
                .call_from(
                    &client,
                    method_names::VOTE_UPDATE,
                    json!({ "id": proposal_id }),
                )
                .await
                .with_context(|| format!("node {i} failed to call vote_update"))?;
            anyhow::ensure!(
                vote_outcome.is_success(),
                "vote_update from node {i} failed: {:?}",
                vote_outcome.failure_message()
            );
            let update_applied: bool = vote_outcome
                .json()
                .with_context(|| format!("vote_update from node {i} returned non-bool"))?;
            if update_applied {
                anyhow::ensure!(
                    i + 1 == self.threshold,
                    "expected exactly {} votes to apply update, got {}",
                    self.threshold,
                    i + 1,
                );
                tracing::info!(votes = i + 1, "contract code update vote threshold reached");
                return Ok(());
            }
        }
        anyhow::bail!("contract code update was not applied after votes from every node")
    }

    /// Wait until the deployed contract code hash matches `sha256(expected_wasm)`.
    pub async fn assert_deployed_code(&self, expected_wasm: &[u8]) -> anyhow::Result<()> {
        let expected = near_kit::CryptoHash::hash(expected_wasm);
        let deadline = tokio::time::Instant::now() + CONTRACT_DEPLOY_TIMEOUT;
        loop {
            let deployed = self.contract.code_hash().await?;
            if deployed == expected {
                tracing::info!(
                    code_hash = %hex::encode(deployed.as_bytes()),
                    "deployed code matches expected WASM",
                );
                return Ok(());
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "deployed code hash {} does not match expected {} — `migrate` likely panicked \
                 and the deploy was rolled back",
                hex::encode(deployed.as_bytes()),
                hex::encode(expected.as_bytes()),
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
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

    pub fn p2p_public_key(&self) -> Ed25519PublicKey {
        match self {
            MpcNodeState::Running(n) => n.setup().p2p_public_key(),
            MpcNodeState::Stopped(s) => s.p2p_public_key(),
        }
    }

    pub fn p2p_url(&self) -> String {
        match self {
            MpcNodeState::Running(n) => n.setup().p2p_url(),
            MpcNodeState::Stopped(s) => s.p2p_url(),
        }
    }

    pub fn p2p_public_key_str(&self) -> String {
        String::from(&self.p2p_public_key())
    }

    pub fn backup_encryption_key_hex(&self) -> &str {
        match self {
            MpcNodeState::Running(n) => n.setup().backup_encryption_key_hex(),
            MpcNodeState::Stopped(s) => s.backup_encryption_key_hex(),
        }
    }

    pub fn near_signer_public_key_str(&self) -> String {
        match self {
            MpcNodeState::Running(n) => n.setup().near_signer_public_key_str(),
            MpcNodeState::Stopped(s) => s.near_signer_public_key_str(),
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

fn generate_signing_keys(
    num_nodes: u64,
) -> (
    Vec<SigningKey>,
    Vec<SigningKey>,
    Vec<SigningKey>,
    Vec<SigningKey>,
) {
    let mut node_keys = Vec::new();
    let mut near_keys = Vec::new();
    let mut p2p_keys = Vec::new();
    let mut operator_keys = Vec::new();
    for i in 0..num_nodes {
        let near_key = generate_deterministic_key(KEY_SEED_NEAR_SIGNER + i);
        let p2p_key = generate_deterministic_key(KEY_SEED_P2P + i);
        let operator_key = generate_deterministic_key(KEY_SEED_OPERATOR + i);
        node_keys.push(near_key.clone());
        near_keys.push(near_key);
        p2p_keys.push(p2p_key);
        operator_keys.push(operator_key);
    }
    (node_keys, near_keys, p2p_keys, operator_keys)
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
    operator_keys: &[SigningKey],
) -> anyhow::Result<()> {
    for (i, (near_key, operator_key)) in near_keys.iter().zip(operator_keys).enumerate() {
        let account = format!("node{i}.{SANDBOX_ROOT_ACCOUNT}");
        tracing::info!(account = %account, "creating MPC node account");
        blockchain
            .create_account_with_keys(&account, 100, &[near_key.clone(), operator_key.clone()])
            .await?;
    }
    Ok(())
}

struct InitContractArgs {
    near_keys: Vec<SigningKey>,
    p2p_keys: Vec<SigningKey>,
    threshold: usize,
    participant_indices: Vec<usize>,
    init_format: ContractInitFormat,
}

async fn init_contract(
    blockchain: &NearBlockchain,
    contract: &DeployedContract,
    ports: &E2ePortAllocator,
    args: InitContractArgs,
) -> anyhow::Result<()> {
    let InitContractArgs {
        near_keys,
        p2p_keys,
        threshold,
        participant_indices,
        init_format,
    } = args;

    let participants = build_participants(&participant_indices, &p2p_keys, ports);
    let params = ThresholdParameters {
        threshold: Threshold(threshold as u64),
        participants,
    };

    tracing::info!(
        threshold,
        num_participants = participant_indices.len(),
        ?init_format,
        "initializing contract"
    );
    let parameters_json = match init_format {
        ContractInitFormat::Current => serde_json::to_value(&params)?,
        ContractInitFormat::Legacy3_9_1 => {
            serde_json::to_value(LegacyThresholdParameters::from(&params))?
        }
    };
    let outcome = contract
        .call(method_names::INIT, json!({ "parameters": parameters_json }))
        .await?;
    anyhow::ensure!(
        outcome.is_success(),
        "init failed: {:?}",
        outcome.failure_message()
    );

    for &i in &participant_indices {
        let account = format!("node{i}.{SANDBOX_ROOT_ACCOUNT}");
        let client = blockchain.client_for(&account, &near_keys[i])?;
        let pubkey =
            near_mpc_crypto_types::Ed25519PublicKey::from(p2p_keys[i].verifying_key().to_bytes());
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
    .map(|_| ())
    .context("contract did not reach Running state after init")
}

async fn add_initial_domains(
    blockchain: &NearBlockchain,
    contract: &DeployedContract,
    operator_keys: &[SigningKey],
    participant_indices: &[usize],
    domains: &[DomainConfig],
) -> anyhow::Result<()> {
    tracing::info!(count = domains.len(), "adding domains");
    let args = json!({ "domains": domains });

    for &i in participant_indices {
        let account = format!("node{i}.{SANDBOX_ROOT_ACCOUNT}");
        let client = blockchain.client_for(&account, &operator_keys[i])?;
        contract
            .call_from(&client, method_names::VOTE_ADD_DOMAINS, args.clone())
            .await
            .with_context(|| format!("node {i} failed to vote add domains"))?;
    }

    wait_for_contract_state(contract, Duration::from_secs(30), |s| {
        matches!(s, ProtocolContractState::Initializing(_))
    })
    .await
    .context("contract did not reach Initializing state after domain addition")?;

    wait_for_contract_state(contract, CLUSTER_WAIT_TIMEOUT, |s| {
        matches!(s, ProtocolContractState::Running(_))
    })
    .await
    .map(|_| ())
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

    let total_nodes = config.num_nodes + config.migration_targets.len();
    tracing::info!(
        count = total_nodes,
        participants = config.num_nodes,
        "starting MPC nodes"
    );
    let mut nodes = Vec::new();
    for i in 0..config.num_nodes {
        let binary_path = if config.binary_paths.len() == 1 {
            config.binary_paths[0].clone()
        } else {
            config.binary_paths[i].clone()
        };

        let foreign_chains_config = if config.node_foreign_chains_configs.is_empty() {
            Default::default()
        } else {
            config.node_foreign_chains_configs[i].clone()
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
            foreign_chains_config,
        })?;
        nodes.push(MpcNodeState::Running(setup.start()?));
    }

    // Start migration target nodes alongside the participants so their
    // near-indexers sync from the same early point in the chain.
    for (i, &source_idx) in config.migration_targets.iter().enumerate() {
        let target_idx = config.num_nodes + i;
        let source = match &nodes[source_idx] {
            MpcNodeState::Running(n) => n.setup(),
            MpcNodeState::Stopped(s) => s,
        };
        let setup = MpcNodeSetup::new(MpcNodeSetupArgs {
            node_index: target_idx,
            home_dir: test_dir.join(format!("node{target_idx}")),
            binary_path: source.binary_path().to_path_buf(),
            signer_account_id: source.account_id().clone(),
            p2p_signing_key: generate_deterministic_key(KEY_SEED_MIGRATION_P2P + target_idx as u64),
            near_signer_key: source.near_signer_key().clone(),
            ports: NodePorts::from_allocator(ports, target_idx),
            mpc_contract_id: contract_account.clone(),
            triples_to_buffer: 10,
            presignatures_to_buffer: 10,
            chain_id: chain_id.clone(),
            near_genesis_path: genesis_path.clone(),
            near_boot_nodes: boot_nodes.clone(),
            foreign_chains_config: Default::default(),
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
            .create_account_with_keys(account.as_ref(), 100, &[key.clone()])
            .await?;
        map.insert(account, key);
    }
    Ok(map)
}

/// Borsh-encoded mirror of the contract's `ProposeUpdateArgs`. We keep it
/// local rather than depending on `mpc-contract` for two fields. `Config` is
/// modeled as `Option<()>` because we never propose a config-only update; the
/// `None` discriminator is `[0u8]` regardless of the inner type.
#[derive(borsh::BorshSerialize)]
struct ProposeUpdateArgsBorsh<'a> {
    code: Option<&'a [u8]>,
    config: Option<()>,
}

/// JSON mirror of the contract's `UpdateId`. `propose_update` returns it and
/// `vote_update` consumes it via the `id` field; both wire it as a bare u64.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct UpdateId(u64);

/// Pre-3.10 mirror of `ThresholdParameters` whose `ParticipantInfo` emits
/// `sign_pk` instead of `tls_public_key`. The 3.9.1 contract's
/// `ParticipantInfo` only knows the legacy field name (no serde alias), so
/// this rewrite is required when calling `init` against that binary.
#[derive(serde::Serialize)]
struct LegacyThresholdParameters {
    threshold: Threshold,
    participants: LegacyParticipants,
}

#[derive(serde::Serialize)]
struct LegacyParticipants {
    next_id: ParticipantId,
    participants: Vec<(ContractAccountId, ParticipantId, LegacyParticipantInfo)>,
}

#[derive(serde::Serialize)]
struct LegacyParticipantInfo {
    url: String,
    sign_pk: Ed25519PublicKey,
}

impl From<&ThresholdParameters> for LegacyThresholdParameters {
    fn from(params: &ThresholdParameters) -> Self {
        let participants = params
            .participants
            .participants
            .iter()
            .map(|(account_id, id, info)| {
                (
                    account_id.clone(),
                    *id,
                    LegacyParticipantInfo {
                        url: info.url.clone(),
                        sign_pk: info.tls_public_key.clone(),
                    },
                )
            })
            .collect();
        Self {
            threshold: params.threshold,
            participants: LegacyParticipants {
                next_id: params.participants.next_id,
                participants,
            },
        }
    }
}

fn build_participants(
    indices: &[usize],
    p2p_keys: &[SigningKey],
    ports: &E2ePortAllocator,
) -> Participants {
    let mut list = Vec::new();
    for (participant_id, &i) in indices.iter().enumerate() {
        let account_id: ContractAccountId =
            format!("node{i}.{SANDBOX_ROOT_ACCOUNT}").parse().unwrap();
        let pubkey = near_mpc_crypto_types::Ed25519PublicKey::from(&p2p_keys[i].verifying_key());
        list.push((
            account_id,
            ParticipantId(participant_id as u32),
            ParticipantInfo {
                url: format!("http://127.0.0.1:{}", ports.p2p_port(i)),
                tls_public_key: pubkey,
            },
        ));
    }
    Participants {
        next_id: ParticipantId(indices.len() as u32),
        participants: list,
    }
}

/// Build a participant list for resharing, preserving existing IDs for nodes
/// that are already participants and assigning new IDs to newcomers.
fn build_participants_from_nodes(
    indices: &[usize],
    nodes: &[MpcNodeState],
    current: &Participants,
) -> Participants {
    let mut next_id = current.next_id;
    let mut list = Vec::new();
    for &node_idx in indices {
        let account: ContractAccountId = nodes[node_idx].account_id().clone();
        let id = current
            .participants
            .iter()
            .find(|(a, _, _)| *a == account)
            .map(|(_, id, _)| *id)
            .unwrap_or_else(|| {
                let id = next_id;
                next_id = ParticipantId(next_id.0 + 1);
                id
            });
        list.push((
            account,
            id,
            ParticipantInfo {
                url: nodes[node_idx].p2p_url(),
                tls_public_key: nodes[node_idx].p2p_public_key(),
            },
        ));
    }
    Participants {
        next_id,
        participants: list,
    }
}

fn generate_deterministic_key(seed: u64) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(seed);
    SigningKey::generate(&mut rng)
}

/// Wait briefly and verify all running nodes haven't crashed.
async fn ensure_nodes_alive(nodes: &mut [MpcNodeState]) -> anyhow::Result<()> {
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (i, node) in nodes.iter_mut().enumerate() {
        if let MpcNodeState::Running(n) = node {
            anyhow::ensure!(
                !n.has_exited(),
                "mpc-node {i} exited early — check {}/{}",
                n.setup().home_dir().display(),
                crate::mpc_node::STDERR_LOG
            );
        }
    }
    Ok(())
}

async fn wait_for_contract_state(
    contract: &DeployedContract,
    timeout: Duration,
    predicate: impl Fn(&ProtocolContractState) -> bool,
) -> anyhow::Result<ProtocolContractState> {
    let max_times = (timeout.as_millis() / POLL_INTERVAL.as_millis()) as usize;
    (|| async {
        match contract.state().await {
            Ok(state) if predicate(&state) => Ok(state),
            Ok(_) => anyhow::bail!("predicate not yet satisfied"),
            Err(e) => {
                tracing::debug!(error = %e, "failed to query contract state (retrying)");
                Err(e)
            }
        }
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(POLL_INTERVAL)
            .with_max_times(max_times),
    )
    .await
    .with_context(|| {
        format!(
            "contract state predicate not satisfied within {}s",
            timeout.as_secs()
        )
    })
}
