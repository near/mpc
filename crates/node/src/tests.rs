use aes_gcm::{Aes256Gcm, KeyInit};
use mpc_contract::primitives::key_state::Keyset;
use mpc_contract::state::ProtocolContractState;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

use tokio::sync::{watch, RwLock};

use crate::config::{
    CKDConfig, ConfigFile, IndexerConfig, KeygenConfig, ParticipantsConfig, PersistentSecrets,
    PresignatureConfig, SecretsConfig, SignatureConfig, SyncMode, TripleConfig, WebUIConfig,
};
use crate::coordinator::Coordinator;
use crate::db::SecretDB;
use crate::indexer::fake::FakeIndexerManager;
use crate::indexer::handler::{CKDArgs, CKDRequestFromChain, SignArgs, SignatureRequestFromChain};
use crate::indexer::IndexerAPI;
use crate::keyshare::{KeyStorageConfig, Keyshare};
use crate::migration_service::spawn_recovery_server_and_run_onboarding;
use crate::p2p::testing::{generate_test_p2p_configs, PortSeed};

use crate::primitives::ParticipantId;
use crate::tests::common::MockTransactionSender;
use crate::tracking::{self, start_root_task, AutoAbortTask};
use crate::web::{start_web_server, static_web_data};
use assert_matches::assert_matches;
use mpc_contract::primitives::domain::{DomainConfig, SignatureScheme};
use mpc_contract::primitives::signature::{Bytes, Payload};
use near_indexer_primitives::types::Finality;
use near_indexer_primitives::CryptoHash;
use near_sdk::AccountId;
use near_time::Clock;
use rand::{Rng, RngCore};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tokio::time::timeout;

pub mod common;

mod basic_cluster;
mod benchmark;
mod changing_participant_details;
mod faulty;
mod multidomain;
mod onboarding;
mod research;
mod resharing;

const DEFAULT_BLOCK_TIME: std::time::Duration = std::time::Duration::from_millis(300);
const DEFAULT_MAX_PROTOCOL_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(30);
const DEFAULT_MAX_SIGNATURE_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(30);

/// Data needed to start running a test node.
pub struct OneNodeTestConfig {
    clock: Clock,
    home_dir: PathBuf,
    pub config: ConfigFile,
    secrets: SecretsConfig,
    indexer: IndexerAPI<MockTransactionSender>,
    _indexer_task: AutoAbortTask<()>,
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

pub fn make_key_storage_config(
    home_dir: PathBuf,
    local_encryption_key: [u8; 16],
) -> KeyStorageConfig {
    KeyStorageConfig {
        home_dir,
        local_encryption_key,
        gcp: None,
    }
}

pub async fn get_keyshares(
    home_dir: PathBuf,
    local_encryption_key: [u8; 16],
    keyset: &Keyset,
) -> anyhow::Result<Vec<Keyshare>> {
    let key_storage_config = make_key_storage_config(home_dir, local_encryption_key);
    let keystore = key_storage_config.create().await.unwrap();
    keystore.get_keyshares(keyset).await
}

impl OneNodeTestConfig {
    pub async fn run(self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.home_dir)?;
        let my_account_id = self.config.my_near_account_id.clone();
        async move {
            let root_future = async move {
                let root_task_handle = tracking::current_task();
                let root_task = OnceLock::new();
                let _ = root_task.set(root_task_handle);
                let (debug_request_sender, _) = tokio::sync::broadcast::channel(10);

                let (_, dummy_protocol_state_receiver) =
                    watch::channel(ProtocolContractState::NotInitialized);
                let (_, dummy_migration_state_receiver) = watch::channel((0, BTreeMap::new()));
                let web_server = start_web_server(
                    root_task.into(),
                    debug_request_sender.clone(),
                    self.config.web_ui.clone(),
                    static_web_data(&self.secrets, None),
                    dummy_protocol_state_receiver,
                    dummy_migration_state_receiver,
                )
                .await?;
                let _web_server = tracking::spawn_checked("web server", web_server);

                let secret_db = SecretDB::new(&self.home_dir, self.secrets.local_storage_aes_key)?;
                let key_storage_config =
                    make_key_storage_config(self.home_dir, self.secrets.local_storage_aes_key);
                let keystore = Arc::new(RwLock::new(
                    key_storage_config
                        .create()
                        .await
                        .expect("require keystore for integration tests"),
                ));

                spawn_recovery_server_and_run_onboarding(
                    self.config.migration_web_ui.clone(),
                    (&self.secrets).into(),
                    self.config.my_near_account_id.clone(),
                    keystore.clone(),
                    self.indexer.my_migration_info_receiver.clone(),
                    self.indexer.contract_state_receiver.clone(),
                    self.indexer.txn_sender.clone(),
                )
                .await
                .unwrap();

                let coordinator = Coordinator {
                    clock: self.clock,
                    config_file: self.config,
                    secrets: self.secrets,
                    secret_db,
                    keyshare_storage: RwLock::new(key_storage_config.create().await.unwrap())
                        .into(),
                    indexer: self.indexer,
                    currently_running_job_name: self.currently_running_job_name,
                    debug_request_sender,
                };
                coordinator.run().await
            };
            start_root_task(&format!("root for {}", my_account_id), root_future)
                .0
                .await?;
            Ok(())
        }
        .await
    }
}

/// Test fixture for integration tests, includes a fake indexer and a set of
/// nodes.
pub struct IntegrationTestSetup {
    pub indexer: FakeIndexerManager,
    pub configs: Vec<OneNodeTestConfig>,
    pub participants: ParticipantsConfig,
}

impl IntegrationTestSetup {
    /// Generates test node configs and a fake indexer; each config can then be used
    /// to start running the node.
    pub fn new(
        clock: Clock,
        temp_dir: &Path,
        participant_accounts: Vec<AccountId>,
        threshold: usize,
        txn_delay_blocks: u64,
        port_seed: PortSeed,
        block_time: std::time::Duration,
    ) -> IntegrationTestSetup {
        let p2p_configs =
            generate_test_p2p_configs(&participant_accounts, threshold, port_seed, None).unwrap();
        let participants = p2p_configs[0].0.participants.clone();
        let mut indexer_manager =
            FakeIndexerManager::new(clock.clone(), txn_delay_blocks, block_time);

        let mut configs = Vec::new();
        for (i, (_, p2p_key)) in p2p_configs.into_iter().enumerate() {
            let config = ConfigFile {
                cores: Some(4),
                // Indexer config is just a dummy.
                indexer: IndexerConfig {
                    concurrency: 1.try_into().unwrap(),
                    finality: Finality::Final,
                    mpc_contract_id: "test".parse().unwrap(),
                    port_override: None,
                    sync_mode: SyncMode::Latest,
                    validate_genesis: false,
                },
                keygen: KeygenConfig { timeout_sec: 60 },
                my_near_account_id: participant_accounts[i].clone(),
                // Don't care since we use the fake indexer
                near_responder_account_id: AccountId::from_str("dont_care").unwrap(),
                presignature: PresignatureConfig {
                    concurrency: 1,
                    desired_presignatures_to_buffer: 5,
                    timeout_sec: 60,
                },
                signature: SignatureConfig { timeout_sec: 60 },
                ckd: CKDConfig { timeout_sec: 60 },
                triple: TripleConfig {
                    concurrency: 1,
                    desired_triples_to_buffer: 10,
                    parallel_triple_generation_stagger_time_sec: 1,
                    timeout_sec: 60,
                },
                web_ui: WebUIConfig {
                    host: "0.0.0.0".to_string(),
                    port: port_seed.web_port(i),
                },
                number_of_responder_keys: 0,
                migration_web_ui: WebUIConfig {
                    host: "0.0.0.0".to_string(),
                    port: port_seed.migration_web_port(i),
                },
            };
            let secrets = SecretsConfig {
                persistent_secrets: PersistentSecrets {
                    p2p_private_key: p2p_key.clone(),
                    near_signer_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
                    near_responder_keys: vec![ed25519_dalek::SigningKey::generate(&mut OsRng)],
                },
                local_storage_aes_key: rand::random(),
                backup_encryption_key: Aes256Gcm::generate_key(OsRng).into(),
            };
            let (indexer_api, task, currently_running_job_name) = indexer_manager.add_indexer_node(
                i.into(),
                participant_accounts[i].clone(),
                p2p_key.verifying_key(),
            );
            configs.push(OneNodeTestConfig {
                clock: clock.clone(),
                config,
                home_dir: temp_dir.join(format!("{}", i)),
                secrets,
                indexer: indexer_api,
                _indexer_task: task,
                currently_running_job_name,
            });
        }
        IntegrationTestSetup {
            indexer: indexer_manager,
            configs,
            participants,
        }
    }

    pub fn get_config(&self, node_index: usize) -> Option<&OneNodeTestConfig> {
        self.configs.get(node_index)
    }
}
/// Request a signature from the indexer and wait for the response.
/// Returns the time taken to receive the response, or None if timed out.
pub async fn request_signature_and_await_response(
    indexer: &mut FakeIndexerManager,
    user: &str,
    domain: &DomainConfig,
    timeout_sec: std::time::Duration,
) -> Option<std::time::Duration> {
    let payload = match domain.scheme {
        SignatureScheme::Secp256k1 => {
            let mut payload = [0; 32];
            rand::thread_rng().fill_bytes(payload.as_mut());
            Payload::Ecdsa(Bytes::new(payload.to_vec()).unwrap())
        }
        SignatureScheme::Ed25519 => {
            let len = rand::thread_rng().gen_range(32..1232);
            let mut payload = vec![0; len];
            rand::thread_rng().fill_bytes(payload.as_mut());
            Payload::Eddsa(Bytes::new(payload.to_vec()).unwrap())
        }
        SignatureScheme::Bls12381 => unreachable!(),
    };
    let request = SignatureRequestFromChain {
        entropy: rand::random(),
        signature_id: CryptoHash(rand::random()),
        receipt_id: CryptoHash(rand::random()),
        predecessor_id: user.parse().unwrap(),
        timestamp_nanosec: rand::random(),
        request: SignArgs {
            domain_id: domain.id,
            path: "m/44'/60'/0'/0/0".to_string(),
            payload,
        },
    };
    tracing::info!(
        "Sending signature request from user {}, payload {:?}",
        user,
        request.request.payload
    );
    indexer.request_signature(request.clone());
    let start_time = std::time::Instant::now();
    loop {
        match timeout(timeout_sec, indexer.next_response()).await {
            Ok(signature) => {
                if signature.request.payload != request.request.payload {
                    // This can legitimately happen when multiple nodes submit responses
                    // for the same signature request. In tests this can happen if the
                    // secondary leader thinks the primary leader is offline when in fact
                    // the network just has not yet been fully established.
                    tracing::info!(
                        "Received signature is not for the signature request we sent (user {})
                         Expected {:?}, actual {:?}",
                        user,
                        request.request.payload,
                        signature.request.payload
                    );
                    continue;
                }
                if signature.request.domain_id != domain.id {
                    tracing::info!(
                        "Received signature is not for the domain we requested (user {})
                         Expected {:?}, actual {:?}",
                        user,
                        domain.id,
                        signature.request.domain_id
                    );
                    continue;
                }
                tracing::info!("Got signature response for user {}", user);
                return Some(start_time.elapsed());
            }
            Err(_) => {
                tracing::info!("Timed out waiting for signature response for user {}", user);
                return None;
            }
        }
    }
}

/// Request a ckd from the indexer and wait for the response.
/// Returns the time taken to receive the response, or None if timed out.
pub async fn request_ckd_and_await_response(
    indexer: &mut FakeIndexerManager,
    user: &str,
    domain: &DomainConfig,
    timeout_sec: std::time::Duration,
) -> Option<std::time::Duration> {
    assert_matches!(
        domain.scheme,
        SignatureScheme::Bls12381,
        "`request_ckd_and_await_response` must be called with a compatible domain",
    );
    let request = CKDRequestFromChain {
        ckd_id: CryptoHash(rand::random()),
        receipt_id: CryptoHash(rand::random()),
        predecessor_id: user.parse().unwrap(),
        entropy: rand::random(),
        timestamp_nanosec: rand::random(),
        request: CKDArgs {
            app_public_key:
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            domain_id: domain.id,
            app_id: user.parse().unwrap(),
        },
    };
    tracing::info!(
        "Sending ckd request from user {}, app_id {:?}, app_public_key {:?}",
        user,
        request.request.app_id,
        request.request.app_public_key,
    );
    indexer.request_ckd(request.clone());
    let start_time = std::time::Instant::now();
    loop {
        match timeout(timeout_sec, indexer.next_response_ckd()).await {
            Ok(ckd_response_args) => {
                if ckd_response_args.request.app_id != request.request.app_id {
                    // This can legitimately happen when multiple nodes submit responses
                    // for the same ckd request. In tests this can happen if the
                    // secondary leader thinks the primary leader is offline when in fact
                    // the network just has not yet been fully established.
                    tracing::info!(
                        "Received ckd is not for the ckd request we sent (user {})
                         Expected {:?}, actual {:?}",
                        user,
                        request.request.app_id,
                        ckd_response_args.request.app_id
                    );
                    continue;
                }
                if ckd_response_args.request.domain_id != domain.id {
                    tracing::info!(
                        "Received ckd is not for the domain we requested (user {})
                         Expected {:?}, actual {:?}",
                        user,
                        domain.id,
                        ckd_response_args.request.domain_id
                    );
                    continue;
                }
                if ckd_response_args.request.app_public_key != request.request.app_public_key {
                    tracing::info!(
                        "Received ckd is not for the app_public_key we requested (user {})
                         Expected {:?}, actual {:?}",
                        user,
                        request.request.app_public_key,
                        ckd_response_args.request.app_public_key
                    );
                    continue;
                }
                tracing::info!("Got response ckd for user {}", user);
                return Some(start_time.elapsed());
            }
            Err(_) => {
                tracing::info!("Timed out waiting for ckd response for user {}", user);
                return None;
            }
        }
    }
}

pub fn into_participant_ids(
    test_generator: &threshold_signatures::test_utils::TestGenerators,
) -> Vec<ParticipantId> {
    test_generator
        .participants
        .iter()
        .map(|p| (*p).into())
        .collect()
}

#[test]
fn test_build_info_metric() {
    // Test that the build info metric can be initialized without panicking
    crate::metrics::init_build_info_metric();

    // Verify that the built crate information is available
    let version = crate::built_info::PKG_VERSION;
    let build_time = crate::built_info::BUILT_TIME_UTC;
    let commit = crate::built_info::GIT_COMMIT_HASH_SHORT.unwrap_or("unknown");
    let rustc_version = crate::built_info::RUSTC_VERSION;

    // Verify that the version information is not "unknown"
    assert_ne!(version, "unknown", "PKG_VERSION should be set");
    assert_ne!(build_time, "unknown", "BUILT_TIME_UTC should be set");
    assert_ne!(commit, "unknown", "GIT_COMMIT_HASH_SHORT should be set");
    assert_ne!(rustc_version, "unknown", "RUSTC_VERSION should be set");

    // Verify that the version string contains all the expected information
    let version_string = &*crate::MPC_VERSION_STRING;
    assert!(version_string.contains(version));
    assert!(version_string.contains(build_time));
    assert!(version_string.contains(commit));
    assert!(version_string.contains(rustc_version));
}

#[test]
fn test_build_info_metric_initialization() {
    // Test that the build info metric can be initialized without panicking
    // This verifies that the compile-time constants are accessible
    crate::metrics::init_build_info_metric();

    // If we get here without panicking, the test passes
    // The metric should now be available in Prometheus with the correct values
}

#[test]
fn test_build_info_metric_values() {
    // Test that the build info metric has the correct values
    crate::metrics::init_build_info_metric();

    // Get the metric value directly
    let metric = &crate::metrics::MPC_BUILD_INFO;
    let version = crate::built_info::PKG_VERSION;
    let build_time = crate::built_info::BUILT_TIME_UTC;
    let commit = crate::built_info::GIT_COMMIT_HASH_SHORT.unwrap_or("unknown");
    let rustc_version = crate::built_info::RUSTC_VERSION;

    // Check that the metric exists with the correct labels
    let gauge = metric.with_label_values(&[version, build_time, commit, rustc_version]);
    let value = gauge.get();

    println!("Metric value: {}", value);
    println!(
        "Expected labels: version={}, build_time={}, commit={}, rustc_version={}",
        version, build_time, commit, rustc_version
    );

    // The value should be 1
    assert_eq!(value, 1);
}
