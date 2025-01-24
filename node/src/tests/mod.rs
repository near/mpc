use cait_sith::protocol::{run_protocol, Participant, Protocol};
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{FullSignature, KeygenOutput, PresignArguments, PresignOutput};
use k256::{AffinePoint, Scalar, Secp256k1};
use std::collections::HashMap;

use crate::config::{
    ConfigFile, IndexerConfig, KeygenConfig, PresignatureConfig, SecretsConfig, SignatureConfig,
    SyncMode, TripleConfig, WebUIConfig,
};
use crate::coordinator::Coordinator;
use crate::db::SecretDB;
use crate::indexer::fake::FakeIndexerManager;
use crate::indexer::handler::{ChainSignatureRequest, SignArgs};
use crate::indexer::IndexerAPI;
use crate::keyshare::KeyshareStorageFactory;
use crate::p2p::testing::generate_test_p2p_configs;
use crate::tracking::{self, start_root_task, AutoAbortTask};
use crate::web::start_web_server;
use k256::elliptic_curve::Field;
use near_indexer_primitives::types::Finality;
use near_sdk::AccountId;
use near_time::{Clock, Duration};
use std::path::{Path, PathBuf};
use tokio::time::timeout;

mod basic_cluster;
mod benchmark;
mod faulty;
mod research;

/// Convenient test utilities to generate keys, triples, presignatures, and signatures.
pub struct TestGenerators {
    num_participants: usize,
    threshold: usize,
}

type ParticipantAndProtocol<T> = (Participant, Box<dyn Protocol<Output = T>>);

impl TestGenerators {
    pub fn new(num_participants: usize, threshold: usize) -> Self {
        Self {
            num_participants,
            threshold,
        }
    }

    pub fn make_keygens(&self) -> HashMap<Participant, KeygenOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<KeygenOutput<Secp256k1>>> = Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::keygen::<Secp256k1>(&participants, participants[i], self.threshold)
                        .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_triples(&self) -> HashMap<Participant, TripleGenerationOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<TripleGenerationOutput<Secp256k1>>> =
            Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::triples::generate_triple::<Secp256k1>(
                        &participants,
                        participants[i],
                        self.threshold,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_presignatures(
        &self,
        triple0s: &HashMap<Participant, TripleGenerationOutput<Secp256k1>>,
        triple1s: &HashMap<Participant, TripleGenerationOutput<Secp256k1>>,
        keygens: &HashMap<Participant, KeygenOutput<Secp256k1>>,
    ) -> HashMap<Participant, PresignOutput<Secp256k1>> {
        let mut protocols: Vec<ParticipantAndProtocol<PresignOutput<Secp256k1>>> = Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::presign::<Secp256k1>(
                        &participants,
                        participants[i],
                        &participants,
                        participants[i],
                        PresignArguments {
                            triple0: triple0s[&participants[i]].clone(),
                            triple1: triple1s[&participants[i]].clone(),
                            keygen_out: keygens[&participants[i]].clone(),
                            threshold: self.threshold,
                        },
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols).unwrap().into_iter().collect()
    }

    pub fn make_signature(
        &self,
        presignatures: &HashMap<Participant, PresignOutput<Secp256k1>>,
        public_key: AffinePoint,
        msg_hash: Scalar,
    ) -> FullSignature<Secp256k1> {
        let mut protocols: Vec<ParticipantAndProtocol<FullSignature<Secp256k1>>> = Vec::new();
        let participants = (0..self.num_participants)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..self.num_participants {
            protocols.push((
                participants[i],
                Box::new(
                    cait_sith::sign::<Secp256k1>(
                        &participants,
                        participants[i],
                        public_key,
                        presignatures[&participants[i]].clone(),
                        msg_hash,
                    )
                    .unwrap(),
                ),
            ));
        }
        run_protocol(protocols)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .1
    }
}

// pub async fn wait_till_tcp_port_free(port: u16) {
//     let mut retries_left = 20;
//     while retries_left > 0 {
//         tracing::info!("Waiting for TCP port {} to be free...", port);
//         let result = std::net::TcpListener::bind(format!("127.0.0.1:{}", port));
//         if result.is_ok() {
//             break;
//         }
//         tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
//         retries_left -= 1;
//     }
//     tracing::info!("TCP Port {} is free", port);
//     assert!(retries_left > 0, "Failed to free TCP port {}", port);
// }

// pub async fn free_resources_after_shutdown(config: &ConfigFile) {
//     let web = wait_till_tcp_port_free(config.web_ui.port);
//     let p2p_port = config
//         .participants
//         .as_ref()
//         .unwrap()
//         .participants
//         .iter()
//         .find(|participant| participant.near_account_id == config.my_near_account_id)
//         .unwrap()
//         .port;
//     let p2p = wait_till_tcp_port_free(p2p_port);
//     futures::future::join(web, p2p).await;
// }

pub struct OneNodeTestConfig {
    clock: Clock,
    home_dir: PathBuf,
    pub config: ConfigFile,
    secrets: SecretsConfig,
    indexer: IndexerAPI,
    indexer_task: AutoAbortTask<()>,
}

impl OneNodeTestConfig {
    pub async fn run(self) -> anyhow::Result<()> {
        let OneNodeTestConfig {
            clock,
            home_dir,
            config,
            secrets,
            indexer,
            indexer_task: _indexer_task,
        } = self;
        std::fs::create_dir_all(&home_dir)?;
        async move {
            let root_future = async move {
                let root_task_handle = tracking::current_task();
                let _web_server = start_web_server(root_task_handle, config.web_ui.clone()).await?;

                let secret_db = SecretDB::new(&home_dir, secrets.local_storage_aes_key)?;

                let keyshare_storage_factory = KeyshareStorageFactory::Local {
                    home_dir: home_dir.clone(),
                    encryption_key: secrets.local_storage_aes_key,
                };

                let coordinator = Coordinator {
                    clock,
                    config_file: config,
                    secrets,
                    secret_db,
                    keyshare_storage_factory,
                    indexer,
                };
                coordinator.run().await
            };
            start_root_task(root_future).0.await?;
            Ok(())
        }
        .await
    }
}

pub fn generate_test_configs_with_fake_indexer(
    clock: Clock,
    temp_dir: &Path,
    participant_accounts: Vec<AccountId>,
    threshold: usize,
    txn_delay: Duration,
    port_seed: u16,
) -> (FakeIndexerManager, Vec<OneNodeTestConfig>) {
    let p2p_configs =
        generate_test_p2p_configs(&participant_accounts, threshold, port_seed).unwrap();
    let participants = p2p_configs[0].0.participants.clone();
    let mut indexer_manager = FakeIndexerManager::new(clock.clone(), participants, txn_delay);

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
            keygen: KeygenConfig { timeout_sec: 10 },
            my_near_account_id: participant_accounts[i].clone(),
            presignature: PresignatureConfig {
                concurrency: 2,
                desired_presignatures_to_buffer: 100,
                timeout_sec: 10,
            },
            signature: SignatureConfig { timeout_sec: 10 },
            triple: TripleConfig {
                concurrency: 1,
                desired_triples_to_buffer: 1000,
                parallel_triple_generation_stagger_time_sec: 1,
                timeout_sec: 10,
            },
            web_ui: WebUIConfig {
                host: "0.0.0.0".to_string(),
                port: (port_seed as u64 * 1000 + 20000 + i as u64)
                    .try_into()
                    .unwrap(),
            },
        };
        let secrets = SecretsConfig {
            local_storage_aes_key: rand::random(),
            p2p_private_key: p2p_key,
        };
        let (indexer_api, task) = indexer_manager.add_indexer_node(participant_accounts[i].clone());
        configs.push(OneNodeTestConfig {
            clock: clock.clone(),
            config,
            home_dir: temp_dir.join(format!("{}", i)),
            secrets,
            indexer: indexer_api,
            indexer_task: task,
        });
    }
    (indexer_manager, configs)
}

/// Request a signature from the indexer and wait for the response.
/// Returns true iff the response was received within the timeout.
pub async fn request_signature_and_await_response(
    indexer: &mut FakeIndexerManager,
    user: &str,
    timeout_sec: u64,
) -> bool {
    tracing::info!("Sending signature request from user {}", user);
    let request = ChainSignatureRequest {
        entropy: rand::random(),
        request_id: rand::random(),
        predecessor_id: user.parse().unwrap(),
        timestamp_nanosec: rand::random(),
        request: SignArgs {
            key_version: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            payload: Scalar::random(&mut rand::thread_rng()),
        },
    };
    indexer.request_signature(request.clone());
    match timeout(
        std::time::Duration::from_secs(timeout_sec),
        indexer.next_response(),
    )
    .await
    {
        Ok(_) => {
            tracing::info!("Got signature response for user {}", user);
            true
        }
        Err(_) => {
            tracing::info!("Timed out waiting for signature respnse for user {}", user);
            false
        }
    }
}
