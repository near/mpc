use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use mpc_node_config::{
    CKDConfig, ConfigFile, ForeignChainsConfig, IndexerConfig, KeygenConfig, SignatureConfig,
    SyncMode, TripleBatchSize, TripleConfig,
};
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::Finality;
use near_mpc_contract_interface::types as dtos;
use near_time::{Clock, FakeClock};

use crate::config::{MpcConfig, ParticipantInfo, ParticipantsConfig};
use crate::db::SecretDB;
use crate::network::MeshNetworkClient;
use crate::primitives::ParticipantId;
use crate::providers::EcdsaSignatureProvider;
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::outcome_signing_key;
use crate::providers::verify_foreign_tx::open_requests::OpenVerifyForeignTxRequestsV2;
use crate::providers::verify_foreign_tx::open_requests::test_chain::TestChain;
use crate::providers::verify_foreign_tx::{VerifyForeignTxProvider, VerifyForeignTxV2Context};
use crate::storage::{SignRequestStorage, VerifyForeignTransactionRequestStorage};
use crate::types::VerifyForeignTxRequestV2;

/// A [`VerifyForeignTxProvider`] without keyshares, RPC providers or a whitelist, where the
/// given supporters support Bitcoin. Its database and indexed blocks live as long as it does.
pub(crate) struct TestProvider {
    pub(crate) provider: VerifyForeignTxProvider,
    _db_dir: tempfile::TempDir,
    _chain: TestChain,
}

impl TestProvider {
    /// The provider of the node of `network`, which indexed [`bitcoin_request`] `since_indexed`
    /// ago.
    pub(crate) fn with_open_request(
        network: Arc<MeshNetworkClient>,
        since_indexed: near_time::Duration,
        supporters: HashSet<ParticipantId>,
    ) -> Self {
        let clock = FakeClock::default();
        let open_requests = Arc::new(OpenVerifyForeignTxRequestsV2::new(clock.clock()));
        let mut chain = TestChain::starting_at(BlockHeight::new(999));
        open_requests.notify_new_block(&chain.extend(vec![bitcoin_request()], vec![]));
        clock.advance(since_indexed);
        Self::new(network, open_requests, chain, supporters)
    }

    /// The provider of the node of `network`, which indexed no request.
    pub(crate) fn without_requests(
        network: Arc<MeshNetworkClient>,
        supporters: HashSet<ParticipantId>,
    ) -> Self {
        let chain = TestChain::starting_at(BlockHeight::new(999));
        Self::new(network, Arc::default(), chain, supporters)
    }

    fn new(
        network: Arc<MeshNetworkClient>,
        open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
        chain: TestChain,
        supporters: HashSet<ParticipantId>,
    ) -> Self {
        let me = network.my_participant_id();
        let config = Arc::new(config());
        let db_dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(db_dir.path(), [1; 16]).unwrap();
        let ecdsa_signature_provider = Arc::new(
            EcdsaSignatureProvider::new(
                config.clone(),
                Arc::new(MpcConfig {
                    my_participant_id: me,
                    participants: participants_config(&network.all_participant_ids()),
                }),
                network.clone(),
                Clock::real(),
                db.clone(),
                Arc::new(SignRequestStorage::new(db.clone()).unwrap()),
                HashMap::new(),
            )
            .unwrap(),
        );
        let provider = VerifyForeignTxProvider::new(
            config,
            tokio::sync::watch::channel(BTreeMap::from([(
                dtos::ForeignChain::Bitcoin,
                supporters,
            )]))
            .1,
            tokio::sync::watch::channel(BTreeMap::new()).1,
            Some(1),
            Arc::new(VerifyForeignTransactionRequestStorage::new(db).unwrap()),
            ecdsa_signature_provider,
            VerifyForeignTxV2Context {
                open_requests,
                signing_key: outcome_signing_key(me),
                network,
            },
        )
        .unwrap();
        Self {
            provider,
            _db_dir: db_dir,
            _chain: chain,
        }
    }
}

/// A V2 request for a Bitcoin transaction.
pub(crate) fn bitcoin_request() -> VerifyForeignTxRequestV2 {
    VerifyForeignTxRequestV2 {
        id: CryptoHash([1; 32]),
        receipt_id: CryptoHash([2; 32]),
        yield_id: dtos::YieldId([3; 32]),
        request_block_height: BlockHeight::new(1000),
        request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(1),
            extractors: [dtos::BitcoinExtractor::BlockHash].into(),
        }),
        domain_id: DomainId(0),
        expected_values_hash: dtos::Hash256([4; 32]),
        entropy: [0; 32],
        timestamp_nanosec: 0,
    }
}

fn participants_config(participants: &[ParticipantId]) -> ParticipantsConfig {
    ParticipantsConfig {
        threshold: 2,
        participants: participants
            .iter()
            .map(|id| ParticipantInfo {
                id: *id,
                address: Ipv4Addr::LOCALHOST.to_string(),
                port: 3000,
                p2p_public_key: SigningKey::from_bytes(&[7; 32]).verifying_key(),
                near_account_id: format!("p{}.near", id.raw()).parse().unwrap(),
            })
            .collect(),
    }
}

fn config() -> ConfigFile {
    ConfigFile {
        my_near_account_id: "test.near".parse().unwrap(),
        web_ui: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        migration_web_ui: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        pprof_bind_address: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        indexer: IndexerConfig {
            concurrency: 1.try_into().unwrap(),
            finality: Finality::Final,
            mpc_contract_id: "mpc.test.near".parse().unwrap(),
            port_override: None,
            wipe_near_data_token: 0,
            sync_mode: SyncMode::Latest,
            validate_genesis: false,
        },
        triple: TripleConfig {
            concurrency: 1,
            desired_triples_to_buffer: 0,
            parallel_triple_generation_stagger_time_sec: 1,
            timeout_sec: 120,
            batch_size: TripleBatchSize::default(),
        },
        signature: SignatureConfig { timeout_sec: 60 },
        ckd: CKDConfig { timeout_sec: 60 },
        keygen: KeygenConfig { timeout_sec: 60 },
        foreign_chains: ForeignChainsConfig::default(),
        cores: None,
        separate_asset_generation_runtime: false,
    }
}
