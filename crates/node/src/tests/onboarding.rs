use std::path::PathBuf;
use std::time::Duration;

use crate::config::{AesKey256, NodeStatus, ParticipantInfo, ParticipantStatus};
use crate::indexer::fake::participant_info_from_config;
use crate::indexer::participants::ContractState;
use crate::migration_service;
use crate::p2p::testing::PortSeed;
use crate::providers::PublicKeyConversion;
use crate::tests::DEFAULT_BLOCK_TIME;
use crate::tests::{
    get_keyshares, request_signature_and_await_response, IntegrationTestSetup,
    DEFAULT_MAX_PROTOCOL_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use mpc_contract::state::ProtocolContractState;
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;
use rand::rngs::OsRng;

use super::OneNodeTestConfig;

struct MigrationTestNodeInfo {
    participant_info: ParticipantInfo,
    home_dir: PathBuf,
    storage_key: [u8; 16],
    migration_service_addr: String,
    p2p_public_key: VerifyingKey,
    near_signer_key: VerifyingKey,
    backup_service_key: AesKey256,
}

impl MigrationTestNodeInfo {
    pub fn new(config: &OneNodeTestConfig, participant_info: ParticipantInfo) -> Self {
        let migration_service_addr = {
            let migration_web_ui = &config.config.migration_web_ui;
            format!("{}:{}", migration_web_ui.host, migration_web_ui.port)
        };

        let p2p_public_key = config
            .secrets
            .persistent_secrets
            .p2p_private_key
            .verifying_key();
        let near_signer_key = config
            .secrets
            .persistent_secrets
            .near_signer_key
            .verifying_key();
        Self {
            participant_info,
            home_dir: config.home_dir.clone(),
            storage_key: config.secrets.local_storage_aes_key,
            migration_service_addr,
            p2p_public_key,
            near_signer_key,
            backup_service_key: config.secrets.backup_encryption_key,
        }
    }
}

/// Runs a cluster of 3 nodes, but with only 2 participants.
/// Two nodes of the cluster are assigned the same account id.
/// Each node has its own home directory and tls key.
/// After the conclusion of the key initialization and passing of a sanity check, the participant
/// set will be forcefully changed.
#[tokio::test]
async fn test_onboarding() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 2;
    const THRESHOLD: usize = 2;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut account_ids: Vec<_> = (0..NUM_PARTICIPANTS)
        .map(|i| format!("test{}", i).parse().unwrap())
        .collect();
    account_ids.push(format!("test{}", 0).parse().unwrap());
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        account_ids,
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::ONBOARDING_TEST,
        DEFAULT_BLOCK_TIME,
    );

    const PARTING_NODE_ID: usize = 0;
    const DESTINATION_NODE_ID: usize = NUM_PARTICIPANTS;
    let all_participants = setup.participants.participants.clone();
    let leaving_node = MigrationTestNodeInfo::new(
        setup.get_config(PARTING_NODE_ID).unwrap(),
        all_participants.get(PARTING_NODE_ID).unwrap().clone(),
    );

    let onboarding_node = MigrationTestNodeInfo::new(
        setup.get_config(DESTINATION_NODE_ID).unwrap(),
        all_participants.get(DESTINATION_NODE_ID).unwrap().clone(),
    );
    let destination_node_info = participant_info_from_config(&onboarding_node.participant_info);
    // Initialize the contract with the first two nodes
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    let domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(initial_participants);
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timout waiting for running state");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    {
        tracing::info!("sanity checking test setup");
        let ProtocolContractState::Running(running) =
            setup.indexer.contract_mut().await.state.clone()
        else {
            panic!("expect running")
        };
        let found_init_partcipants = running.parameters.participants();
        let init_participant_info = found_init_partcipants
            .info(&onboarding_node.participant_info.near_account_id)
            .unwrap();

        let expected_info = participant_info_from_config(&leaving_node.participant_info);
        assert_eq!(init_participant_info, &expected_info);
        assert_ne!(init_participant_info, &destination_node_info);
    }

    let backup_service_key = SigningKey::generate(&mut OsRng);
    {
        tracing::info!("Setting backup and destination node info");
        let mut contract = setup.indexer.contract_mut().await;
        assert!(matches!(&contract.state, ProtocolContractState::Running(_)));
        let backup_service_info = BackupServiceInfo {
            public_key: backup_service_key
                .verifying_key()
                .into_contract_interface_type(),
        };
        contract.migration_service.set_backup_service_info(
            onboarding_node.participant_info.near_account_id.clone(),
            backup_service_info,
        );
        contract.migration_service.set_destination_node_info(
            onboarding_node.participant_info.near_account_id.clone(),
            DestinationNodeInfo {
                signer_account_pk: onboarding_node
                    .near_signer_key
                    .to_near_sdk_public_key()
                    .unwrap(),
                destination_node_info: destination_node_info.clone(),
            },
        );
    }

    setup
        .indexer
        .wait_for_migration_state(
            |state| {
                state
                    .get(&onboarding_node.participant_info.near_account_id)
                    .is_some_and(|(backup_service_info, destination_node_info)| {
                        backup_service_info.is_some() && destination_node_info.is_some()
                    })
            },
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let keyset = {
        let ProtocolContractState::Running(running) = &setup.indexer.contract_mut().await.state
        else {
            panic!("expect running");
        };
        running.keyset.clone()
    };
    let received_keyshares = {
        tracing::info!("Fetching keyshares from parting node.");
        let mut request_sender = migration_service::web::client::connect_to_web_server(
            &backup_service_key,
            leaving_node.migration_service_addr,
            &leaving_node.p2p_public_key,
        )
        .await
        .unwrap();
        let keyshares = migration_service::web::client::make_keyshare_get_request(
            &mut request_sender,
            &keyset,
            &leaving_node.backup_service_key,
        )
        .await
        .unwrap();
        let expected = get_keyshares(leaving_node.home_dir, leaving_node.storage_key, &keyset)
            .await
            .unwrap();
        assert_eq!(keyshares, expected);
        tracing::info!("Received keyshares from parting node.");
        keyshares
    };

    {
        tracing::info!("Sending keyshares to onboarding node");
        let mut request_sender = migration_service::web::client::connect_to_web_server(
            &backup_service_key,
            onboarding_node.migration_service_addr.clone(),
            &onboarding_node.p2p_public_key,
        )
        .await
        .unwrap();
        migration_service::web::client::make_set_keyshares_request(
            &mut request_sender,
            &received_keyshares.clone(),
            &onboarding_node.backup_service_key,
        )
        .await
        .unwrap();
        tracing::info!("Sent keyshares to onboarding node");
    }

    setup
        .indexer
        .wait_for_contract_state(
            |state| {
                matches!(
                    state.node_status(
                        &onboarding_node.participant_info.near_account_id,
                        &onboarding_node.p2p_public_key
                    ),
                    ParticipantStatus::Active(NodeStatus::Active)
                )
            },
            Duration::from_secs(60),
        )
        .await
        .expect("onboarding must succeed");
    {
        tracing::info!("verifying keyshares on disk match expected value");
        let found = get_keyshares(
            onboarding_node.home_dir,
            onboarding_node.storage_key,
            &keyset,
        )
        .await
        .unwrap();
        assert_eq!(received_keyshares, found);
    }

    let ProtocolContractState::Running(running) = setup.indexer.contract_mut().await.state.clone()
    else {
        panic!("expect running")
    };

    tracing::info!("checking participant info is correct");
    let found_partcipants = running.parameters.participants();
    let current_participant_info = found_partcipants
        .info(&onboarding_node.participant_info.near_account_id)
        .unwrap();
    assert_eq!(*current_participant_info, destination_node_info);

    tracing::info!("disabling departed node");
    setup.indexer.disable(0.into()).await;

    tracing::info!("sending signature requests as a sanity check");
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user2",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user3",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}
