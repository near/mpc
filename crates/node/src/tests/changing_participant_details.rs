use crate::indexer::fake::participant_info_from_config;
use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    get_keyshares, request_signature_and_await_response, IntegrationTestSetup,
    DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
};
use crate::tests::{make_key_storage_config, DEFAULT_BLOCK_TIME};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use mpc_contract::state::ProtocolContractState;
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;

/// Runs a cluster of 3 nodes, but with only 2 participants.
/// Two nodes of the cluster are assigned the same account id.
/// Each node has its own home directory and tls key.
/// After the conclusion of the key initialization and passing of a sanity check, the participant
/// set will be forcefully changed.
#[tokio::test]
async fn test_changing_participant_set_test_keyshare_import() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 2;
    const THRESHOLD: usize = 2;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut account_ids: Vec<_> = (0..NUM_PARTICIPANTS)
        .map(|i| format!("test{i}").parse().unwrap())
        .collect();
    account_ids.push(format!("test{}", 0).parse().unwrap());
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        account_ids,
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::RECOVERY_TEST,
        DEFAULT_BLOCK_TIME,
    );

    let home_dir_first = setup.configs.first().unwrap().home_dir.clone();
    let local_encryption_key_first = setup.configs.first().unwrap().secrets.local_storage_aes_key;
    let home_dir_last = setup.configs.last().unwrap().home_dir.clone();
    let local_encryption_key_last = setup.configs.last().unwrap().secrets.local_storage_aes_key;

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
        .expect("Timeout waiting for resharing to complete");
    tracing::info!("we are in running state");

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
    )
    .await
    .is_some());
    tracing::info!("we are in running state");

    {
        // we move the keyset from the first node to the last node.
        let contract = setup.indexer.contract_mut().await;
        let ProtocolContractState::Running(running) = &contract.state else {
            panic!("done");
        };
        let keyset = &running.keyset;
        let keyshares = get_keyshares(home_dir_first, local_encryption_key_first, keyset)
            .await
            .unwrap();

        // test keyshare import
        std::fs::create_dir_all(&home_dir_last).unwrap();
        let key_storage_config = make_key_storage_config(home_dir_last, local_encryption_key_last);
        let mut keystore = key_storage_config.create().await.unwrap();
        keystore.import_backup(keyshares, keyset).await.unwrap();
    }

    // finally, change the participant info. Remove the first node and insert the last node.
    let p_config_info = setup.participants.participants.last().unwrap();
    let p_info = participant_info_from_config(p_config_info);
    setup
        .indexer
        .contract_mut()
        .await
        .update_participant_info(p_config_info.near_account_id.clone(), p_info);

    // as a precaution, disable the first node
    setup.indexer.disable(0.into()).await;

    // Sanity check. Since we are in full-threshold, we have confirmation that the new node is up
    // and running.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
    )
    .await
    .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user2",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
    )
    .await
    .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user3",
        &domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME
    )
    .await
    .is_some());
}
