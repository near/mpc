use crate::p2p::testing::port_seed;
use crate::tests::{DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, IntegrationTestSetup};
use crate::tracking::AutoAbortTask;
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Ed25519PublicKey, OutcomeKeys, Protocol,
    ReconstructionThreshold,
};
use near_time::Clock;
use std::collections::BTreeMap;

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn outcome_key_registrar__should_register_the_persisted_outcome_key_of_each_node() {
    // Given
    const GOVERNANCE_THRESHOLD: usize = 2;
    const RECONSTRUCTION_THRESHOLD: u64 = 2;
    const TXN_DELAY_BLOCKS: u64 = 1;

    let temp_dir = tempfile::tempdir().unwrap();
    let setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        vec!["test0".parse().unwrap(), "test1".parse().unwrap()],
        GOVERNANCE_THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::OUTCOME_KEY_REGISTRATION_TEST,
        DEFAULT_BLOCK_TIME,
    );
    let expected: OutcomeKeys = setup
        .configs
        .iter()
        .map(|node| {
            (
                node.config.my_near_account_id.clone(),
                Ed25519PublicKey::from(
                    &node
                        .secrets
                        .persistent_secrets
                        .outcome_signing_key
                        .verifying_key(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>()
        .into();
    let tls_keys: Vec<Ed25519PublicKey> = setup
        .configs
        .iter()
        .map(|node| {
            Ed25519PublicKey::from(
                &node
                    .secrets
                    .persistent_secrets
                    .p2p_private_key
                    .verifying_key(),
            )
        })
        .collect();
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![DomainConfig {
            id: DomainId(0),
            protocol: Protocol::CaitSith,
            reconstruction_threshold: ReconstructionThreshold::new(RECONSTRUCTION_THRESHOLD),
            purpose: DomainPurpose::ForeignTx,
        }]);
    }

    // When
    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();
    let registered = tokio::time::timeout(DEFAULT_MAX_PROTOCOL_WAIT_TIME, async {
        loop {
            let keys = setup.indexer.contract_mut().await.outcome_keys().clone();
            if keys.len() == expected.len() {
                break keys;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("timed out waiting for every node to register an outcome key");

    // Then
    assert_eq!(registered, expected);
    assert!(
        registered.values().all(|key| !tls_keys.contains(key)),
        "a node registered its TLS key as outcome key"
    );
}
